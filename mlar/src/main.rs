use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use glob::Pattern;
use humansize::{DECIMAL, FormatSize};
use lru::LruCache;
use mla::config::{
    ArchiveReaderConfig, ArchiveWriterConfig, TruncatedReaderConfig, TruncatedReaderDecryptionMode,
};
use mla::crypto::mlakey::{
    MLADecryptionPrivateKey, MLAEncryptionPublicKey, MLAPrivateKey, MLAPublicKey,
    MLASignatureVerificationPublicKey, MLASigningPrivateKey, derive_keypair_from_path,
    generate_mla_keypair, generate_mla_keypair_from_seed,
};
use mla::entry::{ENTRY_NAME_RAW_CONTENT_ALLOWED_BYTES, EntryName, EntryNameError};
use mla::errors::{ConfigError::IncoherentPersistentConfig, Error, TruncatedReadError};
use mla::helpers::{StreamWriter, linear_extract, mla_percent_escape, mla_percent_unescape};
use mla::{ArchiveReader, ArchiveWriter, TruncatedArchiveReader, entry::ArchiveEntry};
use sha2::{Digest, Sha512};
use std::collections::{HashMap, HashSet};
use std::error;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, read_dir};
use std::io::{self, BufRead as _, Read, Seek, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tar::{Builder, Header};

const STDIN_BUFFER_SIZE: usize = 8192;

// ----- Error ------

#[derive(Debug)]
enum MlarError {
    /// Wrap a MLA error
    Mla(Error),
    /// IO Error (not enough data, etc.)
    IO(io::Error),
    /// Configuration error
    Config(mla::errors::ConfigError),
    InvalidEntryNameToPath,
    InvalidGlobPattern,
    SeparatorTooBig,
    EntryNameCountMismatch,
    MissingHash,
}

impl fmt::Display for MlarError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MlarError::InvalidEntryNameToPath => write!(
                f,
                "An MLA entry name cannot be interpreted as a valid MLA path encoding, try listing with --raw-escaped-names to debug"
            ),
            _ => {
                // For now, use the debug derived version
                write!(f, "{self:?}")
            }
        }
    }
}

impl From<Error> for MlarError {
    fn from(error: Error) -> Self {
        MlarError::Mla(error)
    }
}

impl From<io::Error> for MlarError {
    fn from(error: io::Error) -> Self {
        MlarError::IO(error)
    }
}

impl From<mla::errors::ConfigError> for MlarError {
    fn from(error: mla::errors::ConfigError) -> Self {
        MlarError::Config(error)
    }
}

impl error::Error for MlarError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            MlarError::IO(err) => Some(err),
            MlarError::Mla(err) => Some(err),
            MlarError::Config(err) => Some(err),
            MlarError::InvalidEntryNameToPath
            | MlarError::InvalidGlobPattern
            | MlarError::SeparatorTooBig
            | MlarError::EntryNameCountMismatch
            | MlarError::MissingHash => None,
        }
    }
}

// ----- Utils ------

const PATH_ESCAPED_STRING_ALLOWED_BYTES: &[u8; 65] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./\\";

fn escaped_path_to_string(path: &Path) -> String {
    let raw_path = path.display().to_string(); // Path display is guaranteed to be valid UTF-8
    let escaped = mla_percent_escape(raw_path.as_bytes(), PATH_ESCAPED_STRING_ALLOWED_BYTES);
    // Now safe to convert back to UTF-8 string, because we escaped non-allowed bytes
    String::from_utf8(escaped).expect("[ERROR] mla_percent_escape should produce valid UTF-8")
}

/// Allow for different kind of output. As `ArchiveWriter` is parametrized over
/// a Writable type, `ArchiveWriter<File>` and `ArchiveWriter<io::stdout>`
/// can't coexist in the same code path.
enum OutputTypes {
    Stdout,
    File { file: File },
}

impl Write for OutputTypes {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            OutputTypes::Stdout => io::stdout().write(buf),
            OutputTypes::File { file } => file.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            OutputTypes::Stdout => io::stdout().flush(),
            OutputTypes::File { file } => file.flush(),
        }
    }
}

/// Return the parsed version of private keys from arguments `private_keys`
/// Each key is expected to be a file path containing a serialized MLA private key.
/// Returns an error if any file can't be opened or parsed.
fn open_private_keys(
    matches: &ArgMatches,
    private_keys_arg_name: &str,
) -> Result<(Vec<MLADecryptionPrivateKey>, Vec<MLASigningPrivateKey>), Error> {
    let mut private_decryption_keys = Vec::new();
    let mut private_signing_keys = Vec::new();
    if let Some(private_key_args) = matches.get_many::<PathBuf>(private_keys_arg_name) {
        for private_key_arg in private_key_args {
            let mut file = File::open(private_key_arg)?;
            let (private_decryption_key, private_signing_key) =
                MLAPrivateKey::deserialize_private_key(&mut file)
                    .map_err(|_| Error::InvalidKeyFormat)?
                    .get_private_keys();
            private_decryption_keys.push(private_decryption_key);
            private_signing_keys.push(private_signing_key);
        }
    }

    Ok((private_decryption_keys, private_signing_keys))
}

/// Return the parsed version of public keys from arguments `public_keys`
/// Each key is expected to be a file path containing a serialized MLA public key.
/// Returns an error if any file can't be opened or parsed.
fn open_public_keys(
    matches: &ArgMatches,
    pubkey_arg_name: &str,
) -> Result<
    (
        Vec<MLAEncryptionPublicKey>,
        Vec<MLASignatureVerificationPublicKey>,
    ),
    Error,
> {
    let mut public_encryption_keys = Vec::new();
    let mut public_signature_verification_keys = Vec::new();
    if let Some(public_key_args) = matches.get_many::<PathBuf>(pubkey_arg_name) {
        for public_key_arg in public_key_args {
            let mut file = File::open(public_key_arg)?;
            let (public_encryption_key, public_signature_verification_key) =
                MLAPublicKey::deserialize_public_key(&mut file)
                    .map_err(|_| Error::InvalidKeyFormat)?
                    .get_public_keys();
            public_encryption_keys.push(public_encryption_key);
            public_signature_verification_keys.push(public_signature_verification_key);
        }
    }

    Ok((public_encryption_keys, public_signature_verification_keys))
}

/// Return the `ArchiveWriterConfig` corresponding to provided arguments
fn config_from_matches(
    matches: &ArgMatches,
    create_command: bool,
) -> Result<ArchiveWriterConfig, MlarError> {
    // Get compression/encryption/signing layers
    let mut layers = Vec::new();
    if matches.contains_id("layers") {
        for layer in matches.get_many::<String>("layers").unwrap() {
            layers.push(layer.as_str());
        }
    } else {
        // Default layers
        layers.push("compress");
        layers.push("encrypt");
        layers.push("sign");
    }

    let output_public_keys_arg_name = if create_command {
        "public_keys"
    } else {
        "out_pub"
    };

    let output_private_keys_arg_name = if create_command {
        "private_keys"
    } else {
        "out_priv"
    };

    // Encryption layer requested but no public keys given
    if layers.contains(&"encrypt") && !matches.contains_id(output_public_keys_arg_name) {
        eprintln!(
            "[ERROR] Encryption layer was requested, but no '{output_public_keys_arg_name}' was provided."
        );
        return Err(MlarError::Config(IncoherentPersistentConfig));
    }

    // Sign layer requested but no private signing keys
    if layers.contains(&"sign") && !matches.contains_id(output_private_keys_arg_name) {
        eprintln!(
            "[ERROR] Signature layer was requested, but no '{output_private_keys_arg_name}' was provided."
        );
        return Err(MlarError::Config(IncoherentPersistentConfig));
    }

    // Construct base config
    let config = if matches.contains_id(output_public_keys_arg_name) {
        if !layers.contains(&"encrypt") {
            eprintln!(
                "[ERROR] '{output_public_keys_arg_name}' was provided, but 'encrypt' layer was not requested. Enabling encryption."
            );
            return Err(MlarError::Config(IncoherentPersistentConfig));
        }

        let (public_encryption_keys, _pub_sig_keys) =
            open_public_keys(matches, output_public_keys_arg_name).map_err(|error| {
                eprintln!("[ERROR] Unable to open '{output_public_keys_arg_name}': {error}");
                MlarError::Mla(Error::InvalidKeyFormat)
            })?;

        if matches.contains_id(output_private_keys_arg_name) {
            if !layers.contains(&"sign") {
                eprintln!(
                    "[ERROR] '{output_private_keys_arg_name}' was provided, but 'sign' layer was not requested. Enabling signing."
                );
                return Err(MlarError::Config(IncoherentPersistentConfig));
            }

            let (_private_decryption_keys, private_signing_keys) =
                open_private_keys(matches, output_private_keys_arg_name).map_err(|error| {
                    eprintln!("[ERROR] Unable to open '{output_private_keys_arg_name}': {error}");
                    MlarError::Mla(Error::InvalidKeyFormat)
                })?;

            ArchiveWriterConfig::with_encryption_with_signature(
                &public_encryption_keys,
                &private_signing_keys,
            )
        } else {
            ArchiveWriterConfig::with_encryption_without_signature(&public_encryption_keys)
        }
    } else if matches.contains_id(output_private_keys_arg_name) {
        if !layers.contains(&"sign") {
            eprintln!(
                "[ERROR] '{output_private_keys_arg_name}' was provided, but 'sign' layer was not requested. Enabling signing."
            );
            return Err(MlarError::Config(IncoherentPersistentConfig));
        }

        let (_private_decryption_keys, private_signing_keys) =
            open_private_keys(matches, output_private_keys_arg_name).map_err(|error| {
                eprintln!("[ERROR] Unable to open '{output_private_keys_arg_name}': {error}");
                MlarError::Mla(Error::InvalidKeyFormat)
            })?;

        ArchiveWriterConfig::without_encryption_with_signature(&private_signing_keys)
    } else {
        ArchiveWriterConfig::without_encryption_without_signature()
    }?;

    // Add compression if requested or implied by compression level
    let config = if layers.contains(&"compress") || matches.contains_id("compression_level") {
        if !layers.contains(&"compress") && matches.contains_id("compression_level") {
            eprintln!(
                "[ERROR] 'compression_level' was specified without requesting 'compress' layer. Enabling compression."
            );
            return Err(MlarError::Config(IncoherentPersistentConfig));
        }

        if matches.contains_id("compression_level") {
            let comp_level: u32 = *matches
                .get_one::<u32>("compression_level")
                .expect("[ERROR] compression_level must be an int");
            assert!((comp_level <= 11), "compression_level must be in [0 .. 11]");
            config.with_compression_level(comp_level).unwrap()
        } else {
            config
        }
    } else {
        config.without_compression()
    };

    Ok(config)
}

fn destination_from_output_argument(output_argument: &PathBuf) -> Result<OutputTypes, MlarError> {
    let destination = if output_argument.as_os_str() == "-" {
        OutputTypes::Stdout
    } else {
        let path = Path::new(&output_argument);
        OutputTypes::File {
            file: File::create_new(path)?,
        }
    };
    Ok(destination)
}

/// Return an `ArchiveWriter` corresponding to provided arguments
fn writer_from_matches<'a>(
    matches: &ArgMatches,
    create_command: bool,
) -> Result<ArchiveWriter<'a, OutputTypes>, MlarError> {
    let config = config_from_matches(matches, create_command)?;

    // Safe to use unwrap() because the option is required()
    let output = matches.get_one::<PathBuf>("output").unwrap();

    let destination = destination_from_output_argument(output)?;

    // Instantiate output writer
    Ok(ArchiveWriter::from_config(destination, config)?)
}

/// Return the `ArchiveReaderConfig` corresponding to provided arguments and set
/// `Layers::ENCRYPT` if a key is provided
fn readerconfig_from_matches(matches: &ArgMatches) -> Result<ArchiveReaderConfig, MlarError> {
    let incomplete_config = if matches.get_flag("skip_signature_verification") {
        ArchiveReaderConfig::without_signature_verification()
    } else if matches.contains_id("public_keys") {
        let (_public_encryption_keys, public_signature_verification_keys) =
            open_public_keys(matches, "public_keys").map_err(|error| {
                eprintln!("[ERROR] Unable to open public keys: {error}");
                MlarError::Mla(Error::InvalidKeyFormat)
            })?;
        ArchiveReaderConfig::with_signature_verification(&public_signature_verification_keys)
    } else {
        eprintln!("[ERROR] No public keys given and --skip-signature-verification not set");
        return Err(MlarError::Config(IncoherentPersistentConfig));
    };

    if matches.contains_id("private_keys") {
        let (private_dec_keys, _private_sig_keys) = open_private_keys(matches, "private_keys")
            .map_err(|error| {
                eprintln!("[ERROR] Unable to open private keys: {error}");
                MlarError::Mla(Error::InvalidKeyFormat)
            })?;

        if matches.get_flag("accept_unencrypted") {
            Ok(incomplete_config.with_encryption_accept_unencrypted(&private_dec_keys))
        } else {
            Ok(incomplete_config.with_encryption(&private_dec_keys))
        }
    } else if matches.get_flag("accept_unencrypted") {
        Ok(incomplete_config.without_encryption())
    } else {
        eprintln!("[ERROR] No private keys given and --accept-unencrypted not set");
        Err(MlarError::Config(IncoherentPersistentConfig))
    }
}

fn open_mla_file<'a>(matches: &ArgMatches) -> Result<ArchiveReader<'a, File>, MlarError> {
    let config = readerconfig_from_matches(matches)?;

    // Safe to use unwrap() because the option is required()
    let mla_file = matches.get_one::<PathBuf>("input").unwrap();
    let file = File::open(mla_file)?;

    // Instantiate reader
    let (reader, keys_with_valid_signatures) = ArchiveReader::from_config(file, config)?;

    // Signature verification
    if let Some(public_keys) = matches.get_many::<PathBuf>("public_keys")
        && public_keys.count() != keys_with_valid_signatures.len()
        && !matches.get_flag("only_one_key_with_valid_signature_is_ok")
    {
        return Err(MlarError::Mla(Error::NoValidSignatureFound));
    }

    Ok(reader)
}

// Utils: common code to load a mla_file from arguments, fail-safe mode
fn open_failsafe_mla_file<'a>(
    matches: &ArgMatches,
) -> Result<TruncatedArchiveReader<'a, File>, MlarError> {
    let truncated_decryption_mode = if matches.get_flag("allow_unauthenticated_data") {
        TruncatedReaderDecryptionMode::DataEvenUnauthenticated
    } else {
        TruncatedReaderDecryptionMode::OnlyAuthenticatedData
    };

    let config = if matches.contains_id("private_keys") {
        let (private_dec_keys, _private_sig_keys) = open_private_keys(matches, "private_keys")
            .map_err(|error| {
                eprintln!("[ERROR] Unable to open private keys: {error}");
                MlarError::Mla(Error::InvalidKeyFormat)
            })?;

        if matches.get_flag("accept_unencrypted") {
            TruncatedReaderConfig::without_signature_verification_with_encryption_accept_unencrypted(
                &private_dec_keys,
                truncated_decryption_mode,
            )
        } else {
            TruncatedReaderConfig::without_signature_verification_with_encryption(
                &private_dec_keys,
                truncated_decryption_mode,
            )
        }
    } else {
        TruncatedReaderConfig::without_signature_verification_without_encryption()
    };

    // Safe to use unwrap() because the option is required()
    let mla_file = matches.get_one::<PathBuf>("input").unwrap();
    let file = File::open(mla_file)?;

    // Instantiate reader
    Ok(TruncatedArchiveReader::from_config(file, config)?)
}

fn add_file_to_tar<R: Read + Seek, W: Write>(
    tar_file: &mut Builder<W>,
    entry: ArchiveEntry<R>,
) -> Result<(), MlarError> {
    // Use indexes to avoid in-memory copy
    let mut header = Header::new_gnu();
    header.set_size(entry.get_size());
    header.set_mode(0o444); // Create files as read-only
    header.set_cksum();

    let in_tar_path = entry
        .name
        .to_pathbuf()
        .map_err(|_| MlarError::InvalidEntryNameToPath)?;

    tar_file
        .append_data(&mut header, in_tar_path, entry.data)
        .map_err(MlarError::IO)
}

/// Arguments for action 'extract' to match file names in the archive
enum ExtractFileNameMatcher {
    /// Match a list of files, where the order does not matter
    Files(HashSet<PathBuf>),
    /// Match a list of glob patterns
    GlobPatterns(Vec<Pattern>),
    /// No matching argument has been provided, so match all files
    Anything,
}
impl ExtractFileNameMatcher {
    fn from_matches(matches: &ArgMatches) -> Result<Self, MlarError> {
        let Some(entries) = matches.get_many::<PathBuf>("entries") else {
            return Ok(ExtractFileNameMatcher::Anything);
        };
        if matches.get_flag("glob") {
            // Use glob patterns
            Ok(ExtractFileNameMatcher::GlobPatterns(
                entries
                    .map(|path| {
                        let pattern = path.to_str().ok_or(MlarError::InvalidGlobPattern)?;
                        Pattern::new(pattern).map_err(|_| MlarError::InvalidGlobPattern)
                    })
                    .collect::<Result<Vec<Pattern>, MlarError>>()?,
            ))
        } else {
            // Use file names
            Ok(ExtractFileNameMatcher::Files(entries.cloned().collect()))
        }
    }

    fn match_file_name(&self, file_name: &Path) -> bool {
        match self {
            ExtractFileNameMatcher::Files(files) => files.is_empty() || files.contains(file_name),
            ExtractFileNameMatcher::GlobPatterns(patterns) => {
                patterns.is_empty() || patterns.iter().any(|pat| pat.matches_path(file_name))
            }
            ExtractFileNameMatcher::Anything => true,
        }
    }
}

/// Create a file and associate parent directories in a given output directory
fn create_file<P1: AsRef<Path>>(
    output_dir: P1,
    entry_name: &EntryName,
    zone_id: Option<&Vec<u8>>,
    quarantine: Option<&Vec<u8>>,
) -> Result<(File, PathBuf), MlarError> {
    let output_dir_path = output_dir.as_ref();
    let entry_name_pathbuf = entry_name
        .to_pathbuf()
        .map_err(|_| MlarError::InvalidEntryNameToPath)?;
    let extracted_path = output_dir_path.join(&entry_name_pathbuf);
    // Create all directories leading to the file
    if let Some(containing_directory) = extracted_path.parent() {
        if !containing_directory.exists() {
            fs::create_dir_all(containing_directory).map_err(|err| {
                eprintln!(
                    "[ERROR] Failed to create output directory: \"{}\" ({err:?})",
                    escaped_path_to_string(output_dir_path)
                );
                err
            })?;
        }

        // Try to verify that the containing directory is in the output dir,
        // in case the output dir has been hijacked or changed since the start
        let containing_directory = fs::canonicalize(containing_directory).map_err(|err| {
            eprintln!(
                "[ERROR] Failed to canonicalize output directory path: \"{}\" ({err:?})",
                escaped_path_to_string(containing_directory)
            );
            err
        })?;

        if !containing_directory.starts_with(output_dir) {
            let msg = format!(
                "Refusing to extract \"{}\": it would be extracted outside the output directory (in \"{}\")",
                escaped_path_to_string(&entry_name_pathbuf),
                escaped_path_to_string(&containing_directory)
            );
            return Err(MlarError::IO(io::Error::other(format!("[ERROR] {msg}"))));
        }
    }

    let created_file = File::create_new(&extracted_path).map_err(|err| {
        eprintln!(
            "[ERROR] Unable to create \"{}\" ({err:?})",
            escaped_path_to_string(&entry_name_pathbuf)
        );
        err
    })?;

    // Propagate zone identifier
    if let Some(zone_id) = zone_id.as_ref() {
        let zone_id_path = get_zone_identifier_path(&extracted_path)?;
        fs::write(zone_id_path, zone_id).map_err(|err| {
            eprintln!(
                "[ERROR] Unable to propagate zone identifier \"{}\" ({err:?})",
                escaped_path_to_string(&entry_name_pathbuf)
            );
            err
        })?;
    }

    // Propagate macOS quarantine if needed
    if let Some(quarantine_data) = quarantine {
        apply_quarantine(&extracted_path, quarantine_data).map_err(|err| {
            eprintln!(
                "[ERROR] Unable to propagate com.apple.quarantine to \"{}\" ({:?})",
                escaped_path_to_string(&entry_name_pathbuf),
                err
            );
            err
        })?;
    }

    Ok((created_file, extracted_path))
}

/// Wrapper with Write, to append data to a file
///
/// This wrapper is used to avoid opening all files simultaneously, potentially
/// reaching the filesystem limit, but rather appending to file on-demand
///
/// A limited pool of active file, in a LRU cache, is used to avoid too many open-close
struct FileWriter<'a> {
    /// Target file for data appending
    path: PathBuf,
    /// Reference on the cache
    // A `Mutex` is used instead of a `RefCell` as `FileWriter` can be `Send`
    cache: &'a Mutex<LruCache<PathBuf, File>>,
    /// Is verbose mode enabled
    verbose: bool,
    /// `entry_name`
    entry_name: EntryName,
}

/// Max number of fd simultaneously opened
const FILE_WRITER_POOL_SIZE: usize = 1000;

impl Write for FileWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Only one thread is using the FileWriter, safe to `.unwrap()`
        let mut cache = self.cache.lock().unwrap();
        if !cache.contains(&self.path) {
            let file = fs::OpenOptions::new().append(true).open(&self.path)?;
            cache.put(self.path.clone(), file);
            if self.verbose {
                println!(
                    "{}",
                    self.entry_name
                        .to_pathbuf_escaped_string()
                        .map_err(|_| io::Error::other(MlarError::InvalidEntryNameToPath))?
                );
            }
        }
        // Safe to `unwrap` here cause we ensure the element is in the cache (mono-threaded)
        let file = cache.get_mut(&self.path).unwrap();
        file.write(buf)

        // `file` will be closed on deletion from the cache
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Add whatever is specified by `path`
fn add_file_or_dir(
    mla: &mut ArchiveWriter<OutputTypes>,
    path: &Path,
    skip_not_found: bool,
) -> Result<(), MlarError> {
    if path.is_dir() {
        add_dir(mla, path, skip_not_found)?;
    } else {
        let name = EntryName::from_path(path).map_err(|_| MlarError::InvalidEntryNameToPath)?;

        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && skip_not_found => {
                eprintln!(
                    "[WARNING] File \"{}\" does not exist, skipping",
                    name.to_pathbuf_escaped_string()
                        .map_err(|_| MlarError::InvalidEntryNameToPath)?
                );
                return Ok(());
            }
            Err(e) => return Err(MlarError::IO(e)),
        };

        let length = file.metadata().map_err(MlarError::IO)?.len();
        eprintln!(
            " adding: {}",
            name.to_pathbuf_escaped_string()
                .map_err(|_| MlarError::InvalidEntryNameToPath)?
        );

        mla.add_entry(name, length, file)?;
    }
    Ok(())
}

/// Recursively explore a dir to add all the files
/// Ignore empty directory
fn add_dir(
    mla: &mut ArchiveWriter<OutputTypes>,
    dir: &Path,
    skip_not_found: bool,
) -> Result<(), MlarError> {
    match read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(err) => {
                        eprintln!(
                            "[ERROR] Failed to read entry in directory \"{}\" ({:?})",
                            escaped_path_to_string(dir),
                            err
                        );
                        return Err(err.into());
                    }
                };

                let new_path = entry.path();
                if let Err(err) = add_file_or_dir(mla, &new_path, skip_not_found) {
                    eprintln!(
                        "[ERROR] Failed to add \"{}\" ({:?})",
                        escaped_path_to_string(&new_path),
                        err
                    );
                    if !skip_not_found {
                        return Err(err);
                    }
                }
            }
        }
        Err(err) => {
            eprintln!(
                "[ERROR] Failed to read directory \"{}\" ({:?})",
                escaped_path_to_string(dir),
                err
            );
            return Err(err.into());
        }
    }

    Ok(())
}

fn add_from_stdin_separated(
    mla: &mut ArchiveWriter<OutputTypes>,
    mut entry_names: impl Iterator<Item = Result<EntryName, EntryNameError>>,
    separator: &[u8],
) -> Result<(), MlarError> {
    if separator.len() > STDIN_BUFFER_SIZE {
        return Err(MlarError::SeparatorTooBig);
    }

    let mut in_buffer = [0; STDIN_BUFFER_SIZE];
    let mut in_buffer_next_read_offset = 0;
    let mut in_buffer_end_offset;

    let mut entry_id = {
        let name = entry_names
            .next()
            .ok_or(MlarError::EntryNameCountMismatch)?
            .map_err(|_| MlarError::InvalidEntryNameToPath)?;
        mla.start_entry(name)?
    };

    let mut stdin = io::stdin().lock();

    // Read stdin in chunks
    loop {
        let bytes_read_len = stdin.read(&mut in_buffer[in_buffer_next_read_offset..])?;
        if bytes_read_len == 0 {
            // EOF
            break;
        }

        // up to where the buffer has been filled by the read call
        in_buffer_end_offset = in_buffer_next_read_offset + bytes_read_len;

        // Find potential separators
        let mut previous_separator_end_idx = 0;
        let mut eventual_separator_idx = 0;

        // test if we found a separator
        while eventual_separator_idx + separator.len() <= in_buffer_end_offset {
            if in_buffer[eventual_separator_idx..].starts_with(separator) {
                let separator_idx = eventual_separator_idx;
                let content_size = (separator_idx - previous_separator_end_idx) as u64;

                mla.append_entry_content(
                    entry_id,
                    content_size,
                    &in_buffer[previous_separator_end_idx..separator_idx],
                )?;
                mla.end_entry(entry_id)?;

                // Get the next entry name
                let next_entry_name = entry_names
                    .next()
                    .ok_or(MlarError::EntryNameCountMismatch)?
                    .map_err(|_| MlarError::InvalidEntryNameToPath)?;

                entry_id = mla.start_entry(next_entry_name)?;

                // next separator will be at least after this one, so we advance by separator.len()
                eventual_separator_idx = separator_idx + separator.len();
                previous_separator_end_idx = eventual_separator_idx;
            } else {
                eventual_separator_idx += 1;
            }
        }

        // Handle remainder (bytes in buffer) after last separator
        let last_subslice = &in_buffer[previous_separator_end_idx..in_buffer_end_offset];

        // all possible separator prefixes
        let mut separator_prefixes = (1..separator.len()).rev().map(|i| &separator[..i]);
        // we try to find if current stdin chunk ends with a prefix of the separator in case a separator crosses chunk boundaries
        if let Some(separator_prefix) =
            separator_prefixes.find(|prefix| last_subslice.ends_with(prefix))
        {
            // only write content up to potential new separator. If it is not a real separator, rest will be written in next iteration.
            let cut_point = in_buffer_end_offset - separator_prefix.len();
            let content_size = (cut_point - previous_separator_end_idx) as u64;
            mla.append_entry_content(
                entry_id,
                content_size,
                &in_buffer[previous_separator_end_idx..cut_point],
            )?;

            // move the prefix to beginning of buffer
            in_buffer.copy_within(cut_point..in_buffer_end_offset, 0);
            in_buffer_next_read_offset = separator_prefix.len();
        } else {
            // no separator prefix found, write everything in last_subslice
            let content_size = (in_buffer_end_offset - previous_separator_end_idx) as u64;
            mla.append_entry_content(entry_id, content_size, last_subslice)?;
            in_buffer_next_read_offset = 0;
        }
    }

    mla.end_entry(entry_id)?;
    Ok(())
}

fn add_from_stdin(
    mla: &mut ArchiveWriter<OutputTypes>,
    mut entry_names: impl Iterator<Item = Result<EntryName, EntryNameError>>,
    separator: Option<&[u8]>,
) -> Result<(), MlarError> {
    if let Some(separator) = separator {
        add_from_stdin_separated(mla, entry_names, separator)?;
    } else {
        // If no separator is provided, it's assumed that stdin corresponds to a single entry
        let Some(Ok(entry_name)) = entry_names.next() else {
            // This should not happen as there is a default value
            return Err(MlarError::InvalidEntryNameToPath);
        };

        let entry_id = mla.start_entry(entry_name)?;
        let mut archive_entry_writer = StreamWriter::new(mla, entry_id);
        io::copy(&mut io::stdin().lock(), &mut archive_entry_writer)?;
        mla.end_entry(entry_id)?;
    }

    Ok(())
}

// ----- Commands ------

fn create(matches: &ArgMatches) -> Result<(), MlarError> {
    let mut mla = writer_from_matches(matches, true)?;

    if matches.get_flag("stdin_data") {
        let entry_names = matches
            .get_one::<String>("stdin_data_entry_names")
            .expect("[ERROR] stdin_data_entry_names has a default_value")
            .split(',')
            .map(EntryName::from_path);

        let separator = matches
            .get_one::<String>("stdin_data_separator")
            .map(String::as_bytes);

        add_from_stdin(&mut mla, entry_names, separator)?;
    } else {
        let skip_not_found = matches.get_flag("skip-not-found");

        if matches.get_flag("stdin_file_list") {
            for line in io::stdin().lock().lines() {
                let line = line?;
                add_file_or_dir(&mut mla, Path::new(&line), skip_not_found)?;
            }
        } else if let Some(filepaths) = matches.get_many::<PathBuf>("files") {
            for filepath in filepaths {
                add_file_or_dir(&mut mla, Path::new(filepath), skip_not_found)?;
            }
        }
    }

    mla.finalize()?;
    Ok(())
}

fn list(matches: &ArgMatches) -> Result<(), MlarError> {
    let mut mla = open_mla_file(matches)?;

    let mut iter: Vec<EntryName> = mla.list_entries()?.cloned().collect();
    iter.sort();

    for fname in iter {
        let name_to_display = if matches.get_flag("raw-escaped-names") {
            fname.raw_content_to_escaped_string()
        } else if let Ok(s) = fname.to_pathbuf_escaped_string() {
            s
        } else {
            fname
                .to_pathbuf_escaped_string()
                .map_err(|_| MlarError::InvalidEntryNameToPath)?
        };

        let verbose = matches.get_count("verbose");

        if verbose == 0 {
            println!("{name_to_display}");
            continue;
        }

        let mla_file = mla
            .get_entry(fname.clone())?
            .ok_or(MlarError::InvalidEntryNameToPath)?;

        let size = mla_file.get_size().format_size(DECIMAL);
        let filename = mla_file.name;

        if verbose == 1 {
            println!("{name_to_display} - {size}");
        } else {
            // verbose >= 2: include hash
            let hash = mla.get_hash(&filename)?.ok_or(MlarError::MissingHash)?;

            println!("{} - {} ({})", name_to_display, size, hex::encode(hash));
        }
    }

    Ok(())
}

fn get_zone_identifier_path(orig_path: &Path) -> Result<PathBuf, MlarError> {
    let mut zone_id_name = orig_path
        .file_name()
        .ok_or(MlarError::IO(io::Error::other(
            "Internal error: should not have been called on a path without file_name",
        )))?
        .to_os_string();
    zone_id_name.push(OsStr::new(":Zone.Identifier"));
    let mut path_with_zone_id = orig_path.to_owned();
    path_with_zone_id.set_file_name(zone_id_name);
    Ok(path_with_zone_id)
}

#[cfg(target_family = "unix")]
// as function signature must be the same on all platforms
#[allow(clippy::unnecessary_wraps)]
fn get_zone_identifier_os(_orig_path: &Path) -> Result<Option<Vec<u8>>, MlarError> {
    Ok(None)
}

#[cfg(target_family = "windows")]
fn get_zone_identifier_os(orig_path: &Path) -> Result<Option<Vec<u8>>, MlarError> {
    use std::io::ErrorKind;

    let zone_id_path = get_zone_identifier_path(orig_path)?;
    match fs::read(zone_id_path) {
        Ok(zone_id) => Ok(Some(zone_id)),
        Err(e) => {
            let err_kind = e.kind();
            if err_kind == ErrorKind::NotFound || err_kind == ErrorKind::InvalidFilename {
                Ok(None)
            } else {
                Err(io::Error::other("Failed to read zone identifier").into())
            }
        }
    }
}

fn get_zone_identifier(path: &Path) -> Result<Option<Vec<u8>>, MlarError> {
    get_zone_identifier_os(path)
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::unnecessary_wraps)]
fn get_quarantine_data_os(_path: &Path) -> Result<Option<Vec<u8>>, MlarError> {
    Ok(None)
}

#[cfg(target_os = "macos")]
fn get_quarantine_data_os(path: &Path) -> Result<Option<Vec<u8>>, MlarError> {
    use rustix::fs::{Mode, OFlags, fgetxattr, open};
    use rustix::io::Errno;
    use std::ffi::CString;

    let fd = open(path, OFlags::RDONLY, Mode::empty()).map_err(|e| MlarError::IO(e.into()))?;
    let attr_name = CString::new("com.apple.quarantine").unwrap();

    // Buffer to hold xattr data
    let mut buf = vec![0u8; 512];

    match fgetxattr(&fd, &attr_name, &mut buf) {
        Ok(size) => {
            if size > 0 {
                buf.truncate(size);
                Ok(Some(buf))
            } else {
                // Empty attribute
                Ok(Some(Vec::new()))
            }
        }
        Err(err) => match err {
            // NOATTR is alias for NODATA with rustix
            Errno::NOATTR => Ok(None), // attribute not found, return None
            _ => Err(MlarError::IO(err.into())),
        },
    }
}

fn get_quarantine_data(path: &Path) -> Result<Option<Vec<u8>>, MlarError> {
    get_quarantine_data_os(path)
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::unnecessary_wraps)]
fn apply_quarantine_os(_path: &Path, _quarantine_data: &[u8]) -> Result<(), MlarError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_quarantine_os(path: &Path, quarantine_data: &[u8]) -> Result<(), MlarError> {
    use rustix::fs::{Mode, OFlags, fsetxattr, open};
    use std::ffi::CString;

    let quarantine_attr = CString::new("com.apple.quarantine").unwrap();

    let fd = open(path, OFlags::WRONLY | OFlags::NONBLOCK, Mode::empty())
        .map_err(|e| MlarError::IO(e.into()))?;
    fsetxattr(
        &fd,
        &quarantine_attr,
        quarantine_data,
        rustix::fs::XattrFlags::empty(),
    )
    .map_err(|e| MlarError::IO(e.into()))
}

fn apply_quarantine(path: &Path, quarantine_data: &[u8]) -> Result<(), MlarError> {
    apply_quarantine_os(path, quarantine_data)
}

fn extract(matches: &ArgMatches) -> Result<(), MlarError> {
    let file_name_matcher = ExtractFileNameMatcher::from_matches(matches)?;
    // Safe to use unwrap() because the option is required()
    let output_dir = Path::new(matches.get_one::<PathBuf>("outputdir").unwrap());
    let verbose = matches.get_flag("verbose");

    let mut mla = open_mla_file(matches)?;

    // Safe to use unwrap() because the option is required()
    let input_path = matches.get_one::<PathBuf>("input").unwrap();
    let zone_id = get_zone_identifier(input_path)?;
    let quarantine_data = get_quarantine_data(input_path)?;

    // Create the output directory, if it does not exist
    if !output_dir.exists() {
        fs::create_dir(output_dir).map_err(|err| {
            eprintln!(
                "[ERROR] Failed to create output directory \"{}\" ({:?})",
                escaped_path_to_string(output_dir),
                err
            );
            err
        })?;
    }
    let output_dir = fs::canonicalize(output_dir).map_err(|err| {
        eprintln!(
            "[ERROR] Failed to canonicalize output directory path \"{}\" ({:?})",
            escaped_path_to_string(output_dir),
            err
        );
        err
    })?;

    let mut entries_names: Vec<EntryName> = mla.list_entries()?.cloned().collect();
    entries_names.sort();

    if let ExtractFileNameMatcher::Anything = file_name_matcher {
        // Optimisation: use linear extraction
        if verbose {
            println!("Extracting the whole archive using a linear extraction");
        }
        let cache = Mutex::new(LruCache::new(
            NonZeroUsize::new(FILE_WRITER_POOL_SIZE).unwrap(),
        ));
        let mut export: HashMap<&EntryName, FileWriter> = HashMap::new();
        for entry_name in &entries_names {
            let (_file, path) = create_file(
                &output_dir,
                entry_name,
                zone_id.as_ref(),
                quarantine_data.as_ref(),
            )?;
            export.insert(
                entry_name,
                FileWriter {
                    path,
                    cache: &cache,
                    verbose,
                    entry_name: entry_name.clone(),
                },
            );
        }
        return Ok(linear_extract(&mut mla, &mut export)?);
    }

    for entry_name in entries_names {
        // Filter files according to glob patterns or files given as parameters
        if !file_name_matcher.match_file_name(
            &entry_name
                .to_pathbuf()
                .map_err(|_| MlarError::InvalidEntryNameToPath)?,
        ) {
            continue;
        }

        // Look for the file in the archive
        let mut sub_file = match mla.get_entry(entry_name.clone()) {
            Err(err) => {
                eprintln!(
                    "[ERROR] Failed to look up subfile \"{}\" ({err:?})",
                    entry_name
                        .to_pathbuf_escaped_string()
                        .map_err(|_| MlarError::InvalidEntryNameToPath)?
                );
                return Err(err.into());
            }
            Ok(None) => {
                eprintln!(
                    "[ERROR] Failed to find subfile \"{}\" indexed in metadata",
                    entry_name
                        .to_pathbuf_escaped_string()
                        .map_err(|_| MlarError::InvalidEntryNameToPath)?
                );
                return Err(MlarError::InvalidEntryNameToPath);
            }
            Ok(Some(subfile)) => subfile,
        };
        let (mut extracted_file, _path) = create_file(
            &output_dir,
            &entry_name,
            zone_id.as_ref(),
            quarantine_data.as_ref(),
        )?;

        if verbose {
            println!(
                "{}",
                entry_name
                    .to_pathbuf_escaped_string()
                    .map_err(|_| MlarError::InvalidEntryNameToPath)?
            );
        }
        if let Err(err) = io::copy(&mut sub_file.data, &mut extracted_file) {
            eprintln!(
                "[ERROR] Unable to extract \"{}\" ({err:?})",
                entry_name
                    .to_pathbuf_escaped_string()
                    .map_err(|_| MlarError::InvalidEntryNameToPath)?
            );
            return Err(err.into());
        }
    }
    Ok(())
}

fn cat(matches: &ArgMatches) -> Result<(), MlarError> {
    // Safe unwrap since 'output' is required
    let output = matches.get_one::<PathBuf>("output").unwrap();
    let mut destination = destination_from_output_argument(output)?;

    let mut mla = open_mla_file(matches)?;

    // Get entries if provided
    let entries_opt = matches.get_many::<PathBuf>("entries");

    if matches.get_flag("glob") {
        // For glob mode, entries must be provided
        let entries_values = entries_opt.ok_or(MlarError::InvalidEntryNameToPath)?;

        let mut archive_entries_names: Vec<EntryName> = mla.list_entries()?.cloned().collect();
        archive_entries_names.sort();

        for arg_pattern in entries_values {
            let arg_pattern_str = arg_pattern.to_str().ok_or(MlarError::InvalidGlobPattern)?;
            let pat = Pattern::new(arg_pattern_str).map_err(|_| MlarError::InvalidGlobPattern)?;

            for archive_entry_name in &archive_entries_names {
                let pathbuf = archive_entry_name
                    .to_pathbuf()
                    .map_err(|_| MlarError::InvalidEntryNameToPath)?;
                if !pat.matches_path(&pathbuf) {
                    continue;
                }

                let displayable_entry_name = archive_entry_name
                    .to_pathbuf_escaped_string()
                    .map_err(|_| MlarError::InvalidEntryNameToPath)?;

                match mla.get_entry(archive_entry_name.clone()) {
                    Err(err) => {
                        eprintln!(
                            "[ERROR] Error while looking up file \"{displayable_entry_name}\" ({err:?})"
                        );
                        return Err(err.into());
                    }
                    Ok(None) => {
                        eprintln!(
                            "[ERROR] Failed to find subfile \"{displayable_entry_name}\" indexed in metadata"
                        );
                        return Err(MlarError::InvalidEntryNameToPath);
                    }
                    Ok(Some(mut subfile)) => {
                        if let Err(err) = io::copy(&mut subfile.data, &mut destination) {
                            eprintln!(
                                "[ERROR] Unable to extract \"{displayable_entry_name}\" ({err:?})"
                            );
                            return Err(err.into());
                        }
                    }
                }
            }
        }
    } else {
        // Non-glob mode: collect files to extract
        let files_values = if matches.get_flag("raw-escaped-names") {
            let entries_iter = entries_opt.ok_or(MlarError::InvalidEntryNameToPath)?;
            entries_iter
                .map(|name| {
                    let name_str = name
                        .to_str()
                        .ok_or(EntryNameError::InvalidPathComponentContent)?;
                    let bytes = mla_percent_unescape(
                        name_str.as_bytes(),
                        ENTRY_NAME_RAW_CONTENT_ALLOWED_BYTES.as_slice(),
                    )
                    .ok_or(EntryNameError::InvalidPathComponentContent)?;
                    EntryName::from_arbitrary_bytes(&bytes)
                })
                .collect::<Result<Vec<EntryName>, EntryNameError>>()
                .map_err(|_| MlarError::InvalidEntryNameToPath)?
        } else {
            let entries_iter = entries_opt.ok_or(MlarError::InvalidEntryNameToPath)?;
            entries_iter
                .map(EntryName::from_path)
                .collect::<Result<Vec<EntryName>, EntryNameError>>()
                .map_err(|_| MlarError::InvalidEntryNameToPath)?
        };
        // Retrieve all the files that are specified
        for fname in files_values {
            let display_name = fname
                .to_pathbuf_escaped_string()
                .unwrap_or_else(|_| String::from("<invalid path>"));
            match mla.get_entry(fname.clone()) {
                Err(err) => {
                    eprintln!("[ERROR] Error while looking up file \"{display_name}\" ({err:?})");
                    return Err(err.into());
                }
                Ok(None) => {
                    eprintln!("[ERROR] File not found: \"{display_name}\"");
                    return Err(MlarError::InvalidEntryNameToPath);
                }
                Ok(Some(mut subfile)) => {
                    if let Err(err) = io::copy(&mut subfile.data, &mut destination) {
                        eprintln!("[ERROR] Unable to extract \"{display_name}\" ({err:?})");
                        return Err(err.into());
                    }
                }
            }
        }
    }

    Ok(())
}

fn to_tar(matches: &ArgMatches) -> Result<(), MlarError> {
    let mut mla = open_mla_file(matches)?;

    // Safe to use unwrap() because the option is required()
    let output = matches.get_one::<PathBuf>("output").unwrap();
    let destination = destination_from_output_argument(output)?;
    let mut tar_file = Builder::new(destination);

    let mut archive_files: Vec<EntryName> = mla.list_entries()?.cloned().collect();
    archive_files.sort();
    for fname in archive_files {
        let sub_file = match mla.get_entry(fname.clone()) {
            Err(err) => {
                eprintln!(
                    "[ERROR] Error while looking up subfile \"{}\" ({err:?})",
                    &fname
                        .to_pathbuf_escaped_string()
                        .map_err(|_| MlarError::InvalidEntryNameToPath)?
                );
                return Err(err.into());
            }
            Ok(None) => {
                eprintln!(
                    "[ERROR] Failed to find subfile \"{}\" indexed in metadata",
                    &fname
                        .to_pathbuf_escaped_string()
                        .map_err(|_| MlarError::InvalidEntryNameToPath)?
                );
                return Err(MlarError::InvalidEntryNameToPath);
            }
            Ok(Some(subfile)) => subfile,
        };
        if let Err(err) = add_file_to_tar(&mut tar_file, sub_file) {
            eprintln!(
                "[ERROR] Unable to add subfile \"{}\" to tarball ({err:?})",
                &fname
                    .to_pathbuf_escaped_string()
                    .map_err(|_| MlarError::InvalidEntryNameToPath)?
            );
            return Err(err);
        }
    }
    Ok(())
}

fn repair(matches: &ArgMatches) -> Result<(), MlarError> {
    let mut mla = open_failsafe_mla_file(matches)?;
    let mla_out = writer_from_matches(matches, false)?;

    // Convert
    let status = mla.convert_to_archive(mla_out)?;
    match status {
        TruncatedReadError::NoError => {}
        TruncatedReadError::EndOfOriginalArchiveData => {
            eprintln!("[WARNING] The whole archive has been recovered");
        }
        _ => {
            eprintln!("[WARNING] Conversion ends with {status}");
        }
    }
    Ok(())
}

fn convert(matches: &ArgMatches) -> Result<(), MlarError> {
    let mut mla = open_mla_file(matches)?;
    let mut fnames: Vec<EntryName> = match mla.list_entries() {
        Ok(iter) => iter.cloned().collect(),
        Err(err) => {
            eprintln!(
                "[ERROR] Failed to read entries from archive: {err}. The file may be malformed. \
                Consider repairing it using repair sub-command or re-create it."
            );
            return Err(MlarError::InvalidEntryNameToPath);
        }
    };

    fnames.sort();

    let mut mla_out = writer_from_matches(matches, false)?;

    // Convert
    for fname in fnames {
        eprintln!(" converting: {}", fname.raw_content_to_escaped_string());

        let sub_file = match mla.get_entry(fname.clone()) {
            Err(err) => {
                eprintln!(
                    "[ERROR] Failed to retrieve entry \"{}\": {err:?}",
                    fname.raw_content_to_escaped_string()
                );
                return Err(err.into());
            }
            Ok(None) => {
                eprintln!(
                    "[ERROR] Entry not found: {}",
                    fname.raw_content_to_escaped_string()
                );
                return Err(MlarError::InvalidEntryNameToPath);
            }
            Ok(Some(mla_entry)) => mla_entry,
        };

        let size = sub_file.get_size();
        mla_out.add_entry(sub_file.name, size, sub_file.data)?;
    }

    mla_out.finalize().expect("[ERROR] Finalization error");

    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn keygen(matches: &ArgMatches) -> Result<(), MlarError> {
    // Safe to use unwrap() because of the requirement
    let output_base = matches.get_one::<PathBuf>("output-prefix").unwrap();

    let mut output_pub = File::create_new(output_base.with_extension("mlapub"))
        .expect("[ERROR] Unable to create the public file");
    let mut output_priv = File::create_new(output_base.with_extension("mlapriv"))
        .expect("[ERROR] Unable to create the private file");

    // handle seed
    //
    // if set, seed the PRNG with `SHA512(seed bytes as UTF8)[0..32]`
    // if not, seed the PRNG with the dedicated API
    let (privkey, pubkey) = match matches.get_one::<String>("seed") {
        Some(seed) => {
            eprintln!(
                "[WARNING] A seed-based keygen operation is deterministic. An attacker knowing the seed knows the private key and is able to decrypt associated messages"
            );
            let mut hseed = [0u8; 32];
            hseed.copy_from_slice(&Sha512::digest(seed.as_bytes())[0..32]);
            generate_mla_keypair_from_seed(hseed)
        }
        None => generate_mla_keypair()?,
    };

    pubkey
        .serialize_public_key(&mut output_pub)
        .expect("[ERROR] Failed to write the public key");
    privkey
        .serialize_private_key(&mut output_priv)
        .expect("[ERROR] Failed to write the private key");
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn keyderive(matches: &ArgMatches) -> Result<(), MlarError> {
    // Safe to use unwrap() because of the requirement
    let output_base = matches.get_one::<PathBuf>("output-prefix").unwrap();

    let mut output_pub = File::create_new(output_base.with_extension("mlapub"))
        .expect("[ERROR] Unable to create the public file");
    let mut output_priv = File::create_new(output_base.with_extension("mlapriv"))
        .expect("[ERROR] Unable to create the private file");

    // Safe to use unwrap() because of the requirement
    let private_key_arg = matches.get_one::<PathBuf>("input").unwrap();
    let mut file = File::open(private_key_arg)?;

    let secret = MLAPrivateKey::deserialize_private_key(&mut file)
        .map_err(|_| MlarError::Mla(Error::InvalidKeyFormat))?;

    // Safe to unwrap, there is at least one derivation path
    let paths = matches
        .get_many::<String>("path-component")
        .expect("[ERROR] At least one path must be provided");
    let Some((priv_key, pub_key)) = derive_keypair_from_path(paths.map(String::as_bytes), secret)
    else {
        eprintln!("[ERROR] Failed to derive keypair from the given path");
        return Err(MlarError::Mla(Error::InvalidKeyFormat));
    };

    pub_key
        .serialize_public_key(&mut output_pub)
        .expect("[ERROR] Failed to write the public key to the output");
    priv_key
        .serialize_private_key(&mut output_priv)
        .expect("[ERROR] Failed to write the private key to the output");

    Ok(())
}

fn info(matches: &ArgMatches) -> Result<(), MlarError> {
    // Safe to use unwrap() because the option is required()
    let mla_file = matches.get_one::<PathBuf>("input").unwrap();
    let mut src = File::open(mla_file)?;

    let info = mla::info::read_info(&mut src)?;

    let encryption = info.is_encryption_enabled();
    let signature = info.is_signature_enabled();

    // Format Version
    println!("Format version: {}", info.get_format_version());
    println!("Encryption: {encryption}");
    println!("Signature: {signature}");

    Ok(())
}

fn app() -> clap::Command {
    // Common arguments list, for homogeneity
    let input_args = vec![
        Arg::new("input")
            .help("Archive path")
            .long("input")
            .short('i')
            .num_args(1)
            .value_parser(value_parser!(PathBuf))
            .required(true),
        Arg::new("accept_unencrypted")
            .long("accept-unencrypted")
            .help("Accept to operate on unencrypted archives")
            .action(ArgAction::SetTrue),
        Arg::new("only_one_key_with_valid_signature_is_ok")
            .long("only-one-key-with-valid-signature-is-ok")
            .help("If multiple public signing verification keys are given, by default the archive must be correctly signed with all of them. This flag ")
            .action(ArgAction::SetTrue),
        Arg::new("skip_signature_verification")
            .long("skip-signature-verification")
            .help("Skip signature verification whether the archive is signed or not. This enables reading unsigned archives and reading signed archives without the cost of verification.")
            .action(ArgAction::SetTrue),
    ];
    let output_args = vec![
        Arg::new("output")
            .help("Output file path. Use - for stdout")
            .long("output")
            .short('o')
            .value_parser(value_parser!(PathBuf))
            .required(true),
        Arg::new("layers")
            .long("layers")
            .short('l')
            .help("Layers to use. Default is '-l compress -l encrypt -l sign'")
            .value_parser(["compress", "encrypt", "sign"])
            .num_args(0..=1)
            .action(ArgAction::Append),
        Arg::new("compression_level")
            .group("Compression layer")
            .short('q')
            .long("compression_level")
            .value_parser(value_parser!(u32).range(0..=11))
            .help("Compression level (0-11); ; bigger values cause denser, but slower compression"),
    ];
    let both_args = vec![
        Arg::new("private_keys")
            .long("private-key")
            .short('k')
            .help("MLA private key file. If A creates an archive for B, A uses A's private key for signing. For reading, B uses B's private key to decrypt. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.")
            .num_args(1)
            .action(ArgAction::Append)
            .value_parser(value_parser!(PathBuf)),
        Arg::new("public_keys")
            .help("MLA public key file. If A creates an archive for B, A uses B's public key for encryption. For reading, B uses A's public key to verifying the signature. This parameter can be specified multiple times, for example to try many keys for decryption or to sign with multiple keys.")
            .long("public-key")
            .short('p')
            .num_args(1)
            .action(ArgAction::Append)
            .value_parser(value_parser!(PathBuf)),
    ];

    // Main parsing
    Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(
            Command::new("create")
                .about("Create a new MLA Archive")
                .args(&output_args)
                .args(&both_args)
                .arg(
                    Arg::new("files")
                    .help("Files to add")
                    .value_parser(value_parser!(PathBuf))
                    .action(ArgAction::Append)
                )
                .arg(
                    Arg::new("stdin_file_list")
                    .long("stdin-file-list")
                    .help("Add files specified on stdin (one UTF-8 path per line) rather than from positional arguments.")
                    .action(ArgAction::SetTrue)
                    .conflicts_with_all(["stdin_data", "stdin_data_entry_names", "stdin_data_separator"])
                )
                .arg(
                    Arg::new("stdin_data")
                    .long("stdin-data")
                    .help("Pipe archive entries content from stdin. Can be customized with --stdin-data-entry-names and --stdin-data-separator.")
                    .action(ArgAction::SetTrue)
                )
                .arg(
                    Arg::new("stdin_data_entry_names")
                    .long("stdin-data-entry-names")
                    .help("Comma-separated list of entry names to create with regards to content provided on stdin. Default: \"default-entry\".")
                    .value_parser(value_parser!(String))
                    .default_value("default-entry")
                    .num_args(1)
                    .requires("stdin_data")
                )
                .arg(
                    Arg::new("stdin_data_separator")
                    .long("stdin-data-separator")
                    .help("Delimiter string used to separate multiple archive entries from stdin. Required if --stdin-data includes multiple entries. Default: no separator (stdin will thus be treated as a single entry).")
                    .value_parser(value_parser!(String))
                    .num_args(1)
                    .requires("stdin_data")
                )
                .arg(
                    Arg::new("skip-not-found")
                    .long("skip-not-found")
                    .action(ArgAction::SetTrue)
                    .help("Skip files that are not found instead of failing.")
                ),
        )
        .subcommand(
            Command::new("list")
                .about("List entries inside a MLA Archive")
                .before_help("Outputs a list of MLA entries. By default, names are interpreted as paths and escaped like described in `doc/ENTRY_NAME.md`")
                .args(&input_args)
                .args(&both_args)
                .arg(
                    Arg::new("raw-escaped-names")
                        .long("raw-escaped-names")
                        .action(ArgAction::SetTrue)
                        .help("Do not try to interpret entry names as paths and encode everything not alphanumeric or dot"),
                )
                .arg(
                    Arg::new("verbose")
                        .short('v')
                        .action(ArgAction::Count)
                        .help("Verbose listing, with additional information"),
                ),
        )
        .subcommand(
            Command::new("extract")
                .about("Extract entries from a MLA Archive to files")
                .args(&input_args)
                .args(&both_args)
                .arg(
                    Arg::new("outputdir")
                        .help("Output directory where files are extracted")
                        .long("output")
                        .short('o')
                        .num_args(1)
                        .value_parser(value_parser!(PathBuf))
                        .default_value("."),
                )
                .arg(
                    Arg::new("glob")
                        .long("glob")
                        .short('g')
                        .action(ArgAction::SetTrue)
                        .help("Treat specified files as glob patterns"),
                )
                .arg(Arg::new("entries").value_parser(value_parser!(PathBuf)).help("List of entries to extract (all if none given)"))
                .arg(
                    Arg::new("verbose")
                        .long("verbose")
                        .short('v')
                        .action(ArgAction::SetTrue)
                        .help("List entries as they are extracted"),
                ),
        )
        .subcommand(
            Command::new("cat")
                .about("Display entries from a MLA Archive, like 'cat'")
                .args(&input_args)
                .args(&both_args)
                .arg(
                    Arg::new("output")
                        .help("Output file")
                        .long("output")
                        .short('o')
                        .num_args(1)
                        .value_parser(value_parser!(PathBuf))
                        .default_value("-"),
                )
                .arg(
                    Arg::new("glob")
                        .long("glob")
                        .short('g')
                        .action(ArgAction::SetTrue)
                        .help("Treat given entries names as glob patterns"),
                )
                .arg(
                    Arg::new("raw-escaped-names")
                        .long("raw-escaped-names")
                        .action(ArgAction::SetTrue)
                        .help("With this option, entries names given as positional arguments should be specified as displayed by mlar list with this same option. This lets you see entries that cannot be interpreted as valid path."),
                )
                .arg(
                    Arg::new("entries")
                        .required(true)
                        .value_parser(value_parser!(PathBuf))
                        .help("List of entries to output"),
                ),
        )
        .subcommand(
            Command::new("to-tar")
                .about("Convert a MLA Archive to a TAR Archive")
                .args(&input_args)
                .args(&both_args)
                .arg(
                    Arg::new("output")
                        .help("Tar Archive path")
                        .long("output")
                        .short('o')
                        .num_args(1)
                        .value_parser(value_parser!(PathBuf))
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("repair")
                .about("Create a fresh MLA from what can be read from a truncated one but loosing some security (e.g. no signature verification)")
                .args(&input_args)
                .args(&output_args)
                .args(&both_args)
                .arg(
                    Arg::new("out_pub")
                        .help("MLA public key file for output archive encryption")
                        .long("out-pub")
                        .num_args(1)
                        .action(ArgAction::Append)
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("allow_unauthenticated_data")
                        .long("allow-unauthenticated-data")
                        .help("Allow extraction of unauthenticated data from the archive. USE THIS OPTION ONLY IF NECESSARY")
                        .action(ArgAction::SetTrue)
                        .required(false),
                )
                .arg(
                    Arg::new("out_priv")
                        .help("MLA private key file for output archive signing")
                        .long("out-priv")
                        .num_args(1)
                        .action(ArgAction::Append)
                        .value_parser(value_parser!(PathBuf)),
                )
        )
        .subcommand(
            Command::new("convert")
                .about(
                    "Convert a MLA Archive to a fresh new one, with potentially different options",
                )
                .args(&input_args)
                .args(&output_args)
                .args(&both_args)
                .arg(
                    Arg::new("out_pub")
                        .help("MLA public key file for output archive encryption")
                        .long("out-pub")
                        .num_args(1)
                        .action(ArgAction::Append)
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("out_priv")
                        .help("MLA private key file for output archive signing")
                        .long("out-priv")
                        .num_args(1)
                        .action(ArgAction::Append)
                        .value_parser(value_parser!(PathBuf)),
                )
        )
        .subcommand(
            Command::new("keygen")
                .about(
                    "Generate a public/private MLA keypair",
                )
                .arg(
                    Arg::new("output-prefix")
                        .help("Output prefix for the keys. The private key will be in {output-prefix}.mlapriv and the public key will be in {output-prefix}.mlapub")
                        .num_args(1)
                        .value_parser(value_parser!(PathBuf))
                        .required(true)
                )
                .arg(
                    Arg::new("seed")
                        .help("Initial seed for deterministic key generation. THE SEED IS AS SECRET AS THE RESULTING PRIVATE KEY. USE THIS OPTION ONLY IF NECESSARY")
                        .long("seed")
                        .short('s')
                        .num_args(1)
                        .value_parser(value_parser!(String))
                )
        )
        .subcommand(
            Command::new("keyderive")
                .about(
                    "Advanced: Derive a new public/private keypair from an existing one and a public path, see `doc/KEY_DERIVATION.md`",
                )
                .arg(
                    Arg::new("input")
                        .help("Input private key file")
                        .num_args(1)
                        .value_parser(value_parser!(PathBuf))
                        .required(true)
                )
                .arg(
                    Arg::new("output-prefix")
                        .help("Output prefix for the keys. The private key will be in {output}.mlapriv and the public key will be in {output}.mlapub")
                        .num_args(1)
                        .value_parser(value_parser!(PathBuf))
                        .required(true)
                )
                .arg(
                    Arg::new("path-component")
                    .help("Public derivation path, can be specified multiple times")
                    .long("path-component")
                    .short('p')
                    .num_args(1)
                    .action(ArgAction::Append)
                    .value_parser(value_parser!(String))
                )
        )
        .subcommand(
            Command::new("info")
                .about("Get info on a MLA Archive")
                .args(&input_args)
                .arg(
                    Arg::new("verbose")
                        .long("verbose")
                        .short('v')
                        .action(ArgAction::SetTrue)
                        .help("Get extra info for encryption and compression layers"),
                ),
        )
}

fn main() -> Result<(), MlarError> {
    let mut app = app();
    let help = app.render_long_help();
    let matches = app.get_matches();

    // Determine verbose flag in subcommands that supports it
    let (_subcommand_name, _subcommand_matches, verbose) = match matches.subcommand() {
        Some(("list", m)) => {
            let lvl = *m.get_one::<u8>("verbose").unwrap_or(&0);
            ("list", m, lvl > 0)
        }
        Some(("extract", m)) => ("extract", m, m.get_flag("verbose")),
        Some(("info", m)) => ("info", m, m.get_flag("verbose")),
        Some((name, m)) => (name, m, false),
        None => {
            let msg = "[ERROR] At least one command is required.";
            eprintln!("{}", &help);
            return Err(MlarError::IO(io::Error::other(format!("[ERROR] {msg}"))));
        }
    };

    // User-friendly panic output
    // Uses the previously retrieved verbose flag (from subcommand args)
    // Since Rust 2021, panic payloads are always `&'static str` or `String`
    std::panic::set_hook(Box::new(move |panic_info| {
        let msg = match panic_info.payload().downcast_ref::<&str>() {
            Some(s) => *s,
            None => match panic_info.payload().downcast_ref::<String>() {
                // if not `&'static str`
                Some(s) => s.as_str(),
                None => "Unknown panic",
            },
        };
        eprintln!("[ERROR] {msg}");

        if verbose && let Some(location) = panic_info.location() {
            eprintln!("(at {}:{})", location.file(), location.line());
        }
    }));

    // Launch sub-command
    // Use if-let chain instead of match to ensure only one branch is evaluated,
    // avoiding deep stack frames that can cause overflows (especially on Windows).
    let res = if let Some(matches) = matches.subcommand_matches("create") {
        create(matches)
    } else if let Some(matches) = matches.subcommand_matches("list") {
        list(matches)
    } else if let Some(matches) = matches.subcommand_matches("extract") {
        extract(matches)
    } else if let Some(matches) = matches.subcommand_matches("cat") {
        cat(matches)
    } else if let Some(matches) = matches.subcommand_matches("to-tar") {
        to_tar(matches)
    } else if let Some(matches) = matches.subcommand_matches("repair") {
        repair(matches)
    } else if let Some(matches) = matches.subcommand_matches("convert") {
        convert(matches)
    } else if let Some(matches) = matches.subcommand_matches("keygen") {
        keygen(matches)
    } else if let Some(matches) = matches.subcommand_matches("keyderive") {
        keyderive(matches)
    } else if let Some(matches) = matches.subcommand_matches("info") {
        info(matches)
    } else {
        let msg = "[ERROR] At least one command is required.";
        eprintln!("{}", &help);
        return Err(MlarError::IO(io::Error::other(format!("[ERROR] {msg}"))));
    };

    if let Err(err) = res {
        eprintln!("[ERROR] Command ended with error: {err:?}");
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn verify_app() {
        app().debug_assert();
    }

    #[test]
    fn test_get_zone_identifier_path() {
        let input_path = Path::new("C:\\path\\to\\file.txt");
        let expected = Path::new("C:\\path\\to\\file.txt:Zone.Identifier");
        let actual = get_zone_identifier_path(input_path).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_zone_identifier_path_without_filename() {
        for input in &[Path::new(""), Path::new("/")] {
            let result = get_zone_identifier_path(input);
            assert!(
                result.is_err(),
                "Expected error for input {input:?}, but got Ok: {result:?}",
            );
        }
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn test_read_zone_identifier_ads() {
        use std::{
            fs, fs::File, fs::OpenOptions, io::Write, os::windows::fs::OpenOptionsExt, path::Path,
        };
        use winapi::um::winbase::FILE_FLAG_BACKUP_SEMANTICS;

        let path = Path::new("test_file_ads.txt");
        let ads_path_str = format!("{}:Zone.Identifier", path.display());

        // Create dummy file
        File::create(path).unwrap();

        // Open ADS stream with necessary flags and write data
        let mut ads = OpenOptions::new()
            .write(true)
            .create(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&ads_path_str)
            .unwrap();

        ads.write_all(b"[ZoneTransfer]\nZoneId=3").unwrap();

        // Assuming get_zone_identifier reads the ADS correctly
        let result = get_zone_identifier(path).unwrap();
        assert_eq!(result.unwrap(), b"[ZoneTransfer]\nZoneId=3");

        // Cleanup
        fs::remove_file(path).unwrap();
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_zone_identifier_skipped_on_unix() {
        let dummy_path = Path::new("/tmp/somefile.txt");
        let result = get_zone_identifier(dummy_path);
        assert!(result.unwrap().is_none());
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn test_zone_identifier_invalid_utf8() {
        use std::{
            fs, fs::File, fs::OpenOptions, io::Write, os::windows::fs::OpenOptionsExt, path::Path,
        };
        use winapi::um::winbase::FILE_FLAG_BACKUP_SEMANTICS;

        let path = Path::new("test_file_ads_invalid_utf8.txt");
        let ads_path_str = format!("{}:Zone.Identifier", path.display());

        // Create dummy file
        File::create(path).unwrap();

        // Open ADS stream with necessary flags and write data
        let mut ads = OpenOptions::new()
            .write(true)
            .create(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&ads_path_str)
            .unwrap();

        ads.write_all(b"[ZoneTransfer]\nZoneId=\xFF\xFE").unwrap();

        // Should still return the raw bytes without error
        let result = get_zone_identifier(path).unwrap();
        assert_eq!(result.unwrap(), b"[ZoneTransfer]\nZoneId=\xFF\xFE");

        // Cleanup
        fs::remove_file(path).unwrap();
    }

    /// Helper to create a temp file with an optional quarantine attribute set.
    #[cfg(target_os = "macos")]
    fn setup_file_with_quarantine_attr(
        data: Option<&[u8]>,
        filename: &str,
    ) -> std::io::Result<std::path::PathBuf> {
        use rustix::fs::{Mode, OFlags, fsetxattr, open};
        use std::ffi::CString;

        let path = std::env::temp_dir().join(filename);
        File::create(&path)?;

        if let Some(quarantine_data) = data {
            let fd = open(&path, OFlags::WRONLY | OFlags::NONBLOCK, Mode::empty()).unwrap();
            let attr_name = CString::new("com.apple.quarantine").unwrap();
            fsetxattr(
                &fd,
                &attr_name,
                quarantine_data,
                rustix::fs::XattrFlags::empty(),
            )
            .unwrap();
        }

        Ok(path)
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_get_quarantine_data_present() {
        let quarantine_bytes = b"0001;5f2b8f34;Safari;";
        let path = setup_file_with_quarantine_attr(Some(quarantine_bytes), "data_present").unwrap();

        let result = get_quarantine_data_os(&path).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), quarantine_bytes);

        fs::remove_file(path).unwrap();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_get_quarantine_data_absent() {
        let path = setup_file_with_quarantine_attr(None, "data_absent").unwrap();

        // Simulate absence of quarantine xattr
        // fgetxattr will return ENODATA which is ENOATTR in rustix
        let result = get_quarantine_data_os(&path).unwrap();
        assert!(result.is_none());

        fs::remove_file(path).unwrap();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_apply_quarantine_sets_data() {
        let path = setup_file_with_quarantine_attr(None, "sets_data").unwrap();

        let quarantine_bytes = b"0002;5f2b8f34;Safari;";
        apply_quarantine_os(&path, quarantine_bytes).unwrap();

        let read_back = get_quarantine_data_os(&path).unwrap();
        assert_eq!(read_back.unwrap(), quarantine_bytes);

        fs::remove_file(path).unwrap();
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_get_quarantine_data_returns_none() {
        let dummy_path = Path::new("/tmp/nonexistentfile");
        let result = get_quarantine_data_os(dummy_path).unwrap();
        assert!(result.is_none());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_apply_quarantine_noop() {
        let dummy_path = Path::new("/tmp/nonexistentfile");
        let data = b"irrelevant";
        // if it doesn't panic, it's fine
        apply_quarantine_os(dummy_path, data).unwrap();
    }
}
