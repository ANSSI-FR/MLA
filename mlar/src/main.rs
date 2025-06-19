use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use glob::Pattern;
use humansize::{DECIMAL, FormatSize};
use lru::LruCache;
use mla::config::{ArchiveReaderConfig, ArchiveWriterConfig};
use mla::crypto::mlakey::{
    HybridPrivateKey, HybridPublicKey, derive_keypair_from_path, generate_keypair,
    generate_keypair_from_seed, parse_mlakey_privkey_pem, parse_mlakey_pubkey_pem,
};
use mla::entry::{ENTRY_NAME_RAW_CONTENT_ALLOWED_BYTES, EntryName, EntryNameError};
use mla::errors::{Error, TruncatedReadError};
use mla::helpers::{linear_extract, mla_percent_escape, mla_percent_unescape};
use mla::{ArchiveReader, ArchiveWriter, TruncatedArchiveReader, entry::ArchiveEntry};
use sha2::{Digest, Sha512};
use std::collections::{HashMap, HashSet};
use std::error;
use std::fmt;
use std::fs::{self, File, read_dir};
use std::io::{self, BufRead};
use std::io::{Read, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tar::{Builder, Header};

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
            MlarError::InvalidEntryNameToPath => None,
            MlarError::InvalidGlobPattern => None,
        }
    }
}

// ----- Utils ------

const PATH_ESCAPED_STRING_ALLOWED_BYTES: [u8; 65] =
    *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./\\";

fn escaped_path_to_string(path: &Path) -> String {
    String::from_utf8(mla_percent_escape(
        path.display().to_string().as_bytes(),
        PATH_ESCAPED_STRING_ALLOWED_BYTES.as_slice(),
    ))
    .unwrap()
}

/// Allow for different kind of output. As ArchiveWriter is parametrized over
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
fn open_private_keys(matches: &ArgMatches) -> Result<Vec<HybridPrivateKey>, Error> {
    let mut private_keys = Vec::new();
    if let Some(private_key_args) = matches.get_many::<PathBuf>("private_keys") {
        for private_key_arg in private_key_args {
            let mut file = File::open(private_key_arg)?;
            // Load the the key in-memory and parse it
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            let private_key =
                parse_mlakey_privkey_pem(&buf).map_err(|_| Error::InvalidKeyFormat)?;

            private_keys.push(private_key);
        }
    };
    Ok(private_keys)
}

/// Return the parsed version of public keys from arguments `public_keys`
fn open_public_keys(matches: &ArgMatches) -> Result<Vec<HybridPublicKey>, Error> {
    let mut public_keys = Vec::new();

    if let Some(public_key_args) = matches.get_many::<PathBuf>("public_keys") {
        for public_key_arg in public_key_args {
            let mut file = File::open(public_key_arg)?;
            // Load the the key in-memory and parse it
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;

            let public_key = parse_mlakey_pubkey_pem(&buf).map_err(|_| Error::InvalidKeyFormat)?;

            public_keys.push(public_key);
        }
    }
    Ok(public_keys)
}

/// Return the ArchiveWriterConfig corresponding to provided arguments
fn config_from_matches(matches: &ArgMatches) -> Result<ArchiveWriterConfig, MlarError> {
    // Get layers
    let mut layers = Vec::new();
    if matches.contains_id("layers") {
        // Safe to use unwrap() because of the is_present() test
        for layer in matches.get_many::<String>("layers").unwrap() {
            layers.push(layer.as_str());
        }
    } else {
        // Default
        layers.push("compress");
        layers.push("encrypt");
    };

    if layers.contains(&"encrypt") && !matches.contains_id("public_keys") {
        eprintln!("Encryption was asked, but no public key was given");
        return Err(MlarError::Config(
            mla::errors::ConfigError::EncryptionKeyIsMissing,
        ));
    }

    let config = if matches.contains_id("public_keys") {
        if !layers.contains(&"encrypt") {
            eprintln!(
                "[WARNING] 'public_keys' was given, but encrypt layer was not asked. Enabling it"
            );
        }
        let public_keys = match open_public_keys(matches) {
            Ok(public_keys) => public_keys,
            Err(error) => {
                panic!("[ERROR] Unable to open public keys: {}", error);
            }
        };
        ArchiveWriterConfig::with_public_keys(&public_keys)
    } else {
        ArchiveWriterConfig::without_encryption()
    };

    let config = if layers.contains(&"compress") || matches.contains_id("compression_level") {
        if !layers.contains(&"compress") && matches.contains_id("compression_level") {
            eprintln!(
                "[WARNING] 'compression_level' was given, but compression layer was not asked. Enabling it"
            );
        }
        if matches.contains_id("compression_level") {
            let comp_level: u32 = *matches
                .get_one::<u32>("compression_level")
                .expect("compression_level must be an int");
            if comp_level > 11 {
                panic!("compression_level must be in [0 .. 11]");
            }
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
    let destination = if output_argument.as_os_str() != "-" {
        let path = Path::new(&output_argument);
        OutputTypes::File {
            file: File::create(path)?,
        }
    } else {
        OutputTypes::Stdout
    };
    Ok(destination)
}

/// Return an ArchiveWriter corresponding to provided arguments
fn writer_from_matches<'a>(
    matches: &ArgMatches,
) -> Result<ArchiveWriter<'a, OutputTypes>, MlarError> {
    let config = config_from_matches(matches)?;

    // Safe to use unwrap() because the option is required()
    let output = matches.get_one::<PathBuf>("output").unwrap();

    let destination = destination_from_output_argument(output)?;

    // Instantiate output writer
    Ok(ArchiveWriter::from_config(destination, config)?)
}

/// Return the ArchiveReaderConfig corresponding to provided arguments and set
/// Layers::ENCRYPT if a key is provided
fn readerconfig_from_matches(matches: &ArgMatches) -> ArchiveReaderConfig {
    if matches.contains_id("private_keys") {
        let private_keys = match open_private_keys(matches) {
            Ok(private_keys) => private_keys,
            Err(error) => {
                panic!("[ERROR] Unable to open private keys: {}", error);
            }
        };
        if matches.get_flag("accept_unencrypted") {
            ArchiveReaderConfig::with_private_keys_accept_unencrypted(&private_keys)
        } else {
            ArchiveReaderConfig::with_private_keys(&private_keys)
        }
    } else if matches.get_flag("accept_unencrypted") {
        ArchiveReaderConfig::without_encryption()
    } else {
        panic!("No private keys given but --accept-unencrypted was not given")
    }
}

fn open_mla_file<'a>(matches: &ArgMatches) -> Result<ArchiveReader<'a, File>, MlarError> {
    let config = readerconfig_from_matches(matches);

    // Safe to use unwrap() because the option is required()
    let mla_file = matches.get_one::<PathBuf>("input").unwrap();
    let path = Path::new(&mla_file);
    let file = File::open(path)?;

    // Instantiate reader
    Ok(ArchiveReader::from_config(file, config)?)
}

// Utils: common code to load a mla_file from arguments, fail-safe mode
fn open_failsafe_mla_file<'a>(
    matches: &ArgMatches,
) -> Result<TruncatedArchiveReader<'a, File>, MlarError> {
    let config = readerconfig_from_matches(matches);

    // Safe to use unwrap() because the option is required()
    let mla_file = matches.get_one::<PathBuf>("input").unwrap();
    let path = Path::new(&mla_file);
    let file = File::open(path)?;

    // Instantiate reader
    Ok(TruncatedArchiveReader::from_config(file, config)?)
}

fn add_file_to_tar<R: Read, W: Write>(
    tar_file: &mut Builder<W>,
    entry: ArchiveEntry<R>,
) -> Result<(), MlarError> {
    // Use indexes to avoid in-memory copy
    let mut header = Header::new_gnu();
    header.set_size(entry.size);
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
        let entries = match matches.get_many::<PathBuf>("entries") {
            Some(values) => values,
            None => return Ok(ExtractFileNameMatcher::Anything),
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
) -> Result<Option<(File, PathBuf)>, MlarError> {
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
                    " [!] Error while creating output directory path for \"{}\" ({:?})",
                    escaped_path_to_string(output_dir_path),
                    err
                );
                err
            })?;
        }
        // Try to verify that the containing directory is in the output dir, but output dir may have been hijacked since the beginning
        let containing_directory = fs::canonicalize(containing_directory).map_err(|err| {
            eprintln!(
                " [!] Error while canonicalizing extracted file output directory path \"{}\" ({:?})",
                escaped_path_to_string(containing_directory),
                err
            );
            err
        })?;
        if !containing_directory.starts_with(output_dir) {
            eprintln!(
                " [!] Skipping file \"{}\" because it would be extracted outside of the output directory, in {}",
                escaped_path_to_string(&entry_name_pathbuf),
                escaped_path_to_string(&containing_directory)
            );
            return Ok(None);
        }
    }
    Ok(Some((
        File::create(&extracted_path).map_err(|err| {
            eprintln!(
                " [!] Unable to create \"{}\" ({err:?})",
                escaped_path_to_string(&entry_name_pathbuf)
            );
            err
        })?,
        extracted_path,
    )))
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
    /// entry_name
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
fn add_file_or_dir(mla: &mut ArchiveWriter<OutputTypes>, path: &Path) -> Result<(), MlarError> {
    if path.is_dir() {
        add_dir(mla, path)?;
    } else {
        let name = EntryName::from_path(path).map_err(|_| MlarError::InvalidEntryNameToPath)?;
        let file = File::open(path)?;
        let length = file.metadata()?.len();
        eprintln!(
            "{}",
            name.to_pathbuf_escaped_string()
                .map_err(|_| MlarError::InvalidEntryNameToPath)?
        );
        mla.add_entry(name, length, file)?;
    }
    Ok(())
}

/// Recursively explore a dir to add all the files
/// Ignore empty directory
fn add_dir(mla: &mut ArchiveWriter<OutputTypes>, dir: &Path) -> Result<(), MlarError> {
    for file in read_dir(dir)? {
        let new_path = file?.path();
        add_file_or_dir(mla, &new_path)?;
    }
    Ok(())
}

fn add_from_stdin(mla: &mut ArchiveWriter<OutputTypes>) -> Result<(), MlarError> {
    for line in io::stdin().lock().lines() {
        add_file_or_dir(mla, Path::new(&line?))?;
    }
    Ok(())
}

// ----- Commands ------

fn create(matches: &ArgMatches) -> Result<(), MlarError> {
    let mut mla = writer_from_matches(matches)?;

    if let Some(files) = matches.get_many::<PathBuf>("files") {
        for filename in files {
            if filename.as_os_str() == "-" {
                add_from_stdin(&mut mla)?;
            } else {
                let path = Path::new(&filename);
                add_file_or_dir(&mut mla, path)?;
            }
        }
    };

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
        } else {
            fname
                .to_pathbuf_escaped_string()
                .map_err(|_| MlarError::InvalidEntryNameToPath)?
        };
        if matches.get_count("verbose") == 0 {
            println!("{}", name_to_display);
        } else {
            let mla_file = mla.get_entry(fname)?.expect("Unable to get the file");
            let filename = mla_file.name;
            let size = mla_file.size.format_size(DECIMAL);
            if matches.get_count("verbose") == 1 {
                println!("{name_to_display} - {size}");
            } else if matches.get_count("verbose") >= 2 {
                let hash = mla.get_hash(&filename)?.expect("Unable to get the hash");
                println!("{} - {} ({})", name_to_display, size, hex::encode(hash),);
            }
        }
    }
    Ok(())
}

fn extract(matches: &ArgMatches) -> Result<(), MlarError> {
    let file_name_matcher = ExtractFileNameMatcher::from_matches(matches)?;
    let output_dir = Path::new(matches.get_one::<PathBuf>("outputdir").unwrap());
    let verbose = matches.get_flag("verbose");

    let mut mla = open_mla_file(matches)?;

    // Create the output directory, if it does not exist
    if !output_dir.exists() {
        fs::create_dir(output_dir).map_err(|err| {
            eprintln!(
                " [!] Error while creating output directory \"{}\" ({:?})",
                escaped_path_to_string(output_dir),
                err
            );
            err
        })?;
    }
    let output_dir = fs::canonicalize(output_dir).map_err(|err| {
        eprintln!(
            " [!] Error while canonicalizing output directory path \"{}\" ({:?})",
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
            match create_file(&output_dir, entry_name)? {
                Some((_file, path)) => {
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
                None => continue,
            }
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
                    " [!] Error while looking up subfile \"{}\" ({err:?})",
                    entry_name
                        .to_pathbuf_escaped_string()
                        .map_err(|_| MlarError::InvalidEntryNameToPath)?
                );
                continue;
            }
            Ok(None) => {
                eprintln!(
                    " [!] Subfile \"{}\" indexed in metadata could not be found",
                    entry_name
                        .to_pathbuf_escaped_string()
                        .map_err(|_| MlarError::InvalidEntryNameToPath)?
                );
                continue;
            }
            Ok(Some(subfile)) => subfile,
        };
        let (mut extracted_file, _path) = match create_file(&output_dir, &entry_name)? {
            Some(file) => file,
            None => continue,
        };

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
                " [!] Unable to extract \"{}\" ({err:?})",
                entry_name
                    .to_pathbuf_escaped_string()
                    .map_err(|_| MlarError::InvalidEntryNameToPath)?
            );
        }
    }
    Ok(())
}

fn cat(matches: &ArgMatches) -> Result<(), MlarError> {
    let output = matches.get_one::<PathBuf>("output").unwrap();
    let mut destination = destination_from_output_argument(output)?;

    let mut mla = open_mla_file(matches)?;
    if matches.get_flag("glob") {
        let entries_values = matches.get_many::<PathBuf>("entries").unwrap();
        // For each glob patterns, enumerate matching files and display them
        let mut archive_entries_names: Vec<EntryName> = mla.list_entries()?.cloned().collect();
        archive_entries_names.sort();
        for arg_pattern in entries_values {
            let arg_pattern_str = arg_pattern.to_str().ok_or(MlarError::InvalidGlobPattern)?;
            let pat = Pattern::new(arg_pattern_str).map_err(|_| MlarError::InvalidGlobPattern)?;
            for archive_entry_name in &archive_entries_names {
                if !pat.matches_path(
                    &archive_entry_name
                        .to_pathbuf()
                        .map_err(|_| MlarError::InvalidEntryNameToPath)?,
                ) {
                    continue;
                }
                let displayable_entry_name = archive_entry_name
                    .to_pathbuf_escaped_string()
                    .map_err(|_| MlarError::InvalidEntryNameToPath)?;
                match mla.get_entry(archive_entry_name.clone()) {
                    Err(err) => {
                        eprintln!(
                            " [!] Error while looking up file \"{}\" ({err:?})",
                            displayable_entry_name
                        );
                        continue;
                    }
                    Ok(None) => {
                        eprintln!(
                            " [!] Subfile \"{}\" indexed in metadata could not be found",
                            displayable_entry_name
                        );
                        continue;
                    }
                    Ok(Some(mut subfile)) => {
                        if let Err(err) = io::copy(&mut subfile.data, &mut destination) {
                            eprintln!(
                                " [!] Unable to extract \"{}\" ({err:?})",
                                displayable_entry_name
                            );
                        }
                    }
                }
            }
        }
    } else {
        let files_values = if matches.get_flag("raw-escaped-names") {
            matches
                .get_many::<PathBuf>("entries")
                .unwrap()
                .map(|name| {
                    let name = name
                        .to_str()
                        .ok_or(EntryNameError::InvalidPathComponentContent)?;
                    let bytes = mla_percent_unescape(
                        name.as_bytes(),
                        ENTRY_NAME_RAW_CONTENT_ALLOWED_BYTES.as_slice(),
                    )
                    .ok_or(EntryNameError::InvalidPathComponentContent)?;
                    EntryName::from_arbitrary_bytes(&bytes)
                })
                .collect::<Result<Vec<EntryName>, EntryNameError>>()
                .map_err(|_| MlarError::InvalidEntryNameToPath)?
        } else {
            matches
                .get_many::<PathBuf>("entries")
                .unwrap()
                .map(EntryName::from_path)
                .collect::<Result<Vec<EntryName>, EntryNameError>>()
                .map_err(|_| MlarError::InvalidEntryNameToPath)?
        };
        // Retrieve all the files that are specified
        for fname in files_values {
            match mla.get_entry(fname.clone()) {
                Err(err) => {
                    eprintln!(
                        " [!] Error while looking up file \"{}\" ({err:?})",
                        fname
                            .to_pathbuf_escaped_string()
                            .map_err(|_| MlarError::InvalidEntryNameToPath)?
                    );
                    continue;
                }
                Ok(None) => {
                    eprintln!(
                        " [!] File not found: \"{}\"",
                        fname
                            .to_pathbuf_escaped_string()
                            .map_err(|_| MlarError::InvalidEntryNameToPath)?
                    );
                    continue;
                }
                Ok(Some(mut subfile)) => {
                    if let Err(err) = io::copy(&mut subfile.data, &mut destination) {
                        eprintln!(
                            " [!] Unable to extract \"{}\" ({err:?})",
                            fname
                                .to_pathbuf_escaped_string()
                                .map_err(|_| MlarError::InvalidEntryNameToPath)?
                        );
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
                    " [!] Error while looking up subfile \"{}\" ({err:?})",
                    &fname
                        .to_pathbuf_escaped_string()
                        .map_err(|_| MlarError::InvalidEntryNameToPath)?
                );
                continue;
            }
            Ok(None) => {
                eprintln!(
                    " [!] Subfile \"{}\" indexed in metadata could not be found",
                    &fname
                        .to_pathbuf_escaped_string()
                        .map_err(|_| MlarError::InvalidEntryNameToPath)?
                );
                continue;
            }
            Ok(Some(subfile)) => subfile,
        };
        if let Err(err) = add_file_to_tar(&mut tar_file, sub_file) {
            eprintln!(
                " [!] Unable to add subfile \"{}\" to tarball ({err:?})",
                &fname
                    .to_pathbuf_escaped_string()
                    .map_err(|_| MlarError::InvalidEntryNameToPath)?
            );
        }
    }
    Ok(())
}

fn repair(matches: &ArgMatches) -> Result<(), MlarError> {
    let mut mla = open_failsafe_mla_file(matches)?;
    let mla_out = writer_from_matches(matches)?;

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
    };
    Ok(())
}

fn convert(matches: &ArgMatches) -> Result<(), MlarError> {
    let mut mla = open_mla_file(matches)?;
    let mut fnames: Vec<EntryName> = if let Ok(iter) = mla.list_entries() {
        // Read the file list using metadata
        iter.cloned().collect()
    } else {
        panic!("Files is malformed. Please consider repairing the file");
    };
    fnames.sort();

    let mut mla_out = writer_from_matches(matches)?;

    // Convert
    for fname in fnames {
        eprintln!("{}", fname.raw_content_to_escaped_string());
        let sub_file = match mla.get_entry(fname.clone()) {
            Err(err) => {
                eprintln!(
                    "Error while adding {} ({err:?})",
                    fname.raw_content_to_escaped_string()
                );
                continue;
            }
            Ok(None) => {
                eprintln!("Unable to find {}", fname.raw_content_to_escaped_string());
                continue;
            }
            Ok(Some(mla)) => mla,
        };
        mla_out.add_entry(sub_file.name, sub_file.size, sub_file.data)?;
    }
    mla_out.finalize().expect("Finalization error");

    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn keygen(matches: &ArgMatches) -> Result<(), MlarError> {
    // Safe to use unwrap() because of the requirement
    let output_base = matches.get_one::<PathBuf>("output").unwrap();

    let mut output_pub = File::create(Path::new(output_base).with_extension("pub"))
        .expect("Unable to create the public file");
    let mut output_priv = File::create(output_base).expect("Unable to create the private file");

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
            generate_keypair_from_seed(hseed)
        }
        None => generate_keypair(),
    };

    // Output the public key in PEM format, to ease integration in text based
    // configs
    output_pub
        .write_all(pubkey.to_pem().as_bytes())
        .expect("Error writing the public key");

    // Output the private key in PEM format, to ease integration in text based
    output_priv
        .write_all(privkey.to_pem().as_bytes())
        .expect("Error writing the private key");
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn keyderive(matches: &ArgMatches) -> Result<(), MlarError> {
    // Safe to use unwrap() because of the requirement
    let output_base = matches.get_one::<PathBuf>("output").unwrap();

    let mut output_pub = File::create(Path::new(output_base).with_extension("pub"))
        .expect("Unable to create the public file");
    let mut output_priv = File::create(output_base).expect("Unable to create the private file");

    // Safe to use unwrap() because of the requirement
    let private_key_arg = matches.get_one::<PathBuf>("input").unwrap();
    let mut file = File::open(private_key_arg)?;

    // Load the the key in-memory and parse it
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let secret =
        parse_mlakey_privkey_pem(&buf).map_err(|_| MlarError::Mla(Error::InvalidKeyFormat))?;

    // Safe to unwrap, there is at least one derivation path
    let paths = matches
        .get_many::<String>("path-component")
        .expect("[ERROR] At least one path must be provided");
    let key_pair = derive_keypair_from_path(paths.map(String::as_bytes), secret).unwrap();

    // Output the public key in PEM format, to ease integration in text based
    // configs
    output_pub
        .write_all(key_pair.1.to_pem().as_bytes())
        .expect("Error writing the public key");

    // Output the private key in PEM format, to ease integration in text based
    output_priv
        .write_all(key_pair.0.to_pem().as_bytes())
        .expect("Error writing the private key");
    Ok(())
}

fn info(matches: &ArgMatches) -> Result<(), MlarError> {
    // Safe to use unwrap() because the option is required()
    let mla_file = matches.get_one::<PathBuf>("input").unwrap();
    let mut src = File::open(mla_file)?;

    let info = mla::info::read_header_info(&mut src)?;

    let encryption = info.is_encryption_enabled();
    let compression = info.is_compression_enabled();

    // Format Version
    println!("Format version: {}", info.get_format_version());

    // Encryption config
    println!("Encryption: {encryption}");
    println!("Compression: {compression}");

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
        Arg::new("private_keys")
            .long("private-key")
            .short('k')
            .help("MLA private key file to try (PEM format), can be specified multiple times")
            .num_args(1)
            .action(ArgAction::Append)
            .value_parser(value_parser!(PathBuf)),
        Arg::new("accept_unencrypted")
            .long("accept-unencrypted")
            .help("Accept to operate on unencrypted archives")
            .action(ArgAction::SetTrue),
    ];
    let output_args = vec![
        Arg::new("output")
            .help("Output file path. Use - for stdout")
            .long("output")
            .short('o')
            .value_parser(value_parser!(PathBuf))
            .required(true),
        Arg::new("public_keys")
            .help("MLA public key file (PEM format), can be specified multiple times")
            .long("public-key")
            .short('p')
            .num_args(1)
            .action(ArgAction::Append)
            .value_parser(value_parser!(PathBuf)),
        Arg::new("layers")
            .long("layers")
            .short('l')
            .help("Layers to use. Default is '-l compress -l encrypt'")
            .value_parser(["compress", "encrypt"])
            .num_args(0..=1)
            .action(ArgAction::Append),
        Arg::new("compression_level")
            .group("Compression layer")
            .short('q')
            .long("compression_level")
            .value_parser(value_parser!(u32).range(0..=11))
            .help("Compression level (0-11); ; bigger values cause denser, but slower compression"),
    ];

    // Main parsing
    Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(
            Command::new("create")
                .about("Create a new MLA Archive")
                .args(&output_args)
                .arg(
                    Arg::new("files")
                    .help("Files to add")
                    .value_parser(value_parser!(PathBuf))
                    .action(ArgAction::Append)
                ),
        )
        .subcommand(
            Command::new("list")
                .about("List entries inside a MLA Archive")
                .before_help("Outputs a list of MLA entries. By default, names are interpreted as paths and encoded like described in `doc/ENTRY_NAME.md`")
                .args(&input_args)
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
                .about("Create a fresh MLA from what can be read from a truncated one")
                .args(&input_args)
                .args(&output_args),
        )
        .subcommand(
            Command::new("convert")
                .about(
                    "Convert a MLA Archive to a fresh new one, with potentially different options",
                )
                .args(&input_args)
                .args(&output_args),
        )
        .subcommand(
            Command::new("keygen")
                .about(
                    "Generate a public/private MLA keypair",
                )
                .arg(
                    Arg::new("output")
                        .help("Output file for the private key. The public key will be in {output}.pub")
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
                    "Advanced: Derive a new public/private keypair from an existing one and a public path, see `doc/KEYDERIVATION.md`",
                )
                .arg(
                    Arg::new("input")
                        .help("Input private key file")
                        .num_args(1)
                        .value_parser(value_parser!(PathBuf))
                        .required(true)
                )
                .arg(
                    Arg::new("output")
                        .help("Output file for the private key. The public key will be in {output}.pub")
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

fn main() {
    let mut app = app();

    // Launch sub-command
    let help = app.render_long_help();
    let matches = app.get_matches();
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
        eprintln!("Error: at least one command required.");
        eprintln!("{}", &help);
        std::process::exit(1);
    };

    if let Err(err) = res {
        eprintln!("[!] Command ended with error: {err:?}");
        std::process::exit(1);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn verify_app() {
        app().debug_assert();
    }
}
