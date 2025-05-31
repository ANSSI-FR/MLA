use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use glob::Pattern;
use hkdf::Hkdf;
use humansize::{DECIMAL, FormatSize};
use lru::LruCache;
use ml_kem::EncodedSizeUser;
use mla::config::{ArchiveReaderConfig, ArchiveWriterConfig};
use mla::crypto::hybrid::{HybridPrivateKey, HybridPublicKey};
use mla::crypto::mlakey_parser::{
    generate_keypair, parse_mlakey_privkey_der, parse_mlakey_privkey_pem, parse_mlakey_pubkey_pem,
};
use mla::errors::{Error, FailSafeReadError};
use mla::helpers::linear_extract;
use mla::layers::compress::CompressionLayerReader;
use mla::layers::encrypt::EncryptionLayerReader;
use mla::layers::raw::RawLayerReader;
use mla::layers::traits::{InnerReaderTrait, LayerReader};
use mla::{
    ArchiveFailSafeReader, ArchiveFile, ArchiveFooter, ArchiveHeader, ArchiveReader, ArchiveWriter,
    Layers,
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha2::{Digest, Sha512};
use std::collections::{HashMap, HashSet};
use std::error;
use std::fmt;
use std::fs::{self, File, read_dir};
use std::io::{self, BufRead};
use std::io::{Read, Seek, Write};
use std::num::NonZeroUsize;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use tar::{Builder, Header};
use zeroize::Zeroize;

// ----- Error ------

#[derive(Debug)]
pub enum MlarError {
    /// Wrap a MLA error
    MlaError(Error),
    /// IO Error (not enough data, etc.)
    IOError(io::Error),
    /// A private key has been provided, but it is not required
    PrivateKeyProvidedButNotUsed,
    /// Configuration error
    ConfigError(mla::errors::ConfigError),
}

impl fmt::Display for MlarError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // For now, use the debug derived version
        write!(f, "{self:?}")
    }
}

impl From<Error> for MlarError {
    fn from(error: Error) -> Self {
        MlarError::MlaError(error)
    }
}

impl From<io::Error> for MlarError {
    fn from(error: io::Error) -> Self {
        MlarError::IOError(error)
    }
}

impl From<mla::errors::ConfigError> for MlarError {
    fn from(error: mla::errors::ConfigError) -> Self {
        MlarError::ConfigError(error)
    }
}

impl error::Error for MlarError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            MlarError::IOError(err) => Some(err),
            MlarError::MlaError(err) => Some(err),
            MlarError::ConfigError(err) => Some(err),
            _ => None,
        }
    }
}

// ----- Utils ------

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
fn config_from_matches(matches: &ArgMatches) -> ArchiveWriterConfig {
    let mut config = ArchiveWriterConfig::new();

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

    for layer in layers {
        if layer == "compress" {
            config.enable_layer(Layers::COMPRESS);
        } else if layer == "encrypt" {
            config.enable_layer(Layers::ENCRYPT);
        } else {
            panic!("[ERROR] Unknown layer {}", layer);
        }
    }

    // Encryption specifics
    if matches.contains_id("public_keys") {
        if !config.is_layers_enabled(Layers::ENCRYPT) {
            eprintln!(
                "[WARNING] 'public_keys' argument ignored, because 'encrypt' layer is not enabled"
            );
        } else {
            let public_keys = match open_public_keys(matches) {
                Ok(public_keys) => public_keys,
                Err(error) => {
                    panic!("[ERROR] Unable to open public keys: {}", error);
                }
            };
            config.add_public_keys(&public_keys);
        }
    }

    // Compression specifics
    if matches.contains_id("compression_level") {
        if !config.is_layers_enabled(Layers::COMPRESS) {
            eprintln!(
                "[WARNING] 'compression_level' argument ignored, because 'compress' layer is not enabled"
            );
        } else {
            let comp_level: u32 = *matches
                .get_one::<u32>("compression_level")
                .expect("compression_level must be an int");
            if comp_level > 11 {
                panic!("compression_level must be in [0 .. 11]");
            }
            config.with_compression_level(comp_level).unwrap();
        }
    }

    config
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
    let config = config_from_matches(matches);

    // Safe to use unwrap() because the option is required()
    let output = matches.get_one::<PathBuf>("output").unwrap();

    let destination = destination_from_output_argument(output)?;

    // Instantiate output writer
    Ok(ArchiveWriter::from_config(destination, config)?)
}

/// Return the ArchiveReaderConfig corresponding to provided arguments and set
/// Layers::ENCRYPT if a key is provided
fn readerconfig_from_matches(matches: &ArgMatches) -> ArchiveReaderConfig {
    let mut config = ArchiveReaderConfig::new();

    if matches.contains_id("private_keys") {
        let private_keys = match open_private_keys(matches) {
            Ok(private_keys) => private_keys,
            Err(error) => {
                panic!("[ERROR] Unable to open private keys: {}", error);
            }
        };
        config.add_private_keys(&private_keys);
        config.layers_enabled.insert(Layers::ENCRYPT);
    }

    config
}

fn open_mla_file<'a>(matches: &ArgMatches) -> Result<ArchiveReader<'a, File>, MlarError> {
    let config = readerconfig_from_matches(matches);

    // Safe to use unwrap() because the option is required()
    let mla_file = matches.get_one::<PathBuf>("input").unwrap();
    let path = Path::new(&mla_file);
    let mut file = File::open(path)?;

    // If a decryption key is provided, assume the user expects the file to be encrypted
    // If not, avoid opening it
    file.rewind()?;
    let header = ArchiveHeader::from(&mut file)?;
    if config.layers_enabled.contains(Layers::ENCRYPT)
        && !header.config.layers_enabled.contains(Layers::ENCRYPT)
    {
        eprintln!("[-] A private key has been provided, but the archive is not encrypted");
        return Err(MlarError::PrivateKeyProvidedButNotUsed);
    }
    file.rewind()?;

    // Instantiate reader
    Ok(ArchiveReader::from_config(file, config)?)
}

// Utils: common code to load a mla_file from arguments, fail-safe mode
fn open_failsafe_mla_file<'a>(
    matches: &ArgMatches,
) -> Result<ArchiveFailSafeReader<'a, File>, MlarError> {
    let config = readerconfig_from_matches(matches);

    // Safe to use unwrap() because the option is required()
    let mla_file = matches.get_one::<PathBuf>("input").unwrap();
    let path = Path::new(&mla_file);
    let file = File::open(path)?;

    // Instantiate reader
    Ok(ArchiveFailSafeReader::from_config(file, config)?)
}

fn add_file_to_tar<R: Read, W: Write>(
    tar_file: &mut Builder<W>,
    sub_file: ArchiveFile<R>,
) -> io::Result<()> {
    // Use indexes to avoid in-memory copy
    let mut header = Header::new_gnu();
    header.set_size(sub_file.size);
    header.set_mode(0o444); // Create files as read-only
    header.set_cksum();

    // Force relative path, the trivial way (does not support Windows paths)
    let filename = {
        if Path::new(&sub_file.filename).is_absolute() {
            format!("./{}", sub_file.filename)
        } else {
            sub_file.filename
        }
    };

    tar_file.append_data(&mut header, &filename, sub_file.data)
}

/// Arguments for action 'extract' to match file names in the archive
enum ExtractFileNameMatcher {
    /// Match a list of files, where the order does not matter
    Files(HashSet<String>),
    /// Match a list of glob patterns
    GlobPatterns(Vec<Pattern>),
    /// No matching argument has been provided, so match all files
    Anything,
}
impl ExtractFileNameMatcher {
    fn from_matches(matches: &ArgMatches) -> Self {
        let files = match matches.get_many::<String>("files") {
            Some(values) => values,
            None => return ExtractFileNameMatcher::Anything,
        };
        if matches.get_flag("glob") {
            // Use glob patterns
            ExtractFileNameMatcher::GlobPatterns(
                files
                    .map(|pat| {
                        Pattern::new(pat)
                            .map_err(|err| {
                                eprintln!("[!] Invalid glob pattern {pat:?} ({err:?})");
                            })
                            .expect("Invalid glob pattern")
                    })
                    .collect(),
            )
        } else {
            // Use file names
            ExtractFileNameMatcher::Files(files.map(|s| s.to_string()).collect())
        }
    }
    fn match_file_name(&self, file_name: &str) -> bool {
        match self {
            ExtractFileNameMatcher::Files(files) => files.is_empty() || files.contains(file_name),
            ExtractFileNameMatcher::GlobPatterns(patterns) => {
                patterns.is_empty() || patterns.iter().any(|pat| pat.matches(file_name))
            }
            ExtractFileNameMatcher::Anything => true,
        }
    }
}

/// Compute the full path of the final file, using defensive measures
/// similar as what tar-rs does for `Entry::unpack_in`:
/// <https://github.com/alexcrichton/tar-rs/blob/0.4.26/src/entry.rs#L344>
fn get_extracted_path(output_dir: &Path, file_name: &str) -> Option<PathBuf> {
    let mut file_dst = output_dir.to_path_buf();
    for part in Path::new(&file_name).components() {
        match part {
            // Leading '/' characters, root paths, and '.'
            // components are just ignored and treated as "empty
            // components"
            Component::Prefix(..) | Component::RootDir | Component::CurDir => continue,

            // If any part of the filename is '..', then skip over
            // unpacking the file to prevent directory traversal
            // security issues.  See, e.g.: CVE-2001-1267,
            // CVE-2002-0399, CVE-2005-1918, CVE-2007-4131
            Component::ParentDir => {
                eprintln!("[!] Skipping file \"{file_name}\" because it contains \"..\"");
                return None;
            }

            Component::Normal(part) => file_dst.push(part),
        }
    }
    Some(file_dst)
}

/// Create a file and associate parent directories in a given output directory
fn create_file<P1: AsRef<Path>>(
    output_dir: P1,
    fname: &str,
) -> Result<Option<(File, PathBuf)>, MlarError> {
    let extracted_path = match get_extracted_path(output_dir.as_ref(), fname) {
        Some(p) => p,
        None => return Ok(None),
    };
    // Create all directories leading to the file
    let containing_directory = match extracted_path.parent() {
        Some(p) => p,
        None => {
            eprintln!(
                "[!] Skipping file \"{}\" because it does not have a parent (from {})",
                &fname,
                extracted_path.display()
            );
            return Ok(None);
        }
    };
    if !containing_directory.exists() {
        fs::create_dir_all(containing_directory).map_err(|err| {
            eprintln!(
                " [!] Error while creating output directory path for \"{}\" ({:?})",
                output_dir.as_ref().display(),
                err
            );
            err
        })?;
    }

    // Ensure that the containing directory is in the output dir
    let containing_directory = fs::canonicalize(containing_directory).map_err(|err| {
        eprintln!(
            " [!] Error while canonicalizing extracted file output directory path \"{}\" ({:?})",
            containing_directory.display(),
            err
        );
        err
    })?;
    if !containing_directory.starts_with(output_dir) {
        eprintln!(
            " [!] Skipping file \"{}\" because it would be extracted outside of the output directory, in {}",
            fname,
            containing_directory.display()
        );
        return Ok(None);
    }
    Ok(Some((
        File::create(&extracted_path).map_err(|err| {
            eprintln!(" [!] Unable to create \"{fname}\" ({err:?})");
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
    /// Filename in the archive
    fname: &'a str,
}

/// Max number of fd simultaneously opened
pub const FILE_WRITER_POOL_SIZE: usize = 1000;

impl Write for FileWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Only one thread is using the FileWriter, safe to `.unwrap()`
        let mut cache = self.cache.lock().unwrap();
        if !cache.contains(&self.path) {
            let file = fs::OpenOptions::new().append(true).open(&self.path)?;
            cache.put(self.path.clone(), file);
            if self.verbose {
                println!("{}", self.fname);
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
        // This can lead to some non-obvious DuplicateFilename error (files
        // that appear with different file names in the filesystem
        // but mlar raising DuplicateFilename)
        let filename = path.to_string_lossy();
        let file = File::open(path)?;
        let length = file.metadata()?.len();
        eprintln!("{filename}");
        mla.add_file(&filename, length, file)?;
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

    let mut iter: Vec<String> = mla.list_files()?.cloned().collect();
    iter.sort();
    for fname in iter {
        if matches.get_count("verbose") == 0 {
            println!("{fname}");
        } else {
            let mla_file = mla.get_file(fname)?.expect("Unable to get the file");
            let filename = mla_file.filename;
            let size = mla_file.size.format_size(DECIMAL);
            if matches.get_count("verbose") == 1 {
                println!("{filename} - {size}");
            } else if matches.get_count("verbose") >= 2 {
                let hash = mla.get_hash(&filename)?.expect("Unable to get the hash");
                println!("{} - {} ({})", filename, size, hex::encode(hash),);
            }
        }
    }
    Ok(())
}

fn extract(matches: &ArgMatches) -> Result<(), MlarError> {
    let file_name_matcher = ExtractFileNameMatcher::from_matches(matches);
    let output_dir = Path::new(matches.get_one::<PathBuf>("outputdir").unwrap());
    let verbose = matches.get_flag("verbose");

    let mut mla = open_mla_file(matches)?;

    // Create the output directory, if it does not exist
    if !output_dir.exists() {
        fs::create_dir(output_dir).map_err(|err| {
            eprintln!(
                " [!] Error while creating output directory \"{}\" ({:?})",
                output_dir.display(),
                err
            );
            err
        })?;
    }
    let output_dir = fs::canonicalize(output_dir).map_err(|err| {
        eprintln!(
            " [!] Error while canonicalizing output directory path \"{}\" ({:?})",
            output_dir.display(),
            err
        );
        err
    })?;

    let mut iter: Vec<String> = mla.list_files()?.cloned().collect();
    iter.sort();

    if let ExtractFileNameMatcher::Anything = file_name_matcher {
        // Optimisation: use linear extraction
        if verbose {
            println!("Extracting the whole archive using a linear extraction");
        }
        let cache = Mutex::new(LruCache::new(
            NonZeroUsize::new(FILE_WRITER_POOL_SIZE).unwrap(),
        ));
        let mut export: HashMap<&String, FileWriter> = HashMap::new();
        for fname in &iter {
            match create_file(&output_dir, fname)? {
                Some((_file, path)) => {
                    export.insert(
                        fname,
                        FileWriter {
                            path,
                            cache: &cache,
                            verbose,
                            fname,
                        },
                    );
                }
                None => continue,
            }
        }
        return Ok(linear_extract(&mut mla, &mut export)?);
    }

    for fname in iter {
        // Filter files according to glob patterns or files given as parameters
        if !file_name_matcher.match_file_name(&fname) {
            continue;
        }

        // Look for the file in the archive
        let mut sub_file = match mla.get_file(fname.clone()) {
            Err(err) => {
                eprintln!(" [!] Error while looking up subfile \"{fname}\" ({err:?})");
                continue;
            }
            Ok(None) => {
                eprintln!(" [!] Subfile \"{fname}\" indexed in metadata could not be found");
                continue;
            }
            Ok(Some(subfile)) => subfile,
        };
        let (mut extracted_file, _path) = match create_file(&output_dir, &fname)? {
            Some(file) => file,
            None => continue,
        };

        if verbose {
            println!("{fname}");
        }
        io::copy(&mut sub_file.data, &mut extracted_file).map_err(|err| {
            eprintln!(" [!] Unable to extract \"{fname}\" ({err:?})");
            err
        })?;
    }
    Ok(())
}

fn cat(matches: &ArgMatches) -> Result<(), MlarError> {
    let files_values = matches.get_many::<String>("files").unwrap();
    let output = matches.get_one::<PathBuf>("output").unwrap();
    let mut destination = destination_from_output_argument(output)?;

    let mut mla = open_mla_file(matches)?;
    if matches.get_flag("glob") {
        // For each glob patterns, enumerate matching files and display them
        let mut archive_files: Vec<String> = mla.list_files()?.cloned().collect();
        archive_files.sort();
        for arg_pattern in files_values {
            let pat = match Pattern::new(arg_pattern) {
                Ok(pat) => pat,
                Err(err) => {
                    eprintln!(" [!] Invalid glob pattern {arg_pattern:?} ({err:?})");
                    continue;
                }
            };
            for fname in archive_files.iter() {
                if !pat.matches(fname) {
                    continue;
                }
                match mla.get_file(fname.to_string()) {
                    Err(err) => {
                        eprintln!(" [!] Error while looking up file \"{fname}\" ({err:?})");
                        continue;
                    }
                    Ok(None) => {
                        eprintln!(
                            " [!] Subfile \"{fname}\" indexed in metadata could not be found"
                        );
                        continue;
                    }
                    Ok(Some(mut subfile)) => {
                        io::copy(&mut subfile.data, &mut destination).map_err(|err| {
                            eprintln!(" [!] Unable to extract \"{fname}\" ({err:?})");
                            err
                        })?;
                    }
                }
            }
        }
    } else {
        // Retrieve all the files that are specified
        for fname in files_values {
            match mla.get_file(fname.to_string()) {
                Err(err) => {
                    eprintln!(" [!] Error while looking up file \"{fname}\" ({err:?})");
                    continue;
                }
                Ok(None) => {
                    eprintln!(" [!] File not found: \"{fname}\"");
                    continue;
                }
                Ok(Some(mut subfile)) => {
                    io::copy(&mut subfile.data, &mut destination).map_err(|err| {
                        eprintln!(" [!] Unable to extract \"{fname}\" ({err:?})");
                        err
                    })?;
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

    let mut archive_files: Vec<String> = mla.list_files()?.cloned().collect();
    archive_files.sort();
    for fname in archive_files {
        let sub_file = match mla.get_file(fname.clone()) {
            Err(err) => {
                eprintln!(" [!] Error while looking up subfile \"{fname}\" ({err:?})");
                continue;
            }
            Ok(None) => {
                eprintln!(" [!] Subfile \"{fname}\" indexed in metadata could not be found");
                continue;
            }
            Ok(Some(subfile)) => subfile,
        };
        if let Err(err) = add_file_to_tar(&mut tar_file, sub_file) {
            eprintln!(" [!] Unable to add subfile \"{fname}\" to tarball ({err:?})");
        }
    }
    Ok(())
}

fn repair(matches: &ArgMatches) -> Result<(), MlarError> {
    let mut mla = open_failsafe_mla_file(matches)?;
    let mut mla_out = writer_from_matches(matches)?;

    // Convert
    let status = mla.convert_to_archive(&mut mla_out)?;
    match status {
        FailSafeReadError::NoError => {}
        FailSafeReadError::EndOfOriginalArchiveData => {
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
    let mut fnames: Vec<String> = if let Ok(iter) = mla.list_files() {
        // Read the file list using metadata
        iter.cloned().collect()
    } else {
        panic!("Files is malformed. Please consider repairing the file");
    };
    fnames.sort();

    let mut mla_out = writer_from_matches(matches)?;

    // Convert
    for fname in fnames {
        eprintln!("{fname}");
        let sub_file = match mla.get_file(fname.clone()) {
            Err(err) => {
                eprintln!("Error while adding {fname} ({err:?})");
                continue;
            }
            Ok(None) => {
                eprintln!("Unable to find {fname}");
                continue;
            }
            Ok(Some(mla)) => mla,
        };
        mla_out.add_file(&sub_file.filename, sub_file.size, sub_file.data)?;
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
    let mut csprng = match matches.get_one::<String>("seed") {
        Some(seed) => {
            eprintln!(
                "[WARNING] A seed-based keygen operation is deterministic. An attacker knowing the seed knows the private key and is able to decrypt associated messages"
            );
            let mut hseed = [0u8; 32];
            hseed.copy_from_slice(&Sha512::digest(seed.as_bytes())[0..32]);
            ChaChaRng::from_seed(hseed)
        }
        None => ChaChaRng::from_entropy(),
    };

    let key_pair = generate_keypair(&mut csprng).expect("Error while generating the key-pair");

    // Output the public key in PEM format, to ease integration in text based
    // configs
    output_pub
        .write_all(key_pair.public_as_pem().as_bytes())
        .expect("Error writing the public key");

    // Output the private key in PEM format, to ease integration in text based
    output_priv
        .write_all(key_pair.private_as_pem().as_bytes())
        .expect("Error writing the private key");
    Ok(())
}

const DERIVE_PATH_SALT: &[u8; 15] = b"PATH DERIVATION";

/// Return a seed based on a path and an hybrid private key
///
/// The derivation scheme is based on the same ideas than `mla::crypto::hybrid::combine`, ie.
/// 1. a dual-PRF (HKDF-Extract with a uniform random salt \[1\]) to extract entropy from the private key
/// 2. HKDF-Expand to derive along the given path
///
/// seed = HKDF-SHA512(
///     salt=HKDF-SHA512-Extract(salt=0, ikm=ECC-key),
///     ikm=MLKEM-key,
///     info="PATH DERIVATION" . Derivation path
/// )
///
/// Note: the secret is consumed on call
///
/// \[1\] <https://eprint.iacr.org/2023/861>
fn apply_derive(path: &str, mut src: HybridPrivateKey) -> [u8; 32] {
    // Force uniform-randomness on ECC-key, used as the future HKDF "salt" argument
    let (dprf_salt, _hkdf) = Hkdf::<Sha512>::extract(None, src.private_key_ecc.as_bytes());

    // `salt` being uniformly random, HKDF can be viewed as a dual-PRF
    let hkdf: Hkdf<Sha512> = Hkdf::new(Some(&dprf_salt), &src.private_key_ml.as_bytes());
    let mut seed = [0u8; 32];
    hkdf.expand_multi_info(&[DERIVE_PATH_SALT, path.as_bytes()], &mut seed)
        .expect("Unexpected error while derivating along the path");

    // Consume the secret
    src.zeroize();

    seed
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
    let mut secret =
        parse_mlakey_privkey_pem(&buf).map_err(|_| MlarError::MlaError(Error::InvalidKeyFormat))?;

    // Derive the key along the path
    let mut key_pair = None;
    for path in matches
        .get_many::<String>("path")
        .expect("[ERROR] At least one path must be provided")
    {
        let mut csprng = ChaChaRng::from_seed(apply_derive(path, secret));

        // Use the high-level API to avoid duplicating code from curve25519-parser in case of futur changes
        key_pair =
            Some(generate_keypair(&mut csprng).expect("Error while generating the key-pair"));
        secret = parse_mlakey_privkey_der(&key_pair.as_ref().unwrap().private_der).unwrap();
    }

    // Safe to unwrap, there is at least one derivation path
    let key_pair = key_pair.unwrap();

    // Output the public key in PEM format, to ease integration in text based
    // configs
    output_pub
        .write_all(key_pair.public_as_pem().as_bytes())
        .expect("Error writing the public key");

    // Output the private key in PEM format, to ease integration in text based
    output_priv
        .write_all(key_pair.private_as_pem().as_bytes())
        .expect("Error writing the private key");
    Ok(())
}

pub struct ArchiveInfoReader {
    /// MLA Archive format Reader
    //
    /// User's reading configuration
    pub config: ArchiveReaderConfig,
    /// Compressed sizes from CompressionLayer
    pub compressed_size: Option<u64>,
    /// Metadata (from footer if any)
    metadata: Option<ArchiveFooter>,
}

impl ArchiveInfoReader {
    pub fn from_config<'a, R>(
        mut src: R,
        mut config: ArchiveReaderConfig,
    ) -> Result<Self, MlarError>
    where
        R: 'a + InnerReaderTrait,
    {
        // Make sure we read the archive header from the start
        src.rewind()?;
        let header = ArchiveHeader::from(&mut src)?;
        config.load_persistent(header.config)?;

        // Pin the current position (after header) as the new 0
        let mut raw_src = Box::new(RawLayerReader::new(src));
        raw_src.reset_position()?;

        // Enable layers depending on user option. Order is relevant
        let mut src: Box<dyn 'a + LayerReader<'a, R>> = raw_src;
        if config.layers_enabled.contains(Layers::ENCRYPT) {
            src = Box::new(EncryptionLayerReader::new(src, &config.encrypt)?)
        }
        let compressed_size = if config.layers_enabled.contains(Layers::COMPRESS) {
            let mut src_compress = Box::new(CompressionLayerReader::new(src)?);
            src_compress.initialize()?;
            let size = src_compress
                .sizes_info
                .as_ref()
                .map(|v| v.get_compressed_size());
            src = src_compress;
            size
        } else {
            src.initialize()?;
            None
        };

        let metadata = Some(ArchiveFooter::deserialize_from(&mut src)?);

        src.rewind()?;
        Ok(ArchiveInfoReader {
            config,
            compressed_size,
            metadata,
        })
    }

    pub fn get_files_size(&self) -> Result<u64, MlarError> {
        if let Some(ArchiveFooter { files_info, .. }) = &self.metadata {
            Ok(files_info.values().map(|f| f.size).sum())
        } else {
            Err(Error::MissingMetadata.into())
        }
    }
}

fn info(matches: &ArgMatches) -> Result<(), MlarError> {
    // Safe to use unwrap() because the option is required()
    let mla_file = matches.get_one::<PathBuf>("input").unwrap();
    let path = Path::new(&mla_file);
    let mut file = File::open(path)?;

    // Get Header
    let header = ArchiveHeader::from(&mut file)?;

    let encryption = header.config.layers_enabled.contains(Layers::ENCRYPT);
    let compression = header.config.layers_enabled.contains(Layers::COMPRESS);

    // Instantiate reader as needed
    let mla = if compression {
        let config = readerconfig_from_matches(matches);
        Some(ArchiveInfoReader::from_config(file, config)?)
    } else {
        None
    };

    // Format Version
    println!("Format version: {}", header.format_version);

    // Encryption config
    println!("Encryption: {encryption}");
    if encryption && matches.get_flag("verbose") {
        let encrypt_config = header.config.encrypt.expect("Encryption config not found");
        println!(
            "  Recipients: {}",
            encrypt_config
                .hybrid_multi_recipient_encapsulate_key
                .count_keys()
        );
    }

    // Compression config
    println!("Compression: {compression}");
    if compression && matches.get_flag("verbose") {
        let mla_ = mla.expect("MLA is required for verbose compression info");
        let output_size = mla_.get_files_size()?;
        let compressed_size: u64 = mla_.compressed_size.expect("Missing compression size");
        let compression_rate = output_size as f64 / compressed_size as f64;
        println!("  Compression rate: {compression_rate:.2}");
    }

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
            .long("private_keys")
            .short('k')
            .help("Candidates ED25519 private key paths (PEM format)")
            .num_args(1)
            .action(ArgAction::Append)
            .value_parser(value_parser!(PathBuf)),
    ];
    let output_args = vec![
        Arg::new("output")
            .help("Output file path. Use - for stdout")
            .long("output")
            .short('o')
            .value_parser(value_parser!(PathBuf))
            .required(true),
        Arg::new("public_keys")
            .help("ED25519 Public key paths (PEM format)")
            .long("pubkey")
            .short('p')
            .num_args(1)
            .action(ArgAction::Append)
            .value_parser(value_parser!(PathBuf)),
        Arg::new("layers")
            .long("layers")
            .short('l')
            .help("Layers to use. Default is 'compress,encrypt'")
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
                .about("List files inside a MLA Archive")
                .args(&input_args)
                .arg(
                    Arg::new("verbose")
                        .short('v')
                        .action(ArgAction::Count)
                        .help("Verbose listing, with additional information"),
                ),
        )
        .subcommand(
            Command::new("extract")
                .about("Extract files from a MLA Archive")
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
                .arg(Arg::new("files").help("List of extracted files (all if none given)"))
                .arg(
                    Arg::new("verbose")
                        .long("verbose")
                        .short('v')
                        .action(ArgAction::SetTrue)
                        .help("List files as they are extracted"),
                ),
        )
        .subcommand(
            Command::new("cat")
                .about("Display files from a MLA Archive, like 'cat'")
                .args(&input_args)
                .arg(
                    Arg::new("output")
                        .help("Output file where files are displayed")
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
                        .help("Treat given files as glob patterns"),
                )
                .arg(
                    Arg::new("files")
                        .required(true)
                        .help("List of displayed files"),
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
                .about("Try to repair a MLA Archive into a fresh MLA Archive")
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
                    "Generate a public/private keypair, in OpenSSL Ed25519 format, to be used by mlar",
                )
                .arg(
                    Arg::new("output")
                        .help("Output file for the private key. The public key is in {output}.pub")
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
                    "Derive a new public/private keypair from an existing one and a public path, in OpenSSL Ed25519 format, to be used by mlar",
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
                        .help("Output file for the private key. The public key is in {output}.pub")
                        .num_args(1)
                        .value_parser(value_parser!(PathBuf))
                        .required(true)
                )
                .arg(
                    Arg::new("path")
                    .help("Public derivation path")
                    .long("path")
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
    use mla::crypto::hybrid::{MLKEMDecapsulationKey, generate_keypair_from_rng};
    use std::iter::FromIterator;
    use x25519_dalek::StaticSecret;

    #[test]
    fn verify_app() {
        app().debug_assert();
    }

    #[test]
    /// Naive checks for "apply_derive", to avoid naive erros
    fn check_apply_derive() {
        // Ensure determinism
        let rng = ChaChaRng::from_seed([0u8; 32]);
        let (privkey, _pubkey) = generate_keypair_from_rng(rng);

        // Derive along "test"
        let path = "test";
        let seed = apply_derive(path, privkey);
        assert_ne!(seed, [0u8; 32]);

        // Derive along "test2"
        let rng = ChaChaRng::from_seed([0u8; 32]);
        let (privkey, _pubkey) = generate_keypair_from_rng(rng);
        let path = "test2";
        let seed2 = apply_derive(path, privkey);
        assert_ne!(seed, seed2);

        // Ensure the secret depends on both keys
        let mut priv_keys = vec![];
        for i in 0..1 {
            for j in 0..1 {
                priv_keys.push(HybridPrivateKey {
                    private_key_ecc: StaticSecret::from([i as u8; 32]),
                    private_key_ml: MLKEMDecapsulationKey::from_bytes(&[j as u8; 3168].into()),
                });
            }
        }

        // Generated seeds for (0, 0), (0, 1), (1, 0) and (1, 1) must be different
        let seeds: Vec<_> = priv_keys
            .into_iter()
            .map(|pkey| apply_derive("test", pkey))
            .collect();
        assert_eq!(HashSet::<_>::from_iter(seeds.iter()).len(), seeds.len());
    }
}
