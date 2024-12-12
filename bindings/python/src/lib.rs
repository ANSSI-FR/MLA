use std::{
    borrow::Cow,
    collections::HashMap,
    fs::File,
    io::{self, Read},
};

use curve25519_parser::{parse_openssl_25519_privkey, parse_openssl_25519_pubkey};
use mla::{
    config::{ArchiveReaderConfig, ArchiveWriterConfig},
    ArchiveReader, ArchiveWriter, Layers,
};
use pyo3::{
    create_exception,
    exceptions::{PyKeyError, PyRuntimeError, PyTypeError},
    prelude::*,
    types::{PyBytes, PyString, PyTuple, PyType},
};

// -------- Error handling --------

/// Wrapper over MLA custom error, due to the "orphan rule"
/// - WrappedMLA: MLA specifics errors
/// - WrappedPy: Python related errors
#[derive(Debug)]
enum WrappedError {
    WrappedMLA(mla::errors::Error),
    WrappedPy(PyErr),
}

// Add a dedicated MLA Exception (mla.MLAError) and associated sub-Exception
// IOError and AssertionError are not mapped, as they already map to Python Exception
create_exception!(mla, MLAError, pyo3::exceptions::PyException);
create_exception!(mla, WrongMagic, MLAError, "Wrong magic, must be \"MLA\"");
create_exception!(
    mla,
    UnsupportedVersion,
    MLAError,
    "Unsupported version, must be 1"
);
create_exception!(
    mla,
    InvalidECCKeyFormat,
    MLAError,
    "Supplied ECC key is not in the expected format"
);
create_exception!(mla, WrongBlockSubFileType, MLAError, "Wrong BlockSubFile magic has been encountered. Is the deserializion tarting at the beginning of a block?");
create_exception!(
    mla,
    UTF8ConversionError,
    MLAError,
    "An error has occurred while converting into UTF8. This error could"
);
create_exception!(
    mla,
    FilenameTooLong,
    MLAError,
    "Filenames have a limited size `FILENAME_MAX_SIZE`"
);
create_exception!(
    mla,
    WrongArchiveWriterState,
    MLAError,
    "The writer state is not in the expected state for the current operation"
);
create_exception!(
    mla,
    WrongReaderState,
    MLAError,
    "The reader state is not in the expected state for the current operation"
);
create_exception!(
    mla,
    WrongWriterState,
    MLAError,
    "The writer state is not in the expected state for the current operation"
);
create_exception!(
    mla,
    RandError,
    MLAError,
    "Error with the inner random generator"
);
create_exception!(
    mla,
    PrivateKeyNeeded,
    MLAError,
    "A Private Key is required to decrypt the encrypted cipher key"
);
create_exception!(
    mla,
    DeserializationError,
    MLAError,
    "Deserialization error. May happens when starting from a wrong offset / version mismatch"
);
create_exception!(
    mla,
    SerializationError,
    MLAError,
    "Serialization error. May happens on I/O errors"
);
create_exception!(mla, MissingMetadata, MLAError, "Missing metadata (usually means the footer has not been correctly read, a repair might be needed)");
create_exception!(
    mla,
    BadAPIArgument,
    MLAError,
    "Error returned on API call with incorrect argument"
);
create_exception!(
    mla,
    EndOfStream,
    MLAError,
    "End of stream reached, no more data should be expected"
);
create_exception!(
    mla,
    ConfigError,
    MLAError,
    "An error happens in the configuration"
);
create_exception!(mla, DuplicateFilename, MLAError, "Filename already used");
create_exception!(
    mla,
    AuthenticatedDecryptionWrongTag,
    MLAError,
    "Wrong tag while decrypting authenticated data"
);
create_exception!(
    mla,
    HKDFInvalidKeyLength,
    MLAError,
    "Unable to expand while using the HKDF"
);

// Convert potentials errors to the wrapped type

impl From<mla::errors::Error> for WrappedError {
    fn from(err: mla::errors::Error) -> Self {
        WrappedError::WrappedMLA(err)
    }
}

impl From<mla::errors::ConfigError> for WrappedError {
    fn from(err: mla::errors::ConfigError) -> Self {
        WrappedError::WrappedMLA(mla::errors::Error::ConfigError(err))
    }
}

impl From<std::io::Error> for WrappedError {
    fn from(err: std::io::Error) -> Self {
        WrappedError::WrappedPy(err.into())
    }
}

impl From<PyErr> for WrappedError {
    fn from(err: PyErr) -> Self {
        WrappedError::WrappedPy(err)
    }
}

/// Convert back the wrapped type to Python errors
impl From<WrappedError> for PyErr {
    fn from(err: WrappedError) -> PyErr {
        match err {
            WrappedError::WrappedMLA(inner_err) => {
                match inner_err {
                    mla::errors::Error::IOError(err) => PyErr::new::<pyo3::exceptions::PyIOError, _>(err),
                    mla::errors::Error::AssertionError(msg) => PyErr::new::<pyo3::exceptions::PyAssertionError, _>(msg),
                    mla::errors::Error::WrongMagic => PyErr::new::<WrongMagic, _>("Wrong magic, must be \"MLA\""),
                    mla::errors::Error::UnsupportedVersion => PyErr::new::<UnsupportedVersion, _>("Unsupported version, must be 1"),
                    mla::errors::Error::InvalidECCKeyFormat => PyErr::new::<InvalidECCKeyFormat, _>("Supplied ECC key is not in the expected format"),
                    mla::errors::Error::WrongBlockSubFileType => PyErr::new::<WrongBlockSubFileType, _>("Wrong BlockSubFile magic has been encountered. Is the deserializion tarting at the beginning of a block?"),
                    mla::errors::Error::UTF8ConversionError(err) => PyErr::new::<UTF8ConversionError, _>(err),
                    mla::errors::Error::FilenameTooLong => PyErr::new::<FilenameTooLong, _>("Filenames have a limited size `FILENAME_MAX_SIZE`"),
                    mla::errors::Error::WrongArchiveWriterState { current_state, expected_state } => PyErr::new::<WrongArchiveWriterState, _>(format!("The writer state is not in the expected state for the current operation. Current state: {:?}, expected state: {:?}", current_state, expected_state)),
                    mla::errors::Error::WrongReaderState(msg) => PyErr::new::<WrongReaderState, _>(msg),
                    mla::errors::Error::WrongWriterState(msg) => PyErr::new::<WrongWriterState, _>(msg),
                    mla::errors::Error::RandError(err) => PyErr::new::<RandError, _>(format!("{:}", err)),
                    mla::errors::Error::PrivateKeyNeeded => PyErr::new::<PrivateKeyNeeded, _>("A Private Key is required to decrypt the encrypted cipher key"),
                    mla::errors::Error::DeserializationError => PyErr::new::<DeserializationError, _>("Deserialization error. May happens when starting from a wrong offset / version mismatch"),
                    mla::errors::Error::SerializationError => PyErr::new::<SerializationError, _>("Serialization error. May happens on I/O errors"),
                    mla::errors::Error::MissingMetadata => PyErr::new::<MissingMetadata, _>("Missing metadata (usually means the footer has not been correctly read, a repair might be needed)"),
                    mla::errors::Error::BadAPIArgument(msg) => PyErr::new::<BadAPIArgument, _>(msg),
                    mla::errors::Error::EndOfStream => PyErr::new::<EndOfStream, _>("End of stream reached, no more data should be expected"),
                    mla::errors::Error::ConfigError(err) => PyErr::new::<ConfigError, _>(format!("{:}", err)),
                    mla::errors::Error::DuplicateFilename => PyErr::new::<DuplicateFilename, _>("Filename already used"),
                    mla::errors::Error::AuthenticatedDecryptionWrongTag => PyErr::new::<AuthenticatedDecryptionWrongTag, _>("Wrong tag while decrypting authenticated data"),
                    mla::errors::Error::HKDFInvalidKeyLength => PyErr::new::<HKDFInvalidKeyLength, _>("Unable to expand while using the HKDF"),
                }
            },
            WrappedError::WrappedPy(inner_err) => inner_err
        }
    }
}
// -------- mla.FileMetadata --------

#[pyclass]
struct FileMetadata {
    size: Option<u64>,
    hash: Option<[u8; 32]>,
}

#[pymethods]
impl FileMetadata {
    #[getter]
    fn size(&self) -> Option<u64> {
        self.size
    }

    #[getter]
    fn hash(&self) -> Option<Cow<[u8]>> {
        self.hash.as_ref().map(|h| Cow::Borrowed::<[u8]>(h))
    }

    fn __repr__(&self) -> String {
        format!("<FileMetadata size={:?} hash={:?}>", self.size, self.hash)
    }
}

// -------- mla.PublicKeys --------

/// Represents multiple ECC Public Keys
///
/// Instanciate with path (as string) or data (as bytes)
/// PEM and DER format are supported
///
/// Example:
/// ```python
/// pkeys = PublicKeys("/path/to/key.pem", b"""
/// -----BEGIN PUBLIC KEY-----
/// ...
/// -----END PUBLIC KEY-----
/// """)
/// ```
#[derive(Clone)]
#[pyclass]
struct PublicKeys {
    keys: Vec<x25519_dalek::PublicKey>,
}

#[pymethods]
impl PublicKeys {
    #[new]
    #[pyo3(signature = (*args))]
    fn new(args: &PyTuple) -> Result<Self, WrappedError> {
        let mut keys = Vec::new();

        for element in args {
            // String argument: this is a path
            // "/path/to/public.pem"
            if let Ok(path) = element.downcast::<PyString>() {
                let mut file = File::open(path.to_string())?;
                // Load the the ECC key in-memory and parse it
                let mut buf = Vec::new();
                file.read_to_end(&mut buf)?;
                keys.push(
                    parse_openssl_25519_pubkey(&buf)
                        .map_err(|_| mla::errors::Error::InvalidECCKeyFormat)?,
                );
            } else if let Ok(data) = element.downcast::<PyBytes>() {
                keys.push(
                    parse_openssl_25519_pubkey(data.as_bytes())
                        .map_err(|_| mla::errors::Error::InvalidECCKeyFormat)?,
                );
            } else {
                return Err(
                    PyTypeError::new_err("Expect a path (as a string) or data (as bytes)").into(),
                );
            }
        }
        Ok(Self { keys })
    }

    /// DER representation of keys
    #[getter]
    fn keys(&self) -> Vec<Cow<[u8]>> {
        self.keys
            .iter()
            .map(|pubkey| Cow::Owned(Vec::from(pubkey.to_bytes())))
            .collect()
    }
}

// -------- mla.PrivateKeys --------

/// Represents multiple ECC Private Keys
///
/// Instanciate with path (as string) or data (as bytes)
/// PEM and DER format are supported
///
/// Example:
/// ```python
/// pkeys = PrivateKeys("/path/to/key.pem", b"""
/// -----BEGIN PRIVATE KEY-----
/// ...
/// -----END PRIVATE KEY-----
/// """)
/// ```
#[derive(Clone)]
#[pyclass]
struct PrivateKeys {
    keys: Vec<x25519_dalek::StaticSecret>,
}

#[pymethods]
impl PrivateKeys {
    #[new]
    #[pyo3(signature = (*args))]
    fn new(args: &PyTuple) -> Result<Self, WrappedError> {
        let mut keys = Vec::new();

        for element in args {
            // String argument: this is a path
            // "/path/to/public.pem"
            if let Ok(path) = element.downcast::<PyString>() {
                let mut file = File::open(path.to_string())?;
                // Load the the ECC key in-memory and parse it
                let mut buf = Vec::new();
                file.read_to_end(&mut buf)?;
                keys.push(
                    parse_openssl_25519_privkey(&buf)
                        .map_err(|_| mla::errors::Error::InvalidECCKeyFormat)?,
                );
            } else if let Ok(data) = element.downcast::<PyBytes>() {
                keys.push(
                    parse_openssl_25519_privkey(data.as_bytes())
                        .map_err(|_| mla::errors::Error::InvalidECCKeyFormat)?,
                );
            } else {
                return Err(
                    PyTypeError::new_err("Expect a path (as a string) or data (as bytes)").into(),
                );
            }
        }
        Ok(Self { keys })
    }

    /// DER representation of keys
    /// :warning: This keys must be kept secrets!
    #[getter]
    fn keys(&self) -> Vec<Cow<[u8]>> {
        self.keys
            .iter()
            .map(|privkey| Cow::Owned(Vec::from(privkey.to_bytes())))
            .collect()
    }
}

// -------- mla.ConfigWriter --------

// from mla::layers::DEFAULT_COMPRESSION_LEVEL
const DEFAULT_COMPRESSION_LEVEL: u32 = 5;

// This class keep the values of configured object, and can be used to produce an actual
// `ArchiveWriterConfig`. That way, it can be used to produced many of them, as they are
// consumed during the `ArchiveWriter` init (to avoid reusing cryptographic materials)
#[pyclass]
struct WriterConfig {
    layers: Layers,
    compression_level: u32,
    public_keys: Option<PublicKeys>,
}

#[pymethods]
impl WriterConfig {
    #[new]
    #[pyo3(signature = (layers=None, compression_level=DEFAULT_COMPRESSION_LEVEL, public_keys=None))]
    fn new(
        layers: Option<u8>,
        compression_level: u32,
        public_keys: Option<PublicKeys>,
    ) -> Result<Self, WrappedError> {
        // Check parameters
        let layers = match layers {
            Some(layers_enabled) => Layers::from_bits(layers_enabled).ok_or(
                mla::errors::Error::BadAPIArgument("Unknown layers".to_string()),
            )?,
            None => Layers::DEFAULT,
        };

        // Check compression level is correct using a fake object
        ArchiveWriterConfig::new().with_compression_level(compression_level)?;

        Ok(WriterConfig {
            layers,
            compression_level,
            public_keys,
        })
    }

    #[getter]
    fn layers(&self) -> u8 {
        self.layers.bits()
    }

    /// Enable a layer
    fn enable_layer(mut slf: PyRefMut<Self>, layer: u8) -> Result<PyRefMut<Self>, WrappedError> {
        let layer = Layers::from_bits(layer).ok_or(mla::errors::Error::BadAPIArgument(
            "Unknown layer".to_string(),
        ))?;
        slf.layers |= layer;
        Ok(slf)
    }

    /// Disable a layer
    fn disable_layer(mut slf: PyRefMut<Self>, layer: u8) -> Result<PyRefMut<Self>, WrappedError> {
        let layer = Layers::from_bits(layer).ok_or(mla::errors::Error::BadAPIArgument(
            "Unknown layer".to_string(),
        ))?;
        slf.layers &= !layer;
        Ok(slf)
    }

    /// Set several layers at once
    fn set_layers(mut slf: PyRefMut<Self>, layers: u8) -> Result<PyRefMut<Self>, WrappedError> {
        slf.layers = Layers::from_bits(layers).ok_or(mla::errors::Error::BadAPIArgument(
            "Unknown layer".to_string(),
        ))?;
        Ok(slf)
    }

    /// Set the compression level
    /// compression level (0-11); bigger values cause denser, but slower compression
    fn with_compression_level(
        mut slf: PyRefMut<Self>,
        compression_level: u32,
    ) -> Result<PyRefMut<Self>, WrappedError> {
        // Check compression level is correct using a fake object
        ArchiveWriterConfig::new().with_compression_level(compression_level)?;

        slf.compression_level = compression_level;
        Ok(slf)
    }

    #[getter]
    fn compression_level(&self) -> u32 {
        self.compression_level
    }

    /// Set public keys
    fn set_public_keys(
        mut slf: PyRefMut<Self>,
        public_keys: PublicKeys,
    ) -> Result<PyRefMut<Self>, WrappedError> {
        slf.public_keys = Some(public_keys);
        Ok(slf)
    }

    #[getter]
    fn public_keys(&self) -> Option<PublicKeys> {
        self.public_keys.clone()
    }
}

impl WriterConfig {
    /// Create an `ArchiveWriterConfig` out of the python object
    fn to_archive_writer_config(&self) -> Result<ArchiveWriterConfig, WrappedError> {
        let mut config = ArchiveWriterConfig::new();
        config.set_layers(self.layers);
        config.with_compression_level(self.compression_level)?;
        if let Some(ref public_keys) = self.public_keys {
            config.add_public_keys(&public_keys.keys);
        }
        Ok(config)
    }
}

// -------- mla.ConfigReader --------

// This class keep the values of configured object, and can be used to produce an actual
// `ArchiveReaderConfig`. That way, it can be used to produced many of them, as they are
// consumed during the `ArchiveReader` init
#[pyclass]
struct ReaderConfig {
    private_keys: Option<PrivateKeys>,
}

#[pymethods]
impl ReaderConfig {
    #[new]
    #[pyo3(signature = (private_keys=None))]
    fn new(private_keys: Option<PrivateKeys>) -> Self {
        ReaderConfig { private_keys }
    }

    /// Set private keys
    fn set_private_keys(
        mut slf: PyRefMut<Self>,
        private_keys: PrivateKeys,
    ) -> Result<PyRefMut<Self>, WrappedError> {
        slf.private_keys = Some(private_keys);
        Ok(slf)
    }

    #[getter]
    fn private_keys(&self) -> Option<PrivateKeys> {
        self.private_keys.clone()
    }
}

impl ReaderConfig {
    /// Create an `ArchiveReaderConfig` out of the python object
    fn to_archive_reader_config(&self) -> Result<ArchiveReaderConfig, WrappedError> {
        let mut config = ArchiveReaderConfig::new();
        if let Some(ref private_keys) = self.private_keys {
            config.add_private_keys(&private_keys.keys);
            config.layers_enabled |= Layers::ENCRYPT;
        }
        Ok(config)
    }
}

// -------- mla.MLAFile --------

/// `ArchiveWriter` is a generic type. To avoid generating several Python implementation
/// (see https://pyo3.rs/v0.20.2/class.html#no-generic-parameters), this enum explicitely
/// instanciate `ArchiveWriter` for common & expected types
///
/// Additionnaly, as the GC in Python might drop objects at any time, we need to use
/// `'static` lifetime for the writer. This should not be a problem as the writer is not
/// supposed to be used after the drop of the parent object
/// (see https://pyo3.rs/v0.20.2/class.html#no-lifetime-parameters)
enum ExplicitWriters {
    FileWriter(ArchiveWriter<'static, std::fs::File>),
}

/// Wrap calls to the inner type
impl ExplicitWriters {
    fn finalize(&mut self) -> Result<(), mla::errors::Error> {
        match self {
            ExplicitWriters::FileWriter(writer) => {
                writer.finalize()?;
                Ok(())
            }
        }
    }

    fn add_file<R: Read>(
        &mut self,
        key: &str,
        size: u64,
        reader: &mut R,
    ) -> Result<(), mla::errors::Error> {
        match self {
            ExplicitWriters::FileWriter(writer) => {
                writer.add_file(key, size, reader)?;
                Ok(())
            }
        }
    }

    fn start_file(&mut self, key: &str) -> Result<u64, mla::errors::Error> {
        match self {
            ExplicitWriters::FileWriter(writer) => writer.start_file(key),
        }
    }

    fn append_file_content(
        &mut self,
        id: u64,
        size: usize,
        data: &[u8],
    ) -> Result<(), mla::errors::Error> {
        match self {
            ExplicitWriters::FileWriter(writer) => {
                writer.append_file_content(id, size as u64, data)
            }
        }
    }

    fn end_file(&mut self, id: u64) -> Result<(), mla::errors::Error> {
        match self {
            ExplicitWriters::FileWriter(writer) => writer.end_file(id),
        }
    }
}

/// See `ExplicitWriters` for details
enum ExplicitReaders {
    FileReader(ArchiveReader<'static, std::fs::File>),
}

/// Wrap calls to the inner type
impl ExplicitReaders {
    fn list_files(&self) -> Result<impl Iterator<Item = &String>, mla::errors::Error> {
        match self {
            ExplicitReaders::FileReader(reader) => reader.list_files(),
        }
    }
}

/// Opening Mode for a MLAFile
enum OpeningModeInner {
    Read(ExplicitReaders),
    Write(ExplicitWriters),
}

#[pyclass]
pub struct MLAFile {
    /// Wrapping over the rust object, depending on the opening mode
    inner: OpeningModeInner,
    /// Path of the file, used for messages
    path: String,
}

/// Thread safety is assured by Send and Sync traits (marker traits, hence unsafe)
unsafe impl Sync for MLAFile {}

/// Used to check whether the opening mode is the expected one, and unwrap it
/// return a BadAPI argument error if not
/// ```text
/// let inner = check_mode!(self, Read);
/// ```
macro_rules! check_mode {
    ( $self:expr, $x:ident ) => {{
        match &$self.inner {
            OpeningModeInner::$x(inner) => inner,
            _ => {
                return Err(mla::errors::Error::BadAPIArgument(format!(
                    "This API is only callable in {:} mode",
                    stringify!($x)
                ))
                .into())
            }
        }
    }};
    ( mut $self:expr, $x:ident ) => {{
        match &mut $self.inner {
            OpeningModeInner::$x(inner) => inner,
            _ => {
                return Err(mla::errors::Error::BadAPIArgument(format!(
                    "This API is only callable in {:} mode",
                    stringify!($x)
                ))
                .into())
            }
        }
    }};
}

#[pymethods]
impl MLAFile {
    #[new]
    #[pyo3(signature = (path, mode="r", config=None))]
    fn new(path: &str, mode: &str, config: Option<&Bound<'_, PyAny>>) -> Result<Self, WrappedError> {
        match mode {
            "r" => {
                let rconfig = match config {
                    Some(config) => {
                        // Must be a ReaderConfig
                        config
                            .extract::<PyRef<ReaderConfig>>()?
                            .to_archive_reader_config()?
                    }
                    None => ArchiveReaderConfig::new(),
                };
                let input_file = std::fs::File::open(path)?;
                let arch_reader = ArchiveReader::from_config(input_file, rconfig)?;
                Ok(MLAFile {
                    inner: OpeningModeInner::Read(ExplicitReaders::FileReader(arch_reader)),
                    path: path.to_string(),
                })
            }
            "w" => {
                let wconfig = match config {
                    Some(config) => {
                        // Must be a WriterConfig
                        config
                            .extract::<PyRef<WriterConfig>>()?
                            .to_archive_writer_config()?
                    }
                    None => ArchiveWriterConfig::new(),
                };
                let output_file = std::fs::File::create(path)?;
                let arch_writer = ArchiveWriter::from_config(output_file, wconfig)?;
                Ok(MLAFile {
                    inner: OpeningModeInner::Write(ExplicitWriters::FileWriter(arch_writer)),
                    path: path.to_string(),
                })
            }
            _ => Err(mla::errors::Error::BadAPIArgument(format!(
                "Unknown mode {}, use 'r' or 'w'",
                mode
            ))
            .into()),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "<MLAFile path='{:}' mode='{:}'>",
            self.path,
            match self.inner {
                OpeningModeInner::Read(_) => "r",
                OpeningModeInner::Write(_) => "w",
            }
        )
    }

    /// Return the list of files in the archive
    fn keys(&self) -> Result<Vec<String>, WrappedError> {
        let inner = check_mode!(self, Read);
        Ok(inner.list_files()?.map(|x| x.to_string()).collect())
    }

    /// Return the list of the files in the archive, along with metadata
    /// If `include_size` is set, the size will be included in the metadata
    /// If `include_hash` is set, the hash (SHA256) will be included in the metadata
    ///
    /// Example:
    /// ```python
    /// metadatas = archive.list_files(include_size=True, include_hash=True)
    /// for fname, metadata in metadatas.items():
    ///    print(f"File {fname} has size {metadata.size} and hash {metadata.hash}")
    /// ```
    #[pyo3(signature = (include_size=false, include_hash=false))]
    fn list_files(
        &mut self,
        include_size: bool,
        include_hash: bool,
    ) -> Result<HashMap<String, FileMetadata>, WrappedError> {
        let inner = check_mode!(mut self, Read);

        let mut output = HashMap::new();
        let iter: Vec<String> = inner.list_files()?.cloned().collect();
        for fname in iter {
            let mut metadata = FileMetadata {
                size: None,
                hash: None,
            };
            match inner {
                ExplicitReaders::FileReader(mla) => {
                    if include_size {
                        metadata.size = Some(
                            mla.get_file(fname.clone())?
                                .ok_or(PyRuntimeError::new_err(format!(
                                    "File {} not found",
                                    fname
                                )))?
                                .size,
                        );
                    }
                    if include_hash {
                        metadata.hash = Some(
                            mla.get_hash(&fname)?
                                .ok_or(PyRuntimeError::new_err(format!(
                                    "File {} not found",
                                    fname
                                )))?,
                        );
                    }
                }
            }
            output.insert(fname.to_string(), metadata);
        }
        Ok(output)
    }

    /// Return whether the file is in the archive
    fn __contains__(&self, key: &str) -> Result<bool, WrappedError> {
        let inner = check_mode!(self, Read);
        Ok(inner.list_files()?.any(|x| x == key))
    }

    /// Return the content of a file as bytes
    fn __getitem__(&mut self, key: &str) -> Result<Cow<[u8]>, WrappedError> {
        let inner = check_mode!(mut self, Read);
        match inner {
            ExplicitReaders::FileReader(reader) => {
                let mut buf = Vec::new();
                let file = reader.get_file(key.to_string())?;
                if let Some(mut archive_file) = file {
                    archive_file.data.read_to_end(&mut buf)?;
                    Ok(Cow::Owned(buf))
                } else {
                    Err(PyKeyError::new_err(format!("File {} not found", key)).into())
                }
            }
        }
    }

    /// Add a file to the archive
    fn __setitem__(&mut self, key: &str, value: &[u8]) -> Result<(), WrappedError> {
        let writer = check_mode!(mut self, Write);
        match writer {
            ExplicitWriters::FileWriter(writer) => {
                let mut reader = std::io::Cursor::new(value);
                writer.add_file(key, value.len() as u64, &mut reader)?;
                Ok(())
            }
        }
    }

    /// Return the number of file in the archive
    fn __len__(&self) -> Result<usize, WrappedError> {
        let inner = check_mode!(self, Read);
        Ok(inner.list_files()?.count())
    }

    /// Finalize the archive creation. This API *must* be called or essential records will no be written
    /// An archive can only be finalized once
    fn finalize(&mut self) -> Result<(), WrappedError> {
        let inner = check_mode!(mut self, Write);
        Ok(inner.finalize()?)
    }

    // Context management protocol (PEP 0343)
    // https://docs.python.org/3/reference/datamodel.html#context-managers
    fn __enter__(slf: PyRef<Self>) -> PyRef<Self> {
        slf
    }

    // cf. https://pyo3.rs/v0.22.5/function/signature
    #[pyo3(signature = (exc_type=None, _exc_value=None, _traceback=None))]
    fn __exit__(
        &mut self,
        exc_type: Option<&Bound<'_, PyAny>>,
        _exc_value: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> Result<bool, WrappedError> {
        if exc_type.is_some() {
            // An exception occured, let it be raised again
            return Ok(false);
        }

        match self.inner {
            OpeningModeInner::Read(_) => {
                // Nothing to do, dropping this object should close the inner stream
            }
            OpeningModeInner::Write(ref mut writer) => {
                // Finalize. If an exception occured, raise it
                writer.finalize()?;
            }
        }
        Ok(false)
    }

    /// alias for io.BufferedIOBase
    // Purpose: only one import
    #[classattr]
    fn _buffered_type(py: Python) -> Result<&PyType, WrappedError> {
        Ok(py.import("io")?.getattr("BufferedIOBase")?.extract()?)
    }

    /// Write an archive file to @dest, which can be:
    /// - a string, corresponding to the output path
    /// - a writable BufferedIOBase object (file-object like)
    /// If a BufferedIOBase object is provided, the size of the chunck passed to `.write` can be adjusted
    /// through @chunk_size (default to 4MB)
    ///
    /// Example:
    /// ```python
    /// with open("/path/to/extract/file1", "wb") as f:
    ///     archive.write_file_to("file1", f)
    /// ```
    /// Or
    /// ```python
    /// archive.write_file_to("file1", "/path/to/extract/file1")
    /// ```
    #[pyo3(signature = (key, dest, chunk_size=4194304))]
    fn write_file_to(
        &mut self,
        py: Python,
        key: &str,
        dest: &Bound<'_, PyAny>,
        chunk_size: usize,
    ) -> Result<(), WrappedError> {
        let reader = check_mode!(mut self, Read);

        let archive_file = match reader {
            ExplicitReaders::FileReader(reader) => reader.get_file(key.to_string())?,
        };

        if let Ok(dest) = dest.downcast::<PyString>() {
            // dest is a String, this is a path
            // `/path/to/dest`
            let mut output = std::fs::File::create(dest.to_string())?;
            io::copy(&mut archive_file.unwrap().data, &mut output)?;
        } else if dest.is_instance(&py.get_type::<MLAFile>().getattr("_buffered_type")?)? {
            // isinstance(dest, io.BufferedIOBase)
            // offer `.write` (`.close` must be called from the caller)

            let src = &mut archive_file.unwrap().data;
            let mut buf = Vec::from_iter(std::iter::repeat(0).take(chunk_size));
            while let Ok(n) = src.read(&mut buf) {
                if n == 0 {
                    break;
                }
                dest.call_method1("write", (&buf[..n],))?;
            }
        } else {
            return Err(PyTypeError::new_err(
                "Expected a string or a file-object like (subclass of io.RawIOBase)",
            )
            .into());
        }
        Ok(())
    }

    /// Add a file to an archive from @src, which can be:
    /// - a string, corresponding to the input path
    /// - a readable BufferedIOBase object (file-object like)
    /// If a BufferedIOBase object is provided, the size of the chunck passed to `.read` can be adjusted
    /// through @chunk_size (default to 4MB)
    ///
    /// Example:
    /// ```python
    /// archive.add_file_from("file1", "/path/to/file1")
    /// ```
    /// Or
    /// ```python
    /// with open("/path/to/file1", "rb") as f:
    ///    archive.add_file_from("file1", f)
    /// ```
    #[pyo3(signature = (key, src, chunk_size=4194304))]
    fn add_file_from(
        &mut self,
        py: Python,
        key: &str,
        src: &Bound<'_, PyAny>,
        chunk_size: usize,
    ) -> Result<(), WrappedError> {
        let writer = check_mode!(mut self, Write);

        if let Ok(src) = src.downcast::<PyString>() {
            // src is a String, this is a path
            // `/path/to/src`
            let mut input = std::fs::File::open(src.to_string())?;
            writer.add_file(key, input.metadata()?.len(), &mut input)?;
        } else if src.is_instance(&py.get_type::<MLAFile>().getattr("_buffered_type")?)? {
            // isinstance(src, io.BufferedIOBase)
            // offer `.read` (`.close` must be called from the caller)

            let id = writer.start_file(key)?;
            loop {
                match Some(PyBytesMethods::as_bytes(&src
                    .call_method1("read", (chunk_size,))?
                    .extract::<Bound<_>>()?)) {
                    Some(data) => {
                        if data.is_empty() {
                           break;
                        }
                        writer.append_file_content(id, data.len(), data)?;
                    }
                    _ => break,
                }
            }
            writer.end_file(id)?;
        } else {
            return Err(PyTypeError::new_err(
                "Expected a string or a file-object like (subclass of io.RawIOBase)",
            )
            .into());
        }
        Ok(())
    }
}

// -------- Python module instanciation --------

/// Instanciate the Python module
#[pymodule]
#[pyo3(name = "mla")]
fn pymla(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Classes
    m.add_class::<MLAFile>()?;
    m.add_class::<FileMetadata>()?;
    m.add_class::<WriterConfig>()?;
    m.add_class::<PublicKeys>()?;
    m.add_class::<PrivateKeys>()?;
    m.add_class::<ReaderConfig>()?;

    // Exceptions
    m.add("MLAError", py.get_type::<MLAError>())?;
    m.add("WrongMagic", py.get_type::<WrongMagic>())?;
    m.add("UnsupportedVersion", py.get_type::<UnsupportedVersion>())?;
    m.add("InvalidECCKeyFormat", py.get_type::<InvalidECCKeyFormat>())?;
    m.add(
        "WrongBlockSubFileType",
        py.get_type::<WrongBlockSubFileType>(),
    )?;
    m.add("UTF8ConversionError", py.get_type::<UTF8ConversionError>())?;
    m.add("FilenameTooLong", py.get_type::<FilenameTooLong>())?;
    m.add(
        "WrongArchiveWriterState",
        py.get_type::<WrongArchiveWriterState>(),
    )?;
    m.add("WrongReaderState", py.get_type::<WrongReaderState>())?;
    m.add("WrongWriterState", py.get_type::<WrongWriterState>())?;
    m.add("RandError", py.get_type::<RandError>())?;
    m.add("PrivateKeyNeeded", py.get_type::<PrivateKeyNeeded>())?;
    m.add(
        "DeserializationError",
        py.get_type::<DeserializationError>(),
    )?;
    m.add("SerializationError", py.get_type::<SerializationError>())?;
    m.add("MissingMetadata", py.get_type::<MissingMetadata>())?;
    m.add("BadAPIArgument", py.get_type::<BadAPIArgument>())?;
    m.add("EndOfStream", py.get_type::<EndOfStream>())?;
    m.add("ConfigError", py.get_type::<ConfigError>())?;
    m.add("DuplicateFilename", py.get_type::<DuplicateFilename>())?;
    m.add(
        "AuthenticatedDecryptionWrongTag",
        py.get_type::<AuthenticatedDecryptionWrongTag>(),
    )?;
    m.add(
        "HKDFInvalidKeyLength",
        py.get_type::<HKDFInvalidKeyLength>(),
    )?;

    // Add constants
    m.add("LAYER_COMPRESS", Layers::COMPRESS.bits())?;
    m.add("LAYER_ENCRYPT", Layers::ENCRYPT.bits())?;
    m.add("LAYER_DEFAULT", Layers::DEFAULT.bits())?;
    m.add("LAYER_EMPTY", Layers::EMPTY.bits())?;
    m.add("DEFAULT_COMPRESSION_LEVEL", DEFAULT_COMPRESSION_LEVEL)?;
    Ok(())
}
