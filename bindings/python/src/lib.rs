use std::{
    collections::HashMap,
    io::{self, Read},
    sync::Mutex,
};

use ml_kem::EncodedSizeUser;
use mla::crypto::mlakey::{
    parse_mlakey_privkey_der, parse_mlakey_privkey_pem, parse_mlakey_pubkey_der,
    parse_mlakey_pubkey_pem,
};
use mla::{
    ArchiveReader, ArchiveWriter, format::Layers,
    config::{ArchiveReaderConfig, ArchiveWriterConfig},
    crypto::mlakey::{HybridPrivateKey, HybridPublicKey},
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
    InvalidKeyFormat,
    MLAError,
    "Supplied MLA key is not in the expected format"
);
create_exception!(
    mla,
    WrongBlockSubFileType,
    MLAError,
    "Wrong BlockSubFile magic has been encountered. Is the deserializion tarting at the beginning of a block?"
);
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
create_exception!(
    mla,
    MissingMetadata,
    MLAError,
    "Missing metadata (usually means the footer has not been correctly read, a repair might be needed)"
);
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
create_exception!(mla, HPKEError, MLAError, "Error during HPKE computation");
create_exception!(mla, InvalidLastTag, MLAError, "Wrong last block tag");

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
            WrappedError::WrappedMLA(inner_err) => match inner_err {
                mla::errors::Error::IOError(err) => {
                    PyErr::new::<pyo3::exceptions::PyIOError, _>(err)
                }
                mla::errors::Error::AssertionError(msg) => {
                    PyErr::new::<pyo3::exceptions::PyAssertionError, _>(msg)
                }
                mla::errors::Error::WrongMagic => {
                    PyErr::new::<WrongMagic, _>("Wrong magic, must be \"MLA\"")
                }
                mla::errors::Error::UnsupportedVersion => {
                    PyErr::new::<UnsupportedVersion, _>("Unsupported version, must be 1")
                }
                mla::errors::Error::InvalidKeyFormat => PyErr::new::<InvalidKeyFormat, _>(
                    "Supplied MLA key is not in the expected format",
                ),
                mla::errors::Error::WrongBlockSubFileType => {
                    PyErr::new::<WrongBlockSubFileType, _>(
                        "Wrong BlockSubFile magic has been encountered. Is the deserializion tarting at the beginning of a block?",
                    )
                }
                mla::errors::Error::UTF8ConversionError(err) => {
                    PyErr::new::<UTF8ConversionError, _>(err)
                }
                mla::errors::Error::FilenameTooLong => PyErr::new::<FilenameTooLong, _>(
                    "Filenames have a limited size `FILENAME_MAX_SIZE`",
                ),
                mla::errors::Error::WrongArchiveWriterState {
                    current_state,
                    expected_state,
                } => PyErr::new::<WrongArchiveWriterState, _>(format!(
                    "The writer state is not in the expected state for the current operation. Current state: {:?}, expected state: {:?}",
                    current_state, expected_state
                )),
                mla::errors::Error::WrongReaderState(msg) => PyErr::new::<WrongReaderState, _>(msg),
                mla::errors::Error::WrongWriterState(msg) => PyErr::new::<WrongWriterState, _>(msg),
                mla::errors::Error::RandError(err) => {
                    PyErr::new::<RandError, _>(format!("{:}", err))
                }
                mla::errors::Error::PrivateKeyNeeded => PyErr::new::<PrivateKeyNeeded, _>(
                    "A Private Key is required to decrypt the encrypted cipher key",
                ),
                mla::errors::Error::DeserializationError => PyErr::new::<DeserializationError, _>(
                    "Deserialization error. May happens when starting from a wrong offset / version mismatch",
                ),
                mla::errors::Error::SerializationError => PyErr::new::<SerializationError, _>(
                    "Serialization error. May happens on I/O errors",
                ),
                mla::errors::Error::MissingMetadata => PyErr::new::<MissingMetadata, _>(
                    "Missing metadata (usually means the footer has not been correctly read, a repair might be needed)",
                ),
                mla::errors::Error::BadAPIArgument(msg) => PyErr::new::<BadAPIArgument, _>(msg),
                mla::errors::Error::EndOfStream => PyErr::new::<EndOfStream, _>(
                    "End of stream reached, no more data should be expected",
                ),
                mla::errors::Error::ConfigError(err) => {
                    PyErr::new::<ConfigError, _>(format!("{:}", err))
                }
                mla::errors::Error::DuplicateFilename => {
                    PyErr::new::<DuplicateFilename, _>("Filename already used")
                }
                mla::errors::Error::AuthenticatedDecryptionWrongTag => {
                    PyErr::new::<AuthenticatedDecryptionWrongTag, _>(
                        "Wrong tag while decrypting authenticated data",
                    )
                }
                mla::errors::Error::HKDFInvalidKeyLength => {
                    PyErr::new::<HKDFInvalidKeyLength, _>("Unable to expand while using the HKDF")
                }
                mla::errors::Error::HPKEError(msg) => {
                    PyErr::new::<HPKEError, _>(format!("{:}", msg))
                }
                mla::errors::Error::InvalidLastTag => {
                    PyErr::new::<InvalidLastTag, _>("Wrong last block tag")
                }
            },
            WrappedError::WrappedPy(inner_err) => inner_err,
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
    fn hash(&self) -> Option<&[u8; 32]> {
        self.hash.as_ref()
    }

    fn __repr__(&self) -> String {
        format!("<FileMetadata size={:?} hash={:?}>", self.size, self.hash)
    }
}

// -------- mla.PublicKeys --------

/// Represents multiple ECC and MLKEM Public Keys
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
struct PublicKeysInner {
    keys: Vec<HybridPublicKey>,
}

#[pyclass]
struct PublicKeys {
    inner: Mutex<PublicKeysInner>,
}

impl Clone for PublicKeys {
    fn clone(&self) -> Self {
        let inner = self.inner.lock().expect("Mutex poisoned").clone();
        PublicKeys {
            inner: Mutex::new(inner),
        }
    }
}

#[pymethods]
impl PublicKeys {
    #[new]
    #[pyo3(signature = (*args))]
    /// Main constructor: PEM-based
    fn from_pem(args: &Bound<PyTuple>) -> Result<Self, WrappedError> {
        let mut keys = Vec::new();

        for element in args {
            // PEM public key submitted as a string
            // "-----PUBLIC KEY[...]"
            if let Ok(data) = element.downcast::<PyString>() {
                // Convert PyString to &str
                let string = data.to_str()?;
                // Convert &str to &[u8]
                let bytes = string.as_bytes();
                keys.push(
                    parse_mlakey_pubkey_pem(bytes)
                        .map_err(|_| mla::errors::Error::InvalidKeyFormat)?,
                );
            } else if let Ok(data) = element.downcast::<PyBytes>() {
                keys.push(
                    parse_mlakey_pubkey_pem(&data[..])
                        .map_err(|_| mla::errors::Error::InvalidKeyFormat)?,
                );
            } else {
                return Err(PyTypeError::new_err(
                    "Expect a PEM public key as a string or as bytes",
                )
                .into());
            }
        }
        Ok(Self {
            inner: Mutex::new(PublicKeysInner { keys }),
        })
    }

    /// Alternative constructor: DER-based
    #[classmethod]
    #[pyo3(signature = (*args))]
    fn from_der(_cls: &Bound<PyType>, args: &Bound<PyTuple>) -> Result<Self, WrappedError> {
        let mut keys = Vec::new();

        for element in args {
            // DER public key is encoded, hence PyString is not supported below
            if let Ok(data) = element.downcast::<PyBytes>() {
                keys.push(
                    parse_mlakey_pubkey_der(&data[..])
                        .map_err(|_| mla::errors::Error::InvalidKeyFormat)?,
                );
            } else {
                return Err(PyTypeError::new_err("Expect a DER public key as bytes").into());
            }
        }
        Ok(Self {
            inner: Mutex::new(PublicKeysInner { keys }),
        })
    }

    /// DER representation of keys
    #[getter]
    fn keys(&self) -> Vec<Vec<u8>> {
        self.inner
            .lock()
            .expect("Mutex poisoned")
            .keys
            .iter()
            .map(|pubkey| {
                let mut result = Vec::new();
                result.extend(pubkey.public_key_ecc.to_bytes());
                result.extend(pubkey.public_key_ml.as_bytes());
                result
            })
            .collect()
    }
}

// -------- mla.PrivateKeys --------

/// Represents multiple ECC and MLKEM Private Keys
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
struct PrivateKeysInner {
    keys: Vec<HybridPrivateKey>,
}

#[pyclass]
struct PrivateKeys {
    inner: Mutex<PrivateKeysInner>,
}

impl Clone for PrivateKeys {
    fn clone(&self) -> Self {
        let inner = self.inner.lock().expect("Mutex poisoned").clone();
        PrivateKeys {
            inner: Mutex::new(inner),
        }
    }
}

#[pymethods]
impl PrivateKeys {
    #[new]
    #[pyo3(signature = (*args))]
    /// Main constructor: PEM-based
    fn from_pem(args: &Bound<PyTuple>) -> Result<Self, WrappedError> {
        let mut keys: Vec<HybridPrivateKey> = Vec::new();

        for element in args {
            // PEM private key submitted as a string
            // "-----PRIVATE KEY[...]"
            if let Ok(data) = element.downcast::<PyString>() {
                // Convert PyString to &str
                let string = data.to_str()?;
                // Convert &str to &[u8]
                let bytes = string.as_bytes();
                keys.push(
                    parse_mlakey_privkey_pem(bytes)
                        .map_err(|_| mla::errors::Error::InvalidKeyFormat)?,
                );
            } else if let Ok(data) = element.downcast::<PyBytes>() {
                keys.push(
                    parse_mlakey_privkey_pem(&data[..])
                        .map_err(|_| mla::errors::Error::InvalidKeyFormat)?,
                );
            } else {
                return Err(PyTypeError::new_err(
                    "Expect a PEM private key as a string or as bytes",
                )
                .into());
            }
        }
        Ok(Self {
            inner: Mutex::new(PrivateKeysInner { keys }),
        })
    }

    /// Alternative constructor: DER-based
    #[classmethod]
    #[pyo3(signature = (*args))]
    fn from_der(_cls: &Bound<PyType>, args: &Bound<PyTuple>) -> Result<Self, WrappedError> {
        let mut keys: Vec<HybridPrivateKey> = Vec::new();

        for element in args {
            // DER private key is encoded, hence PyString is not supported below
            if let Ok(data) = element.downcast::<PyBytes>() {
                keys.push(
                    parse_mlakey_privkey_der(&data[..])
                        .map_err(|_| mla::errors::Error::InvalidKeyFormat)?,
                );
            } else {
                return Err(PyTypeError::new_err("Expect a DER private key as bytes").into());
            }
        }
        Ok(Self {
            inner: Mutex::new(PrivateKeysInner { keys }),
        })
    }

    /// DER representation of keys
    /// :warning: This keys must be kept secrets!
    #[getter]
    fn keys(&self) -> Vec<Vec<u8>> {
        self.inner
            .lock()
            .expect("Mutex poisoned")
            .keys
            .iter()
            .map(|privkey| {
                let mut result = Vec::new();
                result.extend(privkey.private_key_ecc.to_bytes());
                result.extend(privkey.private_key_ml.as_bytes());
                result
            })
            .collect()
    }
}

// -------- mla.ConfigWriter --------

// from mla::layers::DEFAULT_COMPRESSION_LEVEL
const DEFAULT_COMPRESSION_LEVEL: u32 = 5;

// This class keep the values of configured object, and can be used to produce an actual
// `ArchiveWriterConfig`. That way, it can be used to produced many of them, as they are
// consumed during the `ArchiveWriter` init (to avoid reusing cryptographic materials)
struct WriterConfigInner {
    layers: Layers,
    compression_level: u32,
    public_keys: Option<PublicKeys>,
}

#[pyclass]
struct WriterConfig {
    inner: Mutex<WriterConfigInner>,
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
                mla::errors::Error::BadAPIArgument("Unknown layers".to_owned()),
            )?,
            None => Layers::DEFAULT,
        };

        // Check compression level is correct using a fake object
        ArchiveWriterConfig::new().with_compression_level(compression_level)?;

        Ok(WriterConfig {
            inner: Mutex::new(WriterConfigInner {
                layers,
                compression_level,
                public_keys,
            }),
        })
    }

    #[getter]
    fn layers(&self) -> u8 {
        self.inner.lock().expect("Mutex poisoned").layers.bits()
    }

    /// Enable a layer
    fn enable_layer(slf: PyRefMut<Self>, layer: u8) -> Result<PyRefMut<Self>, WrappedError> {
        let layer = Layers::from_bits(layer).ok_or(mla::errors::Error::BadAPIArgument(
            "Unknown layer".to_owned(),
        ))?;
        slf.inner.lock().expect("Mutex poisoned").layers |= layer;
        Ok(slf)
    }

    /// Disable a layer
    fn disable_layer(slf: PyRefMut<Self>, layer: u8) -> Result<PyRefMut<Self>, WrappedError> {
        let layer = Layers::from_bits(layer).ok_or(mla::errors::Error::BadAPIArgument(
            "Unknown layer".to_owned(),
        ))?;
        slf.inner.lock().expect("Mutex poisoned").layers &= !layer;
        Ok(slf)
    }

    /// Set several layers at once
    fn set_layers(slf: PyRefMut<Self>, layers: u8) -> Result<PyRefMut<Self>, WrappedError> {
        slf.inner.lock().expect("Mutex poisoned").layers = Layers::from_bits(layers).ok_or(
            mla::errors::Error::BadAPIArgument("Unknown layer".to_owned()),
        )?;
        Ok(slf)
    }

    /// Set the compression level
    /// compression level (0-11); bigger values cause denser, but slower compression
    fn with_compression_level(
        slf: PyRefMut<Self>,
        compression_level: u32,
    ) -> Result<PyRefMut<Self>, WrappedError> {
        // Check compression level is correct using a fake object
        ArchiveWriterConfig::new().with_compression_level(compression_level)?;

        slf.inner.lock().expect("Mutex poisoned").compression_level = compression_level;
        Ok(slf)
    }

    #[getter]
    fn compression_level(&self) -> u32 {
        self.inner.lock().expect("Mutex poisoned").compression_level
    }

    /// Set public keys
    fn set_public_keys(
        slf: PyRefMut<Self>,
        public_keys: PublicKeys,
    ) -> Result<PyRefMut<Self>, WrappedError> {
        slf.inner.lock().expect("Mutex poisoned").public_keys = Some(public_keys);
        Ok(slf)
    }

    #[getter]
    fn get_public_keys(&self) -> Option<PublicKeys> {
        self.inner
            .lock()
            .expect("Mutex poisoned")
            .public_keys
            .clone()
    }
}

impl WriterConfig {
    /// Create an `ArchiveWriterConfig` out of the python object
    fn to_archive_writer_config(&self) -> Result<ArchiveWriterConfig, WrappedError> {
        let mut config = ArchiveWriterConfig::new();
        let inner = self.inner.lock().expect("Mutex poisoned");
        config.set_layers(inner.layers);
        config.with_compression_level(inner.compression_level)?;
        if let Some(ref public_keys) = inner.public_keys {
            config.add_public_keys(&public_keys.inner.lock().expect("Mutex poisoned").keys);
        }
        Ok(config)
    }
}

// -------- mla.ConfigReader --------

// This class keep the values of configured object, and can be used to produce an actual
// `ArchiveReaderConfig`. That way, it can be used to produced many of them, as they are
// consumed during the `ArchiveReader` init
struct ReaderConfigInner {
    private_keys: Option<PrivateKeys>,
}

#[pyclass]
struct ReaderConfig {
    inner: Mutex<ReaderConfigInner>,
}

#[pymethods]
impl ReaderConfig {
    #[new]
    #[pyo3(signature = (private_keys=None))]
    fn new(private_keys: Option<PrivateKeys>) -> Self {
        ReaderConfig {
            inner: Mutex::new(ReaderConfigInner { private_keys }),
        }
    }

    /// Set private keys
    fn set_private_keys(
        slf: PyRefMut<Self>,
        private_keys: PrivateKeys,
    ) -> Result<PyRefMut<Self>, WrappedError> {
        slf.inner.lock().expect("Mutex poisoned").private_keys = Some(private_keys);
        Ok(slf)
    }

    #[getter]
    fn private_keys(&self) -> Option<PrivateKeys> {
        self.inner
            .lock()
            .expect("Mutex poisoned")
            .private_keys
            .clone()
    }
}

impl ReaderConfig {
    /// Create an `ArchiveReaderConfig` out of the python object
    fn to_archive_reader_config(&self) -> Result<ArchiveReaderConfig, WrappedError> {
        let mut config = ArchiveReaderConfig::new();
        if let Some(ref private_keys) = self.inner.lock().expect("Mutex poisoned").private_keys {
            config.add_private_keys(&private_keys.inner.lock().expect("Mutex poisoned").keys);
            config.layers_enabled |= Layers::ENCRYPT;
        }
        Ok(config)
    }
}

// -------- mla.MLAFile --------

/// `ArchiveWriter` is a generic type. To avoid generating several Python implementation
/// (see https://pyo3.rs/v0.24.0/class#no-generic-parameters), this enum explicitely
/// instanciate `ArchiveWriter` for common & expected types
///
/// Additionnaly, as the GC in Python might drop objects at any time, we need to use
/// `'static` lifetime for the writer. This should not be a problem as the writer is not
/// supposed to be used after the drop of the parent object
/// (see https://pyo3.rs/v0.24.0/class#no-lifetime-parameters)
enum ExplicitWriter {
    FileWriter(ArchiveWriter<'static, std::fs::File>),
}

fn finalize_if_not_already(opt_writer: &mut Option<Box<ExplicitWriter>>) -> Result<(), WrappedError> {
    match opt_writer.take() {
        Some(writer) => writer.finalize().map_err(WrappedError::from),
        None => Err(mla::errors::Error::BadAPIArgument(
            "Cannot call any API on already finalized MLAFile".to_owned(),
        ).into())
    }
}

/// Wrap calls to the inner type
impl ExplicitWriter {
    fn finalize(self) -> Result<(), mla::errors::Error> {
        match self {
            ExplicitWriter::FileWriter(writer) => {
                writer.finalize()?;
                Ok(())
            }
        }
    }

    fn add_entry<R: Read>(
        &mut self,
        key: &str,
        size: u64,
        reader: &mut R,
    ) -> Result<(), mla::errors::Error> {
        match self {
            ExplicitWriter::FileWriter(writer) => {
                writer.add_entry(key, size, reader)?;
                Ok(())
            }
        }
    }

    fn start_file(&mut self, key: &str) -> Result<u64, mla::errors::Error> {
        match self {
            ExplicitWriter::FileWriter(writer) => writer.start_file(key),
        }
    }

    fn append_file_content(
        &mut self,
        id: u64,
        size: usize,
        data: &[u8],
    ) -> Result<(), mla::errors::Error> {
        match self {
            ExplicitWriter::FileWriter(writer) => {
                writer.append_file_content(id, size as u64, data)
            }
        }
    }

    fn end_file(&mut self, id: u64) -> Result<(), mla::errors::Error> {
        match self {
            ExplicitWriter::FileWriter(writer) => writer.end_file(id),
        }
    }
}

/// See `ExplicitWriter` for details
enum ExplicitReader {
    FileReader(ArchiveReader<'static, std::fs::File>),
}

/// Wrap calls to the inner type
impl ExplicitReader {
    fn list_files(&self) -> Result<impl Iterator<Item = &String>, mla::errors::Error> {
        match self {
            ExplicitReader::FileReader(reader) => reader.list_files(),
        }
    }
}

/// Opening Mode for a MLAFile
enum OpeningModeInner {
    Read(ExplicitReader),
    Write(Option<Box<ExplicitWriter>>),
}

pub struct MLAFileInner {
    /// Wrapping over the rust object, depending on the opening mode
    inner: OpeningModeInner,
    /// Path of the file, used for messages
    path: String,
}

#[pyclass]
struct MLAFile {
    inner: Mutex<MLAFileInner>,
}

impl MLAFile {
    /// Used to check whether the opening mode is the expected one, and unwrap it
    /// return a BadAPI argument error if not
    /// ```text
    /// self.with_reader(|inner| {});
    /// ```
    fn with_reader<F, R>(&self, f: F) -> Result<R, WrappedError>
    where
        F: FnOnce(&mut ExplicitReader) -> Result<R, WrappedError>,
    {
        let mut inner_lock = self.inner.lock().expect("Mutex poisoned");
        match &mut inner_lock.inner {
            OpeningModeInner::Read(inner) => f(inner),
            OpeningModeInner::Write(_) => Err(mla::errors::Error::BadAPIArgument(
                "This API is only callable in Read mode".to_owned(),
            )
            .into()),
        }
    }

    /// Used to check whether the opening mode is the expected one, and unwrap it
    /// return a BadAPI argument error if not
    /// ```text
    /// self.with_writer|inner| {});
    /// ```
    fn with_writer<F, R>(&self, f: F) -> Result<R, WrappedError>
    where
        F: FnOnce(&mut ExplicitWriter) -> Result<R, WrappedError>,
    {
        self.with_maybe_finalized_writer(|opt_inner| match opt_inner {
            Some(inner) => f(inner),
            None => Err(mla::errors::Error::BadAPIArgument(
                "Cannot call any API on already finalized MLAFile".to_owned(),
            ).into())
        })
    }

    fn with_maybe_finalized_writer<F, R>(&self, f: F) -> Result<R, WrappedError>
    where
        F: FnOnce(&mut Option<Box<ExplicitWriter>>) -> Result<R, WrappedError>,
    {
        let mut inner_lock = self.inner.lock().expect("Mutex poisoned");
        match &mut inner_lock.inner {
            OpeningModeInner::Write(opt_inner) => f(opt_inner),
            OpeningModeInner::Read(_) => Err(mla::errors::Error::BadAPIArgument(
                "This API is only callable in Write mode".to_owned(),
            )
            .into()),
        }
    }

}

#[pymethods]
impl MLAFile {
    #[new]
    #[pyo3(signature = (path, mode="r", config=None))]
    fn new(
        path: &str,
        mode: &str,
        config: Option<&Bound<'_, PyAny>>,
    ) -> Result<Self, WrappedError> {
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
                    inner: Mutex::new(MLAFileInner {
                        inner: OpeningModeInner::Read(ExplicitReader::FileReader(arch_reader)),
                        path: path.to_owned(),
                    }),
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
                    inner: Mutex::new(MLAFileInner {
                        inner: OpeningModeInner::Write(Some(Box::new(ExplicitWriter::FileWriter(
                            arch_writer,
                        )))),
                        path: path.to_owned(),
                    }),
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
        let inner = self.inner.lock().expect("Mutex poisoned");
        format!(
            "<MLAFile path='{:}' mode='{:}'>",
            inner.path,
            match inner.inner {
                OpeningModeInner::Read(_) => "r",
                OpeningModeInner::Write(_) => "w",
            }
        )
    }

    /// Return the list of files in the archive
    fn keys(&self) -> Result<Vec<String>, WrappedError> {
        self.with_reader(|inner| Ok(inner.list_files()?.cloned().collect()))
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
        self.with_reader(|inner| {
            let mut output = HashMap::new();
            let iter: Vec<String> = inner.list_files()?.cloned().collect();
            for fname in iter {
                let mut metadata = FileMetadata {
                    size: None,
                    hash: None,
                };
                match inner {
                    ExplicitReader::FileReader(reader) => {
                        if include_size {
                            metadata.size = Some(
                                reader
                                    .get_file(fname.clone())?
                                    .ok_or(PyRuntimeError::new_err(format!(
                                        "File {} not found",
                                        fname
                                    )))?
                                    .size,
                            );
                        }
                        if include_hash {
                            metadata.hash = Some(reader.get_hash(&fname)?.ok_or(
                                PyRuntimeError::new_err(format!("File {} not found", fname)),
                            )?);
                        }
                    }
                }
                output.insert(fname.to_owned(), metadata);
            }
            Ok(output)
        })
    }

    /// Return whether the file is in the archive
    fn __contains__(&self, key: &str) -> Result<bool, WrappedError> {
        self.with_reader(|inner| Ok(inner.list_files()?.any(|x| x == key)))
    }

    /// Return the content of a file as bytes
    fn __getitem__(&mut self, key: &str) -> Result<Vec<u8>, WrappedError> {
        self.with_reader(|inner| match inner {
            ExplicitReader::FileReader(reader) => {
                let file = reader.get_file(key.to_owned())?;
                if let Some(mut archive_file) = file {
                    let mut buf = Vec::new();
                    archive_file.data.read_to_end(&mut buf)?;
                    Ok(buf)
                } else {
                    Err(PyKeyError::new_err(format!("File {} not found", key)).into())
                }
            }
        })
    }

    /// Add a file to the archive
    fn __setitem__(&mut self, key: &str, value: &[u8]) -> Result<(), WrappedError> {
        self.with_writer(|writer| match writer {
            ExplicitWriter::FileWriter(writer) => {
                let mut reader = std::io::Cursor::new(value);
                writer.add_entry(key, value.len() as u64, &mut reader)?;
                Ok(())
            }
        })
    }

    /// Return the number of file in the archive
    fn __len__(&self) -> Result<usize, WrappedError> {
        self.with_reader(|inner| Ok(inner.list_files()?.count()))
    }

    /// Finalize the archive creation. This API *must* be called or essential records will no be written
    /// An archive can only be finalized once
    fn finalize(&mut self) -> Result<(), WrappedError> {
        self.with_maybe_finalized_writer(finalize_if_not_already)
    }

    // Context management protocol (PEP 0343)
    // https://docs.python.org/3/reference/datamodel.html#context-managers
    fn __enter__(slf: PyRef<Self>) -> PyRef<Self> {
        slf
    }

    // cf. https://pyo3.rs/v0.24.0/function/signature.html
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

        match self.inner.lock().expect("Mutex poisoned").inner {
            OpeningModeInner::Read(_) => {
                // Nothing to do, dropping this object should close the inner stream
            }
            OpeningModeInner::Write(ref mut opt_writer) => {
                // Finalize. If an exception occured, raise it
                finalize_if_not_already(opt_writer)?;
            }
        }
        Ok(false)
    }

    /// alias for io.BufferedIOBase
    // Purpose: only one import
    #[classattr]
    fn _buffered_type(py: Python) -> PyResult<Py<PyType>> {
        py.import("io")?.getattr("BufferedIOBase")?.extract()
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
        dest: &Bound<PyAny>,
        chunk_size: usize,
    ) -> Result<(), WrappedError> {
        self.with_reader(|reader| {
            let archive_file = match reader {
                ExplicitReader::FileReader(reader) => reader.get_file(key.to_owned())?,
            };

            if let Ok(dest) = dest.downcast::<PyString>() {
                let mut output = std::fs::File::create(dest.to_string())?;
                io::copy(&mut archive_file.unwrap().data, &mut output)?;
            } else if dest.is_instance(&py.get_type::<MLAFile>().getattr("_buffered_type")?)? {
                let src = &mut archive_file.unwrap().data;
                let mut buf = Vec::from_iter(std::iter::repeat_n(0, chunk_size));
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
        })
    }

    /// Add a file to an archive from @src, which can be:
    /// - a string, corresponding to the input path
    /// - a readable BufferedIOBase object (file-object like)
    /// If a BufferedIOBase object is provided, the size of the chunck passed to `.read` can be adjusted
    /// through @chunk_size (default to 4MB)
    ///
    /// Example:
    /// ```python
    /// archive.add_entry_from("file1", "/path/to/file1")
    /// ```
    /// Or
    /// ```python
    /// with open("/path/to/file1", "rb") as f:
    ///    archive.add_entry_from("file1", f)
    /// ```
    #[pyo3(signature = (key, src, chunk_size=4194304))]
    fn add_entry_from(
        &mut self,
        py: Python,
        key: &str,
        src: &Bound<PyAny>,
        chunk_size: usize,
    ) -> Result<(), WrappedError> {
        self.with_writer(|writer| {
            if let Ok(src) = src.downcast::<PyString>() {
                let mut input = std::fs::File::open(src.to_string())?;
                writer.add_entry(key, input.metadata()?.len(), &mut input)?;
            } else if src.is_instance(&py.get_type::<MLAFile>().getattr("_buffered_type")?)? {
                let id = writer.start_file(key)?;
                loop {
                    let py_bytes = src
                        .call_method1("read", (chunk_size,))?
                        .extract::<Py<PyBytes>>()?;
                    let data = py_bytes.as_bytes(py);
                    if data.is_empty() {
                        break;
                    }
                    writer.append_file_content(id, data.len(), data)?;
                }
                writer.end_file(id)?;
            } else {
                return Err(PyTypeError::new_err(
                    "Expected a string or a file-object like (subclass of io.RawIOBase)",
                )
                .into());
            }
            Ok(())
        })
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
    m.add("InvalidKeyFormat", py.get_type::<InvalidKeyFormat>())?;
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
    m.add("HPKEError", py.get_type::<HPKEError>())?;
    m.add("InvalidLastTag", py.get_type::<InvalidLastTag>())?;

    // Add constants
    m.add("LAYER_COMPRESS", Layers::COMPRESS.bits())?;
    m.add("LAYER_ENCRYPT", Layers::ENCRYPT.bits())?;
    m.add("LAYER_DEFAULT", Layers::DEFAULT.bits())?;
    m.add("LAYER_EMPTY", Layers::EMPTY.bits())?;
    m.add("DEFAULT_COMPRESSION_LEVEL", DEFAULT_COMPRESSION_LEVEL)?;
    Ok(())
}
