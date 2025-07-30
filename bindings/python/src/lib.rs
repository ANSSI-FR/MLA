use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
    io::{self, Read},
    path::PathBuf,
    sync::Mutex,
};
use mla::{
    ArchiveReader, ArchiveWriter,
    config::{ArchiveReaderConfig, ArchiveWriterConfig, DEFAULT_COMPRESSION_LEVEL},
    crypto::mlakey::{MLAPrivateKey, MLAPublicKey},
};
use mla::entry::{ArchiveEntryId, EntryName as RustEntryName};
use pyo3::{
    create_exception,
    exceptions::{PyKeyError, PyRuntimeError, PyTypeError},
    prelude::*,
    pyclass::CompareOp,
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
    EntryNameError
}

// Add a dedicated MLA Exception (mla.MLAError) and associated sub-Exception
// IOError and AssertionError are not mapped, as they already map to Python Exception
create_exception!(mla, MLAError, pyo3::exceptions::PyException);
create_exception!(mla, WrongMagic, MLAError, "Wrong magic, must be \"MLAFAAAA\"");
create_exception!(
    mla,
    UnsupportedVersion,
    MLAError,
    "Unsupported version, must be 2"
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
create_exception!(mla, EncryptionAskedButNotMarkedPresent, MLAError, "User asked for encryption but archive was not marked as encrypted");
create_exception!(mla, EntryNameError, MLAError, "An MLA entry name is invalid for the given operation");
create_exception!(mla, WrongEndMagic, MLAError, "Wrong end magic, must be \"EMLAAAAA\"");
create_exception!(mla, NoValidSignatureFound, MLAError, "Cannot validate any signature");
create_exception!(mla, SignatureVerificationAskedButNoSignatureLayerFound, MLAError, "Signature verification was asked but no signature layer was found");

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

impl From<mla::entry::EntryNameError> for WrappedError {
    fn from(_err: mla::entry::EntryNameError) -> Self {
        WrappedError::EntryNameError
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
                    PyErr::new::<WrongMagic, _>("Wrong magic, must be \"MLAFAAAA\"")
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
                    "The writer state is not in the expected state for the current operation. Current state: {current_state:?}, expected state: {expected_state:?}"
                )),
                mla::errors::Error::WrongReaderState(msg) => PyErr::new::<WrongReaderState, _>(msg),
                mla::errors::Error::WrongWriterState(msg) => PyErr::new::<WrongWriterState, _>(msg),
                mla::errors::Error::RandError => {
                    PyErr::new::<RandError, _>("Rand error")
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
                    PyErr::new::<ConfigError, _>(format!("{err:}"))
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
                mla::errors::Error::HPKEError => {
                    PyErr::new::<HPKEError, _>("HPKE error")
                }
                mla::errors::Error::InvalidLastTag => {
                    PyErr::new::<InvalidLastTag, _>("Wrong last block tag")
                }
                mla::errors::Error::EncryptionAskedButNotMarkedPresent => {
                    PyErr::new::<EncryptionAskedButNotMarkedPresent, _>("User asked for encryption but archive was not marked as encrypted")
                }
                mla::errors::Error::WrongEndMagic => {
                    PyErr::new::<WrongEndMagic, _>("Wrong magic, must be \"EMLAAAAA\"")
                }
                mla::errors::Error::NoValidSignatureFound => {
                    PyErr::new::<NoValidSignatureFound, _>("Cannot validate any signature")
                }
                mla::errors::Error::SignatureVerificationAskedButNoSignatureLayerFound => {
                    PyErr::new::<SignatureVerificationAskedButNoSignatureLayerFound, _>("Signature verification was asked but no signature layer was found")
                }
            },
            WrappedError::WrappedPy(inner_err) => inner_err,
            WrappedError::EntryNameError => PyErr::new::<EntryNameError, _>("An MLA entry name is invalid for the given operation")
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

/// Represents multiple MLA Public Keys
///
/// Instanciate string or bytes containing a public key in MLA key format
#[derive(Clone)]
struct PublicKeysInner {
    keys: Vec<MLAPublicKey>,
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
    fn new(args: &Bound<PyTuple>) -> Result<Self, WrappedError> {
        let mut keys = Vec::new();

        for element in args {
            if let Ok(data) = element.downcast::<PyString>() {
                // Convert PyString to &str
                let string = data.to_str()?;
                // Convert &str to &[u8]
                let bytes = string.as_bytes();
                keys.push(
                    MLAPublicKey::deserialize_public_key(bytes)
                        .map_err(|_| mla::errors::Error::InvalidKeyFormat)?,
                );
            } else if let Ok(data) = element.downcast::<PyBytes>() {
                keys.push(
                    MLAPublicKey::deserialize_public_key(&data[..])
                        .map_err(|_| mla::errors::Error::InvalidKeyFormat)?,
                );
            } else {
                return Err(PyTypeError::new_err(
                    "Expect an MLA public key as a string or as bytes",
                )
                .into());
            }
        }
        Ok(Self {
            inner: Mutex::new(PublicKeysInner { keys }),
        })
    }

    /// String serializations of keys in MLA key format
    #[getter]
    fn keys(&self) -> Result<Vec<String>, WrappedError> {
        self.inner
            .lock()
            .expect("Mutex poisoned")
            .keys
            .iter()
            .map(|pubkey| {let mut v = Vec::new(); pubkey.serialize_public_key(&mut v)?; Ok(String::from_utf8(v).unwrap())})
            .collect()
    }
}

// -------- mla.PrivateKeys --------

/// Represents multiple MLA Private Keys
///
/// Instanciate string or bytes containing a private key in MLA key format
#[derive(Clone)]
struct PrivateKeysInner {
    keys: Vec<MLAPrivateKey>,
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
    fn new(args: &Bound<PyTuple>) -> Result<Self, WrappedError> {
        let mut keys = Vec::new();

        for element in args {
            if let Ok(data) = element.downcast::<PyString>() {
                // Convert PyString to &str
                let string = data.to_str()?;
                // Convert &str to &[u8]
                let bytes = string.as_bytes();
                keys.push(
                    MLAPrivateKey::deserialize_private_key(bytes)
                        .map_err(|_| mla::errors::Error::InvalidKeyFormat)?,
                );
            } else if let Ok(data) = element.downcast::<PyBytes>() {
                keys.push(
                    MLAPrivateKey::deserialize_private_key(&data[..])
                        .map_err(|_| mla::errors::Error::InvalidKeyFormat)?,
                );
            } else {
                return Err(PyTypeError::new_err(
                    "Expect an MLA formatted private key as a string or as bytes",
                )
                .into());
            }
        }
        Ok(Self {
            inner: Mutex::new(PrivateKeysInner { keys }),
        })
    }


    /// String serializations of keys in MLA key format
    #[getter]
    fn keys(&self) -> Result<Vec<String>, WrappedError> {
        self.inner
            .lock()
            .expect("Mutex poisoned")
            .keys
            .iter()
            .map(|privkey| {let mut v = Vec::new(); privkey.serialize_private_key(&mut v)?; Ok(String::from_utf8(v).unwrap())})
            .collect()
    }
}

// -------- mla.ConfigWriter --------

// This class keep the values of configured object, and can be used to produce an actual
// `ArchiveWriterConfig`. That way, it can be used to produced many of them, as they are
// consumed during the `ArchiveWriter` init (to avoid reusing cryptographic materials)
struct WriterConfigInner {
    compression_level: Option<u32>,
    signature_config: Option<PrivateKeys>,
    public_keys: Option<PublicKeys>,
}

#[pyclass]
struct WriterConfig {
    inner: Mutex<WriterConfigInner>,
}

#[pymethods]
impl WriterConfig {
    #[new]
    #[pyo3(signature = (private_keys, public_keys))]
    fn new(
        private_keys: PrivateKeys,
        public_keys: PublicKeys,
    ) -> Result<Self, WrappedError> {

        Ok(WriterConfig {
            inner: Mutex::new(WriterConfigInner {
                compression_level: Some(DEFAULT_COMPRESSION_LEVEL),
                signature_config: Some(private_keys),
                public_keys: Some(public_keys),
            }),
        })
    }

    #[classmethod]
    #[pyo3(signature = (public_keys))]
    fn with_encryption_without_signature(_cls: &Bound<PyType>, public_keys: PublicKeys) -> Result<Self, WrappedError> {
        Ok(WriterConfig {
            inner: Mutex::new(WriterConfigInner {
                compression_level: Some(DEFAULT_COMPRESSION_LEVEL),
                signature_config: None,
                public_keys: Some(public_keys),
            }),
        })
    }

    #[classmethod]
    #[pyo3(signature = (private_keys))]
    fn without_encryption_with_signature(_cls: &Bound<PyType>, private_keys: PrivateKeys) -> Result<Self, WrappedError> {
        Ok(WriterConfig {
            inner: Mutex::new(WriterConfigInner {
                compression_level: Some(DEFAULT_COMPRESSION_LEVEL),
                signature_config: Some(private_keys),
                public_keys: None,
            }),
        })
    }

    #[classmethod]
    #[pyo3(signature = ())]
    fn without_encryption_without_signature(_cls: &Bound<PyType>) -> Result<Self, WrappedError> {
        Ok(WriterConfig {
            inner: Mutex::new(WriterConfigInner {
                compression_level: Some(DEFAULT_COMPRESSION_LEVEL),
                signature_config: None,
                public_keys: None,
            }),
        })
    }

    /// Set the compression level
    /// compression level (0-11); bigger values cause denser, but slower compression
    fn with_compression_level(
        slf: PyRefMut<Self>,
        compression_level: u32,
    ) -> Result<PyRefMut<Self>, WrappedError> {
        // Check compression level is correct using a fake object
        ArchiveWriterConfig::without_encryption_without_signature()?.with_compression_level(compression_level)?;

        slf.inner.lock().expect("Mutex poisoned").compression_level = Some(compression_level);
        Ok(slf)
    }

    fn without_compression(
        slf: PyRefMut<Self>,
    ) -> Result<PyRefMut<Self>, WrappedError> {
        slf.inner.lock().expect("Mutex poisoned").compression_level = None;
        Ok(slf)
    }
}

impl WriterConfig {
    /// Create an `ArchiveWriterConfig` out of the python object
    fn to_archive_writer_config(&self) -> Result<ArchiveWriterConfig, WrappedError> {
        let inner = self.inner.lock().expect("Mutex poisoned");
        let config = match inner.public_keys.as_ref() {
            Some(public_keys) => {
                let encryption_keys = public_keys.inner.lock().expect("Mutex poisoned").keys.iter().map(|k| k.get_encryption_public_key().clone()).collect::<Vec<_>>();
                match inner.signature_config.as_ref() {
                    Some(private_keys) => {
                        let signature_keys = private_keys.inner.lock().expect("Mutex poisoned").keys.iter().map(|k| k.get_signing_private_key().clone()).collect::<Vec<_>>();
                        ArchiveWriterConfig::with_encryption_with_signature(&encryption_keys, &signature_keys)
                    }
                    None => ArchiveWriterConfig::with_encryption_without_signature(&encryption_keys),
                }
            }
            None => match inner.signature_config.as_ref() {
                Some(private_keys) => {
                    let signature_keys = private_keys.inner.lock().expect("Mutex poisoned").keys.iter().map(|k| k.get_signing_private_key().clone()).collect::<Vec<_>>();
                    ArchiveWriterConfig::without_encryption_with_signature(&signature_keys)
                }
                None => ArchiveWriterConfig::without_encryption_without_signature(),
            }
        }?;
        let config = match inner.compression_level.as_ref() {
            Some(compression_level) => config.with_compression_level(*compression_level)?,
            None => config.without_compression(),
        };
        Ok(config)
    }
}

#[pyclass]
struct SignatureConfig {
    inner: Mutex<Option<PublicKeys>>,
}

#[pymethods]
impl SignatureConfig {
    #[new]
    #[pyo3(signature = (public_keys))]
    fn new(public_keys: PublicKeys) -> Self {
        SignatureConfig {
            inner: Mutex::new(Some(public_keys)),
        }
    }

    #[classmethod]
    #[pyo3(signature = ())]
    fn without_signature_verification(_cls: &Bound<PyType>) -> Self {
        SignatureConfig {
            inner: Mutex::new(None),
        }
    }
}

// -------- mla.ConfigReader --------

// This class keep the values of configured object, and can be used to produce an actual
// `ArchiveReaderConfig`. That way, it can be used to produced many of them, as they are
// consumed during the `ArchiveReader` init
struct ReaderConfigInner {
    accept_unencrypted: bool,
    private_keys: Option<PrivateKeys>,
    signature_config: Option<PublicKeys>,
}

#[pyclass]
struct ReaderConfig {
    inner: Mutex<ReaderConfigInner>,
}

#[pymethods]
impl ReaderConfig {
    #[new]
    #[pyo3(signature = (private_keys, signature_config))]
    fn new(private_keys: PrivateKeys, signature_config: &SignatureConfig) -> Self {
        let signature_config = signature_config.inner.lock().expect("Mutex poisoned").clone();
        ReaderConfig {
            inner: Mutex::new(ReaderConfigInner { accept_unencrypted: false, private_keys: Some(private_keys), signature_config }),
        }
    }

    #[classmethod]
    #[pyo3(signature = (private_keys, signature_config))]
    fn with_private_keys_accept_unencrypted(_cls: &Bound<PyType>, private_keys: PrivateKeys, signature_config: &SignatureConfig) -> Self {
        let signature_config = signature_config.inner.lock().expect("Mutex poisoned").clone();
        ReaderConfig {
            inner: Mutex::new(ReaderConfigInner { accept_unencrypted: true, private_keys: Some(private_keys), signature_config }),
        }
    }

    #[classmethod]
    #[pyo3(signature = (signature_config))]
    fn without_encryption(_cls: &Bound<PyType>, signature_config: &SignatureConfig) -> Self {
        let signature_config = signature_config.inner.lock().expect("Mutex poisoned").clone();
        ReaderConfig {
            inner: Mutex::new(ReaderConfigInner { accept_unencrypted: true, private_keys: None, signature_config }),
        }
    }
}

impl ReaderConfig {
    /// Create an `ArchiveReaderConfig` out of the python object
    fn to_archive_reader_config(&self) -> ArchiveReaderConfig {
        let inner = self.inner.lock().expect("Mutex poisoned");

        let incomplete_config = if let Some(ref public_keys) = inner.signature_config {
            let public_keys = public_keys.inner.lock().expect("Mutex poisoned").keys.iter().map(|k| k.get_signature_verification_public_key().clone()).collect::<Vec<_>>();
            ArchiveReaderConfig::with_signature_verification(&public_keys)
        } else {
            ArchiveReaderConfig::without_signature_verification()
        };

        if let Some(ref private_keys) = inner.private_keys {
            let private_keys = private_keys.inner.lock().expect("Mutex poisoned").keys.iter().map(|k| k.get_decryption_private_key().clone()).collect::<Vec<_>>();
            if inner.accept_unencrypted {
                incomplete_config.with_encryption_accept_unencrypted(&private_keys)
            } else {
                incomplete_config.with_encryption(&private_keys)
            }
        } else if inner.accept_unencrypted {
            incomplete_config.without_encryption()
        } else {
            panic!("Given ReaderConfig API this should not happen. Please report bug")
        }
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
        key: RustEntryName,
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

    fn start_entry(&mut self, key: RustEntryName) -> Result<u64, mla::errors::Error> {
        match self {
            ExplicitWriter::FileWriter(writer) => Ok(writer.start_entry(key)?.0),
        }
    }

    fn append_entry_content(
        &mut self,
        id: u64,
        size: usize,
        data: &[u8],
    ) -> Result<(), mla::errors::Error> {
        match self {
            ExplicitWriter::FileWriter(writer) => {
                writer.append_entry_content(ArchiveEntryId(id), size as u64, data)
            }
        }
    }

    fn end_entry(&mut self, id: u64) -> Result<(), mla::errors::Error> {
        match self {
            ExplicitWriter::FileWriter(writer) => writer.end_entry(ArchiveEntryId(id)),
        }
    }
}

/// See `ExplicitWriter` for details
enum ExplicitReader {
    FileReader(ArchiveReader<'static, std::fs::File>),
}

/// Wrap calls to the inner type
impl ExplicitReader {
    fn list_entries(&self) -> Result<impl Iterator<Item = &RustEntryName>, mla::errors::Error> {
        match self {
            ExplicitReader::FileReader(reader) => reader.list_entries(),
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
    #[pyo3(signature = (path, mode, config))]
    fn new(
        path: &str,
        mode: &str,
        config: &Bound<'_, PyAny>,
    ) -> Result<Self, WrappedError> {
        match mode {
            "r" => {
                let rconfig = config
                                .extract::<PyRef<ReaderConfig>>()?
                                .to_archive_reader_config();
                let input_file = std::fs::File::open(path)?;
                let arch_reader = ArchiveReader::from_config(input_file, rconfig)?.0;
                Ok(MLAFile {
                    inner: Mutex::new(MLAFileInner {
                        inner: OpeningModeInner::Read(ExplicitReader::FileReader(arch_reader)),
                        path: path.to_owned(),
                    }),
                })
            }
            "w" => {
                let wconfig = config
                            .extract::<PyRef<WriterConfig>>()?
                            .to_archive_writer_config()?;
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
                "Unknown mode {mode}, use 'r' or 'w'"
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

    /// Return the list of entry names in the archive as `EntryName`s
    fn keys(&self) -> Result<Vec<EntryName>, WrappedError> {
        self.with_reader(|inner| Ok(inner.list_entries()?.cloned().map(EntryName::from_rust_entry_name).collect()))
    }

    /// Return the list of the entries in the archive, along with metadata
    /// If `include_size` is set, the size will be included in the metadata
    /// If `include_hash` is set, the hash (SHA256) will be included in the metadata
    ///
    /// Example:
    /// ```python
    /// metadatas = archive.list_entries(include_size=True, include_hash=True)
    /// for entry_name, metadata in metadatas.items():
    ///    print(f"File {entry_name.to_pathbuf_escaped_string()} has size {metadata.size} and hash {metadata.hash}")
    /// ```
    #[pyo3(signature = (include_size=false, include_hash=false))]
    fn list_entries(
        &mut self,
        include_size: bool,
        include_hash: bool,
    ) -> Result<HashMap<EntryName, FileMetadata>, WrappedError> {
        self.with_reader(|inner| {
            #[allow(clippy::mutable_key_type)]
            let mut output = HashMap::new();
            let iter: Vec<RustEntryName> = inner.list_entries()?.cloned().collect();
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
                                    .get_entry(fname.clone())?
                                    .ok_or(PyRuntimeError::new_err(format!(
                                        "EntryNot found (escaped name): {}",
                                        fname.raw_content_to_escaped_string()
                                    )))?
                                    .size,
                            );
                        }
                        if include_hash {
                            metadata.hash = Some(reader.get_hash(&fname)?.ok_or(
                                PyRuntimeError::new_err(format!("EntryNot found (escaped name): {}", fname.raw_content_to_escaped_string())),
                            )?);
                        }
                    }
                }
                output.insert(EntryName::from_rust_entry_name(fname), metadata);
            }
            Ok(output)
        })
    }

    /// Return whether the given `EntryName` is in the archive
    fn __contains__(&self, key: &EntryName) -> Result<bool, WrappedError> {
        let rust_entry_name = key.to_rust_entry_name();
        self.with_reader(|inner| Ok(inner.list_entries()?.any(|x| x == &rust_entry_name)))
    }

    /// Return the content of an entry indexed by its `EntryName` as bytes
    fn __getitem__(&mut self, key: &EntryName) -> Result<Vec<u8>, WrappedError> {
        self.with_reader(|inner| match inner {
            ExplicitReader::FileReader(reader) => {
                let file = reader.get_entry(key.to_rust_entry_name())?;
                if let Some(mut archive_entry) = file {
                    let mut buf = Vec::new();
                    archive_entry.data.read_to_end(&mut buf)?;
                    Ok(buf)
                } else {
                    Err(PyKeyError::new_err(format!("EntryNot found (escaped name): {}", key.raw_content_to_escaped_string())).into())
                }
            }
        })
    }

    /// Add an entry to the archive indexed by its `EntryName`
    fn __setitem__(&mut self, key: &EntryName, value: &[u8]) -> Result<(), WrappedError> {
        self.with_writer(|writer| match writer {
            ExplicitWriter::FileWriter(writer) => {
                let mut reader = std::io::Cursor::new(value);
                writer.add_entry(key.to_rust_entry_name(), value.len() as u64, &mut reader)?;
                Ok(())
            }
        })
    }

    /// Return the number of file in the archive
    fn __len__(&self) -> Result<usize, WrappedError> {
        self.with_reader(|inner| Ok(inner.list_entries()?.count()))
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

    /// Write an archive entry given by its `EntryName` to @dest, which can be:
    /// - a string, corresponding to the output path
    /// - a writable BufferedIOBase object (file-object like)
    /// If a BufferedIOBase object is provided, the size of the chunck passed to `.write` can be adjusted
    /// through @chunk_size (default to 4MB)
    ///
    /// Example:
    /// ```python
    /// with open("/path/to/extract/file1", "wb") as f:
    ///     archive.write_entry_to(EntryName("file1"), f)
    /// ```
    /// Or
    /// ```python
    /// archive.write_entry_to(EntryName("file1"), "/path/to/extract/file1")
    /// ```
    #[pyo3(signature = (key, dest, chunk_size=4194304))]
    fn write_entry_to(
        &mut self,
        py: Python,
        key: &EntryName,
        dest: &Bound<PyAny>,
        chunk_size: usize,
    ) -> Result<(), WrappedError> {
        self.with_reader(|reader| {
            let archive_entry = match reader {
                ExplicitReader::FileReader(reader) => reader.get_entry(key.to_rust_entry_name())?,
            };

            if let Ok(dest) = dest.downcast::<PyString>() {
                let mut output = std::fs::File::create(dest.to_string())?;
                io::copy(&mut archive_entry.unwrap().data, &mut output)?;
            } else if dest.is_instance(&py.get_type::<MLAFile>().getattr("_buffered_type")?)? {
                let src = &mut archive_entry.unwrap().data;
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

    /// Add an entry named by @src `EntryName` to an archive from @src, which can be:
    /// - a string, corresponding to the input path
    /// - a readable BufferedIOBase object (file-object like)
    /// If a BufferedIOBase object is provided, the size of the chunck passed to `.read` can be adjusted
    /// through @chunk_size (default to 4MB)
    ///
    /// Example:
    /// ```python
    /// archive.add_entry_from(EntryName("file1"), "/path/to/file1")
    /// ```
    /// Or
    /// ```python
    /// with open("/path/to/file1", "rb") as f:
    ///    archive.add_entry_from(EntryName("file1"), f)
    /// ```
    #[pyo3(signature = (key, src, chunk_size=4194304))]
    fn add_entry_from(
        &mut self,
        py: Python,
        key: &EntryName,
        src: &Bound<PyAny>,
        chunk_size: usize,
    ) -> Result<(), WrappedError> {
        let key = key.to_rust_entry_name();
        self.with_writer(|writer| {
            if let Ok(src) = src.downcast::<PyString>() {
                let mut input = std::fs::File::open(src.to_string())?;
                writer.add_entry(key, input.metadata()?.len(), &mut input)?;
            } else if src.is_instance(&py.get_type::<MLAFile>().getattr("_buffered_type")?)? {
                let id = writer.start_entry(key)?;
                loop {
                    let py_bytes = src
                        .call_method1("read", (chunk_size,))?
                        .extract::<Py<PyBytes>>()?;
                    let data = py_bytes.as_bytes(py);
                    if data.is_empty() {
                        break;
                    }
                    writer.append_entry_content(id, data.len(), data)?;
                }
                writer.end_entry(id)?;
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

#[pyclass]
struct EntryName {
    inner: Mutex<RustEntryName>,
}

impl PartialEq for EntryName {
    fn eq(&self, other: &EntryName) -> bool {
        let lhs = self.inner.lock().expect("Mutex poisonned");
        let rhs = other.inner.lock().expect("Mutex poisonned");
        lhs.eq(&rhs)
    }
}

impl Eq for EntryName {}

impl Hash for EntryName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.lock().expect("Mutex poisonned").hash(state);
    }
}

impl EntryName {
    fn from_rust_entry_name(entry_name: RustEntryName) -> Self {
        Self {
            inner: Mutex::new(entry_name)
        }
    }

    fn to_rust_entry_name(&self) -> RustEntryName {
        self.inner.lock().expect("Mutex poisonned").clone()
    }
}

#[pymethods]
impl EntryName {
    #[new]
    #[pyo3(signature = (str_path))]
    /// Builds an EntryName from a str interpreted like a path
    /// 
    /// See Rust `EntryName::from_path` doc to read what this function does
    fn new(str_path: &str) -> Result<Self, WrappedError> {
        Ok(Self {
            inner: Mutex::new(RustEntryName::from_path(str_path)?)
        })
    }

    #[staticmethod]
    #[pyo3(signature = (path))]
    /// Builds an EntryName from an os.PathLike
    /// 
    /// See Rust `EntryName::from_path` doc to read what this function does
    fn from_path(path: PathBuf) -> Result<Self, WrappedError> {
        Ok(Self {
            inner: Mutex::new(RustEntryName::from_path(path)?)
        })
    }

    #[staticmethod]
    #[pyo3(signature = (bytes))]
    /// Builds an EntryName from an os.PathLike
    /// 
    /// See Rust `EntryName::from_arbitrary_bytes` doc to read what this function does
    fn from_arbitrary_bytes(bytes: &[u8]) -> Result<Self, WrappedError> {
        Ok(Self {
            inner: Mutex::new(RustEntryName::from_arbitrary_bytes(bytes)?)
        })
    }

    #[getter]
    /// SECURITY WARNING: See Rust `EntryName::as_arbitrary_bytes` doc to read what this returns
    fn arbitrary_bytes(&self) -> Vec<u8> {
        self.inner.lock().expect("Mutex poisonned").as_arbitrary_bytes().to_vec()
    }

    /// See Rust `EntryName::raw_content_to_escaped_string` doc to read what this function does
    fn raw_content_to_escaped_string(&self) -> String {
        self.inner.lock().expect("Mutex poisonned").raw_content_to_escaped_string()
    }

    /// SECURITY WARNING: See Rust `EntryName::to_pathbuf` doc to read what this function does
    fn to_pathbuf(&self) -> Result<PathBuf, WrappedError> {
        self.inner.lock().expect("Mutex poisonned").to_pathbuf().map_err(|_| WrappedError::EntryNameError)
    }

    /// See Rust `EntryName::to_pathbuf_escaped_string` doc to read what this function does
    fn to_pathbuf_escaped_string(&self) -> Result<String, WrappedError> {
        self.inner.lock().expect("Mutex poisonned").to_pathbuf_escaped_string().map_err(|_| WrappedError::EntryNameError)
    }

    fn __richcmp__(&self, other: &EntryName, op: CompareOp) -> bool {
        op.matches(self.inner.lock().expect("Mutex poisonned").cmp(&other.inner.lock().expect("Mutex poisonned")))
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

// -------- Python module instanciation --------

/// Instanciate the Python module
#[pymodule]
#[pyo3(name = "mla")]
fn pymla(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Classes
    m.add_class::<MLAFile>()?;
    m.add_class::<EntryName>()?;
    m.add_class::<FileMetadata>()?;
    m.add_class::<WriterConfig>()?;
    m.add_class::<PublicKeys>()?;
    m.add_class::<PrivateKeys>()?;
    m.add_class::<SignatureConfig>()?;
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
    m.add("WrongEndMagic", py.get_type::<WrongEndMagic>())?;
    m.add("NoValidSignatureFound", py.get_type::<NoValidSignatureFound>())?;
    m.add("SignatureVerificationAskedButNoSignatureLayerFound", py.get_type::<SignatureVerificationAskedButNoSignatureLayerFound>())?;

    // Add constants
    m.add("DEFAULT_COMPRESSION_LEVEL", DEFAULT_COMPRESSION_LEVEL)?;
    Ok(())
}
