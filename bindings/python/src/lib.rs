use std::{borrow::Cow, collections::HashMap, io::Read};

use mla::{
    config::{ArchiveReaderConfig, ArchiveWriterConfig},
    ArchiveReader, ArchiveWriter, Layers,
};
use pyo3::{
    create_exception,
    exceptions::{PyKeyError, PyRuntimeError},
    prelude::*,
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
        match self.hash {
            Some(ref hash) => Some(Cow::Borrowed(hash)),
            None => None,
        }
    }

    fn __repr__(&self) -> String {
        format!("<FileMetadata size={:?} hash={:?}>", self.size, self.hash)
    }
}

// -------- mla.ConfigWriter --------

// from mla::layers::DEFAULT_COMPRESSION_LEVEL
const DEFAULT_COMPRESSION_LEVEL: u32 = 5;

#[pyclass]
struct WriterConfig {
    inner: ArchiveWriterConfig,
}

#[pymethods]
impl WriterConfig {
    #[new]
    #[pyo3(signature = (layers=None, compression_level=DEFAULT_COMPRESSION_LEVEL))]
    fn new(layers: Option<u8>, compression_level: u32) -> Result<Self, WrappedError> {
        let mut output = WriterConfig {
            inner: ArchiveWriterConfig::new(),
        };
        if let Some(layers_enabled) = layers {
            output
                .inner
                .set_layers(Layers::from_bits(layers_enabled).ok_or(
                    mla::errors::Error::BadAPIArgument(format!("Unknown layers")),
                )?);
        }
        output.inner.with_compression_level(compression_level)?;

        Ok(output)
    }

    #[getter]
    fn layers(&self) -> Result<u8, WrappedError> {
        Ok(self.inner.to_persistent()?.layers_enabled.bits())
    }

    /// Enable a layer
    fn enable_layer(mut slf: PyRefMut<Self>, layer: u8) -> Result<PyRefMut<Self>, WrappedError> {
        slf.inner.enable_layer(
            Layers::from_bits(layer)
                .ok_or(mla::errors::Error::BadAPIArgument(format!("Unknown layer")))?,
        );
        Ok(slf)
    }

    /// Disable a layer
    fn disable_layer(mut slf: PyRefMut<Self>, layer: u8) -> Result<PyRefMut<Self>, WrappedError> {
        slf.inner.disable_layer(
            Layers::from_bits(layer)
                .ok_or(mla::errors::Error::BadAPIArgument(format!("Unknown layer")))?,
        );
        Ok(slf)
    }

    /// Set several layers at once
    fn set_layers(mut slf: PyRefMut<Self>, layers: u8) -> Result<PyRefMut<Self>, WrappedError> {
        slf.inner.set_layers(Layers::from_bits(layers).ok_or(
            mla::errors::Error::BadAPIArgument(format!("Unknown layers")),
        )?);
        Ok(slf)
    }

    /// Set the compression level
    /// compression level (0-11); bigger values cause denser, but slower compression
    fn with_compression_level(
        mut slf: PyRefMut<Self>,
        compression_level: u32,
    ) -> Result<PyRefMut<Self>, WrappedError> {
        slf.inner.with_compression_level(compression_level)?;
        Ok(slf)
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
    #[pyo3(signature = (path, mode="r"))]
    fn new(path: &str, mode: &str) -> Result<Self, WrappedError> {
        match mode {
            "r" => {
                let config = ArchiveReaderConfig::new();
                let input_file = std::fs::File::open(path)?;
                let arch_reader = ArchiveReader::from_config(input_file, config)?;
                Ok(MLAFile {
                    inner: OpeningModeInner::Read(ExplicitReaders::FileReader(arch_reader)),
                    path: path.to_string(),
                })
            }
            "w" => {
                let mut config = ArchiveWriterConfig::new();
                config.enable_layer(Layers::COMPRESS);
                let output_file = std::fs::File::create(path)?;
                let arch_writer = ArchiveWriter::from_config(output_file, config)?;
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

    /// Return the size of a file in the archive
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
                                .ok_or(WrappedError::WrappedPy(PyRuntimeError::new_err(format!(
                                    "File {} not found",
                                    fname
                                ))))?
                                .size,
                        );
                    }
                    if include_hash {
                        metadata.hash =
                            Some(mla.get_hash(&fname)?.ok_or(WrappedError::WrappedPy(
                                PyRuntimeError::new_err(format!("File {} not found", fname)),
                            ))?);
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
                    Err(WrappedError::WrappedPy(PyKeyError::new_err(format!(
                        "File {} not found",
                        key
                    )))
                    .into())
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

    fn __exit__(
        &mut self,
        exc_type: Option<&PyAny>,
        _exc_value: Option<&PyAny>,
        _traceback: Option<&PyAny>,
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
}

// -------- Python module instanciation --------

/// Instanciate the Python module
#[pymodule]
#[pyo3(name = "mla")]
fn pymla(py: Python, m: &PyModule) -> PyResult<()> {
    // Classes
    m.add_class::<MLAFile>()?;
    m.add_class::<FileMetadata>()?;
    m.add_class::<WriterConfig>()?;

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
