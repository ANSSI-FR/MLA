use crate::ArchiveEntryId;
use std::error;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    /// IO Error (not enough data, etc.)
    IOError(io::Error),
    /// Wrong magic, must be "MLA"
    WrongMagic,
    /// Unsupported version, must be 1
    UnsupportedVersion,
    /// Supplied key is not in the expected format
    InvalidKeyFormat,
    /// Wrong BlockSubFile magic has been encountered. Is the deserializion
    /// starting at the beginning of a block?
    WrongBlockSubFileType,
    /// An error has occurred while converting into UTF8. This error could
    /// happens while parsing the block filename
    UTF8ConversionError(std::string::FromUtf8Error),
    /// Filenames have a limited size `FILENAME_MAX_SIZE`
    FilenameTooLong,
    /// The writer state is not in the expected state for the current operation
    WrongArchiveWriterState {
        current_state: String,
        expected_state: String,
    },
    /// Should never happens: an internal assumptions no more hold
    AssertionError(String),
    /// The reader state is not in the expected state for the current operation
    WrongReaderState(String),
    /// The writer state is not in the expected state for the current operation
    WrongWriterState(String),
    /// Error with the inner random generator
    RandError,
    /// A Private Key is required to decrypt the encrypted cipher key
    PrivateKeyNeeded,
    /// Deserialization error. May happens when starting from a wrong offset /
    /// version mismatch
    DeserializationError,
    /// Serialization error. May happens on I/O errors
    SerializationError,
    /// Missing metadata (usually means the footer has not been correctly read,
    /// a repair might be needed)
    MissingMetadata,
    /// Error returned on API call with incorrect argument
    BadAPIArgument(String),
    /// End of stream reached, no more data should be expected
    EndOfStream,
    /// An error happens in the configuration
    ConfigError(ConfigError),
    /// Filename already used
    DuplicateFilename,
    /// Wrong tag while decrypting authenticated data
    AuthenticatedDecryptionWrongTag,
    /// Unable to expand while using the HKDF
    HKDFInvalidKeyLength,
    /// Error during HPKE computation
    HPKEError,
    /// Invalid last tag
    InvalidLastTag,
    /// User asked for encryption but archive was not marked as encrypted
    EncryptionAskedButNotMarkedPresent,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // For now, use the debug derived version
        write!(f, "{self:?}")
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::IOError(error)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(error: std::string::FromUtf8Error) -> Self {
        Error::UTF8ConversionError(error)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        io::Error::other(format!("{error}"))
    }
}

impl From<ConfigError> for Error {
    fn from(error: ConfigError) -> Self {
        match error {
            ConfigError::PrivateKeyNotSet => Error::PrivateKeyNeeded,
            _ => Error::ConfigError(error),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Error::IOError(err) => Some(err),
            Error::UTF8ConversionError(err) => Some(err),
            Error::ConfigError(err) => Some(err),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum TruncatedReadError {
    /// Everything ends correctly
    NoError,
    /// An unexpected EOF occurs while getting the next block
    UnexpectedEOFOnNextBlock,
    /// An IO error occurs while reading the next block
    IOErrorOnNextBlock(io::Error),
    /// A Error occurs while reading the next block
    ErrorOnNextBlock(Error),
    /// An error occurs in the middle of a file
    ErrorInFile(io::Error, String),
    /// A file ID is being reused
    ArchiveFileIDReuse(ArchiveEntryId),
    /// A filename is being reused
    FilenameReuse(String),
    /// Data for a file already closed
    ArchiveFileIDAlreadyClose(ArchiveEntryId),
    /// Content for an unknown file
    ContentForUnknownFile(ArchiveEntryId),
    /// Termination of an unknwown file
    EOFForUnknownFile(ArchiveEntryId),
    /// Wraps an already existing error and indicates which files are not
    /// finished (a file can be finished but uncompleted)
    UnfinishedFiles {
        filenames: Vec<String>,
        stopping_error: Box<TruncatedReadError>,
    },
    /// End of original archive reached - this is the best case
    EndOfOriginalArchiveData,
    /// Error in the FailSafeReader internal state
    FailSafeReadInternalError,
    /// The file's hash does not correspond to the expected one
    HashDiffers {
        expected: Vec<u8>,
        obtained: Vec<u8>,
    },
}

impl fmt::Display for TruncatedReadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // For now, use the debug derived version
        write!(f, "{self:?}")
    }
}

impl error::Error for TruncatedReadError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            TruncatedReadError::IOErrorOnNextBlock(err) => Some(err),
            TruncatedReadError::ErrorOnNextBlock(err) => Some(err),
            TruncatedReadError::ErrorInFile(err, _path) => Some(err),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    IncoherentPersistentConfig,
    // Compression specifics
    CompressionLevelOutOfRange,
    // Encryption specifics
    /// No recipients provided, encryption can't continue
    NoRecipients,
    /// Internal state has not yet been created. A call to `to_persistent` might be missing
    EncryptionKeyIsMissing,
    PrivateKeyNotSet,
    PrivateKeyNotFound,
    MLKEMComputationError,
    DHKEMComputationError,
    KeyCommitmentComputationError,
    /// The encrypted key commitment does not correspond to the key commitment chain
    KeyCommitmentCheckingError,
    /// Error while wrapping or unwrapping the encryption key
    KeyWrappingComputationError,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // For now, use the debug derived version
        write!(f, "{self:?}")
    }
}

impl error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
