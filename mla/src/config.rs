//! `ArchiveReader` and `ArchiveWriter` configuration
use crate::crypto::hybrid::{MLADecryptionPrivateKey, MLAEncryptionPublicKey};
use crate::crypto::mlakey::{MLASignatureVerificationPublicKey, MLASigningPrivateKey};
use crate::errors::ConfigError;
use crate::layers::compress::CompressionConfig;
use crate::layers::encrypt::{EncryptionConfig, EncryptionReaderConfig};
use crate::layers::signature::{SignatureConfig, SignatureReaderConfig};

pub use crate::layers::compress::DEFAULT_COMPRESSION_LEVEL;

/// Configuration to write an archive.
pub struct ArchiveWriterConfig {
    pub(crate) compression: Option<CompressionConfig>,
    pub(crate) encryption: Option<EncryptionConfig>,
    pub(crate) signature: Option<SignatureConfig>,
}

impl ArchiveWriterConfig {
    /// Will encrypt content with given encryption public keys and sign content
    /// with given signature private keys.
    ///
    /// Do not mix up keys. If `A` sends an archive to `B`,
    /// `encryption_public_keys` must contain
    /// `B`'s encryption public key and
    /// `signing_private_keys` must contain `A`'s signature private key.
    ///
    /// Will compress by default with `DEFAULT_COMPRESSION_LEVEL`. Can be
    /// configured with `with_compression_level` and `without_compression`.
    ///
    /// Returns `ConfigError::EncryptionKeyIsMissing` if `encryption_public_keys` is empty.
    /// Returns `ConfigError::PrivateKeyNotSet` if `signing_private_keys` is empty.
    pub fn with_encryption_with_signature(
        encryption_public_keys: &[MLAEncryptionPublicKey],
        signing_private_keys: &[MLASigningPrivateKey],
    ) -> Result<Self, ConfigError> {
        Ok(ArchiveWriterConfig {
            compression: Some(CompressionConfig::default()),
            encryption: Some(EncryptionConfig::new(encryption_public_keys)?),
            signature: Some(SignatureConfig::new(signing_private_keys)?),
        })
    }

    /// WARNING: Will NOT sign content !
    ///
    /// Will encrypt content with given encryption public keys AND WONT SIGN CONTENT.
    ///
    /// Do not mix up keys. If `A` sends an archive to `B`,
    /// `encryption_public_keys` must contain
    /// `B`'s encryption public key.
    ///
    /// Will compress by default with `DEFAULT_COMPRESSION_LEVEL`. Can be
    /// configured with `with_compression_level` and `without_compression`.
    ///
    /// Returns `ConfigError::EncryptionKeyIsMissing` if `encryption_public_keys` is empty.
    pub fn with_encryption_without_signature(
        encryption_public_keys: &[MLAEncryptionPublicKey],
    ) -> Result<Self, ConfigError> {
        Ok(ArchiveWriterConfig {
            compression: Some(CompressionConfig::default()),
            encryption: Some(EncryptionConfig::new(encryption_public_keys)?),
            signature: None,
        })
    }

    /// WARNING: Will NOT encrypt content !
    ///
    /// Will sign content with given signature private keys AND WONT ENCRYPT content.
    ///
    /// Do not mix up keys. If `A` sends an archive to `B`,
    /// `signing_private_keys` must contain `A`'s signature private key.
    ///
    /// Will compress by default with `DEFAULT_COMPRESSION_LEVEL`. Can be
    /// configured with `with_compression_level` and `without_compression`.
    ///
    /// Returns `ConfigError::PrivateKeyNotSet` if `signing_private_keys` is empty.
    pub fn without_encryption_with_signature(
        signing_private_keys: &[MLASigningPrivateKey],
    ) -> Result<Self, ConfigError> {
        Ok(ArchiveWriterConfig {
            compression: Some(CompressionConfig::default()),
            encryption: None,
            signature: Some(SignatureConfig::new(signing_private_keys)?),
        })
    }

    /// WARNING: Will NOT encrypt content and Will NOT sign content !
    ///
    /// Will compress by default with `DEFAULT_COMPRESSION_LEVEL`. Can be
    /// configured with `with_compression_level` and `without_compression`.
    pub fn without_encryption_without_signature() -> Result<Self, ConfigError> {
        Ok(ArchiveWriterConfig {
            compression: Some(CompressionConfig::default()),
            encryption: None,
            signature: None,
        })
    }

    /// Set the compression level (0-11); bigger values cause denser, but slower compression
    pub fn with_compression_level(self, compression_level: u32) -> Result<Self, ConfigError> {
        let ArchiveWriterConfig {
            compression,
            encryption,
            signature,
        } = self;
        let mut compression_config = compression.unwrap_or_default();
        compression_config.set_compression_level(compression_level)?;
        Ok(ArchiveWriterConfig {
            compression: Some(compression_config),
            encryption,
            signature,
        })
    }

    /// Disable compression
    #[must_use]
    pub fn without_compression(mut self) -> ArchiveWriterConfig {
        self.compression = None;
        self
    }
}

/// Configuration used to read an archive.
///
/// Use this to build an `IncompleteArchiveReaderConfig` which you will be able
/// to use to build an `ArchiveReaderConfig`.
pub struct ArchiveReaderConfig {
    pub(crate) accept_unencrypted: bool,
    // Layers specifics
    pub(crate) encrypt: EncryptionReaderConfig,
    pub(crate) signature_reader_config: SignatureReaderConfig,
}

impl ArchiveReaderConfig {
    /// Will refuse to open an archive without signature verified by AT LEAST
    /// one of the given `signature_verification_public_keys`.
    ///
    /// Caller will be able to tell how many and against which keys signatures
    /// were correctly verified by reading `ArchiveReader::from_config` return value.
    pub fn with_signature_verification(
        signature_verification_public_keys: &[MLASignatureVerificationPublicKey],
    ) -> IncompleteArchiveReaderConfig {
        let mut signature_reader_config = SignatureReaderConfig::default();
        signature_reader_config.set_public_keys(signature_verification_public_keys);
        IncompleteArchiveReaderConfig {
            signature_reader_config,
        }
    }

    /// WARNING: Will NOT verify archive signature.
    ///
    /// This skips signature verification whether the archive is signed or not.
    ///
    /// This enables reading unsigned archives and reading signed archives without the cost of verification.
    pub fn without_signature_verification() -> IncompleteArchiveReaderConfig {
        let mut signature_reader_config = SignatureReaderConfig::default();
        signature_reader_config.signature_check = false;
        IncompleteArchiveReaderConfig {
            signature_reader_config,
        }
    }
}

/// Struct returned by one of the `ArchiveReaderConfig` associated functions.
///
/// `IncompleteArchiveReaderConfig` associated functions return an
/// `ArchiveReaderConfig`. Thus you should first call an associated function
/// of `ArchiveReaderConfig` and call an associated function of
/// `IncompleteArchiveReaderConfig` on the result to obtain a valid
/// `ArchiveReaderConfig`.
///
/// This ensures we configure both signature and encryption in a flexible
/// way before being able to operate on an archive.
pub struct IncompleteArchiveReaderConfig {
    signature_reader_config: SignatureReaderConfig,
}

impl IncompleteArchiveReaderConfig {
    /// Will refuse to open an archive without encryption.
    pub fn with_encryption(
        self,
        decryption_private_keys: &[MLADecryptionPrivateKey],
    ) -> ArchiveReaderConfig {
        let mut encrypt = EncryptionReaderConfig::default();
        encrypt.set_private_keys(decryption_private_keys);
        ArchiveReaderConfig {
            accept_unencrypted: false,
            encrypt,
            signature_reader_config: self.signature_reader_config,
        }
    }

    /// WARNING: This will accept reading unencrypted archives !
    ///
    /// If you do not know if an archive is encrypted or not and want to read even if it is NOT, you may use this function.
    /// This avoids having to open the archive a second time after decryption failure, for example to save the cost of doing signature check twice.
    pub fn with_encryption_accept_unencrypted(
        self,
        decryption_private_keys: &[MLADecryptionPrivateKey],
    ) -> ArchiveReaderConfig {
        let mut encrypt = EncryptionReaderConfig::default();
        encrypt.set_private_keys(decryption_private_keys);
        ArchiveReaderConfig {
            accept_unencrypted: false,
            encrypt,
            signature_reader_config: self.signature_reader_config,
        }
    }

    /// Will NOT accept encrypted archives.
    pub fn without_encryption(self) -> ArchiveReaderConfig {
        let encrypt = EncryptionReaderConfig::default();
        ArchiveReaderConfig {
            accept_unencrypted: true,
            encrypt,
            signature_reader_config: self.signature_reader_config,
        }
    }
}

/// `TruncatedReader` decryption mode
#[derive(Default, Clone, Copy, Eq, PartialEq, Debug)]
pub enum TruncatedReaderDecryptionMode {
    /// Returns only the data that have been authenticated (in AEAD meaning, there will be NO signature verification) on decryption
    #[default]
    OnlyAuthenticatedData,
    /// Returns all data, even if not authenticated. In the case where the last content chunk has its aes-gcm tag truncated, this may handle the tag interpreted as encrypted data, thus producing up to 15 bytes of garbage in output.
    DataEvenUnauthenticated,
}

pub struct TruncatedReaderConfig {
    pub(crate) accept_unencrypted: bool,
    // Layers specifics
    pub(crate) encrypt: EncryptionReaderConfig,
    pub(crate) truncated_decryption_mode: TruncatedReaderDecryptionMode,
}

impl TruncatedReaderConfig {
    /// Will refuse to open an archive without encryption.
    pub fn without_signature_verification_with_encryption(
        decryption_private_keys: &[MLADecryptionPrivateKey],
        truncated_mode: TruncatedReaderDecryptionMode,
    ) -> TruncatedReaderConfig {
        let mut encrypt = EncryptionReaderConfig::default();
        encrypt.set_private_keys(decryption_private_keys);
        TruncatedReaderConfig {
            accept_unencrypted: false,
            encrypt,
            truncated_decryption_mode: truncated_mode,
        }
    }

    /// WARNING: This will accept reading unencrypted archives !
    ///
    /// If you do not know if an archive is encrypted or not and want to read even if it is NOT, you may use this function.
    /// This avoids having to open the archive a second time after decryption failure, for example to save the cost of doing signature check twice.
    pub fn without_signature_verification_with_encryption_accept_unencrypted(
        decryption_private_keys: &[MLADecryptionPrivateKey],
        truncated_mode: TruncatedReaderDecryptionMode,
    ) -> TruncatedReaderConfig {
        let mut encrypt = EncryptionReaderConfig::default();
        encrypt.set_private_keys(decryption_private_keys);
        TruncatedReaderConfig {
            accept_unencrypted: false,
            encrypt,
            truncated_decryption_mode: truncated_mode,
        }
    }

    /// Will NOT accept encrypted archives.
    pub fn without_signature_verification_without_encryption() -> TruncatedReaderConfig {
        let encrypt = EncryptionReaderConfig::default();
        TruncatedReaderConfig {
            accept_unencrypted: true,
            encrypt,
            truncated_decryption_mode: TruncatedReaderDecryptionMode::default(),
        }
    }
}
