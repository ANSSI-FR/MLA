use crate::crypto::hybrid::{MLADecryptionPrivateKey, MLAEncryptionPublicKey};
use crate::crypto::mlakey::{MLASignaturePrivateKey, MLASignatureVerificationPublicKey};
use crate::errors::ConfigError;
use crate::layers::compress::CompressionConfig;
use crate::layers::encrypt::{EncryptionConfig, EncryptionReaderConfig};
use crate::layers::signature::{SignatureConfig, SignatureReaderConfig};

/// Configuration to write an archive.
pub struct ArchiveWriterConfig {
    pub(crate) compression_config: Option<CompressionConfig>,
    pub(crate) encryption_config: Option<EncryptionConfig>,
    pub(crate) signature_config: Option<SignatureConfig>,
}

impl ArchiveWriterConfig {
    /// Will sign content with given signature private keys.
    ///
    /// Returns `ConfigError::PrivateKeyNotSet` if `signature_private_keys` is empty.
    pub fn without_encryption_with_signature(
        signature_private_keys: &[MLASignaturePrivateKey],
    ) -> Result<Self, ConfigError> {
        Ok(ArchiveWriterConfig {
            compression_config: Some(CompressionConfig::default()),
            encryption_config: None,
            signature_config: Some(SignatureConfig::new(signature_private_keys)?),
        })
    }

    /// Will encrypt content with given public keys.
    ///
    /// Returns `ConfigError::EncryptionKeyIsMissing` if `encryption_public_keys` is empty.
    pub fn with_public_keys(encryption_public_keys: &[MLAEncryptionPublicKey]) -> Self {
        ArchiveWriterConfig {
            compression_config: Some(CompressionConfig::default()),
            encryption_config: Some(EncryptionConfig::new(encryption_public_keys).unwrap()),
            signature_config: None,
        }
    }

    /// WARNING: Won't encrypt content.
    pub fn without_encryption() -> ArchiveWriterConfig {
        ArchiveWriterConfig {
            compression_config: Some(CompressionConfig::default()),
            encryption_config: None,
            signature_config: None,
        }
    }

    /// Set the compression level
    /// compression level (0-11); bigger values cause denser, but slower compression
    pub fn with_compression_level(self, compression_level: u32) -> Result<Self, ConfigError> {
        let ArchiveWriterConfig {
            compression_config,
            encryption_config,
            signature_config,
        } = self;
        let mut compression_config = compression_config.unwrap_or_default();
        compression_config.set_compression_level(compression_level)?;
        Ok(ArchiveWriterConfig {
            compression_config: Some(compression_config),
            encryption_config,
            signature_config,
        })
    }

    /// Disable compression
    pub fn without_compression(mut self) -> ArchiveWriterConfig {
        self.compression_config = None;
        self
    }
}

/// Configuration used to read an archive.
pub struct ArchiveReaderConfig {
    pub(crate) accept_unencrypted: bool,
    // Layers specifics
    pub(crate) encrypt: EncryptionReaderConfig,
    pub(crate) signature_reader_config: SignatureReaderConfig,
}

impl ArchiveReaderConfig {
    /// Will refuse to open an archive without encryption.
    pub fn with_private_keys(keys: &[MLADecryptionPrivateKey]) -> Self {
        let mut encrypt = EncryptionReaderConfig::default();
        let mut signature_reader_config = SignatureReaderConfig::default();
        signature_reader_config.signature_check = false;
        encrypt.set_private_keys(keys);
        Self {
            accept_unencrypted: false,
            encrypt,
            signature_reader_config,
        }
    }

    /// Will accept to open encrypted and unencrypted archives.
    pub fn with_private_keys_accept_unencrypted(keys: &[MLADecryptionPrivateKey]) -> Self {
        let mut encrypt = EncryptionReaderConfig::default();
        let mut signature_reader_config = SignatureReaderConfig::default();
        signature_reader_config.signature_check = false;
        encrypt.set_private_keys(keys);
        Self {
            accept_unencrypted: true,
            encrypt,
            signature_reader_config,
        }
    }

    /// Won't accept encrypted archives.
    pub fn without_encryption() -> Self {
        let encrypt = EncryptionReaderConfig::default();
        let mut signature_reader_config = SignatureReaderConfig::default();
        signature_reader_config.signature_check = false;
        Self {
            accept_unencrypted: true,
            encrypt,
            signature_reader_config,
        }
    }

    /// Won't accept encrypted archives.
    pub fn without_encryption_with_signature(
        signature_verification_public_keys: &[MLASignatureVerificationPublicKey],
    ) -> Self {
        let encrypt = EncryptionReaderConfig::default();
        let mut signature_reader_config = SignatureReaderConfig::default();
        signature_reader_config.set_public_keys(signature_verification_public_keys);
        Self {
            accept_unencrypted: true,
            encrypt,
            signature_reader_config,
        }
    }
}
