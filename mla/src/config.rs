use bincode::{Decode, Encode};

use crate::crypto::hybrid::{HybridPrivateKey, HybridPublicKey};
use crate::errors::ConfigError;
use crate::format::Layers;
use crate::layers::compress::CompressionConfig;
use crate::layers::encrypt::{
    EncryptionConfig, EncryptionPersistentConfig, EncryptionReaderConfig,
};

/// Configuration to write an archive.
pub struct ArchiveWriterConfig {
    pub(crate) compression_config: Option<CompressionConfig>,
    pub(crate) encryption_config: Option<EncryptionConfig>,
}

impl ArchiveWriterConfig {
    /// Will encrypt content with given public keys.
    pub fn with_public_keys(keys: &[HybridPublicKey]) -> Self {
        let mut encryption_config = EncryptionConfig::default();
        encryption_config.add_public_keys(keys);
        ArchiveWriterConfig {
            compression_config: Some(CompressionConfig::default()),
            encryption_config: Some(encryption_config),
        }
    }

    /// WARNING: Won't encrypt content.
    pub fn without_encryption() -> ArchiveWriterConfig {
        ArchiveWriterConfig {
            compression_config: Some(CompressionConfig::default()),
            encryption_config: None,
        }
    }

    /// Set the compression level
    /// compression level (0-11); bigger values cause denser, but slower compression
    pub fn with_compression_level(self, compression_level: u32) -> Result<Self, ConfigError> {
        let ArchiveWriterConfig {
            compression_config,
            encryption_config,
        } = self;
        let mut compression_config = compression_config.unwrap_or_default();
        compression_config.set_compression_level(compression_level)?;
        Ok(ArchiveWriterConfig {
            compression_config: Some(compression_config),
            encryption_config,
        })
    }

    /// Disable compression
    pub fn without_compression(mut self) -> ArchiveWriterConfig {
        self.compression_config = None;
        self
    }
}

/// Configuration stored in the header, to be reloaded
#[derive(Encode, Decode)]
pub(crate) struct ArchivePersistentConfig {
    pub layers_enabled: Layers,

    // Layers specifics
    pub encrypt: Option<EncryptionPersistentConfig>,
}

/// Configuration used to read an archive.
pub struct ArchiveReaderConfig {
    pub(crate) accept_unencrypted: bool,
    // Layers specifics
    pub(crate) encrypt: EncryptionReaderConfig,
}

impl ArchiveReaderConfig {
    /// Will refuse to open an archive without encryption.
    pub fn with_private_keys(keys: &[HybridPrivateKey]) -> Self {
        let mut encrypt = EncryptionReaderConfig::default();
        encrypt.set_private_keys(keys);
        Self {
            accept_unencrypted: false,
            encrypt,
        }
    }

    /// Will accept to open encrypted and unencrypted archives.
    pub fn with_private_keys_accept_unencrypted(keys: &[HybridPrivateKey]) -> Self {
        let mut encrypt = EncryptionReaderConfig::default();
        encrypt.set_private_keys(keys);
        Self {
            accept_unencrypted: true,
            encrypt,
        }
    }

    /// Won't accept encrypted archives.
    pub fn without_encryption() -> Self {
        let encrypt = EncryptionReaderConfig::default();
        Self {
            accept_unencrypted: true,
            encrypt,
        }
    }
}
