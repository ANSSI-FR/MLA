use crate::Layers;
use crate::errors::ConfigError;
use crate::layers::compress::CompressionConfig;
use crate::layers::encrypt::{
    EncryptionConfig, EncryptionPersistentConfig, EncryptionReaderConfig, InternalEncryptionConfig,
};
use serde::{Deserialize, Serialize};

/// This module implements the configuration capabilities of MLA Archive
///
/// Workflow:
/// ```asciiart
///                      `ArchiveWriterConfig`  <--> User, add recipients, set the compression level, etc.
///                              |
///                              v
///                      -------------- MLA ---
///                              |
///                       .to_persistent()
///                           /       \
/// MLA specifics <= InternalConfig  PersistentConfig => to be stored in the header,
///                                                      for futur reloaded by the Reader
/// ```
/// User's configuration used to prepare an archive
pub struct ArchiveWriterConfig {
    layers_enabled: Layers,

    // Layers specifics
    pub(crate) compress: CompressionConfig,
    pub(crate) encrypt: EncryptionConfig,
}

/// Configuration stored in the header, to be reloaded
#[derive(Serialize, Deserialize)]
pub struct ArchivePersistentConfig {
    pub layers_enabled: Layers,

    // Layers specifics
    pub encrypt: Option<EncryptionPersistentConfig>,
}

/// Internal config, to be used only during MLA processing, by MLA
#[derive(Default)]
pub(crate) struct InternalConfig {
    // Layers specifics
    pub(crate) encrypt: Option<InternalEncryptionConfig>,
}

pub type ConfigResult<'a> = Result<&'a mut ArchiveWriterConfig, ConfigError>;

impl ArchiveWriterConfig {
    /// Start a builder without any layers configured
    pub fn new() -> ArchiveWriterConfig {
        ArchiveWriterConfig {
            layers_enabled: Layers::EMPTY,
            compress: CompressionConfig::default(),
            encrypt: EncryptionConfig::default(),
        }
    }

    /// Enable a layer
    pub fn enable_layer(&mut self, layer: Layers) -> &mut ArchiveWriterConfig {
        self.layers_enabled |= layer;
        self
    }

    /// Disable a layer
    pub fn disable_layer(&mut self, layer: Layers) -> &mut ArchiveWriterConfig {
        self.layers_enabled &= !layer;
        self
    }

    /// Set several layers at once
    pub fn set_layers(&mut self, layers: Layers) -> &mut ArchiveWriterConfig {
        self.layers_enabled = layers;
        self
    }

    /// Get the persistent version, to be stored in the header
    pub(crate) fn to_persistent(
        &self,
    ) -> Result<(ArchivePersistentConfig, InternalConfig), ConfigError> {
        let (encrypt_persistent, encrypt_internal) = if self.is_layers_enabled(Layers::ENCRYPT) {
            let (persistent, internal) = self.encrypt.to_persistent()?;
            (Some(persistent), Some(internal))
        } else {
            (None, None)
        };
        Ok((
            ArchivePersistentConfig {
                layers_enabled: self.layers_enabled,
                encrypt: encrypt_persistent,
            },
            InternalConfig {
                encrypt: encrypt_internal,
            },
        ))
    }

    /// Check if layers are enabled
    pub fn is_layers_enabled(&self, layer: Layers) -> bool {
        self.layers_enabled.contains(layer)
    }

    /// Consistency check
    pub fn check(&self) -> Result<(), ConfigError> {
        if self.is_layers_enabled(Layers::ENCRYPT) {
            self.encrypt.check()?;
        }
        Ok(())
    }
}

impl std::default::Default for ArchiveWriterConfig {
    /// The default version is missing some parameters to work properly; this is intended
    /// Missing parameters:
    /// - ecc_encryption_key
    fn default() -> Self {
        ArchiveWriterConfig {
            layers_enabled: Layers::default(),
            compress: CompressionConfig::default(),
            encrypt: EncryptionConfig::default(),
        }
    }
}

/// User's configuration used to read an archive
#[derive(Default)]
pub struct ArchiveReaderConfig {
    pub layers_enabled: Layers,

    // Layers specifics
    pub encrypt: EncryptionReaderConfig,
}

impl ArchiveReaderConfig {
    /// Start a builder, without any specific option
    pub fn new() -> Self {
        Self {
            layers_enabled: Layers::EMPTY,
            encrypt: EncryptionReaderConfig::default(),
        }
    }

    pub fn load_persistent(
        &mut self,
        config: ArchivePersistentConfig,
    ) -> Result<&mut ArchiveReaderConfig, ConfigError> {
        self.layers_enabled = config.layers_enabled;
        if self.layers_enabled.contains(Layers::ENCRYPT) {
            match config.encrypt {
                Some(to_load) => {
                    self.encrypt.load_persistent(to_load)?;
                }
                None => {
                    return Err(ConfigError::IncoherentPersistentConfig);
                }
            }
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_building() {
        let mut builder = ArchiveWriterConfig::new();
        builder
            .enable_layer(Layers::ENCRYPT)
            .enable_layer(Layers::COMPRESS)
            .disable_layer(Layers::ENCRYPT);
        assert_eq!(builder.layers_enabled, Layers::COMPRESS);
    }
}
