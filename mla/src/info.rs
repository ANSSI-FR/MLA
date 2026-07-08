use std::io::Read;

use crate::{
    MLADeserialize,
    errors::Error,
    format::ArchiveHeader,
    layers::{
        compress::COMPRESSION_LAYER_MAGIC,
        encrypt::ENCRYPTION_LAYER_MAGIC,
        raw::RawLayerTruncatedReader,
        signature::{SIGNATURE_LAYER_MAGIC, SignatureLayerTruncatedReader},
    },
    read_layer_magic,
};

pub struct ArchiveInfo {
    format_version: u32,
    encryption_enabled: bool,
    signature_enabled: bool,
    compression_enabled: bool,
}

impl ArchiveInfo {
    pub fn get_format_version(&self) -> u32 {
        self.format_version
    }

    pub fn is_encryption_enabled(&self) -> bool {
        self.encryption_enabled
    }

    pub fn is_signature_enabled(&self) -> bool {
        self.signature_enabled
    }

    pub fn is_compression_enabled(&self) -> bool {
        self.compression_enabled
    }
}

/// Given an `R` reading from the beginning of an archive, read and parse MLA header to return `ArchiveHeaderInfo`
pub fn read_info<R: Read>(src: &mut R) -> Result<ArchiveInfo, Error> {
    let header = ArchiveHeader::deserialize(src)?;
    let mut current_magic = read_layer_magic(src)?;
    let mut signature_enabled = false;
    let mut encryption_enabled = false;
    let mut compression_enabled = false;

    // Parse layers in order: Signature -> Encryption -> Compression
    if current_magic == *SIGNATURE_LAYER_MAGIC {
        signature_enabled = true;
        // Skip to next layer to find next magic
        let src_wrapper = RawLayerTruncatedReader::new(src);
        let mut sig_reader = SignatureLayerTruncatedReader::new_skip_magic(Box::new(src_wrapper))?;
        current_magic = read_layer_magic(&mut sig_reader)?;
    }

    // Note: We can't easily skip the encryption layer without parsing it,
    // so we'll just check if the current magic is compression
    // TODO: Detect compression in encrypted archives when decryption keys are available
    // Implementation plan:
    // 1. Modify read_info signature to accept optional ArchiveReaderConfig with decryption keys
    // 2. In mlar/src/main.rs info command, add support for private_keys and shared_secret arguments
    // 3. Build config from provided keys and pass to read_info
    // 4. In read_info, if config is provided and current_magic is ENCRYPTION_LAYER_MAGIC:
    //    a. Try to decrypt using ArchiveReader::from_config
    //    b. If decryption succeeds, read first bytes from decrypted stream
    //    c. Use read_layer_magic to detect compression in decrypted data
    //    d. Update compression_enabled accordingly
    // 5. Handle decryption errors gracefully (don't fail if decryption fails)
    // 6. Add tests for encrypted+compressed archives with and without keys
    // Current limitation: Compression status unknown for encrypted archives without decryption
    if current_magic == *ENCRYPTION_LAYER_MAGIC {
        encryption_enabled = true;
        // Try to peek at the next magic after encryption
        // Since we can't parse the encryption layer without a key,
        // we'll assume no compression after encryption (conservative)
    } else if current_magic == *COMPRESSION_LAYER_MAGIC {
        compression_enabled = true;
    }

    Ok(ArchiveInfo {
        format_version: header.format_version_number,
        encryption_enabled,
        signature_enabled,
        compression_enabled,
    })
}
