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

    if current_magic == *ENCRYPTION_LAYER_MAGIC {
        encryption_enabled = true;
        // Since we can't parse the encryption layer without a key,
        // we'll assume no compression after encryption (conservative)
        // Thus: compression detection in encrypted archives is intentionally not supported.
        // Rationale:
        // 1. Principle: Follows https://github.com/ANSSI-FR/MLA/issues/41#issuecomment-760146919 - basic info should work without decryption keys
        // 2. Architecture: Adding decryption to the info command would significantly complicate
        //    the code path and error handling
        // 3. Use case: The info command is designed for quick inspection and scripting,
        //    where requiring private keys would be impractical
        //
        // This is an intentional design limitation, not a missing feature.
        // The CLI output clearly notifies users when compression status is unknown due to encryption.
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
