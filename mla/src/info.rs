use std::io::Read;

use crate::{
    MLADeserialize,
    errors::Error,
    format::ArchiveHeader,
    layers::{
        encrypt::ENCRYPTION_LAYER_MAGIC,
        raw::RawLayerFailSafeReader,
        signature::{SIGNATURE_LAYER_MAGIC, SignatureLayerFailSafeReader},
    },
    read_layer_magic,
};

pub struct ArchiveInfo {
    format_version: u32,
    encryption_enabled: bool,
    signature_enabled: bool,
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
}

/// Given an `R` reading from the beginning of an archive, read and parse MLA header to return `ArchiveHeaderInfo`
pub fn read_info<R: Read>(src: &mut R) -> Result<ArchiveInfo, Error> {
    let header = ArchiveHeader::deserialize(src)?;
    let layer_magic = read_layer_magic(src)?;
    let (encryption_enabled, signature_enabled) = if layer_magic == SIGNATURE_LAYER_MAGIC {
        let src = Box::new(RawLayerFailSafeReader::new(src));
        let mut src = Box::new(SignatureLayerFailSafeReader::new_skip_magic(src)?);
        let next_layer_magic = read_layer_magic(&mut src)?;
        (&next_layer_magic == ENCRYPTION_LAYER_MAGIC, true)
    } else {
        (&layer_magic == ENCRYPTION_LAYER_MAGIC, false)
    };
    Ok(ArchiveInfo {
        format_version: header.format_version_number,
        encryption_enabled,
        signature_enabled,
    })
}
