use std::io::Read;

use crate::{
    errors::Error,
    format::{ArchiveHeader, Layers},
};

pub struct ArchiveHeaderInfo {
    format_version: u32,
    compression_enabled: bool,
    encryption_enabled: bool,
}

impl ArchiveHeaderInfo {
    pub fn get_format_version(&self) -> u32 {
        self.format_version
    }

    pub fn is_compression_enabled(&self) -> bool {
        self.compression_enabled
    }

    pub fn is_encryption_enabled(&self) -> bool {
        self.encryption_enabled
    }
}

/// Given an `R` reading from the beginning of an archive, read and parse MLA header to return `ArchiveHeaderInfo`
pub fn read_header_info<R: Read>(src: &mut R) -> Result<ArchiveHeaderInfo, Error> {
    let header = ArchiveHeader::from(src)?;
    Ok(ArchiveHeaderInfo {
        format_version: header.format_version,
        compression_enabled: header.config.layers_enabled.contains(Layers::ENCRYPT),
        encryption_enabled: header.config.layers_enabled.contains(Layers::ENCRYPT),
    })
}
