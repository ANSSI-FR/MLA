// -------- MLA Format Header --------

use std::io::{Read, Write};

use bincode::{Decode, Encode};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

pub use crate::crypto::hybrid::HybridRecipientEncapsulatedKey;
use crate::{
    BINCODE_CONFIG, MLA_FORMAT_VERSION, MLA_MAGIC, config::ArchivePersistentConfig, errors::Error,
};
pub struct ArchiveHeader {
    pub format_version: u32,
    pub config: ArchivePersistentConfig,
}

impl ArchiveHeader {
    pub fn from<T: Read>(src: &mut T) -> Result<Self, Error> {
        let mut buf = vec![00u8; MLA_MAGIC.len()];
        src.read_exact(buf.as_mut_slice())?;
        if buf != MLA_MAGIC {
            return Err(Error::WrongMagic);
        }
        let format_version = src.read_u32::<LittleEndian>()?;
        if format_version != MLA_FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let config: ArchivePersistentConfig =
            match bincode::decode_from_std_read(src, BINCODE_CONFIG) {
                Ok(config) => config,
                _ => {
                    return Err(Error::DeserializationError);
                }
            };
        Ok(ArchiveHeader {
            format_version,
            config,
        })
    }

    pub(crate) fn dump<T: Write>(&self, dest: &mut T) -> Result<(), Error> {
        dest.write_all(MLA_MAGIC)?;
        dest.write_u32::<LittleEndian>(self.format_version)?;
        if bincode::encode_into_std_write(&self.config, dest, BINCODE_CONFIG).is_err() {
            return Err(Error::SerializationError);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Encode, Decode)]
pub struct Layers(u8);

bitflags! {
    /// Available layers. Order is relevant:
    /// ```ascii-art
    /// [File to blocks decomposition]
    /// [Compression (COMPRESS)]
    /// [Encryption (ENCRYPT)]
    /// [Raw File I/O]
    /// ```
    impl Layers: u8 {
        const ENCRYPT = 0b0000_0001;
        const COMPRESS = 0b0000_0010;
        /// Recommended layering
        const DEFAULT = Self::ENCRYPT.bits() | Self::COMPRESS.bits();
        /// No additional layer (ie, for debugging purpose)
        const DEBUG = 0;
        const EMPTY = 0;
    }
}

impl std::default::Default for Layers {
    fn default() -> Self {
        Layers::DEFAULT
    }
}
