// -------- MLA Format Header --------

use std::io::{Read, Write};

use bincode::{Decode, Encode};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

pub use crate::crypto::hybrid::HybridRecipientEncapsulatedKey;
use crate::{
    config::ArchivePersistentConfig, errors::Error, ArchiveEntryId, ArchiveFileBlockType, Sha256Hash, BINCODE_CONFIG, FILENAME_MAX_SIZE, MLA_FORMAT_VERSION, MLA_MAGIC
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

#[derive(Debug)]
pub enum ArchiveFileBlock<T: Read> {
    /// Usually, a file is made of:
    /// `[FileStart][FileContent]`...`[FileContent][EndOfFile]`
    /// The `id` is used to keep track internally of which file a `ArchiveFileBlock` belongs to
    ///
    /// Start of a file
    FileStart {
        filename: String,
        id: ArchiveEntryId,
    },
    /// File content.
    /// (length, data) is used instead of a Vec to avoid having the whole data
    /// in memory. On parsing, the data can be set to None. It indicates to the
    /// caller that the data is just next to it
    /// TODO: use the same trick than ArchiveReader to avoid the Option
    FileContent {
        length: u64,
        data: Option<T>,
        id: ArchiveEntryId,
    },
    /// End of file (last block) - contains the SHA256 of the whole file
    EndOfFile {
        id: ArchiveEntryId,
        hash: Sha256Hash,
    },
    /// End of archive data (no more files after that)
    EndOfArchiveData,
}

impl<T> ArchiveFileBlock<T>
where
    T: Read,
{
    pub(crate) fn dump<U: Write>(&mut self, dest: &mut U) -> Result<(), Error> {
        match self {
            ArchiveFileBlock::FileStart { filename, id } => {
                dest.write_u8(ArchiveFileBlockType::FileStart as u8)?;
                dest.write_u64::<LittleEndian>(*id)?;
                let bytes = filename.as_bytes();
                let length = bytes.len() as u64;
                if length > FILENAME_MAX_SIZE {
                    return Err(Error::FilenameTooLong);
                }
                dest.write_u64::<LittleEndian>(length)?;
                dest.write_all(bytes)?;
                Ok(())
            }
            ArchiveFileBlock::FileContent { length, data, id } => {
                dest.write_u8(ArchiveFileBlockType::FileContent as u8)?;
                dest.write_u64::<LittleEndian>(*id)?;
                dest.write_u64::<LittleEndian>(*length)?;
                match data {
                    None => {
                        return Err(Error::AssertionError(String::from(
                            "Data missing in file content",
                        )));
                    }
                    Some(content) => {
                        // TODO check length
                        std::io::copy(&mut content.take(*length), dest)?;
                    }
                }
                Ok(())
            }
            ArchiveFileBlock::EndOfFile { id, hash } => {
                dest.write_u8(ArchiveFileBlockType::EndOfFile as u8)?;
                dest.write_u64::<LittleEndian>(*id)?;
                dest.write_all(hash)?;
                Ok(())
            }
            ArchiveFileBlock::EndOfArchiveData => {
                dest.write_u8(ArchiveFileBlockType::EndOfArchiveData as u8)?;
                Ok(())
            }
        }
    }

    pub(crate) fn from(src: &mut T) -> Result<Self, Error> {
        let byte = src.read_u8()?;
        match ArchiveFileBlockType::try_from(byte)? {
            ArchiveFileBlockType::FileStart => {
                let id = src.read_u64::<LittleEndian>()?;
                let length = src.read_u64::<LittleEndian>()?;
                if length > FILENAME_MAX_SIZE {
                    return Err(Error::FilenameTooLong);
                }
                let mut filename = vec![0u8; length as usize];
                src.read_exact(&mut filename)?;
                Ok(ArchiveFileBlock::FileStart {
                    id,
                    filename: String::from_utf8(filename)?,
                })
            }
            ArchiveFileBlockType::FileContent => {
                let id = src.read_u64::<LittleEndian>()?;
                let length = src.read_u64::<LittleEndian>()?;
                // /!\ WARNING: to avoid loading this entire subfileblock's contents
                // in-memory, the `data` reader is None; the `src` now starts at the
                // beginning of the data
                Ok(ArchiveFileBlock::FileContent {
                    length,
                    data: None,
                    id,
                })
            }
            ArchiveFileBlockType::EndOfFile => {
                let id = src.read_u64::<LittleEndian>()?;
                let mut hash = Sha256Hash::default();
                src.read_exact(&mut hash)?;
                Ok(ArchiveFileBlock::EndOfFile { id, hash })
            }
            ArchiveFileBlockType::EndOfArchiveData => Ok(ArchiveFileBlock::EndOfArchiveData),
        }
    }
}
