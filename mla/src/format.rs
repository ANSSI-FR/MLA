// -------- MLA Format Header --------

use std::borrow::BorrowMut;
use std::io::{Read, Write};

use crate::{
    ArchiveEntryBlockType, ArchiveEntryId, Opts, Sha256Hash, entry::EntryName, errors::Error,
};
use crate::{
    MLA_FORMAT_VERSION, MLA_MAGIC, MLADeserialize, MLASerialize, deserialize_entry_name,
    read_layer_magic, serialize_entry_name,
};

const ARCHIVE_ENTRY_BLOCK_MAGIC: &[u8; 4] = b"MAEB";

pub(crate) struct ArchiveHeader {
    pub(crate) format_version_number: u32,
}

impl<W: Write> MLASerialize<W> for ArchiveHeader {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        dest.write_all(MLA_MAGIC)?;
        let mut len = 8;
        len += MLA_FORMAT_VERSION.serialize(dest)?;
        len += Opts.dump(dest)?;
        Ok(len)
    }
}

impl<R: Read> MLADeserialize<R> for ArchiveHeader {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let mla_magic = read_layer_magic(src)?;
        if &mla_magic != MLA_MAGIC {
            return Err(Error::WrongMagic);
        }

        let format_version_number = u32::deserialize(src)?;
        if format_version_number != MLA_FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }

        let _ = Opts::from_reader(src)?; // No option handled at the moment
        Ok(Self {
            format_version_number,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
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
pub enum ArchiveEntryBlock<T: Read> {
    /// Usually, an entry is made of:
    /// `[EntryStart][EntryContent]`...`[EntryContent][EndOfEntry]`
    /// The `id` is used to keep track internally of which file a `ArchiveEntryBlock` belongs to
    ///
    /// Start of an entry
    EntryStart {
        name: EntryName,
        id: ArchiveEntryId,
        opts: Opts,
    },
    /// Entry content.
    /// (length, data) is used instead of a Vec to avoid having the whole data
    /// in memory. On parsing, the data can be set to None. It indicates to the
    /// caller that the data is just next to it
    /// TODO: use the same trick than `ArchiveReader` to avoid the Option
    EntryContent {
        length: u64,
        data: Option<T>,
        id: ArchiveEntryId,
        opts: Opts,
    },
    /// End of file (last block) - contains the SHA256 of the whole file
    EndOfEntry {
        id: ArchiveEntryId,
        hash: Sha256Hash,
        opts: Opts,
    },
    /// End of archive data (no more files after that)
    EndOfArchiveData,
}

impl<T> ArchiveEntryBlock<T>
where
    T: Read,
{
    pub(crate) fn dump<U: Write>(&mut self, dest: &mut U) -> Result<(), Error> {
        dest.write_all(ARCHIVE_ENTRY_BLOCK_MAGIC)?;
        match self {
            ArchiveEntryBlock::EntryStart { name, id, opts } => {
                ArchiveEntryBlockType::EntryStart.serialize(dest)?;
                id.serialize(dest)?;
                serialize_entry_name(name, dest.borrow_mut())?;
                let _ = opts.dump(dest.borrow_mut())?;
                Ok(())
            }
            ArchiveEntryBlock::EntryContent {
                length,
                data,
                id,
                opts,
            } => {
                ArchiveEntryBlockType::EntryContent.serialize(dest)?;
                id.serialize(dest)?;
                let _ = opts.dump(dest.borrow_mut())?;
                length.serialize(dest)?;
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
            ArchiveEntryBlock::EndOfEntry { id, hash, opts } => {
                ArchiveEntryBlockType::EndOfEntry.serialize(dest)?;
                id.serialize(dest)?;
                let _ = opts.dump(dest.borrow_mut())?;
                dest.write_all(hash)?;
                Ok(())
            }
            ArchiveEntryBlock::EndOfArchiveData => {
                ArchiveEntryBlockType::EndOfArchiveData.serialize(dest)?;
                Ok(())
            }
        }
    }

    pub(crate) fn from(mut src: &mut T) -> Result<Self, Error> {
        // just read 4 bytes for the magic, we won't use it
        u32::deserialize(&mut src)?;
        let block_type = ArchiveEntryBlockType::deserialize(&mut src)?;
        match block_type {
            ArchiveEntryBlockType::EntryStart => {
                let id = ArchiveEntryId::deserialize(&mut src)?;
                let name = deserialize_entry_name(&mut src)?;
                let opts = Opts::from_reader(&mut src)?;

                Ok(ArchiveEntryBlock::EntryStart { id, name, opts })
            }
            ArchiveEntryBlockType::EntryContent => {
                let id = ArchiveEntryId::deserialize(&mut src)?;
                let opts = Opts::from_reader(&mut src)?;
                let length = u64::deserialize(&mut src)?;
                // /!\ WARNING: to avoid loading this entire entry block's contents
                // in-memory, the `data` reader is None; the `src` now starts at the
                // beginning of the data
                Ok(ArchiveEntryBlock::EntryContent {
                    length,
                    data: None,
                    id,
                    opts,
                })
            }
            ArchiveEntryBlockType::EndOfEntry => {
                let id = ArchiveEntryId::deserialize(&mut src)?;
                let opts = Opts::from_reader(&mut src)?;
                let mut hash = Sha256Hash::default();
                src.read_exact(&mut hash)?;
                Ok(ArchiveEntryBlock::EndOfEntry { id, hash, opts })
            }
            ArchiveEntryBlockType::EndOfArchiveData => Ok(ArchiveEntryBlock::EndOfArchiveData),
        }
    }
}
