use std::collections::HashMap;
use std::convert::TryFrom;
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
#[macro_use]
extern crate bitflags;
use bincode::Options;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use layers::traits::InnerReaderTrait;
use serde::{Deserialize, Serialize};

pub mod layers;
use crate::layers::compress::{
    CompressionLayerFailSafeReader, CompressionLayerReader, CompressionLayerWriter,
};
use crate::layers::encrypt::{
    EncryptionLayerFailSafeReader, EncryptionLayerReader, EncryptionLayerWriter,
};
use crate::layers::position::PositionLayerWriter;
use crate::layers::raw::{RawLayerFailSafeReader, RawLayerReader, RawLayerWriter};
use crate::layers::traits::{
    InnerWriterTrait, InnerWriterType, LayerFailSafeReader, LayerReader, LayerWriter,
};
pub mod errors;
use crate::errors::{Error, FailSafeReadError};

pub mod config;
use crate::config::{ArchivePersistentConfig, ArchiveReaderConfig, ArchiveWriterConfig};

#[doc(hidden)]
pub mod crypto;
use crate::crypto::hash::{HashWrapperReader, Sha256Hash};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;

pub mod helpers;

// -------- Constants --------

const MLA_MAGIC: &[u8; 3] = b"MLA";
const MLA_FORMAT_VERSION: u32 = 1;
/// Maximum number of UTF-8 characters supported in each file's "name" (which is free
/// to be used as a filename, an absolute path, or... ?). 32KiB was chosen because it
/// supports any path a Windows NT, Linux, FreeBSD, OpenBSD, or NetBSD kernel supports.
const FILENAME_MAX_SIZE: u64 = 65536;
/// Maximum allowed object size (in bytes) to deserialize in-memory, to avoid `DoS` on
/// malformed files
pub(crate) const BINCODE_MAX_DESERIALIZE: u64 = 512 * 1024 * 1024;

bitflags! {
    /// Available layers. Order is relevant:
    /// ```ascii-art
    /// [File to blocks decomposition]
    /// [Compression (COMPRESS)]
    /// [Encryption (ENCRYPT)]
    /// [Raw File I/O]
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Layers: u8 {
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
        Self::DEFAULT
    }
}

pub type ArchiveFileID = u64;

// -------- MLA Format Header --------

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
        let config: ArchivePersistentConfig = match bincode::options()
            .with_limit(BINCODE_MAX_DESERIALIZE)
            .with_fixint_encoding()
            .deserialize_from(src)
        {
            Ok(config) => config,
            _ => {
                return Err(Error::DeserializationError);
            }
        };
        Ok(Self {
            format_version,
            config,
        })
    }

    fn dump<T: Write>(&self, dest: &mut T) -> Result<(), Error> {
        dest.write_all(MLA_MAGIC)?;
        dest.write_u32::<LittleEndian>(self.format_version)?;
        if bincode::options()
            .with_limit(BINCODE_MAX_DESERIALIZE)
            .with_fixint_encoding()
            .serialize_into(dest, &self.config)
            .is_err()
        {
            return Err(Error::SerializationError);
        }
        Ok(())
    }
}

// -------- MLA Format Footer --------

pub struct ArchiveFooter {
    /// Filename -> Corresponding `FileInfo`
    pub files_info: HashMap<String, FileInfo>,
}

impl ArchiveFooter {
    /// Footer:
    /// ```ascii-art
    /// [files_info][files_info length]
    /// ```
    ///
    /// Performs zero-copy serialization of a footer
    fn serialize_into<W: Write>(
        mut dest: W,
        files_info: &HashMap<String, ArchiveFileID>,
        ids_info: &HashMap<ArchiveFileID, FileInfo>,
    ) -> Result<(), Error> {
        let mut serialization_len = 0;

        // Combine `files_info` and `ids_info` to ArchiveFooter.files_info,
        // avoiding copies (only references)
        let mut tmp: HashMap<&String, &FileInfo> = HashMap::new();
        for (k, i) in files_info {
            let v = ids_info.get(i).ok_or_else(|| {
                Error::WrongWriterState(
                    "[ArchiveFooter seriliaze] Unable to find the ID".to_string(),
                )
            })?;
            tmp.insert(k, v);
        }

        if bincode::options()
            .with_limit(BINCODE_MAX_DESERIALIZE)
            .with_fixint_encoding()
            .serialize_into(&mut dest, &tmp)
            .is_err()
        {
            return Err(Error::SerializationError);
        }
        serialization_len += match bincode::serialized_size(&tmp) {
            Ok(size) => size,
            Err(_) => {
                return Err(Error::SerializationError);
            }
        };

        // footer length
        dest.write_u32::<LittleEndian>(
            u32::try_from(serialization_len).map_err(|_| Error::SerializationError)?,
        )?;
        Ok(())
    }

    /// Parses and instantiates a footer from serialized data
    pub fn deserialize_from<R: Read + Seek>(mut src: R) -> Result<Self, Error> {
        // Read the footer length
        let pos = src.seek(SeekFrom::End(-4))?;
        let len = u64::from(src.read_u32::<LittleEndian>()?);

        // Prepare for deserialization
        src.seek(SeekFrom::Start(pos - len))?;

        // Read files_info
        let files_info: HashMap<String, FileInfo> = match bincode::options()
            .with_limit(BINCODE_MAX_DESERIALIZE)
            .with_fixint_encoding()
            .deserialize_from(&mut src.take(len))
        {
            Ok(finfo) => finfo,
            _ => {
                return Err(Error::DeserializationError);
            }
        };
        Ok(Self { files_info })
    }
}

// -------- Writer --------

/// Tags used in each `ArchiveFileBlock` to indicate the type of block that follows
#[derive(Debug)]
#[repr(u8)]
enum ArchiveFileBlockType {
    FileStart = 0x00,
    FileContent = 0x01,

    EndOfArchiveData = 0xFE,
    EndOfFile = 0xFF,
}

impl TryFrom<u8> for ArchiveFileBlockType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value == Self::FileStart as u8 {
            Ok(Self::FileStart)
        } else if value == Self::FileContent as u8 {
            Ok(Self::FileContent)
        } else if value == Self::EndOfFile as u8 {
            Ok(Self::EndOfFile)
        } else if value == Self::EndOfArchiveData as u8 {
            Ok(Self::EndOfArchiveData)
        } else {
            Err(Error::WrongBlockSubFileType)
        }
    }
}

#[derive(Debug)]
pub enum ArchiveFileBlock<T: Read> {
    /// Usually, a file is made of:
    /// `[FileStart][FileContent]`...`[FileContent][EndOfFile]`
    /// The `id` is used to keep track internally of which file a `ArchiveFileBlock` belongs to
    ///
    /// Start of a file
    FileStart { filename: String, id: ArchiveFileID },
    /// File content.
    /// (length, data) is used instead of a Vec to avoid having the whole data
    /// in memory. On parsing, the data can be set to None. It indicates to the
    /// caller that the data is just next to it
    // TODO: use the same trick than `ArchiveReader` to avoid the Option
    FileContent {
        length: u64,
        data: Option<T>,
        id: ArchiveFileID,
    },
    /// End of file (last block) - contains the SHA256 of the whole file
    EndOfFile { id: ArchiveFileID, hash: Sha256Hash },
    /// End of archive data (no more files after that)
    EndOfArchiveData,
}

impl<T> ArchiveFileBlock<T>
where
    T: Read,
{
    fn dump<U: Write>(&mut self, dest: &mut U) -> Result<(), Error> {
        match self {
            Self::FileStart { filename, id } => {
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
            Self::FileContent { length, data, id } => {
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
                        io::copy(&mut content.take(*length), dest)?;
                    }
                }
                Ok(())
            }
            Self::EndOfFile { id, hash } => {
                dest.write_u8(ArchiveFileBlockType::EndOfFile as u8)?;
                dest.write_u64::<LittleEndian>(*id)?;
                dest.write_all(hash)?;
                Ok(())
            }
            Self::EndOfArchiveData => {
                dest.write_u8(ArchiveFileBlockType::EndOfArchiveData as u8)?;
                Ok(())
            }
        }
    }

    fn from(src: &mut T) -> Result<Self, Error> {
        let byte = src.read_u8()?;
        match ArchiveFileBlockType::try_from(byte)? {
            ArchiveFileBlockType::FileStart => {
                let id = src.read_u64::<LittleEndian>()?;
                let length = src.read_u64::<LittleEndian>()?;
                if length > FILENAME_MAX_SIZE {
                    return Err(Error::FilenameTooLong);
                }
                let mut filename = vec![
                    0u8;
                    usize::try_from(length).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Length conversion failed",
                        )
                    })?
                ];
                src.read_exact(&mut filename)?;
                Ok(Self::FileStart {
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
                Ok(Self::FileContent {
                    length,
                    data: None,
                    id,
                })
            }
            ArchiveFileBlockType::EndOfFile => {
                let id = src.read_u64::<LittleEndian>()?;
                let mut hash = Sha256Hash::default();
                src.read_exact(&mut hash)?;
                Ok(Self::EndOfFile { id, hash })
            }
            ArchiveFileBlockType::EndOfArchiveData => Ok(Self::EndOfArchiveData),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ArchiveWriterState {
    /// Initialized, with files opened
    OpenedFiles {
        ids: Vec<ArchiveFileID>,
        hashes: HashMap<ArchiveFileID, Sha256>,
    },
    /// File finalized, no more change allowed
    Finalized,
}

impl ArchiveWriterState {
    /// Wrap a `impl Read` with hash updating, corresponding to the file identified by `id`
    fn wrap_with_hash<R: Read>(
        &mut self,
        id: ArchiveFileID,
        src: R,
    ) -> Result<HashWrapperReader<R>, Error> {
        let hash = match self {
            Self::OpenedFiles { hashes, .. } => match hashes.get_mut(&id) {
                Some(hash) => hash,
                None => {
                    return Err(Error::WrongWriterState(
                        "[wrap_with_hash] Unable to find the ID".to_string(),
                    ));
                }
            },
            Self::Finalized => {
                return Err(Error::WrongWriterState(
                    "[wrap_with_hash] Wrong state".to_string(),
                ));
            }
        };

        Ok(HashWrapperReader::new(src, hash))
    }
}

/// Used to check whether the current state is the one expected
/// ```text
/// check_state!(self.state, ArchiveWriterState::XXX)
/// ```
macro_rules! check_state {
    ( $x:expr, $y:ident ) => {{
        match $x {
            ArchiveWriterState::$y { .. } => (),
            _ => {
                return Err(Error::WrongArchiveWriterState {
                    current_state: format!("{:?}", $x).to_string(),
                    expected_state: format!("{}", "ArchiveWriterState::$y").to_string(),
                });
            }
        }
    }};
}

/// Used to check whether the current state is `OpenedFiles`, with the expected file opened
/// ```text
/// check_state_file_opened!(self.state, file_id)
/// ```
macro_rules! check_state_file_opened {
    ( $x:expr, $y:expr ) => {{
        match $x {
            ArchiveWriterState::OpenedFiles { ids, hashes } => {
                if !ids.contains($y) || !hashes.contains_key($y) {
                    return Err(Error::WrongArchiveWriterState {
                        current_state: format!("{:?}", $x).to_string(),
                        expected_state: "ArchiveWriterState with id $y".to_string(),
                    });
                }
            }
            _ => {
                return Err(Error::WrongArchiveWriterState {
                    current_state: format!("{:?}", $x).to_string(),
                    expected_state: "ArchiveWriterState with id $y".to_string(),
                });
            }
        }
    }};
}

pub struct ArchiveWriter<'a, W: 'a + InnerWriterTrait> {
    /// MLA Archive format writer
    ///
    /// Configuration
    // config is not used for now after archive creation,
    // but it could in the future
    #[allow(dead_code)]
    config: ArchiveWriterConfig,
    ///
    /// Internals part:
    ///
    /// Destination: use a Box to be able to dynamically changes layers
    dest: Box<PositionLayerWriter<'a, W>>,
    /// Internal state
    state: ArchiveWriterState,
    /// Filename -> Corresponding `ArchiveFileID`
    ///
    /// This is done to keep a quick check for filename existence
    files_info: HashMap<String, ArchiveFileID>,
    /// ID -> Corresponding `FileInfo`
    ///
    /// File chunks identify their relative file using the `ArchiveFileID`.
    /// `files_info` and `ids_info` could have been merged into a single `HashMap`
    /// String -> `FileInfo`, at the cost of an additional `HashMap` `ArchiveFileID` ->
    /// String, thus increasing memory footprint.
    /// These hashmaps are actually merged at the last moment, on footer
    /// serialization
    ids_info: HashMap<ArchiveFileID, FileInfo>,
    /// Next file id to use
    next_id: ArchiveFileID,
    /// Current file being written (for continuous block detection)
    current_id: ArchiveFileID,
}

// This is an unstable feature for now (`Vec.remove_item`), use a function
// instead to keep stable compatibility
pub fn vec_remove_item<T: std::cmp::PartialEq>(vec: &mut Vec<T>, item: &T) -> Option<T> {
    let pos = vec.iter().position(|x| *x == *item)?;
    Some(vec.remove(pos))
}

impl<W: InnerWriterTrait> ArchiveWriter<'_, W> {
    pub fn from_config(dest: W, config: ArchiveWriterConfig) -> Result<Self, Error> {
        // Ensure config is correct
        config.check()?;

        // Write archive header
        let mut dest: InnerWriterType<W> = Box::new(RawLayerWriter::new(dest));
        ArchiveHeader {
            format_version: MLA_FORMAT_VERSION,
            config: config.to_persistent()?,
        }
        .dump(&mut dest)?;

        // Enable layers depending on user option
        if config.is_layers_enabled(Layers::ENCRYPT) {
            dest = Box::new(EncryptionLayerWriter::new(dest, &config.encrypt)?);
        }
        if config.is_layers_enabled(Layers::COMPRESS) {
            dest = Box::new(CompressionLayerWriter::new(dest, &config.compress));
        }

        // Upper layer must be a PositionLayer
        let mut final_dest = Box::new(PositionLayerWriter::new(dest));
        final_dest.reset_position();

        // Build initial archive
        Ok(ArchiveWriter {
            config,
            dest: final_dest,
            state: ArchiveWriterState::OpenedFiles {
                ids: Vec::new(),
                hashes: HashMap::new(),
            },
            files_info: HashMap::new(),
            ids_info: HashMap::new(),
            next_id: 0,
            current_id: 0,
        })
    }

    pub fn new(dest: W, public_keys: &[PublicKey]) -> Result<Self, Error> {
        let mut config = ArchiveWriterConfig::default();
        config.add_public_keys(public_keys);
        Self::from_config(dest, config)
    }

    pub fn finalize(&mut self) -> Result<(), Error> {
        // Check final state (empty ids, empty hashes)
        check_state!(self.state, OpenedFiles);
        match &mut self.state {
            ArchiveWriterState::OpenedFiles { ids, hashes } => {
                if !ids.is_empty() || !hashes.is_empty() {
                    return Err(Error::WrongWriterState(
                        "[Finalize] At least one file is still open".to_string(),
                    ));
                }
            }
            ArchiveWriterState::Finalized => {
                // Never happens, due to `check_state!`
                return Err(Error::WrongWriterState(
                    "[Finalize] State have changes inside finalize".to_string(),
                ));
            }
        }
        self.state = ArchiveWriterState::Finalized;

        // Mark the end of the data

        // Use std::io::Empty as a readable placeholder type
        ArchiveFileBlock::EndOfArchiveData::<std::io::Empty> {}.dump(&mut self.dest)?;

        ArchiveFooter::serialize_into(&mut self.dest, &self.files_info, &self.ids_info)?;

        // Recursive call
        self.dest.finalize()?;
        Ok(())
    }

    /// Add the current offset to the corresponding list if the file id is not
    /// the current one, ie. if blocks are not continuous
    fn mark_continuous_block(&mut self, id: ArchiveFileID) -> Result<(), Error> {
        if id != self.current_id {
            let offset = self.dest.position();
            match self.ids_info.get_mut(&id) {
                Some(file_info) => file_info.offsets.push(offset),
                None => {
                    return Err(Error::WrongWriterState(
                        "[mark_continuous_block] Unable to find the ID".to_string(),
                    ));
                }
            }
            self.current_id = id;
        }
        Ok(())
    }

    /// Set the `EoF` offset to the current offset for the corresponding file id
    fn mark_eof(&mut self, id: ArchiveFileID) -> Result<(), Error> {
        let offset = self.dest.position();
        match self.ids_info.get_mut(&id) {
            Some(file_info) => file_info.eof_offset = offset,
            None => {
                return Err(Error::WrongWriterState(
                    "[mark_eof] Unable to find the ID".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Add the current block size to the total size of the corresponding file id
    fn extend_file_size(&mut self, id: ArchiveFileID, block_size: u64) -> Result<(), Error> {
        match self.ids_info.get_mut(&id) {
            Some(file_info) => file_info.size += block_size,
            None => {
                return Err(Error::WrongWriterState(
                    "[extend_file_size] Unable to find the ID".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn start_file(&mut self, filename: &str) -> Result<ArchiveFileID, Error> {
        check_state!(self.state, OpenedFiles);

        if self.files_info.contains_key(filename) {
            return Err(Error::DuplicateFilename);
        }

        // Create ID for this file
        let id = self.next_id;
        self.next_id += 1;
        self.current_id = id;
        self.files_info.insert(filename.to_string(), id);

        // Save the current position
        self.ids_info.insert(
            id,
            FileInfo {
                offsets: vec![self.dest.position()],
                size: 0,
                eof_offset: 0,
            },
        );
        // Use std::io::Empty as a readable placeholder type
        ArchiveFileBlock::FileStart::<std::io::Empty> {
            filename: filename.to_string(),
            id,
        }
        .dump(&mut self.dest)?;

        match &mut self.state {
            ArchiveWriterState::OpenedFiles { ids, hashes } => {
                ids.push(id);
                hashes.insert(id, Sha256::default());
            }
            ArchiveWriterState::Finalized => {
                // Never happens, due to `check_state!`
                return Err(Error::WrongWriterState(
                    "[StartFile] State have changes inside start_file".to_string(),
                ));
            }
        }
        Ok(id)
    }

    pub fn append_file_content<U: Read>(
        &mut self,
        id: ArchiveFileID,
        size: u64,
        src: U,
    ) -> Result<(), Error> {
        check_state_file_opened!(&self.state, &id);

        if size == 0 {
            // Avoid creating 0-sized block
            return Ok(());
        }

        self.mark_continuous_block(id)?;
        self.extend_file_size(id, size)?;
        let src = self.state.wrap_with_hash(id, src)?;

        ArchiveFileBlock::FileContent {
            id,
            length: size,
            data: Some(src),
        }
        .dump(&mut self.dest)
    }

    pub fn end_file(&mut self, id: ArchiveFileID) -> Result<(), Error> {
        check_state_file_opened!(&self.state, &id);

        let hash = match &mut self.state {
            ArchiveWriterState::OpenedFiles { ids, hashes } => {
                let hash = hashes.remove(&id).ok_or_else(|| {
                    Error::WrongWriterState("[EndFile] Unable to retrieve the hash".to_string())
                })?;
                vec_remove_item(ids, &id);
                hash.finalize().into()
            }
            ArchiveWriterState::Finalized => {
                // Never happens, due to `check_state_file_opened!`
                return Err(Error::WrongWriterState(
                    "[EndFile] State have changes inside end_file".to_string(),
                ));
            }
        };

        self.mark_continuous_block(id)?;
        self.mark_eof(id)?;
        // Use std::io::Empty as a readable placeholder type
        ArchiveFileBlock::EndOfFile::<std::io::Empty> { id, hash }.dump(&mut self.dest)?;

        Ok(())
    }

    pub fn add_file<U: Read>(&mut self, filename: &str, size: u64, src: U) -> Result<(), Error> {
        let id = self.start_file(filename)?;
        self.append_file_content(id, size, src)?;
        self.end_file(id)
    }

    /// Unwraps the inner writer
    pub fn into_raw(self) -> W {
        self.dest.into_raw()
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.dest.flush()
    }
}

// -------- Reader --------

#[derive(Debug)]
pub struct ArchiveFile<T: Read> {
    /// File inside a MLA Archive
    pub filename: String,
    pub data: T,
    pub size: u64,
}

#[derive(PartialEq, Debug)]
enum BlocksToFileReaderState {
    // Remaining size
    InFile(usize),
    Ready,
    Finish,
}

#[derive(Debug)]
pub struct BlocksToFileReader<'a, R: Read + Seek> {
    /// This structure wraps the internals to get back a file's content
    src: &'a mut R,
    state: BlocksToFileReaderState,
    /// id of the File being read
    id: ArchiveFileID,
    /// position in `offsets` of the last offset used
    current_offset: usize,
    /// List of offsets of continuous blocks corresponding to where the file can be read
    offsets: &'a [u64],
}

impl<'a, R: Read + Seek> BlocksToFileReader<'a, R> {
    fn new(src: &'a mut R, offsets: &'a [u64]) -> Result<Self, Error> {
        // Set the inner layer at the start of the file
        src.seek(SeekFrom::Start(offsets[0]))?;

        // Read file information header
        let ArchiveFileBlock::FileStart { id, .. } = ArchiveFileBlock::from(src)? else {
            return Err(Error::WrongReaderState(
                "[BlocksToFileReader] A file must start with a FileStart".to_string(),
            ));
        };

        Ok(BlocksToFileReader {
            src,
            state: BlocksToFileReaderState::Ready,
            id,
            current_offset: 0,
            offsets,
        })
    }

    /// Move `self.src` to the next continuous block
    fn move_to_next_block(&mut self) -> Result<(), Error> {
        self.current_offset += 1;
        if self.current_offset >= self.offsets.len() {
            return Err(Error::WrongReaderState(
                "[BlocksToFileReader] No more continuous blocks".to_string(),
            ));
        }
        self.src
            .seek(SeekFrom::Start(self.offsets[self.current_offset]))?;
        Ok(())
    }
}

impl<T: Read + Seek> Read for BlocksToFileReader<'_, T> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let (remaining, count) = match self.state {
            BlocksToFileReaderState::Ready => {
                // Start a new block FileContent
                match ArchiveFileBlock::from(&mut self.src)? {
                    ArchiveFileBlock::FileContent { length, id, .. } => {
                        if id != self.id {
                            self.move_to_next_block()?;
                            return self.read(into);
                        }
                        let count = self.src.by_ref().take(length).read(into)?;
                        let length_usize = usize::try_from(length).map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Length conversion failed",
                            )
                        })?;
                        (length_usize - count, count)
                    }
                    ArchiveFileBlock::EndOfFile { id, .. } => {
                        if id != self.id {
                            self.move_to_next_block()?;
                            return self.read(into);
                        }
                        self.state = BlocksToFileReaderState::Finish;
                        return Ok(0);
                    }
                    ArchiveFileBlock::FileStart { id, .. } => {
                        if id != self.id {
                            self.move_to_next_block()?;
                            return self.read(into);
                        }
                        return Err(Error::WrongReaderState(
                            "[BlocksToFileReader] Start with a wrong block type".to_string(),
                        )
                        .into());
                    }
                    ArchiveFileBlock::EndOfArchiveData => {
                        return Err(Error::WrongReaderState(
                            "[BlocksToFileReader] Try to read the end of the archive".to_string(),
                        )
                        .into());
                    }
                }
            }
            BlocksToFileReaderState::InFile(remaining) => {
                let count = self.src.by_ref().take(remaining as u64).read(into)?;
                (remaining - count, count)
            }
            BlocksToFileReaderState::Finish => {
                return Ok(0);
            }
        };
        if remaining > 0 {
            self.state = BlocksToFileReaderState::InFile(remaining);
        } else {
            // remaining is 0 (> never happens thanks to take)
            self.state = BlocksToFileReaderState::Ready;
        }
        Ok(count)
    }
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct FileInfo {
    /// File information to save in the footer
    ///
    /// Offsets of continuous chunks of `ArchiveFileBlock`
    offsets: Vec<u64>,
    /// Size of the file, in bytes
    pub size: u64,
    /// Offset of the `ArchiveFileBlock::EndOfFile`
    ///
    /// This offset is used to retrieve information from the `EoF` tag, such as
    /// the file hash
    eof_offset: u64,
}

pub struct ArchiveReader<'a, R: 'a + InnerReaderTrait> {
    /// MLA Archive format Reader
    ///
    /// User's reading configuration
    pub config: ArchiveReaderConfig,
    /// Source
    src: Box<dyn 'a + LayerReader<'a, R>>,
    /// Metadata (from footer if any)
    metadata: Option<ArchiveFooter>,
}

impl<'b, R: 'b + InnerReaderTrait> ArchiveReader<'b, R> {
    pub fn from_config(mut src: R, mut config: ArchiveReaderConfig) -> Result<Self, Error> {
        // Make sure we read the archive header from the start
        src.rewind()?;
        let header = ArchiveHeader::from(&mut src)?;
        config.load_persistent(header.config)?;

        // Pin the current position (after header) as the new 0
        let mut raw_src = Box::new(RawLayerReader::new(src));
        raw_src.reset_position()?;

        // Enable layers depending on user option. Order is relevant
        let mut src: Box<dyn 'b + LayerReader<'b, R>> = raw_src;
        if config.layers_enabled.contains(Layers::ENCRYPT) {
            src = Box::new(EncryptionLayerReader::new(src, &config.encrypt)?);
        }
        if config.layers_enabled.contains(Layers::COMPRESS) {
            src = Box::new(CompressionLayerReader::new(src)?);
        }
        src.initialize()?;

        // Read the footer
        let metadata = Some(ArchiveFooter::deserialize_from(&mut src)?);

        // Reset the position for further uses
        src.rewind()?;

        Ok(ArchiveReader {
            config,
            src,
            metadata,
        })
    }

    pub fn new(src: R) -> Result<Self, Error> {
        Self::from_config(src, ArchiveReaderConfig::new())
    }

    /// Return an iterator on filenames present in the archive
    ///
    /// Order is not relevant, and may change
    pub fn list_files(&self) -> Result<impl Iterator<Item = &String>, Error> {
        if let Some(ArchiveFooter { files_info, .. }) = &self.metadata {
            Ok(files_info.keys())
        } else {
            Err(Error::MissingMetadata)
        }
    }

    pub fn get_hash(&mut self, filename: &str) -> Result<Option<Sha256Hash>, Error> {
        if let Some(ArchiveFooter { files_info }) = &self.metadata {
            // Get file relative information
            let file_info = match files_info.get(filename) {
                None => return Ok(None),
                Some(finfo) => finfo,
            };
            // Set the inner layer at the start of the EoF tag
            self.src.seek(SeekFrom::Start(file_info.eof_offset))?;

            // Return the file hash
            match ArchiveFileBlock::from(&mut self.src)? {
                ArchiveFileBlock::EndOfFile { hash, .. } => Ok(Some(hash)),
                _ => Err(Error::WrongReaderState(
                    "[ArchiveReader] eof_offset must point to a EoF".to_string(),
                )),
            }
        } else {
            Err(Error::MissingMetadata)
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn get_file(
        &mut self,
        filename: String,
    ) -> Result<Option<ArchiveFile<BlocksToFileReader<Box<dyn 'b + LayerReader<'b, R>>>>>, Error>
    {
        if let Some(ArchiveFooter { files_info }) = &self.metadata {
            // Get file relative information
            let file_info = match files_info.get(&filename) {
                None => return Ok(None),
                Some(finfo) => finfo,
            };
            if file_info.offsets.is_empty() {
                return Err(Error::WrongReaderState(
                    "[ArchiveReader] A file must have at least one offset".to_string(),
                ));
            }

            // Instantiate the file representation
            let reader = BlocksToFileReader::new(&mut self.src, &file_info.offsets)?;
            Ok(Some(ArchiveFile {
                filename,
                data: reader,
                size: file_info.size,
            }))
        } else {
            Err(Error::MissingMetadata)
        }
    }
}

// This code is very similar with MLAArchiveReader

pub struct ArchiveFailSafeReader<'a, R: 'a + Read> {
    /// MLA Archive format Reader (fail-safe)
    ///
    /// User's reading configuration
    // config is not used for now after reader creation,
    // but it could in the future
    #[allow(dead_code)]
    config: ArchiveReaderConfig,
    /// Source
    src: Box<dyn 'a + LayerFailSafeReader<'a, R>>,
}

// Size of the repaired file blocks
const CACHE_SIZE: usize = 8 * 1024 * 1024; // 8MB

/// Used to update the error state only if it was `NoError`
/// ```text
/// update_error!(error_var, FailSafeReadError::...)
/// ```
macro_rules! update_error {
    ( $x:ident = $y:expr ) => {
        #[allow(clippy::single_match)]
        match $x {
            FailSafeReadError::NoError => {
                $x = $y;
            }
            _ => {}
        }
    };
}

impl<'b, R: 'b + Read> ArchiveFailSafeReader<'b, R> {
    pub fn from_config(mut src: R, mut config: ArchiveReaderConfig) -> Result<Self, Error> {
        let header = ArchiveHeader::from(&mut src)?;
        config.load_persistent(header.config)?;

        // Enable layers depending on user option. Order is relevant
        let mut src: Box<dyn 'b + LayerFailSafeReader<'b, R>> =
            Box::new(RawLayerFailSafeReader::new(src));
        if config.layers_enabled.contains(Layers::ENCRYPT) {
            src = Box::new(EncryptionLayerFailSafeReader::new(src, &config.encrypt)?);
        }
        if config.layers_enabled.contains(Layers::COMPRESS) {
            src = Box::new(CompressionLayerFailSafeReader::new(src)?);
        }

        Ok(Self { config, src })
    }

    pub fn new(src: R) -> Result<Self, Error> {
        Self::from_config(src, ArchiveReaderConfig::new())
    }

    /// Fail-safe / best-effort conversion of the current archive to a correct
    /// one. On success, returns the reason conversion terminates (ideally,
    /// `EndOfOriginalArchiveData`)
    #[allow(clippy::cognitive_complexity)]
    pub fn convert_to_archive<W: InnerWriterTrait>(
        &mut self,
        output: &mut ArchiveWriter<W>,
    ) -> Result<FailSafeReadError, Error> {
        let mut error = FailSafeReadError::NoError;

        // Associate an id retrieved from the archive to repair, to the
        // corresponding output file id
        let mut id_failsafe2id_output: HashMap<ArchiveFileID, ArchiveFileID> = HashMap::new();
        // Associate an id retrieved from the archive to corresponding filename
        let mut id_failsafe2filename: HashMap<ArchiveFileID, String> = HashMap::new();
        // List of IDs from the archive already fully added
        let mut id_failsafe_done = Vec::new();
        // Associate an id retrieved from the archive with its ongoing Hash
        let mut id_failsafe2hash: HashMap<ArchiveFileID, Sha256> = HashMap::new();

        'read_block: loop {
            match ArchiveFileBlock::from(&mut self.src) {
                Err(Error::IOError(err)) => {
                    if err.kind() == std::io::ErrorKind::UnexpectedEof {
                        update_error!(error = FailSafeReadError::UnexpectedEOFOnNextBlock);
                        break;
                    }
                    update_error!(error = FailSafeReadError::IOErrorOnNextBlock(err));
                    break;
                }
                Err(err) => {
                    update_error!(error = FailSafeReadError::ErrorOnNextBlock(err));
                    break;
                }
                Ok(block) => {
                    match block {
                        ArchiveFileBlock::FileStart { filename, id } => {
                            if let Some(_id_output) = id_failsafe2id_output.get(&id) {
                                update_error!(error = FailSafeReadError::ArchiveFileIDReuse(id));
                                break 'read_block;
                            }
                            if id_failsafe_done.contains(&id) {
                                update_error!(
                                    error = FailSafeReadError::ArchiveFileIDAlreadyClose(id)
                                );
                                break 'read_block;
                            }

                            id_failsafe2filename.insert(id, filename.clone());
                            let id_output = match output.start_file(&filename) {
                                Err(Error::DuplicateFilename) => {
                                    update_error!(
                                        error = FailSafeReadError::FilenameReuse(filename)
                                    );
                                    break 'read_block;
                                }
                                Err(err) => {
                                    return Err(err);
                                }
                                Ok(id) => id,
                            };
                            id_failsafe2id_output.insert(id, id_output);
                            id_failsafe2hash.insert(id, Sha256::default());
                        }
                        ArchiveFileBlock::FileContent { length, id, .. } => {
                            let id_output = if let Some(id_output) = id_failsafe2id_output.get(&id)
                            {
                                *id_output
                            } else {
                                update_error!(error = FailSafeReadError::ContentForUnknownFile(id));
                                break 'read_block;
                            };
                            if id_failsafe_done.contains(&id) {
                                update_error!(
                                    error = FailSafeReadError::ArchiveFileIDAlreadyClose(id)
                                );
                                break 'read_block;
                            }
                            let fname = id_failsafe2filename.get(&id).expect(
                                "`id_failsafe2filename` not more sync with `id_failsafe2id_output`",
                            );
                            let hash = id_failsafe2hash.get_mut(&id).expect(
                                "`id_failsafe2hash` not more sync with `id_failsafe2id_output`",
                            );

                            // Limit the reader to at most the file's content
                            let src = &mut (&mut self.src).take(length);

                            // `Read` trait normally garantees that if an error is returned by `.read()`, no data
                            // has been read
                            //
                            // It must then be equivalent to
                            // - call `n` times the API for 1 byte looking for the first fail
                            // - call the API for `n` bytes, possibly returning a first bunch of bytes then a failure
                            //
                            // The second method is used to reduced the calls' count while repairing large files.
                            // Being equivalent to the first method, it should extracts as many bytes as possible
                            // from the potentially broken stream.
                            //
                            // Note: some `Read` implementation does not respect this contract, as it might be
                            // subject to different interpretation

                            // This buffer is used to reduced the resulting file fragmentation by aggregating `read` results
                            let mut buf = vec![0; CACHE_SIZE];
                            'content: loop {
                                let mut next_write_pos = 0;
                                'buf_fill: loop {
                                    match src.read(&mut buf[next_write_pos..]) {
                                        Ok(read) => {
                                            if read == 0 {
                                                // EOF
                                                break 'buf_fill;
                                            }
                                            next_write_pos += read;
                                        }
                                        Err(err) => {
                                            // Stop reconstruction
                                            output.append_file_content(
                                                id_output,
                                                next_write_pos as u64,
                                                &buf[..next_write_pos],
                                            )?;
                                            update_error!(
                                                error = FailSafeReadError::ErrorInFile(
                                                    err,
                                                    fname.clone()
                                                )
                                            );
                                            break 'read_block;
                                        }
                                    }
                                    // Cache full
                                    if next_write_pos >= CACHE_SIZE {
                                        break 'buf_fill;
                                    }
                                }
                                output.append_file_content(
                                    id_output,
                                    next_write_pos as u64,
                                    &buf[..next_write_pos],
                                )?;
                                hash.update(&buf[..next_write_pos]);
                                if next_write_pos < CACHE_SIZE {
                                    // EOF
                                    break 'content;
                                }
                            }
                        }
                        ArchiveFileBlock::EndOfFile { id, hash } => {
                            let id_output = if let Some(id_output) = id_failsafe2id_output.get(&id)
                            {
                                *id_output
                            } else {
                                update_error!(error = FailSafeReadError::EOFForUnknownFile(id));
                                break 'read_block;
                            };
                            if id_failsafe_done.contains(&id) {
                                update_error!(
                                    error = FailSafeReadError::ArchiveFileIDAlreadyClose(id)
                                );
                                break 'read_block;
                            }
                            if let Some(hash_archive) = id_failsafe2hash.remove(&id) {
                                let computed_hash = hash_archive.finalize();
                                if computed_hash.as_slice() != hash {
                                    update_error!(
                                        error = FailSafeReadError::HashDiffers {
                                            expected: Vec::from(computed_hash.as_slice()),
                                            obtained: Vec::from(&hash[..]),
                                        }
                                    );
                                    break 'read_block;
                                }
                            } else {
                                // Synchronisation error
                                update_error!(error = FailSafeReadError::FailSafeReadInternalError);
                                break 'read_block;
                            }

                            output.end_file(id_output)?;
                            id_failsafe_done.push(id);
                        }
                        ArchiveFileBlock::EndOfArchiveData => {
                            // Expected end
                            update_error!(error = FailSafeReadError::EndOfOriginalArchiveData);
                            break 'read_block;
                        }
                    }
                }
            }
        }

        let mut unfinished_files = Vec::new();

        // Clean-up files still opened
        for (id_failsafe, id_output) in id_failsafe2id_output {
            if id_failsafe_done.contains(&id_failsafe) {
                // File is OK
                continue;
            }

            let fname = id_failsafe2filename
                .get(&id_failsafe)
                .expect("`id_failsafe2filename` not more sync with `id_failsafe2id_output`");
            output.end_file(id_output)?;

            unfinished_files.push(fname.clone());
        }

        // Report which files are not completed, if any
        if !unfinished_files.is_empty() {
            error = FailSafeReadError::UnfinishedFiles {
                filenames: unfinished_files,
                stopping_error: Box::new(error),
            };
        }

        output.finalize()?;
        Ok(error)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use curve25519_parser::{parse_openssl_25519_privkey, parse_openssl_25519_pubkey};
    use rand::distr::{Distribution, StandardUniform};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;
    #[cfg(feature = "send")]
    use static_assertions;
    #[cfg(feature = "send")]
    use std::fs::File;
    use std::io::{Cursor, Empty, Read};
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn read_dump_header() {
        let header = ArchiveHeader {
            format_version: MLA_FORMAT_VERSION,
            config: ArchivePersistentConfig {
                layers_enabled: Layers::default(),
                encrypt: None,
            },
        };
        let mut buf = Vec::new();
        header.dump(&mut buf).unwrap();
        println!("{buf:?}");

        let header_rebuild = ArchiveHeader::from(&mut buf.as_slice()).unwrap();
        assert_eq!(header_rebuild.config.layers_enabled, Layers::default());
    }

    #[test]
    fn dump_block() {
        let mut buf = Vec::new();
        let id = 0;
        let hash = Sha256Hash::default();

        // std::io::Empty is used because a type with Read is needed
        ArchiveFileBlock::FileStart::<Empty> {
            id,
            filename: String::from("foobaré.exe"),
        }
        .dump(&mut buf)
        .unwrap();

        let fake_content = vec![1, 2, 3, 4];
        let mut block = ArchiveFileBlock::FileContent {
            id,
            length: fake_content.len() as u64,
            data: Some(fake_content.as_slice()),
        };
        block.dump(&mut buf).unwrap();

        // std::io::Empty is used because a type with Read is needed
        ArchiveFileBlock::EndOfFile::<Empty> { id, hash }
            .dump(&mut buf)
            .unwrap();

        println!("{buf:?}");
    }

    #[test]
    fn blocks_to_file() {
        // Create several blocks
        let mut buf = Vec::new();
        let id = 0;
        let hash = Sha256Hash::default();

        let mut block = ArchiveFileBlock::FileStart::<&[u8]> {
            id,
            filename: String::from("foobar"),
        };
        block.dump(&mut buf).unwrap();
        let fake_content = vec![1, 2, 3, 4];
        let mut block = ArchiveFileBlock::FileContent {
            id,
            length: fake_content.len() as u64,
            data: Some(fake_content.as_slice()),
        };
        block.dump(&mut buf).unwrap();
        let fake_content2 = vec![5, 6, 7, 8];
        let mut block = ArchiveFileBlock::FileContent {
            id,
            length: fake_content2.len() as u64,
            data: Some(fake_content2.as_slice()),
        };
        block.dump(&mut buf).unwrap();

        // std::io::Empty is used because a type with Read is needed
        ArchiveFileBlock::EndOfFile::<Empty> { id, hash }
            .dump(&mut buf)
            .unwrap();

        let mut data_source = std::io::Cursor::new(buf);
        let offsets = [0];
        let mut reader =
            BlocksToFileReader::new(&mut data_source, &offsets).expect("BlockToFileReader failed");
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output.len(), fake_content.len() + fake_content2.len());
        let mut expected_output = Vec::new();
        expected_output.extend(fake_content);
        expected_output.extend(fake_content2);
        assert_eq!(output, expected_output);
        assert_eq!(reader.state, BlocksToFileReaderState::Finish);
    }

    #[test]
    fn new_mla() {
        let file = Vec::new();
        // Use a deterministic RNG in tests, for reproductability. DO NOT DO THIS IS IN ANY RELEASED BINARY!
        let mut rng = ChaChaRng::seed_from_u64(0);
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let key = StaticSecret::from(bytes);
        let mut mla = ArchiveWriter::new(file, std::slice::from_ref(&PublicKey::from(&key)))
            .expect("Writer init failed");

        let fake_file = vec![1, 2, 3, 4];
        mla.add_file("my_file", fake_file.len() as u64, fake_file.as_slice())
            .unwrap();
        let fake_file = vec![5, 6, 7, 8];
        let fake_file2 = vec![9, 10, 11, 12];
        let id = mla.start_file("my_file2").unwrap();
        mla.append_file_content(id, fake_file.len() as u64, fake_file.as_slice())
            .unwrap();
        mla.append_file_content(id, fake_file2.len() as u64, fake_file2.as_slice())
            .unwrap();
        mla.end_file(id).unwrap();
        mla.finalize().unwrap();

        let mla_key = *mla.config.encryption_key();
        let mla_nonce = *mla.config.encryption_nonce();
        let dest = mla.into_raw();
        let buf = Cursor::new(dest.as_slice());
        let mut config = ArchiveReaderConfig::new();
        config.add_private_keys(std::slice::from_ref(&key));
        let mut mla_read = ArchiveReader::from_config(buf, config).unwrap();
        assert_eq!(
            (mla_key, mla_nonce),
            mla_read.config.get_encrypt_parameters().unwrap()
        );

        let mut file = mla_read.get_file("my_file".to_string()).unwrap().unwrap();
        let mut rez = Vec::new();
        file.data.read_to_end(&mut rez).unwrap();
        assert_eq!(rez, vec![1, 2, 3, 4]);
        // Explicit drop here, because otherwise mla_read.get_file() cannot be
        // recall. It is not detected by the NLL analysis
        drop(file);
        let mut file2 = mla_read.get_file("my_file2".to_string()).unwrap().unwrap();
        let mut rez2 = Vec::new();
        file2.data.read_to_end(&mut rez2).unwrap();
        assert_eq!(rez2, vec![5, 6, 7, 8, 9, 10, 11, 12]);
    }

    #[allow(clippy::type_complexity)]
    pub fn build_archive(
        layers: Option<Layers>,
        interleaved: bool,
    ) -> (
        ArchiveWriter<'static, Vec<u8>>,
        StaticSecret,
        Vec<(String, Vec<u8>)>,
    ) {
        // Build an archive with 3 files
        let file = Vec::new();
        // Use a deterministic RNG in tests, for reproductability. DO NOT DO THIS IS IN ANY RELEASED BINARY!
        let mut rng = ChaChaRng::seed_from_u64(0);
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let key = StaticSecret::from(bytes);
        let mut config = ArchiveWriterConfig::new();
        config
            .set_layers(layers.unwrap_or_default())
            .add_public_keys(&[PublicKey::from(&key)]);
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let fname1 = "my_file1".to_string();
        let fname2 = "my_file2".to_string();
        let fname3 = "my_file3".to_string();
        let fake_file_part1 = vec![1, 2, 3];
        let fake_file_part2 = vec![4, 5, 6, 7, 8];
        let mut fake_file1 = Vec::new();
        fake_file1.extend_from_slice(fake_file_part1.as_slice());
        fake_file1.extend_from_slice(fake_file_part2.as_slice());
        let fake_file2 = vec![9, 10, 11, 12];
        let fake_file3 = vec![13, 14, 15];

        if interleaved {
            // Interleaved writes, expected result is:
            // [File1 start]
            // [File1 content 1 2 3]
            // [File2 start]
            // [File2 content 9 10 11 12]
            // [File3 start]
            // [File3 content 13 14 15]
            // [File3 end]
            // [File1 content 4 5 6 7 8]
            // [File1 end]
            // [File2 end]
            let id_file1 = mla.start_file(&fname1).unwrap();
            mla.append_file_content(
                id_file1,
                fake_file_part1.len() as u64,
                fake_file_part1.as_slice(),
            )
            .unwrap();
            let id_file2 = mla.start_file(&fname2).unwrap();
            mla.append_file_content(id_file2, fake_file2.len() as u64, fake_file2.as_slice())
                .unwrap();
            mla.add_file(&fname3, fake_file3.len() as u64, fake_file3.as_slice())
                .unwrap();
            mla.append_file_content(
                id_file1,
                fake_file_part2.len() as u64,
                fake_file_part2.as_slice(),
            )
            .unwrap();
            mla.end_file(id_file1).unwrap();
            mla.end_file(id_file2).unwrap();
        } else {
            mla.add_file(&fname1, fake_file1.len() as u64, fake_file1.as_slice())
                .unwrap();
            mla.add_file(&fname2, fake_file2.len() as u64, fake_file2.as_slice())
                .unwrap();
            mla.add_file(&fname3, fake_file3.len() as u64, fake_file3.as_slice())
                .unwrap();
        }

        mla.finalize().unwrap();

        (
            mla,
            key,
            vec![
                (fname1, fake_file1),
                (fname2, fake_file2),
                (fname3, fake_file3),
            ],
        )
    }

    #[test]
    fn interleaved_files() {
        // Build an archive with 3 interleaved files
        let (mla, key, files) = build_archive(None, true);

        let dest = mla.into_raw();
        let buf = Cursor::new(dest.as_slice());
        let mut config = ArchiveReaderConfig::new();
        config.add_private_keys(std::slice::from_ref(&key));
        let mut mla_read = ArchiveReader::from_config(buf, config).unwrap();

        for (fname, content) in files {
            let mut file = mla_read.get_file(fname).unwrap().unwrap();
            let mut rez = Vec::new();
            file.data.read_to_end(&mut rez).unwrap();
            assert_eq!(rez, content);
        }
    }

    #[test]
    fn mla_multi_layering() {
        // Test the building-then-reading of a file using different layering
        // approach

        // Use a deterministic RNG in tests, for reproductability. DO NOT DO THIS IS IN ANY RELEASED BINARY!
        let mut rng = ChaChaRng::seed_from_u64(0);

        for layering in &[
            Layers::DEBUG,
            Layers::ENCRYPT,
            Layers::COMPRESS,
            Layers::default(),
        ] {
            println!("Layering: {layering:?}");

            // Build initial file in a stream
            let file = Vec::new();
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            let key = StaticSecret::from(bytes);
            let mut config = ArchiveWriterConfig::new();
            config
                .set_layers(*layering)
                .add_public_keys(std::slice::from_ref(&PublicKey::from(&key)));
            let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

            // Write a file in one part
            let fake_file = vec![1, 2, 3, 4];
            mla.add_file("my_file", fake_file.len() as u64, fake_file.as_slice())
                .unwrap();
            // Write a file in multiple part
            let fake_file = vec![5, 6, 7, 8];
            let fake_file2 = vec![9, 10, 11, 12];
            let id = mla.start_file("my_file2").unwrap();
            mla.append_file_content(id, fake_file.len() as u64, fake_file.as_slice())
                .unwrap();
            mla.append_file_content(id, fake_file2.len() as u64, fake_file2.as_slice())
                .unwrap();
            mla.end_file(id).unwrap();
            mla.finalize().unwrap();

            // Read the obtained stream
            let dest = mla.into_raw();
            let buf = Cursor::new(dest.as_slice());
            let mut config = ArchiveReaderConfig::new();
            config.add_private_keys(std::slice::from_ref(&key));
            let mut mla_read = ArchiveReader::from_config(buf, config).unwrap();

            let mut file = mla_read.get_file("my_file".to_string()).unwrap().unwrap();
            let mut rez = Vec::new();
            file.data.read_to_end(&mut rez).unwrap();
            assert_eq!(rez, vec![1, 2, 3, 4]);
            // Explicit drop here, because otherwise mla_read.get_file() cannot be
            // recall. It is not detected by the NLL analysis
            drop(file);
            let mut file2 = mla_read.get_file("my_file2".to_string()).unwrap().unwrap();

            // Read the file in 2 blocks: 6, then 2 bytes (it is made of two 4-bytes block)
            let mut rez2 = [0u8; 6];
            file2.data.read_exact(&mut rez2).unwrap();
            assert_eq!(rez2, [5, 6, 7, 8, 9, 10]);
            let mut rez3 = Vec::new();
            let mut final_rez = Vec::new();
            file2.data.read_to_end(&mut rez3).unwrap();
            final_rez.extend(rez2);
            final_rez.extend(rez3);
            assert_eq!(final_rez, vec![5, 6, 7, 8, 9, 10, 11, 12]);
        }
    }

    #[test]
    fn list_and_read_files() {
        // Build an archive with 3 files
        let (mla, key, files) = build_archive(None, false);

        let dest = mla.into_raw();
        let buf = Cursor::new(dest.as_slice());
        let mut config = ArchiveReaderConfig::new();
        config.add_private_keys(std::slice::from_ref(&key));
        let mut mla_read = ArchiveReader::from_config(buf, config).unwrap();

        // Check the list of files is correct
        let mut sorted_list: Vec<String> = mla_read.list_files().unwrap().cloned().collect();
        sorted_list.sort();
        assert_eq!(
            sorted_list,
            files
                .iter()
                .map(|(x, _y)| x.clone())
                .collect::<Vec<String>>(),
        );

        // Get and check file per file, not in the writing order
        for (fname, content) in files.iter().rev() {
            let mut mla_file = mla_read.get_file(fname.clone()).unwrap().unwrap();
            assert_eq!(mla_file.filename, fname.clone());
            let mut buf = Vec::new();
            mla_file.data.read_to_end(&mut buf).unwrap();
            assert_eq!(&buf, content);
        }
    }

    #[test]
    fn convert_failsafe() {
        // Build an archive with 3 files
        let (mla, key, files) = build_archive(None, false);

        // Prepare the failsafe reader
        let dest = mla.into_raw();
        let mut config = ArchiveReaderConfig::new();
        config.add_private_keys(std::slice::from_ref(&key));
        let mut mla_fsread = ArchiveFailSafeReader::from_config(dest.as_slice(), config).unwrap();

        // Prepare the writer
        let dest_w = Vec::new();
        let mut config = ArchiveWriterConfig::new();
        config
            .enable_layer(Layers::COMPRESS)
            .enable_layer(Layers::ENCRYPT)
            .add_public_keys(&[PublicKey::from(&key)]);
        let mut mla_w = ArchiveWriter::from_config(dest_w, config).expect("Writer init failed");

        // Conversion
        match mla_fsread.convert_to_archive(&mut mla_w).unwrap() {
            FailSafeReadError::EndOfOriginalArchiveData => {
                // We expect to ends with the final tag - all files have been
                // read and we stop on the tag before the footer
            }
            status => {
                panic!("Unexpected status: {status}");
            }
        }

        // New archive can now be checked
        let dest2 = mla_w.into_raw();
        let buf2 = Cursor::new(dest2.as_slice());
        let mut config = ArchiveReaderConfig::new();
        config.add_private_keys(std::slice::from_ref(&key));
        let mut mla_read = ArchiveReader::from_config(buf2, config).unwrap();

        // Check the list of files is correct
        let mut sorted_list: Vec<String> = mla_read.list_files().unwrap().cloned().collect();
        sorted_list.sort();
        assert_eq!(
            sorted_list,
            files
                .iter()
                .map(|(x, _y)| x.clone())
                .collect::<Vec<String>>(),
        );

        // Get and check file per file, not in the writing order
        for (fname, content) in files.iter().rev() {
            let mut mla_file = mla_read.get_file(fname.clone()).unwrap().unwrap();
            assert_eq!(mla_file.filename, fname.clone());
            let mut buf = Vec::new();
            mla_file.data.read_to_end(&mut buf).unwrap();
            assert_eq!(&buf, content);
        }
    }

    #[test]
    fn convert_trunc_failsafe() {
        for interleaved in &[false, true] {
            // Build an archive with 3 files, without compressing to truncate at the correct place
            let (mla, key, files) =
                build_archive(Some(Layers::default() ^ Layers::COMPRESS), *interleaved);
            // Truncate the resulting file (before the footer, hopefully after the header), and prepare the failsafe reader
            let footer_size = usize::try_from(bincode::serialized_size(&mla.files_info).unwrap())
                .expect("Serialized size exceeds usize limit")
                + 4;
            let dest = mla.into_raw();

            for remove in &[1, 10, 30, 50, 70, 95, 100] {
                let mut config = ArchiveReaderConfig::new();
                config.add_private_keys(std::slice::from_ref(&key));
                let mut mla_fsread = ArchiveFailSafeReader::from_config(
                    &dest[..dest.len() - footer_size - remove],
                    config,
                )
                .expect("Unable to create");

                // Prepare the writer
                let dest_w = Vec::new();
                let mut mla_w = ArchiveWriter::new(dest_w, &[PublicKey::from(&key)])
                    .expect("Writer init failed");

                // Conversion
                let _status = mla_fsread.convert_to_archive(&mut mla_w).unwrap();

                // New archive can now be checked
                let dest2 = mla_w.into_raw();
                let buf2 = Cursor::new(dest2.as_slice());
                let mut config = ArchiveReaderConfig::new();
                config.add_private_keys(std::slice::from_ref(&key));
                let mut mla_read = ArchiveReader::from_config(buf2, config).unwrap();

                // Check *the start of* the files list is correct
                let expected = files
                    .iter()
                    .map(|(x, _y)| x.clone())
                    .collect::<Vec<String>>();
                let mut file_list = mla_read
                    .list_files()
                    .unwrap()
                    .cloned()
                    .collect::<Vec<String>>();
                file_list.sort();
                assert_eq!(
                    file_list[..],
                    expected[..file_list.len()],
                    "File lists not equal {} interleaving and {} bytes removed",
                    if *interleaved { "with" } else { "without" },
                    remove
                );

                // Get and check file per file, not in the writing order
                for (fname, content) in files.iter().rev() {
                    // The file may be missing
                    let Some(mut mla_file) = mla_read.get_file(fname.clone()).unwrap() else {
                        continue;
                    };
                    // If the file is present, ensure there are bytes and the first
                    // bytes are the same
                    assert_eq!(mla_file.filename, fname.clone());
                    let mut buf = Vec::new();
                    mla_file.data.read_to_end(&mut buf).unwrap();
                    assert_ne!(
                        buf.len(),
                        0,
                        "Read 0 bytes from subfile {} {} interleaving and {} bytes removed",
                        mla_file.filename,
                        if *interleaved { "with" } else { "without" },
                        remove
                    );
                    assert_eq!(&buf[..], &content[..buf.len()]);
                }
            }
            // /!\ This test doesn't ensure the code is doing the best effort; it only check the result is correct.
        }
    }

    #[test]
    fn avoid_duplicate_filename() {
        let buf = Vec::new();
        let config = ArchiveWriterConfig::new();
        let mut mla = ArchiveWriter::from_config(buf, config).unwrap();
        mla.add_file("Test", 4, vec![1, 2, 3, 4].as_slice())
            .unwrap();
        assert!(
            mla.add_file("Test", 4, vec![1, 2, 3, 4].as_slice())
                .is_err()
        );
        assert!(mla.start_file("Test").is_err());
    }

    #[test]
    fn check_file_size() {
        // Build an archive with 3 non-interleaved files and another with
        // interleaved files
        for interleaved in &[false, true] {
            let (mla, key, files) = build_archive(None, *interleaved);

            for (fname, data) in &files {
                let id = mla.files_info.get(fname).unwrap();
                let size = mla.ids_info.get(id).unwrap().size;
                assert_eq!(size, data.len() as u64);
            }

            let dest = mla.into_raw();
            let buf = Cursor::new(dest.as_slice());
            let mut config = ArchiveReaderConfig::new();
            config.add_private_keys(std::slice::from_ref(&key));
            let mut mla_read = ArchiveReader::from_config(buf, config).unwrap();

            for (fname, data) in &files {
                let mla_file = mla_read.get_file(fname.to_string()).unwrap().unwrap();
                assert_eq!(mla_file.size, data.len() as u64);
            }
        }
    }

    #[test]
    fn failsafe_detect_integrity() {
        // Build an archive with 3 files
        let (mla, _key, files) = build_archive(Some(Layers::DEBUG), false);

        // Swap the first 2 bytes of file1
        let mut dest = mla.into_raw();
        let expect = files[0].1.as_slice();
        let pos: Vec<usize> = dest
            .iter()
            .enumerate()
            .filter_map(|e| {
                if e.0 + expect.len() < dest.len() && &dest[e.0..e.0 + expect.len()] == expect {
                    Some(e.0)
                } else {
                    None
                }
            })
            .collect();
        dest.swap(pos[0], pos[0] + 1);

        // Prepare the failsafe reader
        let mut mla_fsread =
            ArchiveFailSafeReader::from_config(dest.as_slice(), ArchiveReaderConfig::new())
                .unwrap();

        // Prepare the writer
        let dest_w = Vec::new();
        let mut mla_w = ArchiveWriter::from_config(dest_w, ArchiveWriterConfig::new())
            .expect("Writer init failed");

        // Conversion
        match mla_fsread.convert_to_archive(&mut mla_w).unwrap() {
            FailSafeReadError::UnfinishedFiles {
                filenames,
                stopping_error,
            } => {
                // We expect to ends with a HashDiffers on first file
                assert_eq!(filenames, vec![files[0].0.to_string()]);
                match *stopping_error {
                    FailSafeReadError::HashDiffers { .. } => {}
                    _ => {
                        panic!("Unexpected stopping_error: {stopping_error}");
                    }
                }
            }
            status => {
                panic!("Unexpected status: {status}");
            }
        }
    }

    #[test]
    fn get_hash() {
        // Build an archive with 3 files
        let (mla, key, files) = build_archive(None, false);

        // Prepare the reader
        let dest = mla.into_raw();
        let buf = Cursor::new(dest.as_slice());
        let mut config = ArchiveReaderConfig::new();
        config.add_private_keys(std::slice::from_ref(&key));
        let mut mla_read = ArchiveReader::from_config(buf, config).unwrap();

        // Get hashes and compare
        for (filename, content) in files {
            let hash = mla_read.get_hash(&filename).unwrap().unwrap();

            let mut hasher = Sha256::new();
            hasher.update(content);
            let result = hasher.finalize();
            assert_eq!(result.as_slice(), hash);
        }
    }

    fn make_format_regression_files() -> HashMap<String, Vec<u8>> {
        // Build files easily scriptables and checkable
        let mut files: HashMap<String, Vec<u8>> = HashMap::new();

        // One simple file
        let mut simple: Vec<u8> = Vec::new();
        for i in 0..=255 {
            simple.push(i);
        }
        let pattern = simple.clone();
        files.insert("simple".to_string(), simple);

        // One big file (10 MB)
        let big: Vec<u8> = pattern
            .iter()
            .cycle()
            .take(10 * 1024 * 1024)
            .copied()
            .collect();
        files.insert("big".to_string(), big);

        // Some constant files
        for i in 0..=255 {
            files.insert(
                format!("file_{i}").to_string(),
                std::iter::repeat_n(i, 0x1000).collect::<Vec<u8>>(),
            );
        }

        // sha256 sum of them
        let mut sha256sum: Vec<u8> = Vec::new();
        let mut info: Vec<(&String, &Vec<_>)> = files.iter().collect();
        info.sort_by(|i1, i2| Ord::cmp(&i1.0, &i2.0));
        for (fname, content) in &info {
            let mut hasher = Sha256::new();
            hasher.update(content);
            sha256sum.extend_from_slice(hex::encode(hasher.finalize()).as_bytes());
            sha256sum.push(0x20);
            sha256sum.push(0x20);
            sha256sum.extend(fname.as_bytes());
            sha256sum.push(0x0a);
        }
        files.insert("sha256sum".to_string(), sha256sum);
        files
    }

    #[test]
    fn create_archive_format_version() {
        // Build an archive to be committed, for format regression
        let file = Vec::new();

        // Use committed keys
        let pem_pub: &'static [u8] = include_bytes!("../../samples/test_x25519_archive_v1_pub.pem");
        let pub_key = parse_openssl_25519_pubkey(pem_pub).unwrap();

        let mut config = ArchiveWriterConfig::new();
        config
            .set_layers(Layers::default())
            .add_public_keys(&[pub_key]);
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let files = make_format_regression_files();
        // First, add a simple file
        let fname_simple = "simple".to_string();
        mla.add_file(
            &fname_simple,
            files.get(&fname_simple).unwrap().len() as u64,
            files.get(&fname_simple).unwrap().as_slice(),
        )
        .unwrap();

        // Second, add interleaved files
        let fnames: Vec<String> = (0..=255).map(|i| format!("file_{i}")).collect();
        let mut name2id: HashMap<_, _> = HashMap::new();

        // Start files in normal order
        (0..=255)
            .map(|i| {
                let id = mla.start_file(&fnames[i]).unwrap();
                name2id.insert(&fnames[i], id);
            })
            .for_each(drop);

        // Add some parts in reverse order
        (0..=255)
            .rev()
            .map(|i| {
                let id = name2id.get(&fnames[i]).unwrap();
                mla.append_file_content(*id, 32, &files.get(&fnames[i]).unwrap()[..32])
                    .unwrap();
            })
            .for_each(drop);

        // Add the rest of files in normal order
        (0..=255)
            .map(|i| {
                let id = name2id.get(&fnames[i]).unwrap();
                let data = &files.get(&fnames[i]).unwrap()[32..];
                mla.append_file_content(*id, data.len() as u64, data)
                    .unwrap();
            })
            .for_each(drop);

        // Finish files in reverse order
        (0..=255)
            .rev()
            .map(|i| {
                let id = name2id.get(&fnames[i]).unwrap();
                mla.end_file(*id).unwrap();
            })
            .for_each(drop);

        // Add a big file
        let fname_big = "big".to_string();
        mla.add_file(
            &fname_big,
            files.get(&fname_big).unwrap().len() as u64,
            files.get(&fname_big).unwrap().as_slice(),
        )
        .unwrap();

        // Add sha256sum file
        let fname_sha256sum = "sha256sum".to_string();
        mla.add_file(
            &fname_sha256sum,
            files.get(&fname_sha256sum).unwrap().len() as u64,
            files.get(&fname_sha256sum).unwrap().as_slice(),
        )
        .unwrap();
        mla.finalize().unwrap();

        // UNCOMMENT THESE LINES TO UPDATE THE FILE
        // UPDATE THE VERSION NUMBER
        /*
        std::fs::File::create(std::path::Path::new(&format!(
            "../samples/archive_v{}.mla",
            MLA_FORMAT_VERSION
        )))
        .unwrap()
        .write(&mla.into_raw())
        .unwrap();
         */
    }

    #[test]
    fn check_archive_format_v1() {
        let pem_priv: &'static [u8] = include_bytes!("../../samples/test_x25519_archive_v1.pem");

        let mla_data: &'static [u8] = include_bytes!("../../samples/archive_v1.mla");
        let files = make_format_regression_files();

        // Build Reader
        let buf = Cursor::new(mla_data);
        let mut config = ArchiveReaderConfig::new();
        config.add_private_keys(&[parse_openssl_25519_privkey(pem_priv).unwrap()]);
        let mut mla_read = ArchiveReader::from_config(buf, config).unwrap();

        // Build FailSafeReader
        let mut config = ArchiveReaderConfig::new();
        config.add_private_keys(&[parse_openssl_25519_privkey(pem_priv).unwrap()]);
        let mut mla_fsread = ArchiveFailSafeReader::from_config(mla_data, config).unwrap();

        // Repair the archive (without any damage, but trigger the corresponding code)
        let dest_w = Vec::new();
        let mut mla_w = ArchiveWriter::from_config(dest_w, ArchiveWriterConfig::new())
            .expect("Writer init failed");
        if matches!(
            mla_fsread.convert_to_archive(&mut mla_w).unwrap(),
            FailSafeReadError::EndOfOriginalArchiveData
        ) {
            // Everything runs as expected
        } else {
            panic!();
        }
        // Get a reader on the repaired archive
        let buf2 = Cursor::new(mla_w.into_raw());
        let mut mla_repread = ArchiveReader::from_config(buf2, ArchiveReaderConfig::new()).unwrap();

        assert_eq!(files.len(), mla_read.list_files().unwrap().count());
        assert_eq!(files.len(), mla_repread.list_files().unwrap().count());

        // Get and check file per file
        for (fname, content) in &files {
            let mut mla_file = mla_read.get_file(fname.clone()).unwrap().unwrap();
            let mut mla_rep_file = mla_repread.get_file(fname.clone()).unwrap().unwrap();
            assert_eq!(mla_file.filename, fname.clone());
            assert_eq!(mla_rep_file.filename, fname.clone());
            let mut buf = Vec::new();
            mla_file.data.read_to_end(&mut buf).unwrap();
            assert_eq!(buf.as_slice(), content.as_slice());
            let mut buf = Vec::new();
            mla_rep_file.data.read_to_end(&mut buf).unwrap();
            assert_eq!(buf.as_slice(), content.as_slice());
        }
    }

    #[test]
    fn empty_blocks() {
        // Add a file with containning an empty block - it should works
        let file = Vec::new();
        let mut mla = ArchiveWriter::from_config(file, ArchiveWriterConfig::new())
            .expect("Writer init failed");

        let fname = "my_file".to_string();
        let fake_file = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let id = mla.start_file(&fname).expect("start_file");
        mla.append_file_content(id, 4, &fake_file[..4])
            .expect("add content");
        mla.append_file_content(id, 0, &fake_file[..1])
            .expect("add content empty");
        mla.append_file_content(id, fake_file.len() as u64 - 4, &fake_file[4..])
            .expect("add rest");
        mla.end_file(id).unwrap();

        mla.finalize().unwrap();
        let mla_data = mla.into_raw();

        let buf = Cursor::new(mla_data);
        let mut mla_read =
            ArchiveReader::from_config(buf, ArchiveReaderConfig::new()).expect("archive reader");
        let mut out = Vec::new();
        mla_read
            .get_file(fname)
            .unwrap()
            .unwrap()
            .data
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out.as_slice(), fake_file.as_slice());
    }

    #[test]
    #[ignore]
    fn more_than_u32_file() {
        const MORE_THAN_U32: u64 = 0x0001_0001_0000; // U32_max + 0x10000
        const MAX_SIZE: u64 = 5 * 1024 * 1024 * 1024; // 5 GB
        const CHUNK_SIZE: usize = 10 * 1024 * 1024; // 10 MB

        // Use a deterministic RNG in tests, for reproductability. DO NOT DO THIS IS IN ANY RELEASED BINARY!
        let mut rng = ChaChaRng::seed_from_u64(0);
        let mut rng_data = ChaChaRng::seed_from_u64(0);

        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let key = StaticSecret::from(bytes);
        let mut config = ArchiveWriterConfig::default();
        config.add_public_keys(std::slice::from_ref(&PublicKey::from(&key)));
        let file = Vec::new();
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        // At least one file will be bigger than 32bits
        let id1 = mla.start_file("file_0").unwrap();
        let mut cur_size = 0;
        while cur_size < MORE_THAN_U32 {
            let size = std::cmp::min(u64::from(rng.next_u32()), MORE_THAN_U32 - cur_size);
            let data: Vec<u8> = StandardUniform
                .sample_iter(&mut rng_data)
                .take(usize::try_from(size).expect("Failed to convert size to usize"))
                .collect();
            mla.append_file_content(id1, size, data.as_slice()).unwrap();
            cur_size += size;
        }
        mla.end_file(id1).unwrap();

        let mut nb_file = 1;

        // Complete up to MAX_SIZE
        while cur_size < MAX_SIZE {
            let id = mla.start_file(format!("file_{nb_file:}").as_str()).unwrap();
            let size = std::cmp::min(u64::from(rng.next_u32()), MAX_SIZE - cur_size);
            let data: Vec<u8> = StandardUniform
                .sample_iter(&mut rng_data)
                .take(usize::try_from(size).expect("Failed to convert size to usize"))
                .collect();
            mla.append_file_content(id, size, data.as_slice()).unwrap();
            cur_size += size;
            mla.end_file(id).unwrap();
            nb_file += 1;
        }
        mla.finalize().unwrap();

        // List files and check the list
        let mla_data = mla.into_raw();

        let buf = Cursor::new(mla_data);
        let mut config = ArchiveReaderConfig::new();
        config.add_private_keys(&[key]);
        let mut mla_read = ArchiveReader::from_config(buf, config).expect("archive reader");

        let file_names: Vec<String> = (0..nb_file).map(|nb| format!("file_{nb:}")).collect();
        let mut file_list = mla_read
            .list_files()
            .unwrap()
            .cloned()
            .collect::<Vec<String>>();
        file_list.sort();
        assert_eq!(file_list, file_names);

        // Check files content

        // Using the same seed than the one used for data creation, we can compare expected content
        let mut rng_data = ChaChaRng::seed_from_u64(0);

        let mut chunk = vec![0u8; CHUNK_SIZE];
        for file_name in file_names {
            let mut file_stream = mla_read.get_file(file_name).unwrap().unwrap().data;
            loop {
                let read = file_stream.read(&mut chunk).unwrap();
                let expect: Vec<u8> = StandardUniform
                    .sample_iter(&mut rng_data)
                    .take(read)
                    .collect();
                assert_eq!(&chunk[..read], expect.as_slice());
                if read == 0 {
                    break;
                }
            }
        }
    }

    #[test]
    #[cfg(feature = "send")]
    fn test_send() {
        static_assertions::assert_cfg!(feature = "send");
        static_assertions::assert_impl_all!(File: Send);
        static_assertions::assert_impl_all!(ArchiveWriter<File>: Send);
        static_assertions::assert_impl_all!(ArchiveReader<File>: Send);
    }
}
