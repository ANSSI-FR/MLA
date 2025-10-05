use std::io::{self, Read, Seek, SeekFrom, Take, Write};
use std::{cmp, fmt};

use bincode::Options;
use brotli::BrotliState;
use brotli::writer::StandardAlloc;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use crate::layers::traits::{
    InnerWriterTrait, InnerWriterType, LayerFailSafeReader, LayerReader, LayerWriter,
};
use crate::{BINCODE_MAX_DESERIALIZE, Error};

use crate::config::{ArchiveWriterConfig, ConfigResult};
use crate::errors::ConfigError;

use super::traits::InnerReaderTrait;

// ---------- Config ----------

/// A bigger value means a better compression ratio, less indexes to save (in
/// memory), but also a slower random access. In the worst case, an access may
/// implies decompressing a whole block to obtain just the last byte.
///
/// According to benchmarking on compression of representative data, 4MB seems
/// to be a good choice
const UNCOMPRESSED_DATA_SIZE: u32 = 4 * 1024 * 1024;

/// A bigger value means a better compression ratio, but a slower compression
///
/// According to benchmarking on compression of representative data, level 5
/// seems to be a good choice
const DEFAULT_COMPRESSION_LEVEL: u32 = 5;

/// Default value which seems advised by brotli libraries
const BROTLI_LOG_WINDOW: u32 = 22;

pub struct CompressionConfig {
    compression_level: u32,
}

impl std::default::Default for CompressionConfig {
    fn default() -> Self {
        Self {
            compression_level: DEFAULT_COMPRESSION_LEVEL,
        }
    }
}

impl ArchiveWriterConfig {
    /// Set the compression level
    /// compression level (0-11); bigger values cause denser, but slower compression
    pub const fn with_compression_level(&mut self, compression_level: u32) -> ConfigResult<'_> {
        if compression_level > 11 {
            Err(ConfigError::CompressionLevelOutOfRange)
        } else {
            self.compress.compression_level = compression_level;
            Ok(self)
        }
    }
}

// ---------- Reader ----------

/// See `CompressionLayerWriter` for more information
enum CompressionLayerReaderState<R: Read> {
    /// Ready contains the real inner destination
    Ready(R),
    /// How many uncompressed bytes have already been read for the current
    /// block
    InData {
        read: u32,
        uncompressed_size: u32,
        /// Use a Box to avoid a too big enum
        /// Use a `Take` to instanciate the `Decompressor` only on the current block's compressed bytes
        decompressor: Box<brotli::Decompressor<Take<R>>>,
    },
    /// Empty is a placeholder to allow state replacement
    Empty,
}

impl<R: Read> fmt::Debug for CompressionLayerReaderState<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready(_inner) => write!(f, "Ready"),
            Self::InData { .. } => write!(f, "InData"),
            Self::Empty => write!(f, "Empty"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SizesInfo {
    /// Ordered list of chunk compressed size; only set at init
    pub compressed_sizes: Vec<u32>,
    /// Last block uncompressed size
    last_block_size: u32,
}

impl SizesInfo {
    /// Get the uncompressed block size of block `block_num`
    const fn uncompressed_block_size_at(&self, block_num: usize) -> u32 {
        if block_num < self.compressed_sizes.len() - 1 {
            UNCOMPRESSED_DATA_SIZE
        } else {
            self.last_block_size
        }
    }

    /// Get the compressed block at position `uncompressed_pos`
    fn compressed_block_size_at(&self, uncompressed_pos: u64) -> Result<u32, Error> {
        let block_num = uncompressed_pos / u64::from(UNCOMPRESSED_DATA_SIZE);
        let index = usize::try_from(block_num)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Integer conversion failed"))?;
        Ok(self.compressed_sizes[index])
    }

    /// Maximum uncompressed available position
    fn max_uncompressed_pos(&self) -> u64 {
        (self.compressed_sizes.len() as u64 - 1) * u64::from(UNCOMPRESSED_DATA_SIZE)
            + u64::from(self.last_block_size)
    }

    // Sum the compressed_sizes
    pub fn get_compressed_size(&self) -> u64 {
        self.compressed_sizes.iter().map(|v| u64::from(*v)).sum()
    }
}

pub struct CompressionLayerReader<'a, R: 'a + Read> {
    state: CompressionLayerReaderState<Box<dyn 'a + LayerReader<'a, R>>>,
    pub sizes_info: Option<SizesInfo>,
    /// Position in the under-layer (uncompressed stream)
    // /!\ Due to the decompressor having a block size of the compressed size,
    // any read on it may forward the inner layer to the beginning of the next
    // block
    //
    // [compressed block][compressed block]
    //      ^            ^
    //      |            The inner layer is here
    //      We're actually here
    //
    // Additionnaly, the `brotli` implementation may consume more or less bytes
    // than presumed. For instance, the compression may dump n bytes, while the
    // decompressor is able to recover the decompressed part with only n -
    // epsilon bytes.
    //
    // As a result, `underlayer_pos` and `inner` position
    // corrected with `sizes_info` may seems unsync; `underlayer_pos` is the one
    // to trust.
    underlayer_pos: u64,
}

impl<R: Read> CompressionLayerReaderState<R> {
    fn into_inner(self) -> R {
        match self {
            Self::Ready(inner) => inner,
            Self::InData { decompressor, .. } => decompressor.into_inner().into_inner(),
            // `panic!` explicitly called to avoid propagating an error which
            // must never happens (ie, calling `into_inner` in an inconsistent
            // internal state)
            Self::Empty => panic!("[Reader] Empty type to inner is impossible"),
        }
    }
}

impl<'a, R: 'a + Read> CompressionLayerReader<'a, R> {
    pub fn new(mut inner: Box<dyn 'a + LayerReader<'a, R>>) -> Result<Self, Error> {
        let underlayer_pos = inner.stream_position()?;
        Ok(Self {
            state: CompressionLayerReaderState::Ready(inner),
            sizes_info: None,
            underlayer_pos,
        })
    }

    /// Returns whether `uncompressed_pos` is in the data stream
    /// If no index is used, always return `true`
    fn pos_in_stream(&self, uncompressed_pos: u64) -> bool {
        self.sizes_info
            .as_ref()
            .is_none_or(|sizes_info| uncompressed_pos < sizes_info.max_uncompressed_pos())
    }

    /// Instantiate a new decompressor at position `uncompressed_pos`
    /// `uncompressed_pos` must be a compressed block's starting position
    fn new_decompressor_at<S: Read + Seek>(
        &self,
        inner: S,
        uncompressed_pos: u64,
    ) -> Result<brotli::Decompressor<Take<S>>, Error> {
        // Ensure it's a starting position
        if !uncompressed_pos.is_multiple_of(u64::from(UNCOMPRESSED_DATA_SIZE)) {
            return Err(Error::BadAPIArgument(
                "[new_decompressor_at] not a starting position".to_string(),
            ));
        }

        // Check we are still in the stream
        if !self.pos_in_stream(uncompressed_pos) {
            // No more in the compressed stream -> nothing to read
            return Err(Error::EndOfStream);
        }

        match &self.sizes_info {
            Some(sizes_info) => {
                // Use index for faster decompression
                let compressed_block_size =
                    sizes_info.compressed_block_size_at(uncompressed_pos)? as usize;
                Ok(brotli::Decompressor::new(
                    // Make the Decompressor work only on the compressed block's bytes, no more
                    inner.take(compressed_block_size as u64),
                    compressed_block_size,
                ))
            }
            None => Err(Error::MissingMetadata),
        }
    }

    // TODO add regression test
    /// Get the uncompressed block size at position `uncompressed_pos`
    /// `uncompressed_pos` must be a compressed block's starting position
    fn uncompressed_block_size_at(&self, uncompressed_pos: u64) -> Result<u32, Error> {
        // Ensure it's a starting position
        if !uncompressed_pos.is_multiple_of(u64::from(UNCOMPRESSED_DATA_SIZE)) {
            return Err(Error::BadAPIArgument(
                "[uncompressed_block_size_at] not a starting position".to_string(),
            ));
        }

        // Check we are still in the stream
        if !self.pos_in_stream(uncompressed_pos) {
            // No more in the compressed stream -> nothing to read
            return Err(Error::EndOfStream);
        }

        match &self.sizes_info {
            Some(sizes_info) => {
                // Use index for faster decompression

                // Get the uncompressed block size
                let block_num = uncompressed_pos / u64::from(UNCOMPRESSED_DATA_SIZE);
                Ok(
                    sizes_info.uncompressed_block_size_at(usize::try_from(block_num).map_err(
                        |_| io::Error::new(io::ErrorKind::InvalidData, "Integer conversion failed"),
                    )?),
                )
            }
            None => Err(Error::MissingMetadata),
        }
    }

    // TODO add regression test
    /// Resynchronize the inner layer with `uncompressed_pos` (ie., seek inner with expected position)
    /// `uncompressed_pos` must be a compressed block's starting position
    fn sync_inner_with_uncompressed_pos<S: Read + Seek>(
        &self,
        inner: &mut S,
        uncompressed_pos: u64,
    ) -> Result<(), Error> {
        // Ensure it's a starting position
        if !uncompressed_pos.is_multiple_of(u64::from(UNCOMPRESSED_DATA_SIZE)) {
            return Err(Error::BadAPIArgument(
                "[sync_inner_with_uncompressed_pos] not a starting position".to_string(),
            ));
        }

        // Check we are still in the stream
        if !self.pos_in_stream(uncompressed_pos) {
            // No more in the compressed stream -> nothing to read
            return Err(Error::EndOfStream);
        }

        // Find the right block
        let block_num = uncompressed_pos / u64::from(UNCOMPRESSED_DATA_SIZE);
        match &self.sizes_info {
            Some(SizesInfo {
                compressed_sizes, ..
            }) => {
                // Move the underlayer at the start of the block
                let start_position = compressed_sizes
                    .iter()
                    .take(usize::try_from(block_num).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Integer conversion failed")
                    })?)
                    .map(|size| u64::from(*size))
                    .sum();
                inner.seek(SeekFrom::Start(start_position))?;
            }
            None => {
                return Err(Error::MissingMetadata);
            }
        }
        Ok(())
    }
}

impl<'a, R: 'a + InnerReaderTrait> LayerReader<'a, R> for CompressionLayerReader<'a, R> {
    fn into_inner(self) -> Option<Box<dyn 'a + LayerReader<'a, R>>> {
        Some(self.state.into_inner())
    }

    fn into_raw(self: Box<Self>) -> R {
        self.state.into_inner().into_raw()
    }

    fn initialize(&mut self) -> Result<(), Error> {
        match &mut self.state {
            CompressionLayerReaderState::Ready(inner) => {
                // Recursive call
                inner.initialize()?;

                // Read the footer: [SizesInfo][SizesInfo length, on 4 bytes]
                let pos = inner.seek(SeekFrom::End(-4))?;
                let len = u64::from(inner.read_u32::<LittleEndian>()?);

                // Read SizesInfo
                inner.seek(SeekFrom::Start(pos - len))?;
                self.sizes_info = match bincode::options()
                    .with_limit(BINCODE_MAX_DESERIALIZE)
                    .with_fixint_encoding()
                    .deserialize_from(inner.take(len))
                {
                    Ok(sinfo) => Some(sinfo),
                    _ => {
                        return Err(Error::DeserializationError);
                    }
                };

                Ok(())
            }
            _ => {
                // At init, should not be in this state
                Err(Error::WrongReaderState(
                    "[Compression Layer]: on initialization, must be in Ready state".to_string(),
                ))
            }
        }
    }
}

impl<'a, R: 'a + Read + Seek> Read for CompressionLayerReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.pos_in_stream(self.underlayer_pos) {
            // No more in the compressed stream -> nothing to read
            return Ok(0);
        }

        // Use this mem::replace trick to be able to get back the compressor
        // inner and freely move from CompressionLayerReaderState to others
        let old_state = std::mem::replace(&mut self.state, CompressionLayerReaderState::Empty);
        match old_state {
            CompressionLayerReaderState::Ready(mut inner) => {
                self.sync_inner_with_uncompressed_pos(&mut inner, self.underlayer_pos)?;
                let decompressor = Box::new(self.new_decompressor_at(inner, self.underlayer_pos)?);
                let uncompressed_size = self.uncompressed_block_size_at(self.underlayer_pos)?;
                self.state = CompressionLayerReaderState::InData {
                    read: 0,
                    uncompressed_size,
                    decompressor,
                };
                self.read(buf)
            }
            CompressionLayerReaderState::InData {
                read,
                uncompressed_size,
                mut decompressor,
            } => {
                if read > uncompressed_size {
                    return Err(Error::WrongReaderState(
                        "[Compression Layer] Too much data read".to_string(),
                    )
                    .into());
                }
                if read == uncompressed_size {
                    self.state =
                        CompressionLayerReaderState::Ready(decompressor.into_inner().into_inner());
                    // Start a new block, fill it with new values!
                    return self.read(buf);
                }
                let size = std::cmp::min((uncompressed_size - read) as usize, buf.len());
                let read_add = decompressor.read(&mut buf[..size])?;
                self.underlayer_pos += read_add as u64;
                self.state = CompressionLayerReaderState::InData {
                    read: read
                        + u32::try_from(read_add).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "Integer conversion failed")
                        })?,
                    uncompressed_size,
                    decompressor,
                };
                Ok(read_add)
            }
            CompressionLayerReaderState::Empty => Err(Error::WrongReaderState(
                "[Compression Layer] Should never happens, unless an error already occurs before"
                    .to_string(),
            )
            .into()),
        }
    }
}

impl<R: Read + Seek> Seek for CompressionLayerReader<'_, R> {
    /// Seek to the position `pos` in the uncompressed stream
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Seeking may instantiate a decompressor, and therefore position the
        // inner layer at the end of the asked position's compressed block
        match &self.sizes_info {
            Some(_sizes_info) => {
                match pos {
                    SeekFrom::Start(pos) => {
                        // Find the right block
                        let inside_block = pos % u64::from(UNCOMPRESSED_DATA_SIZE);
                        let rounded_pos = pos - inside_block;

                        // Move the underlayer at the start of the block
                        let old_state =
                            std::mem::replace(&mut self.state, CompressionLayerReaderState::Empty);
                        let mut inner = old_state.into_inner();
                        self.sync_inner_with_uncompressed_pos(&mut inner, rounded_pos)?;

                        // New decompressor at the start of the block
                        let mut decompressor = self.new_decompressor_at(inner, rounded_pos)?;
                        let uncompressed_size = self.uncompressed_block_size_at(rounded_pos)?;

                        // Move forward inside the block to reach the expected position
                        io::copy(&mut (&mut decompressor).take(inside_block), &mut io::sink())?;
                        self.state = CompressionLayerReaderState::InData {
                            read: u32::try_from(inside_block).map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "Integer conversion failed",
                                )
                            })?,
                            uncompressed_size,
                            decompressor: Box::new(decompressor),
                        };
                        self.underlayer_pos = pos;
                        Ok(pos)
                    }
                    SeekFrom::Current(pos) => {
                        // Get the position and do nothing
                        if pos == 0 {
                            Ok(self.underlayer_pos)
                        } else if let Ok(pos_i64) = i64::try_from(self.underlayer_pos) {
                            let new_pos = pos + pos_i64;
                            if new_pos >= 0 {
                                self.seek(SeekFrom::Start(u64::try_from(new_pos).map_err(
                                    |_| {
                                        io::Error::new(
                                            io::ErrorKind::InvalidInput,
                                            "Resulting position is negative",
                                        )
                                    },
                                )?))
                            } else {
                                Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "Resulting position is negative",
                                ))
                            }
                        } else {
                            Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "Invalid underlayer_pos value",
                            ))
                        }

                        // TODO: Possible optimization:
                        // - if pos is positive and inside the current block,
                        // just advance the decompressor
                    }
                    SeekFrom::End(pos) => {
                        if pos > 0 {
                            // Seeking past the end is unsupported
                            return Err(Error::EndOfStream.into());
                        }

                        let end_pos = self.sizes_info.as_ref().unwrap().max_uncompressed_pos();
                        let distance_from_end = -pos;
                        if distance_from_end >= 0 {
                            self.seek(SeekFrom::Start(
                                end_pos
                                    - u64::try_from(distance_from_end).map_err(|_| {
                                        io::Error::new(
                                            io::ErrorKind::InvalidInput,
                                            "Invalid distance_from_end value",
                                        )
                                    })?,
                            ))
                        } else {
                            Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "Negative seek offset",
                            ))
                        }
                    }
                }
            }
            None => Err(Error::MissingMetadata.into()),
        }
    }
}

// ---------- Writer ----------

/// Wrap a Writer with counting of written bytes
struct WriterWithCount<W: Write> {
    inner: W,
    pos: u32,
}

impl<W: Write> WriterWithCount<W> {
    const fn new(inner: W) -> Self {
        Self { inner, pos: 0 }
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for WriterWithCount<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf).inspect(|&i| {
            match u32::try_from(i) {
                Ok(value) => self.pos += value,
                Err(_) => {
                    // Handle the error explicitly
                    let _ = io::Error::new(io::ErrorKind::InvalidData, "Integer conversion failed");
                }
            }
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

enum CompressionLayerWriterState<W: Write> {
    /// Ready contains the real inner destination
    Ready(W),
    /// How many uncompressed bytes have already been written for the current
    /// block
    // Use a Box to avoid a too big enum
    InData(u32, Box<brotli::CompressorWriter<WriterWithCount<W>>>),
    /// Empty is a placeholder to allow state replacement
    Empty,
}

/// Compression layer is made of independent `CompressedBlock`, ending by an index for seekable accesses
/// `[CompressedBlock][CompressedBlock]`...`[CompressedBlock][Index]`
///
/// Compression is made of nested independent compressed block of a fixed
/// uncompressed size
///
/// Pro:
/// * no need to store the compressed size
/// * compression can be streamed (storing the compressed size before the
///   compressed block leads to either seekable stream, which is not an option
///   here, or full-memory compression before actual write, which add limits to
///   the memory footprint)
///
/// Cons:
/// * if the index is lost, a slow decompression with a block size of 1 is
///   needed to found the `CompressedBlock` boundaries
pub struct CompressionLayerWriter<'a, W: 'a + InnerWriterTrait> {
    state: CompressionLayerWriterState<InnerWriterType<'a, W>>,
    /// Ordered list of compressed size of block of `UNCOMPRESSED_DATA_SIZE`
    /// bytes
    //
    /// Thus, accessing the `n`th byte in the sublayer, is accessing the `n %
    /// C`th uncompressed byte in the chunk beginning at `sum(compressed_sizes[:n
    /// / C])`, with `C = UNCOMPRESSED_DATA_SIZE`
    compressed_sizes: Vec<u32>,
    // From config
    compression_level: u32,
}

impl<W: InnerWriterTrait> CompressionLayerWriterState<W> {
    fn into_inner(self) -> W {
        match self {
            Self::Ready(inner) => inner,
            Self::InData(_written, compress) => compress.into_inner().into_inner(),
            // `panic!` explicitly called to avoid propagating an error which
            // must never happens (ie, calling `into_inner` in an inconsistent
            // internal state)
            Self::Empty => panic!("[Writer] Empty type to inner is impossible"),
        }
    }
}

impl<'a, W: 'a + InnerWriterTrait> CompressionLayerWriter<'a, W> {
    pub fn new(inner: InnerWriterType<'a, W>, config: &CompressionConfig) -> Self {
        Self {
            state: CompressionLayerWriterState::Ready(inner),
            compressed_sizes: Vec::new(),
            compression_level: config.compression_level,
        }
    }
}

impl<'a, W: 'a + InnerWriterTrait> LayerWriter<'a, W> for CompressionLayerWriter<'a, W> {
    fn into_inner(self) -> Option<InnerWriterType<'a, W>> {
        Some(self.state.into_inner())
    }

    fn into_raw(self: Box<Self>) -> W {
        self.state.into_inner().into_raw()
    }

    fn finalize(&mut self) -> Result<(), Error> {
        // Use this mem::replace trick to be able to get back the compressor
        // inner and freely move from CompressionLayerWriterState to others
        let old_state = std::mem::replace(&mut self.state, CompressionLayerWriterState::Empty);
        let mut last_block_size = 0;
        let mut inner = match old_state {
            CompressionLayerWriterState::Ready(inner) => inner,
            CompressionLayerWriterState::InData(written, compress) => {
                let inner_count = compress.into_inner();
                self.compressed_sizes.push(inner_count.pos);
                last_block_size = written;
                inner_count.into_inner()
            }
            CompressionLayerWriterState::Empty => {
                // Should never happens, except if an error already occurs before
                return Err(Error::WrongReaderState("[Compression Layer] bad state in finalization, an error may already occurs before".to_string()));
            }
        };

        // Footer:
        // [SizesInfo][SizesInfo length]

        // `std::mem::replace` used to perform zero-copy serialization of `self.compressed_sizes`
        // The values is restored just after the operation (non-thread safe, but
        // in a multi-thread env, we will already required a lock for the
        // writing)
        let compressed_sizes = std::mem::take(&mut self.compressed_sizes);
        let sinfo = SizesInfo {
            compressed_sizes,
            last_block_size,
        };
        if bincode::options()
            .with_limit(BINCODE_MAX_DESERIALIZE)
            .with_fixint_encoding()
            .serialize_into(&mut inner, &sinfo)
            .is_err()
        {
            return Err(Error::SerializationError);
        }
        match bincode::serialized_size(&sinfo) {
            Ok(size) => {
                inner.write_u32::<LittleEndian>(
                    u32::try_from(size).map_err(|_| Error::SerializationError)?,
                )?;
            }
            Err(_) => {
                return Err(Error::SerializationError);
            }
        }
        self.compressed_sizes = sinfo.compressed_sizes;

        // Recursive call
        inner.finalize()?;
        // Store inner, for further into_inner / into_raw calls
        self.state = CompressionLayerWriterState::Ready(inner);
        Ok(())
    }
}

impl<'a, W: 'a + InnerWriterTrait> Write for CompressionLayerWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Use this mem::replace trick to be able to get back the compressor
        // inner and freely move from CompressionLayerWriterState to others
        let old_state = std::mem::replace(&mut self.state, CompressionLayerWriterState::Empty);
        match old_state {
            CompressionLayerWriterState::Ready(inner) => {
                let inner_count = WriterWithCount::new(inner);
                let mut compress = brotli::CompressorWriter::new(
                    inner_count,
                    0,
                    self.compression_level,
                    BROTLI_LOG_WINDOW,
                );
                let size = std::cmp::min(UNCOMPRESSED_DATA_SIZE as usize, buf.len());
                let written = compress.write(&buf[..size])?;
                self.state = CompressionLayerWriterState::InData(
                    u32::try_from(written).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Integer conversion failed"))?,
                    Box::new(compress),
                );
                Ok(written)
            }
            CompressionLayerWriterState::InData(written, mut compress) => {
                if written > UNCOMPRESSED_DATA_SIZE {
                    return Err(Error::WrongReaderState(
                        "[Compression Layer] Too much written".to_string(),
                    ).into());
                }
                if written == UNCOMPRESSED_DATA_SIZE {
                    let inner_count = compress.into_inner();
                    self.compressed_sizes.push(inner_count.pos);
                    self.state = CompressionLayerWriterState::Ready(inner_count.into_inner());
                    // Start a new block, fill it with new values!
                    return self.write(buf);
                }
                let size = std::cmp::min((UNCOMPRESSED_DATA_SIZE - written) as usize, buf.len());
                let written_add = compress.write(&buf[..size])?;
                self.state =
                    CompressionLayerWriterState::InData(
                        written + u32::try_from(written_add).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "Integer conversion failed")
                        })?,
                        compress,
                    );
                Ok(written_add)
            }
            CompressionLayerWriterState::Empty => {
                Err(Error::WrongReaderState("[Compression Layer] On write, should never happens, unless an error already occurs before".to_string()).into())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.state {
            CompressionLayerWriterState::Ready(inner) => inner.flush(),
            CompressionLayerWriterState::InData(_written, compress) => compress.flush(),
            CompressionLayerWriterState::Empty => {
                // Should never happens, except if an error already occurs before
                Err(Error::WrongReaderState("[Compression Layer] On flush, should never happens, unless an error already occurs before".to_string()).into())
            }
        }
    }
}

// ---------- Fail-Safe Reader ----------

pub struct CompressionLayerFailSafeReader<'a, R: 'a + Read> {
    /// While decompressing, one doesn't know in advance the number of compressed bytes
    /// As a result, the following is done:
    /// 1. read from the source inside a buffer
    /// 2. decompress the data from the buffer
    ///     - if there is still data to decompress, go to 1.
    ///     - if this is the end of the stream, continue to 3.
    /// 3. the decompressor may have read too many bytes, ie. `[end of stream n-1][start of stream n]`
    ///    `                                                                     ^                 ^
    ///    `                                                                 `input_offset`    last read position
    /// 4. rewind, using the cache, to `input_offset`
    ///
    /// A cache must be used, as the source is `Read` but not `Seek`.
    /// `input_offset` is guaranted to be in the cache because it must be in the decompressor working buffer,
    /// and the working buffer is contained in the cache (in the worst case, it is the whole cache)
    ///
    /// Cache management:
    /// ```ascii
    ///                cache_filled_offset
    ///                        v
    /// cache: [................    ]
    ///            ^
    ///        read_offset
    /// ```
    /// Data read from the source, not yet used
    cache: Vec<u8>,
    /// Bytes valid in the cache: [0..`cache_filled_offset`[ (0 -> no valid data)
    cache_filled_len: usize,
    /// Next offset to read from the cache
    /// Invariant:
    ///     - `read_offset <= cache_filled_offset`
    read_offset: usize,
    /// Internal decompressor state
    brotli_state: Box<BrotliState<StandardAlloc, StandardAlloc, StandardAlloc>>,
    /// Number of bytes decompressed and returned for the current stream
    uncompressed_read: u32,
    /// Inner layer (data source)
    inner: BrotliStreamReader<Box<dyn 'a + LayerFailSafeReader<'a, R>>>,
    /// Flag telling if we should decompress byte by byte
    byte_by_byte_decompression: bool,
}

impl<'a, R: 'a + Read> CompressionLayerFailSafeReader<'a, R> {
    pub fn new(inner: Box<dyn 'a + LayerFailSafeReader<'a, R>>) -> Self {
        CompressionLayerFailSafeReader {
            cache: vec![0u8; FAIL_SAFE_BUFFER_INITIAL_SIZE],
            read_offset: 0,
            cache_filled_len: 0,
            brotli_state: Box::new(BrotliState::new(
                StandardAlloc::default(),
                StandardAlloc::default(),
                StandardAlloc::default(),
            )),
            uncompressed_read: 0,
            inner: BrotliStreamReader::new(inner),
            byte_by_byte_decompression: false,
        }
    }

    fn fail_safe_decompress_stream(
        &mut self,
        mut args: FailSafeDecompressStreamParams,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        match brotli::BrotliDecompressStream(
            &mut args.available_in,
            &mut args.input_offset,
            &self.cache[self.read_offset..self.cache_filled_len],
            &mut args.available_out,
            &mut args.output_offset,
            buf,
            &mut args.written,
            &mut self.brotli_state,
        ) {
            brotli::BrotliResult::ResultSuccess => {
                // End of stream reached

                // Rewind the cache to the actual start of the new block
                // input_offset \in [0; cache_filled_len - read_offset[
                self.read_offset += args.input_offset;

                // Reset others
                self.brotli_state = Box::new(BrotliState::new(
                    StandardAlloc::default(),
                    StandardAlloc::default(),
                    StandardAlloc::default(),
                ));

                self.uncompressed_read = 0;

                self.inner
                    .new_brotli_stream(self.cache_filled_len - self.read_offset);

                if args.output_offset == 0 {
                    return self.read(buf);
                }

                Ok(args.output_offset)
            }
            brotli::BrotliResult::NeedsMoreInput => {
                // Bytes may have been read and produced
                self.read_offset += args.input_offset;
                self.uncompressed_read += u32::try_from(args.output_offset).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Integer conversion failed")
                })?;

                if args.output_offset == 0 {
                    // (NeedsMoreInput && output_offset == 0) means we can't produce output without more input
                    //
                    // if cache is full
                    if self.read_offset == 0 && self.cache_filled_len == self.cache.len() {
                        self.cache.resize(self.cache.len() + 1, 0);
                    } else {
                        // move cache content at offset zero to make room for other input
                        self.cache
                            .copy_within(self.read_offset..self.cache_filled_len, 0);
                        self.cache_filled_len -= self.read_offset;
                        self.read_offset = 0;
                        if self.byte_by_byte_decompression {
                            // Revert to one byte cache length if it was previously increased
                            if self.cache.len() != 1 {
                                self.cache.resize(1, 0);
                            }
                        }
                    }

                    let read = self.inner.read(&mut self.cache[self.cache_filled_len..])?;
                    if read == 0 {
                        // No more data from inner and the cache has been fully read
                        // -> return either an error or Ok(0)
                        if self.uncompressed_read > 0 {
                            // Inside a stream and no more data available
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "No more data from the inner layer",
                            ));
                        }
                        // No more data available but not in a stream
                        return Ok(0);
                    }
                    self.cache_filled_len += read;
                    return self.read(buf);
                }
                Ok(args.output_offset)
            }
            brotli::BrotliResult::NeedsMoreOutput => {
                // Bytes may have been read and produced
                self.read_offset += args.input_offset;
                self.uncompressed_read += u32::try_from(args.output_offset).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Integer conversion failed")
                })?;

                Ok(args.output_offset)
            }
            brotli::BrotliResult::ResultFailure => {
                if self.byte_by_byte_decompression {
                    // byte by byte reading fails: we cannot recover anymore data
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid data while decompressing",
                    ))
                } else {
                    // we retry with a cache size of 1 because BrotliDecompressStream
                    // may hold unreturned decompressed data in its internal state otherwise
                    self.byte_by_byte_decompression = true;
                    self.cache.resize(1, 0);
                    self.cache_filled_len = 0;
                    self.read_offset = 0;
                    self.brotli_state = Box::new(BrotliState::new(
                        StandardAlloc::default(),
                        StandardAlloc::default(),
                        StandardAlloc::default(),
                    ));
                    let number_of_already_decompressed_bytes = self.uncompressed_read;
                    self.uncompressed_read = 0;
                    // rewind to brotli stream start
                    self.inner.rewind_to_stream_start();
                    // skip over bytes that were already decompressed before the rewind
                    // by reading and discarding them into a sink, so they aren't returned again
                    io::copy(
                        &mut self.take(u64::from(number_of_already_decompressed_bytes)),
                        &mut io::sink(),
                    )?;
                    self.read(buf)
                }
            }
        }
    }
}

impl<'a, R: 'a + Read> LayerFailSafeReader<'a, R> for CompressionLayerFailSafeReader<'a, R> {
    fn into_inner(self) -> Option<Box<dyn 'a + LayerFailSafeReader<'a, R>>> {
        Some(self.inner.into_inner())
    }

    fn into_raw(self: Box<Self>) -> R {
        self.inner.into_inner().into_raw()
    }
}

const FAIL_SAFE_BUFFER_INITIAL_SIZE: usize = 4096;

impl<'a, R: 'a + Read> Read for CompressionLayerFailSafeReader<'a, R> {
    /// This `read` may end by failing.
    /// Even in the best configuration, when the inner layer is not broken, the
    /// decompression will fail if attempting to read not-compressed data such as
    /// `CompressionLayerReader` footer.
    /// This is OK right now because the only usage is `TruncatedArchiveReader::convert_to_archive`
    /// which stops reading when `EndOfArchiveData` is encountered.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.uncompressed_read > UNCOMPRESSED_DATA_SIZE {
            return Err(Error::WrongReaderState(
                "[Compress FailSafe Layer] Too much data read".to_string(),
            )
            .into());
        }

        if buf.is_empty() {
            return Ok(0);
        }

        // Number of bytes available in the source
        let available_in = self.cache_filled_len - self.read_offset;
        // IN: Offset in the source
        // OUT: Offset in the source after the decompression pass
        let input_offset = 0;
        // Available spaces in the output
        let available_out = buf.len();
        // IN: Offset in the output
        // OUT: number of bytes written in the output
        let output_offset = 0;
        // OUT: total number of byte written for the current stream (cumulative)
        let written = 0;

        let params = FailSafeDecompressStreamParams {
            available_in,
            input_offset,
            available_out,
            output_offset,
            written,
        };
        self.fail_safe_decompress_stream(params, buf)
    }
}

struct FailSafeDecompressStreamParams {
    available_in: usize,
    input_offset: usize,
    available_out: usize,
    output_offset: usize,
    written: usize,
}

/// This is a reader for the inner content with a cache.
/// The inner content is meant to be a succession of brotli streams.
/// This reader caches the current stream, giving possibility to rewind at its stat.
struct BrotliStreamReader<R> {
    cache: Vec<u8>,
    inner: R,
    number_of_bytes_read: usize,
}

impl<R> BrotliStreamReader<R> {
    const fn new(inner: R) -> Self {
        Self {
            cache: Vec::new(),
            inner,
            number_of_bytes_read: 0,
        }
    }

    fn into_inner(self) -> R {
        self.inner
    }

    /// Drop the previous brotli stream from the cache, move cached part of the
    /// new brotli stream to start of cache and get ready to read and cache the rest
    fn new_brotli_stream(&mut self, offset_from_current_pos: usize) {
        let cache_len = self.cache.len();
        // Take the cached new brotli stream and move it to the start of the cache
        self.cache
            .copy_within(offset_from_current_pos..cache_len, 0);
        // discard the rest of the cache
        let new_cache_len = cache_len - offset_from_current_pos;
        self.cache.truncate(new_cache_len);
        self.number_of_bytes_read = new_cache_len;
    }

    /// Rewind at start of cached data
    const fn rewind_to_stream_start(&mut self) {
        self.number_of_bytes_read = 0;
    }
}

impl<R: Read> Read for BrotliStreamReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.number_of_bytes_read < self.cache.len() {
            // we previously got rewound: read from cache
            let remaining_in_cache = self.cache.len() - self.number_of_bytes_read;
            let copy_len = cmp::min(remaining_in_cache, buf.len());
            buf[0..copy_len].copy_from_slice(
                &self.cache[self.number_of_bytes_read..(self.number_of_bytes_read + copy_len)],
            );
            self.number_of_bytes_read += copy_len;
            Ok(copy_len)
        } else {
            // we are reading uncached data: read it and cache it
            let nread = self.inner.read(buf)?;
            self.cache.extend_from_slice(&buf[..nread]);
            self.number_of_bytes_read += nread;
            Ok(nread)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Layers;

    use crate::layers::raw::{RawLayerFailSafeReader, RawLayerReader, RawLayerWriter};
    use brotli::writer::StandardAlloc;
    use rand::SeedableRng;
    use rand::distr::{Alphanumeric, Distribution, StandardUniform};
    use std::io::{Cursor, Read, Write};
    use std::time::Instant;

    // Use few UNCOMPRESSED_DATA_SIZE to force few blocks, and
    // UNCOMPRESSED_DATA_SIZE / 2 to add a non complete one
    static SIZE: usize = (UNCOMPRESSED_DATA_SIZE * 2 + UNCOMPRESSED_DATA_SIZE / 2) as usize;

    // Return a vector of data of size SIZE
    fn get_data() -> Vec<u8> {
        // Use only alphanumeric charset to allow for compression
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0);
        let data: Vec<u8> = Alphanumeric.sample_iter(&mut rng).take(SIZE).collect();
        assert_eq!(data.len(), SIZE);
        data
    }

    // Return a vector of uncompressable data (ie. purely random) of size SIZE
    fn get_uncompressable_data() -> Vec<u8> {
        // Use only alphanumeric charset to allow for compression
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0);
        let data: Vec<u8> = StandardUniform.sample_iter(&mut rng).take(SIZE).collect();
        assert_eq!(data.len(), SIZE);
        data
    }

    #[test]
    fn compress_layer_writer() {
        // Test with one "CompressedBlock"
        let file = Vec::new();
        let mut comp = Box::new(CompressionLayerWriter::new(
            Box::new(RawLayerWriter::new(file)),
            &CompressionConfig::default(),
        ));
        let mut fake_data = vec![1, 2, 3, 4];
        let fake_data2 = vec![5, 6, 7, 8];
        comp.write_all(fake_data.as_slice()).unwrap();
        comp.write_all(fake_data2.as_slice()).unwrap();
        let file = comp.into_raw();

        let mut src = Cursor::new(file.as_slice());
        let mut reader = brotli::Decompressor::new(&mut src, 0);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        println!("{buf:?}");
        fake_data.extend(fake_data2);
        assert_eq!(fake_data, buf);
    }

    #[test]
    fn compress_layer_several() {
        // Test with several CompressedBlock - ensure that having only
        // compressed blocks without header is enough to be able to distinguish
        // them at decompression, knowing the uncompressed block size

        let data = get_data();
        let bytes = data.as_slice();

        let file = Vec::new();
        let mut comp = Box::new(CompressionLayerWriter::new(
            Box::new(RawLayerWriter::new(file)),
            &CompressionConfig::default(),
        ));
        let now = Instant::now();
        comp.write_all(bytes).unwrap();
        println!(
            "Compression: {} us for {} bytes",
            now.elapsed().as_micros(),
            bytes.len()
        );

        let file = comp.into_raw();
        println!("{}", file.len());
        let mut src = Cursor::new(file.as_slice());
        // Highlight the use of BrotliDecompressStream
        let now = Instant::now();
        let mut buf = vec![0; UNCOMPRESSED_DATA_SIZE as usize];

        // A similar result can be obtained by using a buffer_size of 1, as demonstrated below
        //
        // Using a Decompressor with a bigger buffer size lead to an over read of the inner source:
        // let mut reader = brotli::Decompressor::new(&mut src, 4096);
        // reader.read_exact(&mut buf).expect("First buffer");
        //
        // reader.__0.__0.input_offset -> current offset in the underlying buffer
        // reader.__0.__0: DecompressorCustomIo
        // src.position() - buffer_size + input_offset -> actual last byte read
        //
        // But this information is not exposed by the API

        let mut brotli_state = BrotliState::new(
            StandardAlloc::default(),
            StandardAlloc::default(),
            StandardAlloc::default(),
        );

        // at this point the decompressor simply needs an input and output buffer and the ability to track
        // the available data left in each buffer
        let mut available_in = file.len();
        let mut input_offset = 0;
        let mut available_out = buf.len();
        let mut output_offset = 0;
        let mut written = 0;

        if matches!(
            brotli::BrotliDecompressStream(
                &mut available_in,
                &mut input_offset,
                src.get_ref(),
                &mut available_out,
                &mut output_offset,
                &mut buf,
                &mut written,
                &mut brotli_state,
            ),
            brotli::BrotliResult::ResultSuccess
        ) {
        } else {
            panic!()
        }

        // Ensure the decompression is correct
        assert_eq!(written, buf.len());
        assert_eq!(buf.len(), UNCOMPRESSED_DATA_SIZE as usize);
        assert_eq!(buf.as_slice(), &bytes[..(UNCOMPRESSED_DATA_SIZE as usize)]);

        // Use the `input_offset` information to seek to the beginning of the next compressed block
        src.set_position(input_offset as u64);

        // Use a Decompressor with a buffer size of 1, as a replacement of the above optimization (must be compatible)
        let mut reader = brotli::Decompressor::new(&mut src, 1);
        let mut buf2 = vec![0; UNCOMPRESSED_DATA_SIZE as usize];
        reader.read_exact(&mut buf2).expect("Second buffer");
        assert_eq!(buf2.len(), UNCOMPRESSED_DATA_SIZE as usize);
        assert_eq!(
            buf2.as_slice(),
            &bytes[(UNCOMPRESSED_DATA_SIZE as usize)..((UNCOMPRESSED_DATA_SIZE * 2) as usize)]
        );

        let mut reader = brotli::Decompressor::new(&mut src, 1);
        let mut buf3 = vec![0; SIZE - buf.len() - buf2.len()];
        reader.read_exact(&mut buf3).expect("Last buffer");
        assert_eq!(buf.len() + buf2.len() + buf3.len(), SIZE);
        assert_eq!(
            buf3.as_slice(),
            &bytes[(buf.len() + buf2.len())..(buf.len() + buf2.len() + buf3.len())]
        );

        println!(
            "Decompression: {} us for {} bytes",
            now.elapsed().as_micros(),
            buf.len() + buf2.len() + buf3.len()
        );
        println!("Buf sizes {} {} {}", buf.len(), buf2.len(), buf3.len());
    }

    #[test]
    fn compress_layer() {
        // Compress then decompress with dedicated Layer structs

        for data in [get_data(), get_uncompressable_data()] {
            let bytes = data.as_slice();

            let file = Vec::new();
            let mut comp = Box::new(CompressionLayerWriter::new(
                Box::new(RawLayerWriter::new(file)),
                &CompressionConfig::default(),
            ));
            let now = Instant::now();
            comp.write_all(bytes).unwrap();
            comp.finalize().unwrap();
            let file = comp.into_raw();
            let buf = Cursor::new(file.as_slice());
            let mut decomp =
                Box::new(CompressionLayerReader::new(Box::new(RawLayerReader::new(buf))).unwrap());
            decomp.initialize().unwrap();
            let mut buf = Vec::new();
            decomp.read_to_end(&mut buf).unwrap();
            println!(
                "Compression / Decompression: {} us for {} bytes ({} compressed)",
                now.elapsed().as_micros(),
                bytes.len(),
                file.len()
            );
            assert_eq!(buf.len(), bytes.len());
            assert_eq!(buf.as_slice(), bytes);
        }
    }

    #[test]
    fn compress_failsafe_layer() {
        // Compress then decompress with Fail-Safe Layer structs

        for data in [get_data(), get_uncompressable_data()] {
            let bytes = data.as_slice();

            let file = Vec::new();
            let mut comp = Box::new(CompressionLayerWriter::new(
                Box::new(RawLayerWriter::new(file)),
                &CompressionConfig::default(),
            ));
            let now = Instant::now();
            comp.write_all(bytes).unwrap();
            comp.finalize().unwrap();
            let file = comp.into_raw();
            let mut decomp = Box::new(CompressionLayerFailSafeReader::new(Box::new(
                RawLayerFailSafeReader::new(file.as_slice()),
            )));
            let mut buf = Vec::new();
            // This must end with an error, when we start reading the footer (invalid for decompression)
            decomp.read_to_end(&mut buf).unwrap_err();
            println!(
                "Compression / Decompression (fail-safe): {} us for {} bytes ({} compressed)",
                now.elapsed().as_micros(),
                bytes.len(),
                file.len()
            );
            assert_eq!(buf.len(), bytes.len());
            assert_eq!(buf.as_slice(), bytes);
        }
    }

    #[test]
    fn compress_failsafe_truncated() {
        // Compress then decompress with Fail-Safe Layer structs, while truncating the intermediate buffer

        for data in [get_data(), get_uncompressable_data()] {
            let bytes = data.as_slice();

            let file = Vec::new();
            let mut comp = Box::new(CompressionLayerWriter::new(
                Box::new(RawLayerWriter::new(file)),
                &CompressionConfig::default(),
            ));
            let now = Instant::now();
            comp.write_all(bytes).unwrap();
            comp.finalize().unwrap();
            let file = comp.into_raw();

            // Truncate at the middle
            let stop = file.len() / 2;

            let mut decomp = Box::new(CompressionLayerFailSafeReader::new(Box::new(
                RawLayerFailSafeReader::new(&file[..stop]),
            )));
            let mut buf = Vec::new();
            // This is expected to end with an error
            decomp.read_to_end(&mut buf).unwrap_err();
            println!(
                "Compression / Decompression (fail-safe): {} us for {} bytes ({} compressed, {} keeped)",
                now.elapsed().as_micros(),
                bytes.len(),
                file.len(),
                buf.len(),
            );
            // Ensure the obtained bytes are correct
            assert_eq!(buf.as_slice(), &bytes[..buf.len()]);
            // We hope still having enough data (keeping half of the compressed
            // stream should give us at least a third of the uncompressed stream)
            assert!(buf.len() >= bytes.len() / 3);
        }
    }

    #[test]
    fn compress_layer_with_footer() {
        // Inspect footer of Compress / decompress

        let data = get_data();
        let bytes = data.as_slice();

        let file = Vec::new();
        let mut comp = Box::new(CompressionLayerWriter::new(
            Box::new(RawLayerWriter::new(file)),
            &CompressionConfig::default(),
        ));
        comp.write_all(bytes).unwrap();
        comp.finalize().unwrap();

        let mut compressed_sizes = Vec::new();
        compressed_sizes.extend_from_slice(&comp.compressed_sizes);

        let file = comp.into_raw();
        let buf = Cursor::new(file.as_slice());
        let mut decomp =
            Box::new(CompressionLayerReader::new(Box::new(RawLayerReader::new(buf))).unwrap());
        decomp.initialize().unwrap();

        // Check the footer has been correctly re-read
        assert_eq!(
            compressed_sizes,
            decomp.sizes_info.unwrap().compressed_sizes
        );
    }

    #[test]
    fn seek_with_footer() {
        for data in [get_data(), get_uncompressable_data()] {
            let bytes = data.as_slice();

            let file = Vec::new();
            let mut comp = Box::new(CompressionLayerWriter::new(
                Box::new(RawLayerWriter::new(file)),
                &CompressionConfig::default(),
            ));
            comp.write_all(bytes).unwrap();
            comp.finalize().unwrap();

            let file = comp.into_raw();
            let buf = Cursor::new(file.as_slice());
            let mut decomp =
                Box::new(CompressionLayerReader::new(Box::new(RawLayerReader::new(buf))).unwrap());
            decomp.initialize().unwrap();

            // Seek in the first block
            let pos = decomp.seek(SeekFrom::Start(5)).unwrap();
            assert_eq!(pos, 5);
            let mut buf = [0u8; 5];
            decomp.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, &bytes[5..10]);

            // Seek in the second block
            let pos = decomp
                .seek(SeekFrom::Start((UNCOMPRESSED_DATA_SIZE + 4).into()))
                .unwrap();
            assert_eq!(pos, (UNCOMPRESSED_DATA_SIZE + 4).into());
            let mut buf = [0u8; 5];
            decomp.read_exact(&mut buf).unwrap();
            assert_eq!(
                &buf,
                &bytes[usize::try_from(pos).unwrap()..usize::try_from(pos + 5).unwrap()]
            );
            // Seek relatively (same block)
            let pos = decomp.seek(SeekFrom::Current(2)).unwrap();
            assert_eq!(pos, (UNCOMPRESSED_DATA_SIZE + 4 + 5 + 2).into());
            let mut buf = [0u8; 5];
            decomp.read_exact(&mut buf).unwrap();
            assert_eq!(
                &buf,
                &bytes[usize::try_from(pos).unwrap()..usize::try_from(pos + 5).unwrap()]
            );
            // Seek relatively (next block)
            let pos = decomp
                .seek(SeekFrom::Current(UNCOMPRESSED_DATA_SIZE.into()))
                .unwrap();
            assert_eq!(pos, (UNCOMPRESSED_DATA_SIZE * 2 + 4 + 5 + 2 + 5).into());
            let mut buf = [0u8; 5];
            decomp.read_exact(&mut buf).unwrap();
            assert_eq!(
                &buf,
                &bytes[usize::try_from(pos).unwrap()..usize::try_from(pos + 5).unwrap()]
            );
            // Seek relatively (backward)
            let pos = decomp.seek(SeekFrom::Current(-5)).unwrap();
            assert_eq!(pos, (UNCOMPRESSED_DATA_SIZE * 2 + 4 + 5 + 2 + 5).into());
            let mut buf = [0u8; 5];
            decomp.read_exact(&mut buf).unwrap();
            assert_eq!(
                &buf,
                &bytes[usize::try_from(pos).unwrap()..usize::try_from(pos + 5).unwrap()]
            );
            // Seek from end
            let pos = decomp.seek(SeekFrom::End(-5)).unwrap();
            assert_eq!(pos, (SIZE - 5) as u64);
            let mut buf = [0u8; 5];
            decomp.read_exact(&mut buf).unwrap();
            assert_eq!(
                &buf,
                &bytes[usize::try_from(pos).unwrap()..usize::try_from(pos + 5).unwrap()]
            );
        }
    }

    #[test]
    fn sizes_info() {
        let sizes_info = SizesInfo {
            compressed_sizes: vec![1, 2, 5],
            last_block_size: 42,
        };

        assert_eq!(
            sizes_info.uncompressed_block_size_at(1),
            UNCOMPRESSED_DATA_SIZE
        );
        assert_eq!(sizes_info.uncompressed_block_size_at(3), 42);

        assert_eq!(
            sizes_info.max_uncompressed_pos(),
            2 * u64::from(UNCOMPRESSED_DATA_SIZE) + 42
        );

        assert_eq!(
            sizes_info
                .compressed_block_size_at(u64::from(UNCOMPRESSED_DATA_SIZE) + 1)
                .unwrap(),
            2
        );
    }

    #[test]
    fn compress_config() {
        // Check the compression level is indeed use
        let data = get_data();
        let bytes = data.as_slice();

        let file = Vec::new();
        let mut config = ArchiveWriterConfig::new();
        config
            .enable_layer(Layers::COMPRESS)
            .with_compression_level(0)
            .unwrap();
        let mut comp = Box::new(CompressionLayerWriter::new(
            Box::new(RawLayerWriter::new(file)),
            &config.compress,
        ));
        comp.write_all(bytes).unwrap();
        comp.finalize().unwrap();

        let file2 = Vec::new();
        let mut config2 = ArchiveWriterConfig::new();
        config2
            .enable_layer(Layers::COMPRESS)
            .with_compression_level(5)
            .unwrap();
        let mut comp2 = Box::new(CompressionLayerWriter::new(
            Box::new(RawLayerWriter::new(file2)),
            &config2.compress,
        ));
        comp2.write_all(bytes).unwrap();
        comp2.finalize().unwrap();

        // file2 must be better compressed than file
        let file = comp.into_raw();
        let file2 = comp2.into_raw();
        assert!(file.len() > file2.len());

        // Check content
        let buf = Cursor::new(file.as_slice());
        let mut buf_out = Vec::new();
        let mut decomp =
            Box::new(CompressionLayerReader::new(Box::new(RawLayerReader::new(buf))).unwrap());
        decomp.initialize().unwrap();
        decomp.read_to_end(&mut buf_out).unwrap();
        let buf2 = Cursor::new(file2.as_slice());
        let mut buf_out2 = Vec::new();
        let mut decomp =
            Box::new(CompressionLayerReader::new(Box::new(RawLayerReader::new(buf2))).unwrap());
        decomp.initialize().unwrap();
        decomp.read_to_end(&mut buf_out2).unwrap();
        assert_eq!(buf_out, buf_out2);
    }

    #[test]
    fn test_new_brotli_stream_discards_old_cache() {
        let data = b"0123456789";
        let inner = std::io::Cursor::new(data);
        let mut reader = BrotliStreamReader::new(inner);

        let mut buf = [0; 10];
        reader.read_exact(&mut buf).unwrap(); // cache now has all 10 bytes

        // Start new brotli stream at offset 5 (i.e., keep "56789")
        reader.new_brotli_stream(5);

        // Ensure only the new stream is in cache
        assert_eq!(&reader.cache, b"56789");

        // Rewind to start of new stream
        reader.rewind_to_stream_start();
        let mut buf2 = [0; 5];
        reader.read_exact(&mut buf2).unwrap();
        assert_eq!(&buf2, b"56789");
    }

    #[test]
    fn test_read_continues_after_cache() {
        let data = b"abcdeFGHIJ";
        let inner = std::io::Cursor::new(data);
        let mut reader = BrotliStreamReader::new(inner);

        let mut buf = [0; 5];
        reader.read_exact(&mut buf).unwrap(); // read "abcde"
        assert_eq!(&buf, b"abcde");

        let mut buf2 = [0; 5];
        reader.read_exact(&mut buf2).unwrap(); // read "FGHIJ" from inner
        assert_eq!(&buf2, b"FGHIJ");
    }
}
