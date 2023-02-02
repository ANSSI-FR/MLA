use bincode::Options;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};

use crate::layers::traits::{
    InnerWriterTrait, InnerWriterType, LayerFailSafeReader, LayerReader, LayerWriter,
};
use crate::{Error, BINCODE_MAX_DESERIALIZE};
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::config::{ArchiveWriterConfig, ConfigResult};
use crate::errors::ConfigError;

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
        CompressionConfig {
            compression_level: DEFAULT_COMPRESSION_LEVEL,
        }
    }
}

impl ArchiveWriterConfig {
    /// Set the compression level
    /// compression level (0-11); bigger values cause denser, but slower compression
    pub fn with_compression_level(&mut self, compression_level: u32) -> ConfigResult {
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
        // Use a Box to avoid a too big enum
        decompressor: Box<brotli::Decompressor<R>>,
    },
    /// Empty is a placeholder to allow state replacement
    Empty,
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
    fn uncompressed_block_size_at(&self, block_num: usize) -> u32 {
        if block_num < self.compressed_sizes.len() - 1 {
            UNCOMPRESSED_DATA_SIZE
        } else {
            self.last_block_size
        }
    }

    /// Get the compressed block at position `uncompressed_pos`
    fn compressed_block_size_at(&self, uncompressed_pos: u64) -> u32 {
        let block_num = uncompressed_pos / (UNCOMPRESSED_DATA_SIZE as u64);
        self.compressed_sizes[block_num as usize]
    }

    /// Maximum uncompressed available position
    fn max_uncompressed_pos(&self) -> u64 {
        (self.compressed_sizes.len() as u64 - 1) * UNCOMPRESSED_DATA_SIZE as u64
            + self.last_block_size as u64
    }

    // Sum the compressed_sizes
    pub fn get_compressed_size(&self) -> u64 {
        self.compressed_sizes.iter().map(|v| *v as u64).sum()
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
            CompressionLayerReaderState::Ready(inner) => inner,
            CompressionLayerReaderState::InData { decompressor, .. } => decompressor.into_inner(),
            // `panic!` explicitly called to avoid propagating an error which
            // must never happens (ie, calling `into_inner` in an inconsistent
            // internal state)
            _ => panic!("[Reader] Empty type to inner is impossible"),
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
        match &self.sizes_info {
            Some(sizes_info) => {
                let pos_max = sizes_info.max_uncompressed_pos();
                uncompressed_pos < pos_max
            }
            None => true,
        }
    }

    /// Instantiate a new decompressor at position `uncompressed_pos`
    /// `uncompressed_pos` must be a compressed block's starting position
    fn new_decompressor_at<S: Read + Seek>(
        &self,
        inner: S,
        uncompressed_pos: u64,
    ) -> Result<brotli::Decompressor<S>, Error> {
        // Ensure it's a starting position
        if uncompressed_pos % (UNCOMPRESSED_DATA_SIZE as u64) != 0 {
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
                Ok(brotli::Decompressor::new(
                    inner,
                    sizes_info.compressed_block_size_at(uncompressed_pos) as usize,
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
        if uncompressed_pos % (UNCOMPRESSED_DATA_SIZE as u64) != 0 {
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
                let block_num = uncompressed_pos / (UNCOMPRESSED_DATA_SIZE as u64);
                Ok(sizes_info.uncompressed_block_size_at(block_num as usize))
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
        if uncompressed_pos % (UNCOMPRESSED_DATA_SIZE as u64) != 0 {
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
        let block_num = uncompressed_pos / (UNCOMPRESSED_DATA_SIZE as u64);
        match &self.sizes_info {
            Some(SizesInfo {
                compressed_sizes, ..
            }) => {
                // Move the underlayer at the start of the block
                let start_position = compressed_sizes
                    .iter()
                    .take(block_num as usize)
                    .map(|size| *size as u64)
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

impl<'a, R: 'a + Read + Seek> LayerReader<'a, R> for CompressionLayerReader<'a, R> {
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
                let len = inner.read_u32::<LittleEndian>()? as u64;

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
                    self.state = CompressionLayerReaderState::Ready(decompressor.into_inner());
                    // Start a new block, fill it with new values!
                    return self.read(buf);
                }
                let size = std::cmp::min((uncompressed_size - read) as usize, buf.len());
                let read_add = decompressor.read(&mut buf[..size])?;
                self.underlayer_pos += read_add as u64;
                self.state = CompressionLayerReaderState::InData {
                    read: read + read_add as u32,
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

impl<'a, R: Read + Seek> Seek for CompressionLayerReader<'a, R> {
    /// Seek to the position `pos` in the uncompressed stream
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Seeking may instantiate a decompressor, and therefore position the
        // inner layer at the end of the asked position's compressed block
        match &self.sizes_info {
            Some(_sizes_info) => {
                match pos {
                    SeekFrom::Start(pos) => {
                        // Find the right block
                        let inside_block = pos % (UNCOMPRESSED_DATA_SIZE as u64);
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
                            read: inside_block as u32,
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
                        } else {
                            self.seek(SeekFrom::Start((pos + self.underlayer_pos as i64) as u64))
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
                        self.seek(SeekFrom::Start(end_pos - distance_from_end as u64))
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
    fn new(inner: W) -> Self {
        Self { inner, pos: 0 }
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for WriterWithCount<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf).map(|i| {
            self.pos += i as u32;
            i
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

/// Compression layer is made of independent CompressedBlock, ending by an index for seekable accesses
/// [CompressedBlock][CompressedBlock]...[CompressedBlock][Index]
///
/// Compression is made of nested independent compressed block of a fixed
/// uncompressed size
/// Pro:
/// * no need to store the compressed size
/// * compression can be streamed (storing the compressed size before the
/// compressed block leads to either seekable stream, which is not an option
/// here, or full-memory compression before actual write, which add limits to
/// the memory footprint)
/// Cons:
/// * if the index is lost, a slow decompression with a block size of 1 is
/// needed to found the CompressedBlock boundaries
pub struct CompressionLayerWriter<'a, W: 'a + InnerWriterTrait> {
    state: CompressionLayerWriterState<InnerWriterType<'a, W>>,
    // Ordered list of compressed size of block of `UNCOMPRESSED_DATA_SIZE`
    // bytes
    //
    // Thus, accessing the `n`th byte in the sublayer, is accessing the `n %
    // C`th uncompressed byte in the chunk beginning at `sum(compressed_sizes[:n
    // / C])`, with `C = UNCOMPRESSED_DATA_SIZE`
    compressed_sizes: Vec<u32>,
    // From config
    compression_level: u32,
}

impl<W: InnerWriterTrait> CompressionLayerWriterState<W> {
    fn into_inner(self) -> W {
        match self {
            CompressionLayerWriterState::Ready(inner) => inner,
            CompressionLayerWriterState::InData(_written, compress) => {
                compress.into_inner().into_inner()
            }
            // `panic!` explicitly called to avoid propagating an error which
            // must never happens (ie, calling `into_inner` in an inconsistent
            // internal state)
            _ => panic!("[Writer] Empty type to inner is impossible"),
        }
    }
}

impl<'a, W: 'a + InnerWriterTrait> CompressionLayerWriter<'a, W> {
    pub fn new(
        inner: InnerWriterType<'a, W>,
        config: &CompressionConfig,
    ) -> CompressionLayerWriter<'a, W> {
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
        };
        match bincode::serialized_size(&sinfo) {
            Ok(size) => {
                inner.write_u32::<LittleEndian>(size as u32)?;
            }
            Err(_) => {
                return Err(Error::SerializationError);
            }
        };
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
                self.state = CompressionLayerWriterState::InData(written as u32, Box::new(compress));
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
                    CompressionLayerWriterState::InData(written + written_add as u32, compress);
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
    state: CompressionLayerReaderState<Box<dyn 'a + LayerFailSafeReader<'a, R>>>,
}

impl<'a, R: 'a + Read> CompressionLayerFailSafeReader<'a, R> {
    pub fn new(inner: Box<dyn 'a + LayerFailSafeReader<'a, R>>) -> Result<Self, Error> {
        Ok(Self {
            state: CompressionLayerReaderState::Ready(inner),
        })
    }
}

impl<'a, R: 'a + Read> LayerFailSafeReader<'a, R> for CompressionLayerFailSafeReader<'a, R> {
    fn into_inner(self) -> Option<Box<dyn 'a + LayerFailSafeReader<'a, R>>> {
        Some(self.state.into_inner())
    }

    fn into_raw(self: Box<Self>) -> R {
        self.state.into_inner().into_raw()
    }
}

impl<'a, R: 'a + Read> Read for CompressionLayerFailSafeReader<'a, R> {
    /// This `read` is expected to end by failing
    ///
    /// Even in the best configuration, when the inner layer is not broken, the
    /// decompression will fail while reading not-compressed data such as
    /// CompressionLayerReader footer
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Use this mem::replace trick to be able to get back the compressor
        // inner and freely move from CompressionLayerReaderState to others
        let old_state = std::mem::replace(&mut self.state, CompressionLayerReaderState::Empty);
        match old_state {
            CompressionLayerReaderState::Ready(inner) => {
                // Default values, for "repair" mode

                // Use a block size of `1` to ensure the decompression
                // will stop on the first byte of the next CompressionBlock.
                // This is slower, but we don't have index, and
                // therefore we don't know the compressed block size
                let decompressor = Box::new(brotli::Decompressor::new(inner, 1));
                self.state = CompressionLayerReaderState::InData {
                    read: 0,
                    // Default values, for "repair" mode
                    uncompressed_size: UNCOMPRESSED_DATA_SIZE,
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
                        "[Compress FailSafe Layer] Too much data read".to_string(),
                    )
                    .into());
                }
                if read == uncompressed_size {
                    // Consume the rest of the current decompressor. Due to the
                    // brotli implementation, a few bytes might remains, even if
                    // we already obtain the expected number of bytes. Thanks to
                    // the brotli format, the decompressor is able to stop at
                    // the end of the current block.
                    io::copy(&mut decompressor, &mut io::sink())?;
                    // Start a new block, fill it with new values
                    self.state = CompressionLayerReaderState::Ready(decompressor.into_inner());
                    return self.read(buf);
                }
                let size = std::cmp::min((uncompressed_size - read) as usize, buf.len());
                let read_add = decompressor.read(&mut buf[..size])?;
                self.state = CompressionLayerReaderState::InData {
                    read: read + read_add as u32,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Layers;

    use crate::layers::raw::{RawLayerFailSafeReader, RawLayerReader, RawLayerWriter};
    use rand::distributions::{Alphanumeric, Distribution, Standard};
    use rand::SeedableRng;
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
        let data: Vec<u8> = Standard.sample_iter(&mut rng).take(SIZE).collect();
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
        // Use a block size of 1 to be sure that the decompression will stop on
        // the first byte of the next CompressionBlock (-> slower, but in
        // reality, we will have index with compressed size)
        let now = Instant::now();

        let mut reader = brotli::Decompressor::new(&mut src, 1);
        let mut buf = vec![0; UNCOMPRESSED_DATA_SIZE as usize];
        reader.read_exact(&mut buf).expect("First buffer");
        assert_eq!(buf.len(), UNCOMPRESSED_DATA_SIZE as usize);
        assert_eq!(buf.as_slice(), &bytes[..(UNCOMPRESSED_DATA_SIZE as usize)]);

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

        for data in vec![get_data(), get_uncompressable_data()] {
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

        for data in vec![get_data(), get_uncompressable_data()] {
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
            let mut decomp = Box::new(
                CompressionLayerFailSafeReader::new(Box::new(RawLayerFailSafeReader::new(
                    file.as_slice(),
                )))
                .unwrap(),
            );
            let mut buf = Vec::new();
            // This may ends with an error, when we start reading the footer (invalid for decompression)
            decomp.read_to_end(&mut buf).unwrap();
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

        for data in vec![get_data(), get_uncompressable_data()] {
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

            let mut decomp = Box::new(
                CompressionLayerFailSafeReader::new(Box::new(RawLayerFailSafeReader::new(
                    &file[..stop],
                )))
                .unwrap(),
            );
            let mut buf = Vec::new();
            // This is expected to ends with an error
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
        for data in vec![get_data(), get_uncompressable_data()] {
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
            assert_eq!(&buf, &bytes[pos as usize..(pos + 5) as usize]);

            // Seek relatively (same block)
            let pos = decomp.seek(SeekFrom::Current(2)).unwrap();
            assert_eq!(pos, (UNCOMPRESSED_DATA_SIZE + 4 + 5 + 2).into());
            let mut buf = [0u8; 5];
            decomp.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, &bytes[pos as usize..(pos + 5) as usize]);

            // Seek relatively (next block)
            let pos = decomp
                .seek(SeekFrom::Current(UNCOMPRESSED_DATA_SIZE.into()))
                .unwrap();
            assert_eq!(pos, (UNCOMPRESSED_DATA_SIZE * 2 + 4 + 5 + 2 + 5).into());
            let mut buf = [0u8; 5];
            decomp.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, &bytes[pos as usize..(pos + 5) as usize]);

            // Seek relatively (backward)
            let pos = decomp.seek(SeekFrom::Current(-5)).unwrap();
            assert_eq!(pos, (UNCOMPRESSED_DATA_SIZE * 2 + 4 + 5 + 2 + 5).into());
            let mut buf = [0u8; 5];
            decomp.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, &bytes[pos as usize..(pos + 5) as usize]);

            // Seek from end
            let pos = decomp.seek(SeekFrom::End(-5)).unwrap();
            assert_eq!(pos, (SIZE - 5) as u64);
            let mut buf = [0u8; 5];
            decomp.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, &bytes[pos as usize..(pos + 5) as usize]);
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
            2 * UNCOMPRESSED_DATA_SIZE as u64 + 42
        );

        assert_eq!(
            sizes_info.compressed_block_size_at(UNCOMPRESSED_DATA_SIZE as u64 + 1),
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
        let mut buf2_out = Vec::new();
        let mut decomp =
            Box::new(CompressionLayerReader::new(Box::new(RawLayerReader::new(buf2))).unwrap());
        decomp.initialize().unwrap();
        decomp.read_to_end(&mut buf2_out).unwrap();
        assert_eq!(buf_out, buf2_out);
    }
}
