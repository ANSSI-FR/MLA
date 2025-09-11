use std::io::{self, ErrorKind};
use std::io::{Read, Seek, SeekFrom};

use crate::Error;
use crate::layers::traits::LayerReader;

use super::traits::InnerReaderTrait;

// ---------- Writer ----------

// pub struct StripHeadTailWriter<W: InnerWriterTrait> {
// inner: W,
// }

// impl<W: InnerWriterTrait> StripHeadTailWriter<W> {
// pub fn new(inner: W) -> Self {
// Self { inner }
// }
// }

// impl<'a, W: InnerWriterTrait> LayerWriter<'a, W> for StripHeadTailWriter<W> {
// fn finalize(self: Box<Self>) -> Result<W, Error> {
// // No recursive call, this is the last layer
// Ok(self.inner)
// }
// }

// impl<W: InnerWriterTrait> Write for StripHeadTailWriter<W> {
// /// Wrapper on inner
// fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
// self.inner.write(buf)
// }

// /// Wrapper on inner
// fn flush(&mut self) -> io::Result<()> {
// self.inner.flush()
// }
// }

// ---------- Reader ----------

/// Layer that provides a view of the inner layer,
/// with a specified number of bytes stripped from the beginning and end
pub struct StripHeadTailReader<'a, R: InnerReaderTrait> {
    inner: Box<dyn 'a + LayerReader<'a, R>>,
    head_len: u64,
    tail_len: u64,
    inner_len_incl_head_tail: u64,
    current_position_in_this_layer: u64,
}
// mut inner: Box<dyn 'a + LayerReader<'a, R>>
impl<'a, R: InnerReaderTrait> StripHeadTailReader<'a, R> {
    pub fn new(
        inner: Box<dyn 'a + LayerReader<'a, R>>,
        head_len: u64,
        tail_len: u64,
        inner_len_incl_head_tail: u64,
        current_position_in_this_layer: u64,
    ) -> Result<Self, Error> {
        let stripped_len = head_len
            .checked_add(tail_len)
            .ok_or(Error::WrongReaderState("Internal error".into()))?;
        if stripped_len > inner_len_incl_head_tail {
            Err(Error::WrongReaderState("Internal error".into()))
        } else {
            Ok(Self {
                inner,
                head_len,
                tail_len,
                inner_len_incl_head_tail,
                current_position_in_this_layer,
            })
        }
    }

    #[inline(always)]
    fn tail_offset_from_inner_start(&self) -> u64 {
        self.inner_len_incl_head_tail - self.tail_len
    }

    #[inline(always)]
    fn this_layer_length(&self) -> u64 {
        self.inner_len_incl_head_tail - self.head_len - self.tail_len
    }
}

impl<'a, R: InnerReaderTrait> LayerReader<'a, R> for StripHeadTailReader<'a, R> {
    fn into_raw(self: Box<Self>) -> R {
        self.inner.into_raw()
    }

    fn initialize(&mut self) -> Result<(), Error> {
        self.inner.initialize()
    }
}

impl<R: InnerReaderTrait> Seek for StripHeadTailReader<'_, R> {
    /// Offer a position relatively to `self.offset_pos`
    fn seek(&mut self, asked_seek: SeekFrom) -> io::Result<u64> {
        match asked_seek {
            SeekFrom::Start(asked_offset) => {
                let new_inner_position = asked_offset
                    .checked_add(self.head_len)
                    .ok_or(ErrorKind::InvalidInput)?;
                if new_inner_position > self.tail_offset_from_inner_start() {
                    Err(ErrorKind::InvalidInput.into())
                } else {
                    self.inner.seek(SeekFrom::Start(new_inner_position))?;
                    self.current_position_in_this_layer = asked_offset;
                    Ok(asked_offset)
                }
            }
            SeekFrom::Current(asked_offset) => {
                let new_current_position_in_this_layer = self
                    .current_position_in_this_layer
                    .checked_add_signed(asked_offset)
                    .ok_or(ErrorKind::InvalidInput)?;
                if new_current_position_in_this_layer > self.this_layer_length() {
                    Err(ErrorKind::InvalidInput.into())
                } else {
                    self.inner.seek(asked_seek)?;
                    self.current_position_in_this_layer = new_current_position_in_this_layer;
                    Ok(new_current_position_in_this_layer)
                }
            }
            SeekFrom::End(asked_offset) => {
                let new_current_position = self
                    .this_layer_length()
                    .checked_add_signed(asked_offset)
                    .ok_or(ErrorKind::InvalidInput)?;
                if asked_offset > 0 {
                    Err(ErrorKind::InvalidInput.into())
                } else {
                    let inner_offset = asked_offset
                        .checked_sub_unsigned(self.tail_len)
                        .ok_or(ErrorKind::InvalidInput)?;
                    self.inner.seek(SeekFrom::End(inner_offset))?;
                    self.current_position_in_this_layer = new_current_position;
                    Ok(new_current_position)
                }
            }
        }
    }
}

impl<R: InnerReaderTrait> Read for StripHeadTailReader<'_, R> {
    /// Wrapper on inner
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let remaining_bytes_in_inner_layer =
            self.this_layer_length() - self.current_position_in_this_layer;
        let inner_ref = &mut self.inner;
        let n = inner_ref.take(remaining_bytes_in_inner_layer).read(into)?;
        self.current_position_in_this_layer +=
            u64::try_from(n).map_err(|_| io::Error::other("read overflowed u64"))?;
        Ok(n)
    }
}

// ---------- TruncatedReader ----------

// // Dummy layer, standing for the last layer (wrapping I/O)
// pub struct StripHeadTailTruncatedReader<R: Read> {
// inner: R,
// }

// impl<R: Read> StripHeadTailTruncatedReader<R> {
// pub fn new(inner: R) -> Self {
// Self { inner }
// }
// }

// impl<R: Read> Read for StripHeadTailTruncatedReader<R> {
// /// Wrapper on inner
// fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
// self.inner.read(into)
// }
// }

// impl<'a, R: Read> LayerTruncatedReader<'a, R> for StripHeadTailTruncatedReader<R> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RawLayerReader;
    use std::io::{Cursor, Read, Seek, SeekFrom};

    #[test]
    fn test_strip_head_tail_basic() {
        let data = b"abcdefghij";
        let inner = Cursor::new(data.to_vec());
        let raw_layer = RawLayerReader::new(inner);
        let mut boxed_inner = Box::new(raw_layer);

        boxed_inner.seek(SeekFrom::Start(2)).unwrap();
        let mut reader = StripHeadTailReader::new(
            boxed_inner,
            2,  // head_len
            3,  // tail_len
            10, // inner_len_incl_head_tail
            0,  // current_position_in_this_layer
        )
        .unwrap();

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, b"cdefg");
    }

    #[test]
    fn test_strip_head_tail_seek() {
        let data = b"abcdefghij";
        let inner = Cursor::new(data.to_vec());
        let raw_layer = RawLayerReader::new(inner);
        let mut boxed_inner = Box::new(raw_layer);
        boxed_inner.seek(SeekFrom::Start(4)).unwrap();

        let mut reader = StripHeadTailReader::new(boxed_inner, 2, 3, 10, 2).unwrap();

        // Seek to position 2 in the exposed layer (should be 'e')
        reader.seek(SeekFrom::Start(2)).unwrap();
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(buf[0], b'e');

        // Seek to end and try to read (should get 0 bytes)
        reader.seek(SeekFrom::End(0)).unwrap();
        let mut buf = [0u8; 1];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_strip_head_tail_full_strip() {
        let data = b"abcdefghij";
        let inner = Cursor::new(data.to_vec());
        let raw_layer = RawLayerReader::new(inner);
        let mut boxed_inner = Box::new(raw_layer);
        boxed_inner.seek(SeekFrom::Start(5)).unwrap();

        // Strip all bytes
        let result = StripHeadTailReader::new(boxed_inner, 5, 5, 10, 0);
        assert!(result.is_ok());
        let mut reader = result.unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_strip_head_tail_invalid_seek() {
        let data = b"abcdefghij";
        let inner = Cursor::new(data.to_vec());
        let raw_layer = RawLayerReader::new(inner);
        let mut boxed_inner = Box::new(raw_layer);
        boxed_inner.seek(SeekFrom::Start(2)).unwrap();

        let mut reader = StripHeadTailReader::new(boxed_inner, 2, 3, 10, 0).unwrap();

        // Try to seek beyond the end of the layer
        let result = reader.seek(SeekFrom::Start(8));
        assert!(result.is_err());
    }

    #[test]
    fn test_strip_head_tail_zero_length_inner() {
        let data = b"";
        let inner = Cursor::new(data.to_vec());
        let raw_layer = RawLayerReader::new(inner);
        let boxed_inner = Box::new(raw_layer);

        let mut reader = StripHeadTailReader::new(boxed_inner, 0, 0, 0, 0).unwrap();

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_strip_head_tail_negative_seek() {
        let data = b"abcdefghij";
        let inner = Cursor::new(data.to_vec());
        let raw_layer = RawLayerReader::new(inner);
        let mut boxed_inner = Box::new(raw_layer);
        boxed_inner.seek(SeekFrom::Start(5)).unwrap();

        let mut reader = StripHeadTailReader::new(boxed_inner, 2, 3, 10, 3).unwrap();

        // Seek backwards by 2 from current position 3 (should go to position 1)
        let pos = reader.seek(SeekFrom::Current(-2)).unwrap();
        assert_eq!(pos, 1);
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(buf[0], b'd');
    }

    #[test]
    fn test_strip_head_tail_excessive_strip() {
        let data = b"abcdefghij";
        let inner = Cursor::new(data.to_vec());
        let raw_layer = RawLayerReader::new(inner);
        let mut boxed_inner = Box::new(raw_layer);
        boxed_inner.seek(SeekFrom::Start(6)).unwrap();

        // head + tail > inner_len_incl_head_tail
        let result = StripHeadTailReader::new(boxed_inner, 6, 5, 10, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_strip_head_tail_partial_reads() {
        let data = b"abcdefghij";
        let inner = Cursor::new(data.to_vec());
        let raw_layer = RawLayerReader::new(inner);
        let mut boxed_inner = Box::new(raw_layer);
        boxed_inner.seek(SeekFrom::Start(2)).unwrap();

        let mut reader = StripHeadTailReader::new(boxed_inner, 2, 3, 10, 0).unwrap();

        let mut buf = [0u8; 2];
        let mut out = Vec::new();

        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }

        assert_eq!(&out, b"cdefg");
    }
}
