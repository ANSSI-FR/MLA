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

/// Layer offering a view of inner layer but with given number of bytes striped from the begining and end
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

impl<'a, R: InnerReaderTrait> Seek for StripHeadTailReader<'a, R> {
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

impl<'a, R: InnerReaderTrait> Read for StripHeadTailReader<'a, R> {
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

// ---------- FailSafeReader ----------

// // Dummy layer, standing for the last layer (wrapping I/O)
// pub struct StripHeadTailFailSafeReader<R: Read> {
// inner: R,
// }

// impl<R: Read> StripHeadTailFailSafeReader<R> {
// pub fn new(inner: R) -> Self {
// Self { inner }
// }
// }

// impl<R: Read> Read for StripHeadTailFailSafeReader<R> {
// /// Wrapper on inner
// fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
// self.inner.read(into)
// }
// }

// impl<'a, R: Read> LayerFailSafeReader<'a, R> for StripHeadTailFailSafeReader<R> {}
