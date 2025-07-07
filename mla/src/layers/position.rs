use std::io::Write;
use std::io::{self, Read};

use crate::Error;
use crate::layers::traits::{InnerWriterTrait, InnerWriterType, LayerWriter};

// ---------- Writer ----------

/// Layer used to track how many bytes have been written
pub struct PositionLayerWriter<'a, W: 'a + InnerWriterTrait> {
    inner: InnerWriterType<'a, W>,
    pos: u64,
}

impl<'a, W: 'a + InnerWriterTrait> PositionLayerWriter<'a, W> {
    pub fn new(inner: InnerWriterType<'a, W>) -> Self {
        Self { inner, pos: 0 }
    }

    /// Get the current position (ie, how many bytes written since last position
    /// reset)
    pub fn position(&self) -> u64 {
        self.pos
    }

    pub fn reset_position(&mut self) -> u64 {
        let before = self.pos;
        self.pos = 0;
        before
    }
}

impl<'a, W: 'a + InnerWriterTrait> LayerWriter<'a, W> for PositionLayerWriter<'a, W> {
    fn finalize(self: Box<Self>) -> Result<W, Error> {
        // Nothing to do

        // Recursive call
        self.inner.finalize()
    }
}

impl<'a, W: 'a + InnerWriterTrait> Write for PositionLayerWriter<'a, W> {
    /// Wrapper on inner
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.pos += written as u64;
        Ok(written)
    }

    /// Wrapper on inner
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) struct PositionLayerReader<R> {
    inner: R,
    pos: u64,
}

impl<R> PositionLayerReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self { inner, pos: 0 }
    }

    /// Get the current position (ie, how many bytes read since last position
    /// reset)
    pub(crate) fn position(&self) -> u64 {
        self.pos
    }
}

impl<R: Read> Read for PositionLayerReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.pos += u64::try_from(n).or(Err(io::Error::other("Failed to convert usize to u64")))?;
        Ok(n)
    }
}
