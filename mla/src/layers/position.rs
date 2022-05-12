use std::io;
use std::io::Write;

use crate::layers::traits::{InnerWriterTrait, InnerWriterType, LayerWriter};
use crate::Error;

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
    fn into_inner(self) -> Option<InnerWriterType<'a, W>> {
        Some(self.inner)
    }

    fn into_raw(self: Box<Self>) -> W {
        self.inner.into_raw()
    }

    fn finalize(&mut self) -> Result<(), Error> {
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
