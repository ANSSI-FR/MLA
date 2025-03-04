use std::io;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::Error;
use crate::layers::traits::{
    InnerWriterTrait, InnerWriterType, LayerFailSafeReader, LayerReader, LayerWriter,
};

use super::traits::InnerReaderTrait;

// ---------- Writer ----------

/// Dummy layer, standing for the last layer (wrapping I/O)
pub struct RawLayerWriter<W: InnerWriterTrait> {
    inner: W,
}

impl<W: InnerWriterTrait> RawLayerWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<'a, W: InnerWriterTrait> LayerWriter<'a, W> for RawLayerWriter<W> {
    fn into_inner(self) -> Option<InnerWriterType<'a, W>> {
        None
    }

    fn into_raw(self: Box<Self>) -> W {
        self.inner
    }

    fn finalize(&mut self) -> Result<(), Error> {
        // No recursive call, this is the last layer
        Ok(())
    }
}

impl<W: InnerWriterTrait> Write for RawLayerWriter<W> {
    /// Wrapper on inner
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    /// Wrapper on inner
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------- Reader ----------

/// Dummy layer, standing for the last layer (wrapping I/O)
pub struct RawLayerReader<R: InnerReaderTrait> {
    inner: R,
    // Offset to use in position
    offset_pos: u64,
}

impl<R: InnerReaderTrait> RawLayerReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            offset_pos: 0,
        }
    }

    /// Mark the current position as the position 0
    pub fn reset_position(&mut self) -> io::Result<()> {
        self.offset_pos = self.inner.stream_position()?;
        Ok(())
    }
}

impl<'a, R: InnerReaderTrait> LayerReader<'a, R> for RawLayerReader<R> {
    fn into_inner(self) -> Option<Box<dyn 'a + LayerReader<'a, R>>> {
        None
    }

    fn into_raw(self: Box<Self>) -> R {
        self.inner
    }

    fn initialize(&mut self) -> Result<(), Error> {
        // No recursive call, this is the last layer
        Ok(())
    }
}

impl<R: InnerReaderTrait> Seek for RawLayerReader<R> {
    /// Offer a position relatively to `self.offset_pos`
    fn seek(&mut self, ask_pos: SeekFrom) -> io::Result<u64> {
        match ask_pos {
            SeekFrom::Start(pos) => {
                self.inner.seek(SeekFrom::Start(self.offset_pos + pos))?;
                Ok(pos)
            }
            SeekFrom::Current(_pos) => {
                let inner_pos = self.inner.seek(ask_pos)?;
                if inner_pos < self.offset_pos {
                    self.inner.seek(SeekFrom::Start(self.offset_pos))?;
                    Ok(0)
                } else {
                    Ok(inner_pos - self.offset_pos)
                }
            }
            SeekFrom::End(_pos) => {
                let inner_pos = self.inner.seek(ask_pos)?;
                if inner_pos < self.offset_pos {
                    self.inner.seek(SeekFrom::Start(self.offset_pos))?;
                    Ok(0)
                } else {
                    Ok(inner_pos - self.offset_pos)
                }
            }
        }
    }
}

impl<R: InnerReaderTrait> Read for RawLayerReader<R> {
    /// Wrapper on inner
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        self.inner.read(into)
    }
}

// ---------- FailSafeReader ----------

/// Dummy layer, standing for the last layer (wrapping I/O)
pub struct RawLayerFailSafeReader<R: Read> {
    inner: R,
}

impl<R: Read> RawLayerFailSafeReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R: Read> Read for RawLayerFailSafeReader<R> {
    /// Wrapper on inner
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        self.inner.read(into)
    }
}

impl<'a, R: Read> LayerFailSafeReader<'a, R> for RawLayerFailSafeReader<R> {
    fn into_inner(self) -> Option<Box<dyn 'a + LayerFailSafeReader<'a, R>>> {
        None
    }

    fn into_raw(self: Box<Self>) -> R {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::traits::{LayerReader, LayerWriter};

    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    static DATA: [u8; 4] = [1, 2, 3, 4];

    #[test]
    fn basic_ops() {
        let buf = Vec::new();

        // Write
        let mut raw_w = Box::new(RawLayerWriter::new(buf));
        raw_w.write_all(&DATA).unwrap();
        raw_w.finalize().unwrap();

        // Read
        let buf = Cursor::new(raw_w.into_raw());
        let mut raw_r = Box::new(RawLayerReader::new(buf));
        raw_r.initialize().unwrap();
        let mut output = Vec::new();
        raw_r.read_to_end(&mut output).unwrap();
        assert_eq!(output.as_slice(), &DATA);

        // Seek
        raw_r.seek(SeekFrom::Start(2)).unwrap();
        let mut output = Vec::new();
        raw_r.read_to_end(&mut output).unwrap();
        assert_eq!(output.as_slice(), &DATA[2..]);
    }

    #[test]
    fn relative_seek() {
        let buf = Vec::new();

        // Write
        let mut raw_w = Box::new(RawLayerWriter::new(buf));
        raw_w.write_all(&DATA).unwrap();
        let data2 = b"abcdef";
        raw_w.write_all(data2).unwrap();
        raw_w.finalize().unwrap();

        // Read
        let buf = Cursor::new(raw_w.into_raw());
        let mut raw_r = Box::new(RawLayerReader::new(buf));
        raw_r.initialize().unwrap();
        let mut output = [0u8; 4];
        raw_r.read_exact(&mut output).unwrap();
        assert_eq!(&output, &DATA);

        // Start playing with relative seek
        raw_r.reset_position().unwrap();
        assert_eq!(raw_r.stream_position().unwrap(), 0);
        assert_eq!(raw_r.seek(SeekFrom::Current(-1)).unwrap(), 0);
        assert_eq!(raw_r.seek(SeekFrom::Current(1)).unwrap(), 1);
        let mut buf = Vec::new();
        raw_r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), b"bcdef");
        assert_eq!(raw_r.stream_position().unwrap(), data2.len() as u64);

        raw_r.rewind().unwrap();
        assert_eq!(raw_r.seek(SeekFrom::Start(3)).unwrap(), 3);
        let mut buf = Vec::new();
        raw_r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), b"def");
        assert_eq!(raw_r.stream_position().unwrap(), data2.len() as u64);

        assert_eq!(raw_r.seek(SeekFrom::End(0)).unwrap(), data2.len() as u64);
        assert_eq!(raw_r.seek(SeekFrom::End(-6)).unwrap(), 0);
        assert_eq!(raw_r.seek(SeekFrom::End(-10)).unwrap(), 0);
        assert_eq!(raw_r.seek(SeekFrom::End(-4)).unwrap(), 2);
        let mut buf = Vec::new();
        raw_r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.as_slice(), b"cdef");
        assert_eq!(raw_r.stream_position().unwrap(), data2.len() as u64);
    }

    #[test]
    fn basic_failsafe_ops() {
        let buf = Vec::new();

        // Write
        let mut raw_w = Box::new(RawLayerWriter::new(buf));
        raw_w.write_all(&DATA).unwrap();
        raw_w.finalize().unwrap();

        // Read
        let buf = raw_w.into_raw();
        let mut raw_r = Box::new(RawLayerFailSafeReader::new(buf.as_slice()));
        let mut output = Vec::new();
        raw_r.read_to_end(&mut output).unwrap();
        assert_eq!(output.as_slice(), &DATA);
    }

    #[test]
    fn basic_failsafe_truncated() {
        let buf = Vec::new();

        // Write
        let mut raw_w = Box::new(RawLayerWriter::new(buf));
        raw_w.write_all(&DATA).unwrap();
        raw_w.finalize().unwrap();

        // Read
        let buf = raw_w.into_raw();
        // Truncate at the middle
        let stop = buf.len() / 2;
        let mut raw_r = Box::new(RawLayerFailSafeReader::new(&buf[..stop]));
        let mut output = Vec::new();
        raw_r.read_to_end(&mut output).unwrap();
        // Thanks to the raw layer construction, we can recover `stop` bytes
        assert_eq!(output.as_slice(), &DATA[..stop]);
    }
}
