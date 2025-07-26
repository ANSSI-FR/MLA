use sha2::{Digest, Sha256, Sha512};
use std::io::Read;
use std::io::{self, Write};

pub(crate) type Sha256Hash = [u8; 32];

pub(crate) struct HashWrapperReader<'a, R: Read, H = Sha256> {
    /// Wrapper over a `impl Read` updating `hash` on each call to `read`
    inner: R,
    hash: &'a mut H,
}

impl<'a, R: Read, H> HashWrapperReader<'a, R, H> {
    pub(crate) fn new(inner: R, hash: &'a mut H) -> Self {
        Self { inner, hash }
    }

    pub(crate) fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read, H: Digest> Read for HashWrapperReader<'_, R, H> {
    /// Wrapper on inner with hash update
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(into)?;
        self.hash.update(&into[..read]);
        Ok(read)
    }
}

pub(crate) struct HashWrapperWriter<'a, W, H = Sha512> {
    /// Wrapper over a `impl Write` updating `hash` on each call to `write`
    inner: W,
    hash: &'a mut H,
}

impl<'a, W, H> HashWrapperWriter<'a, W, H> {
    pub(crate) fn new(inner: W, hash: &'a mut H) -> Self {
        Self { inner, hash }
    }

    pub(crate) fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write, H: Digest> Write for HashWrapperWriter<'_, W, H> {
    /// Wrapper on inner with hash update
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hash.update(buf);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
