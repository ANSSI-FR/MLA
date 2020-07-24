use sha2::{Digest, Sha256};
use std::io;
use std::io::Read;

pub(crate) type Sha256Hash = [u8; 32];

pub(crate) struct HashWrapperReader<'a, R: Read> {
    /// Wrapper over a `impl Read` updating `hash` on each call to `read`
    inner: R,
    hash: &'a mut Sha256,
}

impl<'a, R: Read> HashWrapperReader<'a, R> {
    pub(crate) fn new(inner: R, hash: &'a mut Sha256) -> Self {
        Self { inner, hash }
    }
}

impl<'a, R: Read> Read for HashWrapperReader<'a, R> {
    /// Wrapper on inner with hash update
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(into)?;
        self.hash.update(&into[..read]);
        Ok(read)
    }
}
