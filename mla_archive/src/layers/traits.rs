use crate::Error;
use std::io::{Read, Seek, Write};

/// Trait to be implemented by layer writers
pub trait LayerWriter<'a, W: Write>: Write {
    /// Unwraps the inner writer
    fn into_inner(self) -> Option<Box<dyn 'a + LayerWriter<'a, W>>>;

    /// Unwraps the original I/O writer
    // Use a Box<Self> to be able to move out the inner value; without it, self
    // is used, which is an unsized 'dyn X' and therefore cannot be moved
    fn into_raw(self: Box<Self>) -> W;

    /// Finalize the current layer, like adding the footer.
    ///
    /// This method is responsible of recursively calling (postfix) `finalize`
    /// on inner layer if any
    fn finalize(&mut self) -> Result<(), Error>;
}

/// Trait to be implemented by layer readers
pub trait LayerReader<'a, R: Read + Seek>: Read + Seek {
    /// Unwraps the inner reader
    fn into_inner(self) -> Option<Box<dyn 'a + LayerReader<'a, R>>>;

    /// Unwraps the original I/O reader
    // Use a Box<Self> to be able to move out the inner value; without it, self
    // is used, which is an unsized 'dyn X' and therefore cannot be moved
    fn into_raw(self: Box<Self>) -> R;

    /// Initialize the current layer, like reading the footer.
    ///
    /// This method is responsible of recursively calling (postfix) `initialize`
    /// on inner layer if any
    fn initialize(&mut self) -> Result<(), Error>;
}

/// Trait to be implemented by layer for their fail-safe mode reading
pub trait LayerFailSafeReader<'a, R: Read>: Read {
    /// Unwraps the inner reader
    fn into_inner(self) -> Option<Box<dyn 'a + LayerFailSafeReader<'a, R>>>;

    /// Unwraps the original I/O reader
    // Use a Box<Self> to be able to move out the inner value; without it, self
    // is used, which is an unsized 'dyn X' and therefore cannot be moved
    fn into_raw(self: Box<Self>) -> R;
}
