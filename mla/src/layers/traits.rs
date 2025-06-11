use crate::Error;
use std::io::{Read, Seek, Write};

// Here, feature `send` is used to force `Send` on Box<dyn> type
// Indeed, the auto-derivation of Send is not able to automatically propagates it
// As a result, forcing `Send` on the Layers forces it on the initial `W` (writable) and `R` (readable) types
// To avoid this restriction when `Send` is not required, a feature is used

/// Type alias for Layer Writer inner type
#[cfg(not(feature = "send"))]
pub type InnerWriterType<'a, W> = Box<dyn 'a + LayerWriter<'a, W>>;
#[cfg(feature = "send")]
pub type InnerWriterType<'a, W> = Box<dyn 'a + LayerWriter<'a, W> + Send>;

/// Trait alias for Layer Writer writable destination
// Type aliases are not yet stable
// See https://github.com/rust-lang/rust/issues/41517
// -> use a dummy trait instead
#[cfg(not(feature = "send"))]
pub trait InnerWriterTrait: Write {}
#[cfg(not(feature = "send"))]
impl<T: Write> InnerWriterTrait for T {}

#[cfg(feature = "send")]
pub trait InnerWriterTrait: Write + Send {}
#[cfg(feature = "send")]
impl<T: Write + Send> InnerWriterTrait for T {}

/// Trait to be implemented by layer writers
pub trait LayerWriter<'a, W: InnerWriterTrait>: Write {
    /// Finalize the current layer, like adding the footer.
    ///
    /// This method is responsible of recursively calling (postfix) `finalize`
    /// on inner layer if any
    fn finalize(self: Box<Self>) -> Result<W, Error>;
}

/// Trait alias for Layer Reader readable source
// Type aliases are not yet stable
// See https://github.com/rust-lang/rust/issues/41517
// -> use a dummy trait instead
#[cfg(not(feature = "send"))]
pub trait InnerReaderTrait: Read + Seek {}
#[cfg(not(feature = "send"))]
impl<T: Read + Seek> InnerReaderTrait for T {}

#[cfg(feature = "send")]
pub trait InnerReaderTrait: Read + Seek + Send {}
#[cfg(feature = "send")]
impl<T: Read + Seek + Send> InnerReaderTrait for T {}

/// Trait to be implemented by layer readers
pub trait LayerReader<'a, R: InnerReaderTrait>: InnerReaderTrait {
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
pub trait LayerFailSafeReader<'a, R: Read>: Read {}
