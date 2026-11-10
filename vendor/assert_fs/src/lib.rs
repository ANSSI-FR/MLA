//! Filesystem fixtures and assertions for testing.
//!
//! `assert_fs` aims to simplify
//! - Setting up files for your tests to consume
//! - Asserting on files produced by your tests
//!
//! ## Overview
//!
//! Setting up a fixture
//! - [`TempDir`] or [`NamedTempFile`] for a sandbox to test in.
//! - [`touch`][`FileTouch`] a [`ChildPath`] or [`NamedTempFile`]
//! - [`write_binary`][`FileWriteBin`] a [`ChildPath`] or [`NamedTempFile`]
//! - [`write_str`][`FileWriteStr`] a [`ChildPath`] or [`NamedTempFile`]
//! - [`write_file`][`FileWriteFile`] a [`ChildPath`] or [`NamedTempFile`]
//! - [`copy_from`][`PathCopy`] a pristine folder to a [`ChildPath`] or [`TempDir`]
//! - [`symlink_to_file`][`SymlinkToFile`] a [`ChildPath`] or [`NamedTempFile`]
//! - [`symlink_to_dir`][`SymlinkToDir`] a [`ChildPath`] or [`TempDir`]
//!
//! Validating
//! - [`assert`][`PathAssert`] a [`ChildPath`], [`TempDir`], or [`NamedTempFile`]
//!
//! ## Example
//!
//! Here is a trivial example:
//!
//! ```rust
//! use assert_fs::prelude::*;
//! use predicates::prelude::*;
//!
//! let temp = assert_fs::TempDir::new().unwrap();
//! let input_file = temp.child("foo.txt");
//! input_file.touch().unwrap();
//!
//! // ... do something with input_file ...
//!
//! input_file.assert("");
//! temp.child("bar.txt").assert(predicate::path::missing());
//!
//! temp.close().unwrap();
//! ```
//!
//! [`ChildPath`]: fixture::ChildPath
//! [`FileTouch`]: fixture::FileTouch
//! [`FileWriteBin`]: fixture::FileWriteBin
//! [`FileWriteStr`]: fixture::FileWriteStr
//! [`FileWriteFile`]: fixture::FileWriteFile
//! [`SymlinkToDir`]: fixture::SymlinkToDir
//! [`SymlinkToFile`]: fixture::SymlinkToFile
//! [`PathCopy`]: fixture::PathCopy
//! [`PathAssert`]: assert::PathAssert
//! [dir-diff]: https://crates.io/crates/dir-diff

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::print_stderr)]
#![warn(clippy::print_stdout)]

pub mod assert;
pub mod fixture;

// Pulling this in for convenience-sake
#[doc(inline)]
pub use crate::fixture::TempDir;

// Pulling this in for convenience-sake
#[doc(inline)]
pub use crate::fixture::NamedTempFile;

/// Extension traits that are useful to have available.
pub mod prelude {
    pub use crate::assert::PathAssert;
    pub use crate::fixture::FileTouch;
    pub use crate::fixture::FileWriteBin;
    pub use crate::fixture::FileWriteFile;
    pub use crate::fixture::FileWriteStr;
    pub use crate::fixture::PathChild;
    pub use crate::fixture::PathCopy;
    pub use crate::fixture::PathCreateDir;
    pub use crate::fixture::SymlinkToDir;
    pub use crate::fixture::SymlinkToFile;
}

mod color;
use color::Palette;

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
