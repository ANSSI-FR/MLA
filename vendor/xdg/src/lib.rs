#![cfg(any(unix, target_os = "redox"))]

mod base_directories;
pub use crate::base_directories::{
    BaseDirectories, Error as BaseDirectoriesError, FileFindIterator,
};
