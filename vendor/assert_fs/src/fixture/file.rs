use std::ffi;
use std::path;

use super::errors::FixtureError;
use super::errors::FixtureKind;
use super::errors::ResultChainExt;

/// A potential file in the filesystem that is automatically deleted when
/// it goes out of scope.
///
/// The [`NamedTempFile`] type creates a directory on the file system that
/// is deleted once it goes out of scope. At construction, the
/// `NamedTempFile` creates a new directory with a randomly generated name.
///
/// The constructor, [`NamedTempFile::new`], creates directories in
/// the location returned by [`std::env::temp_dir()`].
///
/// After creating a `NamedTempFile`, work with the file system by doing
/// standard [`std::fs`] file system operations on its [`Path`],
/// which can be retrieved with [`NamedTempFile::path()`]. Once the `NamedTempFile`
/// value is dropped, the parent directory will be deleted, along with the file. It is your
/// responsibility to ensure that no further file system operations are attempted inside the
/// temporary directory once it has been deleted.
///
/// # Resource Leaking
///
/// Various platform-specific conditions may cause `NamedTempFile` to fail
/// to delete the underlying directory. It's important to ensure that
/// handles (like [`File`] and [`ReadDir`]) to the file inside the
/// directory is dropped before the `NamedTempFile` goes out of scope. The
/// `NamedTempFile` destructor will silently ignore any errors in deleting
/// the directory; to instead handle errors call [`NamedTempFile::close()`].
///
/// Note that if the program exits before the `NamedTempFile` destructor is
/// run, such as via [`std::process::exit()`], by segfaulting, or by
/// receiving a signal like `SIGINT`, then the temporary directory
/// will not be deleted.
///
/// # Examples
///
/// Create a temporary file.
///
/// ```
/// use assert_fs::fixture::NamedTempFile;
///
/// let tmp_file = NamedTempFile::new("foo.rs").unwrap();
///
/// // Ensure deletion happens.
/// tmp_file.close().unwrap();
/// ```
///
/// [`File`]: std::fs::File
/// [`Path`]: std::path::Path
/// [`ReadDir`]: std::fs::ReadDir
#[derive(Debug)]
pub struct NamedTempFile {
    temp: Inner,
    path: path::PathBuf,
}

#[derive(Debug)]
enum Inner {
    Temp(tempfile::TempDir),
    Persisted,
}

impl NamedTempFile {
    /// Attempts to make a temporary file inside of `env::temp_dir()`.
    ///
    /// The file and parent directory will be automatically deleted once the returned
    /// `NamedTempFile` is destroyed.
    ///
    /// # Errors
    ///
    /// If the parent directory can not be created, `Err` is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use assert_fs::fixture::NamedTempFile;
    ///
    /// let tmp_file = NamedTempFile::new("foo.rs").unwrap();
    ///
    /// // Ensure deletion happens.
    /// tmp_file.close().unwrap();
    /// ```
    pub fn new<S>(name: S) -> Result<Self, FixtureError>
    where
        S: AsRef<ffi::OsStr>,
    {
        let temp = tempfile::TempDir::new().chain(FixtureError::new(FixtureKind::CreateDir))?;
        let path = temp.path().join(name.as_ref());
        let temp = Inner::Temp(temp);
        Ok(Self { temp, path })
    }

    /// Conditionally persist the temporary file for debug purposes.
    ///
    /// Note: this operation is not reversible, i.e. `into_persistent_if(false)` is a no-op.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use assert_fs::fixture::NamedTempFile;
    ///
    /// let tmp_file = NamedTempFile::new("foo.rs")
    ///     .unwrap()
    ///     .into_persistent_if(std::env::var_os("TEST_PERSIST_FILES").is_some());
    ///
    /// // Ensure deletion happens.
    /// tmp_file.close().unwrap();
    /// ```
    pub fn into_persistent_if(self, yes: bool) -> Self {
        if !yes {
            return self;
        }

        self.into_persistent()
    }

    /// Persist the temporary file for debug purposes.
    ///
    /// Note: this operation is not reversible, i.e. `into_persistent_if(false)` is a no-op.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use assert_fs::fixture::NamedTempFile;
    ///
    /// let tmp_file = NamedTempFile::new("foo.rs")
    ///     .unwrap()
    ///     .into_persistent();
    ///
    /// // Ensure deletion happens.
    /// tmp_file.close().unwrap();
    /// ```
    pub fn into_persistent(mut self) -> Self {
        let mut temp = Inner::Persisted;
        ::std::mem::swap(&mut self.temp, &mut temp);
        if let Inner::Temp(temp) = temp {
            _ = temp.into_path();
        }

        self
    }

    /// Accesses the [`Path`] to the temporary file.
    ///
    /// [`Path`]: std::path::Path
    ///
    /// # Examples
    ///
    /// ```
    /// use assert_fs::fixture::NamedTempFile;
    ///
    /// let tmp_file = NamedTempFile::new("foo.rs").unwrap();
    ///
    /// println!("{}", tmp_file.path().display());
    ///
    /// // Ensure deletion happens.
    /// tmp_file.close().unwrap();
    /// ```
    pub fn path(&self) -> &path::Path {
        &self.path
    }

    /// Closes and removes the temporary file and parent directory, returning a `Result`.
    ///
    /// Although `NamedTempFile` removes the directory on drop, in the destructor
    /// any errors are ignored. To detect errors cleaning up the temporary
    /// directory, call `close` instead.
    ///
    /// # Errors
    ///
    /// This function may return a variety of [`std::io::Error`]s that result from deleting the
    /// temporary file and parent directory, These errors may be platform specific.
    ///
    ///
    /// # Examples
    ///
    /// ```
    /// use assert_fs::fixture::NamedTempFile;
    ///
    /// let tmp_file = NamedTempFile::new("foo.rs").unwrap();
    ///
    /// // Ensure deletion happens.
    /// tmp_file.close().unwrap();
    /// ```
    pub fn close(self) -> Result<(), FixtureError> {
        match self.temp {
            Inner::Temp(temp) => temp
                .close()
                .chain(FixtureError::new(FixtureKind::Cleanup))?,
            Inner::Persisted => (),
        }
        Ok(())
    }
}

impl AsRef<path::Path> for NamedTempFile {
    fn as_ref(&self) -> &path::Path {
        self.path()
    }
}

impl std::ops::Deref for NamedTempFile {
    type Target = path::Path;
    #[inline]
    fn deref(&self) -> &path::Path {
        self.path()
    }
}
