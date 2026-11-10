use std::ffi::OsStr;
use std::path;

use super::errors::FixtureError;
use super::errors::FixtureKind;
use super::errors::ResultChainExt;

/// A directory in the filesystem that is automatically deleted when
/// it goes out of scope.
///
/// The [`TempDir`] type creates a directory on the file system that
/// is deleted once it goes out of scope. At construction, the
/// `TempDir` creates a new directory with a randomly generated name.
///
/// The constructor, [`TempDir::new()`], creates directories in
/// the location returned by [`std::env::temp_dir()`].
///
/// After creating a `TempDir`, work with the file system by doing
/// standard [`std::fs`] file system operations on its [`Path`],
/// which can be retrieved with [`TempDir::path()`]. Once the `TempDir`
/// value is dropped, the directory at the path will be deleted, along
/// with any files and directories it contains. It is your responsibility
/// to ensure that no further file system operations are attempted
/// inside the temporary directory once it has been deleted.
///
/// # Resource Leaking
///
/// Various platform-specific conditions may cause `TempDir` to fail
/// to delete the underlying directory. It's important to ensure that
/// handles (like [`File`] and [`ReadDir`]) to files inside the
/// directory are dropped before the `TempDir` goes out of scope. The
/// `TempDir` destructor will silently ignore any errors in deleting
/// the directory; to instead handle errors call [`TempDir::close()`].
///
/// Note that if the program exits before the `TempDir` destructor is
/// run, such as via [`std::process::exit()`], by segfaulting, or by
/// receiving a signal like `SIGINT`, then the temporary directory
/// will not be deleted.
///
/// # Examples
///
/// Create a temporary directory with a generated name:
///
/// ```
/// use assert_fs::fixture::TempDir;
///
/// let tmp_dir = TempDir::new().unwrap();
///
/// // Ensure deletion happens.
/// tmp_dir.close().unwrap();
/// ```
///
/// [`File`]: std::fs::File
/// [`Path`]: std::path::Path
/// [`ReadDir`]: std::fs::ReadDir
#[derive(Debug)]
pub struct TempDir {
    temp: Inner,
}

#[derive(Debug)]
enum Inner {
    Temp(tempfile::TempDir),
    Persisted(path::PathBuf),
}

impl TempDir {
    /// Attempts to make a temporary directory inside of `env::temp_dir()`.
    ///
    /// The directory and everything inside it will be automatically deleted
    /// once the returned `TempDir` is destroyed.
    ///
    /// # Errors
    ///
    /// If the directory can not be created, `Err` is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use assert_fs::fixture::TempDir;
    ///
    /// let tmp_dir = TempDir::new().unwrap();
    ///
    /// // Ensure deletion happens.
    /// tmp_dir.close().unwrap();
    /// ```
    pub fn new() -> Result<Self, FixtureError> {
        let temp = tempfile::TempDir::new().chain(FixtureError::new(FixtureKind::CreateDir))?;
        let temp = Inner::Temp(temp);
        Ok(Self { temp })
    }

    /// Attempts to make a temporary directory inside of `dir`.
    ///
    /// The directory and everything inside it will be automatically deleted
    /// once the returned `TempDir` is destroyed.
    ///
    /// # Errors
    ///
    /// If the directory can not be created, `Err` is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use assert_fs::fixture::TempDir;
    ///
    /// // Create a directory inside of the current directory.
    /// let tmp_dir = TempDir::new_in(".").unwrap();
    ///
    /// // Ensure deletion happens.
    /// tmp_dir.close().unwrap();
    /// ```
    pub fn new_in<P: AsRef<path::Path>>(dir: P) -> Result<Self, FixtureError> {
        let temp =
            tempfile::TempDir::new_in(dir).chain(FixtureError::new(FixtureKind::CreateDir))?;
        let temp = Inner::Temp(temp);
        Ok(Self { temp })
    }

    /// Attempts to make a temporary directory with the specified prefix inside
    /// of `env::temp_dir()`.
    ///
    /// The directory and everything inside it will be automatically deleted
    /// once the returned `TempDir` is destroyed.
    ///
    /// # Errors
    ///
    /// If the directory can not be created, `Err` is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use assert_fs::fixture::TempDir;
    ///
    /// let tmp_dir = TempDir::with_prefix("foo-").unwrap();
    ///
    /// // Ensure deletion happens.
    /// tmp_dir.close().unwrap();
    /// ```
    pub fn with_prefix<S: AsRef<OsStr>>(prefix: S) -> Result<Self, FixtureError> {
        let temp = tempfile::TempDir::with_prefix(prefix)
            .chain(FixtureError::new(FixtureKind::CreateDir))?;
        let temp = Inner::Temp(temp);
        Ok(Self { temp })
    }

    /// Attempts to make a temporary directory with the specified prefix inside
    /// the specified directory.
    ///
    /// The directory and everything inside it will be automatically deleted
    /// once the returned `TempDir` is destroyed.
    ///
    /// # Errors
    ///
    /// If the directory can not be created, `Err` is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use assert_fs::fixture::TempDir;
    ///
    /// // Create a directory with prefix "foo-" inside the current directory.
    /// let tmp_dir = TempDir::with_prefix_in("foo-", ".").unwrap();
    ///
    /// // Ensure deletion happens.
    /// tmp_dir.close().unwrap();
    /// ```
    pub fn with_prefix_in<S: AsRef<OsStr>, P: AsRef<path::Path>>(
        prefix: S,
        dir: P,
    ) -> Result<Self, FixtureError> {
        let temp = tempfile::TempDir::with_prefix_in(prefix, dir)
            .chain(FixtureError::new(FixtureKind::CreateDir))?;
        let temp = Inner::Temp(temp);
        Ok(Self { temp })
    }

    /// Conditionally persist the temporary directory for debug purposes.
    ///
    /// Note: this operation is not reversible, i.e. `into_persistent_if(false)` is a no-op.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use assert_fs::fixture::TempDir;
    ///
    /// let tmp_dir = TempDir::new()
    ///     .unwrap()
    ///     .into_persistent_if(std::env::var_os("TEST_PERSIST_FILES").is_some());
    ///
    /// // Ensure deletion happens.
    /// tmp_dir.close().unwrap();
    /// ```
    pub fn into_persistent_if(self, yes: bool) -> Self {
        if !yes {
            return self;
        }

        self.into_persistent()
    }

    /// Persist the temporary directory for debug purposes.
    ///
    /// Note: this operation is not reversible, i.e. `into_persistent_if(false)` is a no-op.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use assert_fs::fixture::TempDir;
    ///
    /// let tmp_dir = TempDir::new()
    ///     .unwrap()
    ///     .into_persistent();
    ///
    /// // Ensure deletion happens.
    /// tmp_dir.close().unwrap();
    /// ```
    pub fn into_persistent(self) -> Self {
        let path = match self.temp {
            Inner::Temp(temp) => temp.into_path(),
            Inner::Persisted(path) => path,
        };
        let temp = Inner::Persisted(path);
        Self { temp }
    }

    /// Accesses the [`Path`] to the temporary directory.
    ///
    /// [`Path`]: std::path::Path
    ///
    /// # Examples
    ///
    /// ```
    /// use assert_fs::fixture::TempDir;
    ///
    /// let tmp_dir = TempDir::new().unwrap();
    ///
    /// println!("{}", tmp_dir.path().display());
    ///
    /// tmp_dir.close().unwrap();
    /// ```
    pub fn path(&self) -> &path::Path {
        match self.temp {
            Inner::Temp(ref temp) => temp.path(),
            Inner::Persisted(ref path) => path.as_path(),
        }
    }

    /// Closes and removes the temporary directory, returning a `Result`.
    ///
    /// Although `TempDir` removes the directory on drop, in the destructor
    /// any errors are ignored. To detect errors cleaning up the temporary
    /// directory, call `close` instead.
    ///
    /// # Errors
    ///
    /// This function may return a variety of [`std::io::Error`]s that result from deleting
    /// the files and directories contained with the temporary directory,
    /// as well as from deleting the temporary directory itself. These errors
    /// may be platform specific.
    ///
    ///
    /// # Examples
    ///
    /// ```
    /// use assert_fs::fixture::TempDir;
    ///
    /// let tmp_dir = TempDir::new().unwrap();
    ///
    /// // Ensure deletion happens.
    /// tmp_dir.close().unwrap();
    /// ```
    pub fn close(self) -> Result<(), FixtureError> {
        match self.temp {
            Inner::Temp(temp) => temp
                .close()
                .chain(FixtureError::new(FixtureKind::Cleanup))?,
            Inner::Persisted(_) => (),
        }
        Ok(())
    }
}

impl AsRef<path::Path> for TempDir {
    fn as_ref(&self) -> &path::Path {
        self.path()
    }
}

impl std::ops::Deref for TempDir {
    type Target = path::Path;
    #[inline]
    fn deref(&self) -> &path::Path {
        self.path()
    }
}
