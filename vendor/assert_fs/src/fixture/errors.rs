//! Error types for fixtures.

use std::error::Error;
use std::fmt;

pub(crate) trait ChainError {
    fn chain<F>(self, cause: F) -> Self
    where
        F: Error + Send + Sync + 'static;
}

pub(crate) trait ResultChainExt<T> {
    fn chain<C>(self, chainable: C) -> Result<T, C>
    where
        C: ChainError;
}

impl<T, E> ResultChainExt<T> for Result<T, E>
where
    E: Error + Send + Sync + 'static,
{
    fn chain<C>(self, chainable: C) -> Result<T, C>
    where
        C: ChainError,
    {
        self.map_err(|e| chainable.chain(e))
    }
}

/// Fixture initialization cause.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixtureKind {
    /// Failed when walking the source tree.
    Walk,
    /// Failed when copying a file.
    CopyFile,
    /// Failed when writing to a file.
    WriteFile,
    /// Failed when creating a directory.
    CreateDir,
    /// Failed to cleanup fixture.
    Cleanup,
    /// Failed to create symlink
    Symlink,
}

impl fmt::Display for FixtureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Walk => write!(f, "Failed when walking the source tree,"),
            Self::CopyFile => write!(f, "Failed when copying a file."),
            Self::WriteFile => write!(f, "Failed when writing to a file."),
            Self::CreateDir => write!(f, "Failed when creating a directory."),
            Self::Cleanup => write!(f, "Failed to cleanup fixture."),
            Self::Symlink => write!(f, "Failed when symlinking to the target."),
        }
    }
}

/// Failure when initializing the fixture.
#[derive(Debug)]
pub struct FixtureError {
    kind: FixtureKind,
    cause: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl FixtureError {
    /// Create a `FixtureError`.
    pub fn new(kind: FixtureKind) -> Self {
        Self { kind, cause: None }
    }

    /// Fixture initialization cause.
    pub fn kind(&self) -> FixtureKind {
        self.kind
    }
}

impl Error for FixtureError {
    fn description(&self) -> &str {
        "Failed to initialize fixture"
    }

    fn cause(&self) -> Option<&dyn Error> {
        self.cause.as_ref().map(|c| {
            let c: &dyn Error = c.as_ref();
            c
        })
    }
}

impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.cause {
            Some(ref cause) => write!(
                f,
                "Failed to initialize fixture: {}\nCause: {}",
                self.kind, cause
            ),
            None => write!(f, "Failed to initialize fixture: {}", self.kind),
        }
    }
}

impl ChainError for FixtureError {
    fn chain<F>(mut self, cause: F) -> Self
    where
        F: Error + Send + Sync + 'static,
    {
        self.cause = Some(Box::new(cause));
        self
    }
}
