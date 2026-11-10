//! Filesystem assertions.
//!
//! See [`PathAssert`].
//!
//! # Examples
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

use std::fmt;
use std::path;

#[cfg(feature = "color")]
use anstream::panic;
use predicates::path::PredicateFileContentExt;
use predicates::str::PredicateStrExt;
use predicates_tree::CaseTreeExt;

use crate::fixture;

/// Assert the state of files within [`TempDir`].
///
/// This uses [`IntoPathPredicate`] to provide short-hands for common cases, accepting:
/// - `Predicate<Path>` for validating a path.
/// - `Predicate<str>` for validating the content of the file.
/// - `&[u8]` or `&str` representing the content of the file.
///
/// See [`predicates`] for more predicates.
///
/// # Examples
///
/// ```rust
/// use assert_fs::prelude::*;
/// use predicates::prelude::*;
///
/// let temp = assert_fs::TempDir::new().unwrap();
/// let input_file = temp.child("foo.txt");
/// input_file.touch().unwrap();
///
/// // ... do something with input_file ...
///
/// input_file.assert("");
/// temp.child("bar.txt").assert(predicate::path::missing());
///
/// temp.close().unwrap();
/// ```
///
/// [`TempDir`]: super::TempDir
pub trait PathAssert {
    /// Assert the state of files within [`TempDir`].
    ///
    /// This uses [`IntoPathPredicate`] to provide short-hands for common cases, accepting:
    /// - `Predicate<Path>` for validating a path.
    /// - `Predicate<str>` for validating the content of the file.
    /// - `&[u8]` or `&str` representing the content of the file.
    ///
    /// See [`predicates`] for more predicates.
    ///
    /// # Panic
    ///
    /// Will panic if the condition is not satisfied
    ///
    /// # Examples
    ///
    /// ```rust
    /// use assert_fs::prelude::*;
    /// use predicates::prelude::*;
    ///
    /// let temp = assert_fs::TempDir::new().unwrap();
    /// let input_file = temp.child("foo.txt");
    /// input_file.touch().unwrap();
    ///
    /// // ... do something with input_file ...
    ///
    /// input_file.assert("");
    /// // or
    /// input_file.assert(predicate::str::is_empty());
    ///
    /// temp.child("bar.txt").assert(predicate::path::missing());
    ///
    /// temp.close().unwrap();
    /// ```
    ///
    /// [`TempDir`]: super::TempDir
    #[track_caller]
    fn assert<I, P>(&self, pred: I) -> &Self
    where
        I: IntoPathPredicate<P>,
        P: predicates_core::Predicate<path::Path>;
}

impl PathAssert for fixture::TempDir {
    #[track_caller]
    fn assert<I, P>(&self, pred: I) -> &Self
    where
        I: IntoPathPredicate<P>,
        P: predicates_core::Predicate<path::Path>,
    {
        assert(self.path(), pred);
        self
    }
}

impl PathAssert for fixture::NamedTempFile {
    #[track_caller]
    fn assert<I, P>(&self, pred: I) -> &Self
    where
        I: IntoPathPredicate<P>,
        P: predicates_core::Predicate<path::Path>,
    {
        assert(self.path(), pred);
        self
    }
}

impl PathAssert for fixture::ChildPath {
    #[track_caller]
    fn assert<I, P>(&self, pred: I) -> &Self
    where
        I: IntoPathPredicate<P>,
        P: predicates_core::Predicate<path::Path>,
    {
        assert(self.path(), pred);
        self
    }
}

#[track_caller]
fn assert<I, P>(path: &path::Path, pred: I)
where
    I: IntoPathPredicate<P>,
    P: predicates_core::Predicate<path::Path>,
{
    let pred = pred.into_path();
    if let Some(case) = pred.find_case(false, path) {
        let palette = crate::Palette::color();
        panic!(
            "Unexpected file, failed {:#}\n{:#}={:#}",
            case.tree(),
            palette.key("path"),
            palette.value(path.display())
        );
    }
}

/// Used by [`PathAssert`] to convert Self into the needed [`predicates_core::Predicate<Path>`].
///
/// # Examples
///
/// ```rust
/// use std::path;
///
/// use assert_fs::prelude::*;
/// use predicates::prelude::*;
///
/// let temp = assert_fs::TempDir::new().unwrap();
///
/// // ... do something with input_file ...
///
/// temp.child("bar.txt").assert(predicate::path::missing()); // Uses IntoPathPredicate
///
/// temp.close().unwrap();
/// ```
pub trait IntoPathPredicate<P>
where
    P: predicates_core::Predicate<path::Path>,
{
    /// The type of the predicate being returned.
    type Predicate;

    /// Convert to a predicate for testing a path.
    fn into_path(self) -> P;
}

impl<P> IntoPathPredicate<P> for P
where
    P: predicates_core::Predicate<path::Path>,
{
    type Predicate = P;

    fn into_path(self) -> Self::Predicate {
        self
    }
}

/// Keep `predicates` concrete Predicates out of our public API.
/// [`predicates_core::Predicate`] used by [`IntoPathPredicate`] for bytes.
///
/// # Example
///
/// ```rust
/// use assert_fs::prelude::*;
///
/// let temp = assert_fs::TempDir::new().unwrap();
/// let input_file = temp.child("foo.txt");
/// input_file.touch().unwrap();
///
/// // ... do something with input_file ...
///
/// input_file.assert(b"" as &[u8]); // uses BytesContentPathPredicate
///
/// temp.close().unwrap();
/// ```
#[derive(Debug)]
pub struct BytesContentPathPredicate(
    predicates::path::FileContentPredicate<predicates::ord::EqPredicate<&'static [u8]>>,
);

impl BytesContentPathPredicate {
    pub(crate) fn new(value: &'static [u8]) -> Self {
        let pred = predicates::ord::eq(value).from_file_path();
        Self(pred)
    }
}

impl predicates_core::reflection::PredicateReflection for BytesContentPathPredicate {
    fn parameters<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = predicates_core::reflection::Parameter<'a>> + 'a> {
        self.0.parameters()
    }

    /// Nested `Predicate`s of the current `Predicate`.
    fn children<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = predicates_core::reflection::Child<'a>> + 'a> {
        self.0.children()
    }
}

impl predicates_core::Predicate<path::Path> for BytesContentPathPredicate {
    fn eval(&self, item: &path::Path) -> bool {
        self.0.eval(item)
    }

    fn find_case<'a>(
        &'a self,
        expected: bool,
        variable: &path::Path,
    ) -> Option<predicates_core::reflection::Case<'a>> {
        self.0.find_case(expected, variable)
    }
}

impl fmt::Display for BytesContentPathPredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl IntoPathPredicate<BytesContentPathPredicate> for &'static [u8] {
    type Predicate = BytesContentPathPredicate;

    fn into_path(self) -> Self::Predicate {
        Self::Predicate::new(self)
    }
}

/// Keep `predicates` concrete Predicates out of our public API.
/// [`predicates_core::Predicate`] used by `IntoPathPredicate` for `str`.
///
/// # Example
///
/// ```rust
/// use assert_fs::prelude::*;
///
/// let temp = assert_fs::TempDir::new().unwrap();
/// let input_file = temp.child("foo.txt");
/// input_file.touch().unwrap();
///
/// // ... do something with input_file ...
///
/// input_file.assert(""); // Uses StrContentPathPredicate
///
/// temp.close().unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct StrContentPathPredicate(
    predicates::path::FileContentPredicate<
        predicates::str::Utf8Predicate<predicates::str::DifferencePredicate>,
    >,
);

impl StrContentPathPredicate {
    pub(crate) fn new(value: String) -> Self {
        let pred = predicates::str::diff(value).from_utf8().from_file_path();
        Self(pred)
    }
}

impl predicates_core::reflection::PredicateReflection for StrContentPathPredicate {
    fn parameters<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = predicates_core::reflection::Parameter<'a>> + 'a> {
        self.0.parameters()
    }

    /// Nested `Predicate`s of the current `Predicate`.
    fn children<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = predicates_core::reflection::Child<'a>> + 'a> {
        self.0.children()
    }
}

impl predicates_core::Predicate<path::Path> for StrContentPathPredicate {
    fn eval(&self, item: &path::Path) -> bool {
        self.0.eval(item)
    }

    fn find_case<'a>(
        &'a self,
        expected: bool,
        variable: &path::Path,
    ) -> Option<predicates_core::reflection::Case<'a>> {
        self.0.find_case(expected, variable)
    }
}

impl fmt::Display for StrContentPathPredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl IntoPathPredicate<StrContentPathPredicate> for String {
    type Predicate = StrContentPathPredicate;

    fn into_path(self) -> Self::Predicate {
        Self::Predicate::new(self)
    }
}

impl IntoPathPredicate<StrContentPathPredicate> for &str {
    type Predicate = StrContentPathPredicate;

    fn into_path(self) -> Self::Predicate {
        Self::Predicate::new(self.to_owned())
    }
}

impl IntoPathPredicate<StrContentPathPredicate> for &String {
    type Predicate = StrContentPathPredicate;

    fn into_path(self) -> Self::Predicate {
        Self::Predicate::new(self.to_owned())
    }
}

/// Keep `predicates` concrete Predicates out of our public API.
/// [`predicates_core::Predicate`] used by `IntoPathPredicate` for `str` predicates.
///
/// # Example
///
/// ```rust
/// use assert_fs::prelude::*;
/// use predicates::prelude::*;
///
/// let temp = assert_fs::TempDir::new().unwrap();
/// let input_file = temp.child("foo.txt");
/// input_file.touch().unwrap();
///
/// // ... do something with input_file ...
///
/// input_file.assert(predicate::str::is_empty()); // Uses StrPathPredicate
///
/// temp.close().unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct StrPathPredicate<P: predicates_core::Predicate<str>>(
    predicates::path::FileContentPredicate<predicates::str::Utf8Predicate<P>>,
);

impl<P> StrPathPredicate<P>
where
    P: predicates_core::Predicate<str>,
{
    pub(crate) fn new(value: P) -> Self {
        let pred = value.from_utf8().from_file_path();
        Self(pred)
    }
}

impl<P> predicates_core::reflection::PredicateReflection for StrPathPredicate<P>
where
    P: predicates_core::Predicate<str>,
{
    fn parameters<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = predicates_core::reflection::Parameter<'a>> + 'a> {
        self.0.parameters()
    }

    /// Nested `Predicate`s of the current `Predicate`.
    fn children<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = predicates_core::reflection::Child<'a>> + 'a> {
        self.0.children()
    }
}

impl<P> predicates_core::Predicate<path::Path> for StrPathPredicate<P>
where
    P: predicates_core::Predicate<str>,
{
    fn eval(&self, item: &path::Path) -> bool {
        self.0.eval(item)
    }

    fn find_case<'a>(
        &'a self,
        expected: bool,
        variable: &path::Path,
    ) -> Option<predicates_core::reflection::Case<'a>> {
        self.0.find_case(expected, variable)
    }
}

impl<P> fmt::Display for StrPathPredicate<P>
where
    P: predicates_core::Predicate<str>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<P> IntoPathPredicate<StrPathPredicate<P>> for P
where
    P: predicates_core::Predicate<str>,
{
    type Predicate = StrPathPredicate<P>;

    fn into_path(self) -> Self::Predicate {
        Self::Predicate::new(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use predicates::prelude::*;

    // Since IntoPathPredicate exists solely for conversion, test it under that scenario to ensure
    // it works as expected.
    fn convert_path<I, P>(pred: I) -> P
    where
        I: IntoPathPredicate<P>,
        P: Predicate<path::Path>,
    {
        pred.into_path()
    }

    #[test]
    fn into_path_from_pred() {
        let pred = convert_path(predicate::eq(path::Path::new("hello.md")));
        let case = pred.find_case(false, path::Path::new("hello.md"));
        println!("Failing case: {case:?}");
        assert!(case.is_none());
    }

    #[test]
    fn into_path_from_bytes() {
        let pred = convert_path(b"hello\n" as &[u8]);
        let case = pred.find_case(false, path::Path::new("tests/fixture/hello.txt"));
        println!("Failing case: {case:?}");
        assert!(case.is_none());
    }

    #[test]
    fn into_path_from_str() {
        let pred = convert_path("hello\n");
        let case = pred.find_case(false, path::Path::new("tests/fixture/hello.txt"));
        println!("Failing case: {case:?}");
        assert!(case.is_none());
    }
}
