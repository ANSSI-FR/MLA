//! Handling of archive entries and their name
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};

use crate::{MLADeserialize, MLASerialize, errors::Error, format::ArchiveEntryBlock};

/// Represents a unique identifier for an entry in the archive.
/// Used to maintain references to entries while writing an archive.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct ArchiveEntryId(pub u64);

impl<W: Write> MLASerialize<W> for ArchiveEntryId {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        self.0.serialize(dest)
    }
}

impl<R: Read> MLADeserialize<R> for ArchiveEntryId {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        Ok(ArchiveEntryId(u64::deserialize(src)?))
    }
}

mod entryname {
    use std::{
        ffi::OsStr,
        fmt,
        path::{Component, Path, PathBuf},
    };

    use crate::{FILENAME_MAX_SIZE, helpers::mla_percent_escape};

    /// Allowed bytes in `EntryName::to_pathbuf_escaped_string` output. Documented there.
    pub static ENTRY_NAME_PATHBUF_ESCAPED_STRING_ALLOWED_BYTES: [u8; 66] =
        *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_/";
    /// Allowed bytes in `EntryName::raw_content_to_escaped_string` output. Documented there.
    pub static ENTRY_NAME_RAW_CONTENT_ALLOWED_BYTES: [u8; 65] =
        *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_";

    // https://github.com/MicrosoftDocs/win32/blob/63e70903d18b0637e62ffab6656c4a388ef0f2ce/desktop-src/FileIO/naming-a-file.md
    #[cfg(target_family = "windows")]
    static WINDOWS_FORBIDDEN_PATH_BYTES: [u8; 40] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, b'"', b'*', b':', b'<', b'>', b'?', 0x5C, b'|',
    ];
    #[cfg(target_family = "windows")]
    static WINDOWS_FORBIDDEN_NAMES: [&[u8]; 31] = [
        b"con",
        b"prn",
        b"aux",
        b"nul",
        b"com1",
        b"com2",
        b"com3",
        b"com4",
        b"com5",
        b"com6",
        b"com7",
        b"com8",
        b"com9",
        b"com\xc2\xb2",
        b"com\xc2\xb3",
        b"com\xc2\xb9",
        b"lpt1",
        b"lpt2",
        b"lpt3",
        b"lpt4",
        b"lpt5",
        b"lpt6",
        b"lpt7",
        b"lpt8",
        b"lpt9",
        b"lpt\xc2\xb2",
        b"lpt\xc2\xb3",
        b"lpt\xc2\xb9",
        b"clock$",
        b"conin$",
        b"conout$",
    ];

    #[derive(Debug)]
    pub enum EntryNameError {
        ForbiddenPathTraversalComponent,
        InvalidPathComponentContent,
        EntryNameTooLong,
    }

    impl fmt::Display for EntryNameError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
            write!(
                f,
                "{}",
                match self {
                    EntryNameError::ForbiddenPathTraversalComponent =>
                        "forbidden path traversal component",
                    EntryNameError::InvalidPathComponentContent => "invalid path component",
                    EntryNameError::EntryNameTooLong => "entry name is too long",
                }
            )
        }
    }

    impl std::error::Error for EntryNameError {}

    /// Arbitrary bytes representing an archive entry name. WARNING, see rest of its documentation.
    ///
    /// Every constructor ensures it is not empty.
    ///
    /// See `doc/ENTRY_NAME.md` for more details.
    #[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
    pub struct EntryName {
        name: Vec<u8>,
    }

    impl fmt::Debug for EntryName {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "EntryName \"{}\"", self.raw_content_to_escaped_string())
        }
    }

    impl EntryName {
        /// Constructs an `EntryName` from a borrowed byte slice.
        ///
        /// Use with caution: arbitrary bytes are stored as-is, without checking for nulls,
        /// slashes, path traversal (`..`), or encoding. This function is useful when reading
        /// raw archive entries or crafting low-level names.
        ///
        /// Prefer using [`EntryName::from_path`] if you're working with real filesystem paths.
        ///
        /// Returns an `EntryNameError::InvalidPathComponentContent` if the slice is empty,
        /// or `EntryNameError::EntryNameTooLong` if it exceeds `FILENAME_MAX_SIZE`.
        pub fn from_arbitrary_bytes(bytes: &[u8]) -> Result<Self, EntryNameError> {
            Self::from_arbitrary_bytes_vec(bytes.to_vec())
        }

        /// Like [`EntryName::from_arbitrary_bytes`], but takes ownership of the byte vector.
        ///
        /// Stores the bytes directly with no validation for slashes, nulls, control characters, or encoding.
        /// Useful for low-level operations. Returns an error if the input is empty or too long.
        pub fn from_arbitrary_bytes_vec(bytes: Vec<u8>) -> Result<Self, EntryNameError> {
            let u64len =
                u64::try_from(bytes.len()).map_err(|_| EntryNameError::EntryNameTooLong)?;
            if bytes.is_empty() {
                Err(EntryNameError::InvalidPathComponentContent)
            } else if u64len > FILENAME_MAX_SIZE {
                Err(EntryNameError::EntryNameTooLong)
            } else {
                Ok(Self { name: bytes })
            }
        }

        /// WARNING: you are given bytes controlled by the one who made the entry name.
        /// It may contain arbitrary bytes like slash, backslash, `..`,
        /// `C:\\{}...]`, newline, spaces, carriage return, terminal escape sequences,
        /// Unicode chars like U+0085 or RTLO, HTML, SQL, semicolons, homoglyphs, etc.
        pub fn as_arbitrary_bytes(&self) -> &[u8] {
            self.name.as_slice()
        }

        /// Converts a `Path` into an `EntryName`, with normalization and platform-aware encoding.
        ///
        /// The path is first normalized:
        /// - Only `Component::Normal` parts are kept.
        /// - Each `..` removes the previous component, if any.
        ///
        /// On Windows:
        /// - The path is converted from UTF-16LE to UTF-8.
        /// - Backslashes are replaced with slashes (`/`) before serialization.
        ///
        /// On Unix:
        /// - The path is serialized as-is.
        ///
        /// This normalization ensures that a path converted with [`EntryName::from_path`] on one OS
        /// and converted back using [`EntryName::to_pathbuf`] on another OS will likely retain the
        /// intended structure.
        ///
        /// Errors:
        /// - Returns `EntryNameError::InvalidPathComponentContent` if the resulting path is empty
        ///   or contains invalid characters (on Windows).
        /// - Returns `EntryNameError::EntryNameTooLong` if the resulting name exceeds `FILENAME_MAX_SIZE`.
        pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, EntryNameError> {
            let components = {
                let mut stack = Vec::new();
                for component in path.as_ref().components() {
                    match component {
                        Component::Prefix(_) | Component::RootDir | Component::CurDir => (),
                        Component::ParentDir => {
                            stack.pop();
                        }
                        Component::Normal(os_str) => {
                            stack.push(normal_component_osstr_to_bytes(os_str)?);
                        }
                    }
                }
                stack
            };
            let name = components.join(&b'/');
            Self::from_arbitrary_bytes_vec(name)
        }

        /// Escaped String representation of an `EntryName` raw content bytes
        ///
        /// See `doc/ENTRY_NAME.md`
        ///
        /// You may want to use `EntryName::to_pathbuf_escaped_string` which has
        /// a different encoding than this function but cannot represent arbitrary bytes.
        ///
        /// You may prefer another encoding tailored to where the name will be used.
        /// See `EntryName::as_arbitrary_bytes` documentation.
        pub fn raw_content_to_escaped_string(&self) -> String {
            String::from_utf8(mla_percent_escape(
                &self.name,
                ENTRY_NAME_RAW_CONTENT_ALLOWED_BYTES.as_slice(),
            ))
            .unwrap()
        }

        /// WARNING: you are given path components controlled by the one who made the entry name.
        /// The resulting `PathBuf` may contain almost arbitrary bytes like
        /// slash, backslash, newline, carriage return, terminal escape sequences,
        /// Unicode chars like U+0085 or RTLO, etc.
        ///
        /// Please also keep in mind that two different `EntryName` or returned
        /// `PathBuf` may map to same path on OS (eg. Windows case
        /// insensitivity; Windows trailing dots, whitespace (including
        /// things like ogham space mark); zero-width unicode chars on
        /// HFS+; etc.).
        ///
        /// The OS may not allow creating files with the returned `PathBuf` if
        /// it contains some forbidden characters (eg. Windows).
        ///
        /// This function returns the path interpretation of an entry name.
        /// This function checks for validity against rules described in
        /// `doc/ENTRY_NAME.md` and only them.
        /// For example, the returned `PathBuf` will only contain
        /// `std::path::Component::Normal` components.
        /// Otherwise an `EntryNameError` is returned.
        ///
        /// You may want to perform other checks on the resulting `PathBuf` depending on how it will be used.
        ///
        /// For display or other purpose, you may want to use `EntryName::to_pathbuf_escaped_string`.
        ///
        /// Details are documented in `doc/ENTRY_NAME.md`.
        ///
        /// See `EntryName::from_path`.
        pub fn to_pathbuf(&self) -> Result<PathBuf, EntryNameError> {
            check_os_indep_path_rules(&self.name)?;
            to_pathbuf_os(&self.name)
        }

        /// Escaped String representation of an `EntryName` as a path
        ///
        /// See `doc/ENTRY_NAME.md`
        ///
        /// Computed with `self::to_pathbuf()?`, followed by enforcement of
        /// slash as a separator, encoded as UTF-8 bytes and
        /// escaped with `helpers::mla_percent_escape` preserving
        /// ASCII slash, ASCII alphanumeric chars and ASCII dot.
        ///
        /// This differs from `EntryName::raw_content_to_escaped_string` with
        /// regards to path restrictions and separator representation.
        ///
        /// You may prefer another encoding tailored to where the name will be used.
        /// See `EntryName::to_pathbuf` documentation.
        pub fn to_pathbuf_escaped_string(&self) -> Result<String, EntryNameError> {
            let pathbuf = self.to_pathbuf()?;
            let components = pathbuf
                .components()
                .map(to_normal_component_osstr)
                .collect::<Result<Vec<_>, EntryNameError>>()?;
            let slash_separated_osstr = components.join("/".as_ref());
            let bytes_to_escape = osstr_to_bytes_os(&slash_separated_osstr)?;
            Ok(String::from_utf8(mla_percent_escape(
                bytes_to_escape,
                ENTRY_NAME_PATHBUF_ESCAPED_STRING_ALLOWED_BYTES.as_slice(),
            ))
            .unwrap())
        }
    }

    #[cfg(target_family = "unix")]
    #[allow(clippy::unnecessary_wraps)]
    fn osstr_to_bytes_os(os_str: &OsStr) -> Result<&[u8], EntryNameError> {
        use std::os::unix::ffi::OsStrExt;

        Ok(os_str.as_bytes())
    }

    #[cfg(target_family = "windows")]
    fn osstr_to_bytes_os(os_str: &OsStr) -> Result<&[u8], EntryNameError> {
        os_str
            .to_str()
            .ok_or(EntryNameError::InvalidPathComponentContent)
            .map(str::as_bytes)
    }

    #[cfg(target_family = "unix")]
    #[allow(clippy::unnecessary_wraps)]
    fn to_pathbuf_os(bytes: &[u8]) -> Result<PathBuf, EntryNameError> {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

        Ok(PathBuf::from(OsStr::from_bytes(bytes)))
    }

    #[cfg(target_family = "windows")]
    fn to_pathbuf_os(bytes: &[u8]) -> Result<PathBuf, EntryNameError> {
        // check windows specific forbidden bytes
        if bytes
            .iter()
            .any(|b| WINDOWS_FORBIDDEN_PATH_BYTES.as_slice().contains(b))
        {
            return Err(EntryNameError::InvalidPathComponentContent);
        }
        let components = bytes.split(|b| *b == b'/');
        if components.clone().any(is_windows_forbidden_component) {
            return Err(EntryNameError::InvalidPathComponentContent);
        }
        // convert to PathBuf
        components
            .map(|component| {
                str::from_utf8(component).map_err(|_| EntryNameError::InvalidPathComponentContent)
            })
            .collect::<Result<PathBuf, EntryNameError>>()
    }

    fn to_normal_component_osstr(component: Component<'_>) -> Result<&OsStr, EntryNameError> {
        match component {
            Component::Normal(component_osstr) => {
                if component_osstr.is_empty() {
                    Err(EntryNameError::InvalidPathComponentContent)
                } else {
                    Ok(component_osstr)
                }
            }
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => Err(EntryNameError::ForbiddenPathTraversalComponent),
        }
    }

    #[cfg(target_family = "unix")]
    #[allow(clippy::unnecessary_wraps)]
    fn normal_component_osstr_to_bytes(os_str: &OsStr) -> Result<&[u8], EntryNameError> {
        use std::os::unix::ffi::OsStrExt;

        Ok(os_str.as_bytes())
    }

    #[cfg(target_family = "windows")]
    fn normal_component_osstr_to_bytes(os_str: &OsStr) -> Result<&[u8], EntryNameError> {
        match os_str.to_str() {
            Some(s) => Ok(s.as_bytes()),
            None => Err(EntryNameError::InvalidPathComponentContent),
        }
    }

    fn check_os_indep_path_rules(bytes: &[u8]) -> Result<(), EntryNameError> {
        if bytes.first() == Some(&b'/') {
            Err(EntryNameError::ForbiddenPathTraversalComponent)
        } else {
            let mut components = bytes.split(|b| *b == b'/');
            if components.any(is_invalid_os_indep_component) {
                Err(EntryNameError::InvalidPathComponentContent)
            } else {
                Ok(())
            }
        }
    }

    fn is_invalid_os_indep_component(component: &[u8]) -> bool {
        component.is_empty()
            || component.contains(&0)
            || (component == b".")
            || (component == b"..")
    }

    // https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html
    #[cfg(target_family = "windows")]
    fn is_windows_forbidden_component(name: &[u8]) -> bool {
        // strip everything after '.', ':' or ' '
        let name = name.split(|b| *b == b'.').next().unwrap_or_default();
        let name = name.split(|b| *b == b':').next().unwrap_or_default();
        let name = name.split(|b| *b == b' ').next().unwrap_or_default();
        let name = name.to_ascii_lowercase();
        WINDOWS_FORBIDDEN_NAMES.contains(&name.as_slice())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[cfg(not(target_family = "windows"))]
        #[test]
        fn test_entry_name_allows_windows_reserved_on_unix() {
            let names: &[&[u8]] = &[b"con", b"con.txt", b"com1.log", b"nul ", b"lpt9:", b"con."];

            for &name in names {
                let entry = EntryName::from_arbitrary_bytes(name).unwrap();
                let result = entry.to_pathbuf();
                assert!(
                    result.is_ok(),
                    "Expected {:?} to be accepted on Unix",
                    std::str::from_utf8(name).unwrap_or("<invalid UTF-8>")
                );
            }
        }

        #[cfg(target_family = "windows")]
        #[test]
        fn test_windows_forbidden_last_components() {
            let forbidden: &[&[u8]] = &[
                b"con",
                b"con.txt",
                b"com1.log",
                b"nul ",
                b"lpt9:",
                b"com3.data.bak",
                b"con.",
                b"lpt1 ",
            ];

            for &name in forbidden {
                assert!(
                    is_windows_forbidden_component(name),
                    "Expected {:?} to be forbidden",
                    std::str::from_utf8(name).unwrap_or("<invalid UTF-8>")
                );
            }

            let allowed: &[&[u8]] = &[
                b"content",
                b"config.json",
                b"compare1.txt",
                b"compile.rs",
                b"laptop9.txt",       // not lpt9
                b"communication.log", // not comX
            ];

            for &name in allowed {
                assert!(
                    !is_windows_forbidden_component(name),
                    "Expected {:?} to be allowed",
                    std::str::from_utf8(name).unwrap_or("<invalid UTF-8>")
                );
            }
        }

        #[cfg(target_family = "windows")]
        #[test]
        fn test_entry_name_rejects_windows_reserved_names() {
            let reserved: &[&[u8]] = &[b"con", b"con.txt", b"com1.log", b"nul ", b"lpt9:"];

            for &name in reserved {
                let entry = EntryName::from_arbitrary_bytes(name).unwrap();
                let result = entry.to_pathbuf();
                assert!(
                    matches!(result, Err(EntryNameError::InvalidPathComponentContent)),
                    "Expected {:?} to be rejected by to_pathbuf",
                    std::str::from_utf8(name).unwrap_or("<invalid UTF-8>")
                );
            }
        }
    }
}

pub use entryname::{
    ENTRY_NAME_PATHBUF_ESCAPED_STRING_ALLOWED_BYTES, ENTRY_NAME_RAW_CONTENT_ALLOWED_BYTES,
    EntryName, EntryNameError,
};

pub(crate) fn serialize_entry_name(name: &EntryName, mut dst: impl Write) -> Result<u64, Error> {
    let slice = name.as_arbitrary_bytes();
    let mut serialization_length = slice.len().serialize(&mut dst)?;
    serialization_length += slice.serialize(&mut dst)?;
    Ok(serialization_length)
}
pub(crate) fn deserialize_entry_name(mut src: impl Read) -> Result<EntryName, Error> {
    let n = MLADeserialize::deserialize(&mut src)?;
    let mut name = Vec::new();
    src.take(n)
        .read_to_end(&mut name)
        .map_err(|_| Error::DeserializationError)?;
    EntryName::from_arbitrary_bytes_vec(name).map_err(|_| Error::DeserializationError)
}

/// Represents an entry in the archive.
pub struct ArchiveEntry<'a, T> {
    pub name: EntryName,
    pub data: ArchiveEntryDataReader<'a, T>,
}

impl<T> ArchiveEntry<'_, T> {
    pub fn get_size(&self) -> u64 {
        self.data.offsets_and_sizes.iter().map(|p| p.1).sum()
    }
}

#[derive(PartialEq, Debug)]
enum ArchiveEntryDataReaderState {
    // Remaining size
    InEntryContent(u64),
    // underlying position is at a block header
    Ready,
    Finish,
}

/// Structure available in an `ArchiveEntry` `data` field, enabling one to `Read` and `Seek` inside an archive entry.
pub struct ArchiveEntryDataReader<'a, R> {
    /// This structure wraps the internals to get back a file's content
    src: &'a mut R,
    state: ArchiveEntryDataReaderState,
    /// id of the File being read
    id: ArchiveEntryId,
    /// index in `offsets_and_sizes` of the block to read at next `ArchiveEntryDataReader.read()` call
    current_offsets_and_sizes_index: usize,
    /// List of offsets of continuous blocks corresponding to where the file can be read
    offsets_and_sizes: &'a [(u64, u64)],
}

impl<'a, R: Read + Seek> ArchiveEntryDataReader<'a, R> {
    pub(crate) fn new(
        src: &'a mut R,
        offsets_and_sizes: &'a [(u64, u64)],
    ) -> Result<ArchiveEntryDataReader<'a, R>, Error> {
        // Set the inner layer at the start of the file
        let start_offset = get_start_offset_in_src(offsets_and_sizes)?;
        src.seek(SeekFrom::Start(start_offset))?;

        // Read file information header
        let ArchiveEntryBlock::EntryStart { id, .. } = ArchiveEntryBlock::from(src)? else {
            return Err(Error::WrongReaderState(
                "[ArchiveEntryDataReader] A file must start with an EntryStart".to_string(),
            ));
        };

        Ok(ArchiveEntryDataReader {
            src,
            state: ArchiveEntryDataReaderState::Ready,
            id,
            current_offsets_and_sizes_index: 1,
            offsets_and_sizes,
        })
    }

    fn increment_current_offsets_and_sizes_index(&mut self) -> Result<(), Error> {
        self.current_offsets_and_sizes_index += 1;
        if self.current_offsets_and_sizes_index >= self.offsets_and_sizes.len() {
            Err(Error::WrongReaderState(
                "[ArchiveEntryDataReader] No more continuous blocks".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Move `self.src` to the next continuous block
    fn move_to_block_at_current_offsets_and_sizes_index(&mut self) -> Result<(), Error> {
        self.src.seek(SeekFrom::Start(
            self.offsets_and_sizes[self.current_offsets_and_sizes_index].0,
        ))?;
        Ok(())
    }
}

impl<T: Read + Seek> Read for ArchiveEntryDataReader<'_, T> {
    fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
        let (remaining, count) = match self.state {
            ArchiveEntryDataReaderState::Ready => {
                // Start a new block EntryContent
                match ArchiveEntryBlock::from(&mut self.src)? {
                    ArchiveEntryBlock::EntryContent { length, id, .. } => {
                        if id == self.id {
                            let count = self.src.by_ref().take(length).read(into)?;
                            let count_as_u64 = usize_as_u64(count)?;
                            (length - count_as_u64, count)
                        } else {
                            self.move_to_block_at_current_offsets_and_sizes_index()?;
                            return self.read(into);
                        }
                    }
                    ArchiveEntryBlock::EndOfEntry { id, .. } => {
                        if id == self.id {
                            self.state = ArchiveEntryDataReaderState::Finish;
                            return Ok(0);
                        }

                        self.move_to_block_at_current_offsets_and_sizes_index()?;
                        return self.read(into);
                    }
                    ArchiveEntryBlock::EntryStart { id, .. } => {
                        if id == self.id {
                            self.increment_current_offsets_and_sizes_index()?;
                        }
                        self.move_to_block_at_current_offsets_and_sizes_index()?;
                        return self.read(into);
                    }
                    ArchiveEntryBlock::EndOfArchiveData => {
                        return Err(Error::WrongReaderState(
                            "[ArchiveEntryDataReader] Try to read the end of the archive"
                                .to_string(),
                        )
                        .into());
                    }
                }
            }
            ArchiveEntryDataReaderState::InEntryContent(remaining) => {
                let count = self.src.by_ref().take(remaining).read(into)?;
                let count_as_u64 = usize_as_u64(count)?;
                (remaining - count_as_u64, count)
            }
            ArchiveEntryDataReaderState::Finish => {
                return Ok(0);
            }
        };
        if remaining > 0 {
            self.state = ArchiveEntryDataReaderState::InEntryContent(remaining);
        } else {
            // remaining is 0 (> never happens thanks to take)
            self.current_offsets_and_sizes_index += 1;
            self.state = ArchiveEntryDataReaderState::Ready;
        }
        Ok(count)
    }
}

impl<T: Read + Seek> Seek for ArchiveEntryDataReader<'_, T> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(asked_seek_offset) => {
                let mut sum = 0;
                let mut found = None;
                // look for block containing asked_seek_offset
                for (index, (offset, size)) in self.offsets_and_sizes.iter().copied().enumerate() {
                    sum += size;
                    if sum > asked_seek_offset {
                        // return found info and index
                        found = Some((offset, size, index));
                        break;
                    }
                }

                if sum == asked_seek_offset {
                    // we seeked to end offset
                    let last_index = self.offsets_and_sizes.len() - 1;
                    let (offset, size) = self.offsets_and_sizes[last_index];
                    found = Some((offset, size, last_index));
                }

                if let Some((offset, size, index)) = found {
                    self.src.seek(SeekFrom::Start(offset))?;
                    self.state = ArchiveEntryDataReaderState::Ready;
                    self.current_offsets_and_sizes_index = index;
                    let mut v = Vec::new();
                    let offset_from_block_start = usize::try_from(asked_seek_offset - (sum - size))
                        .map_err(|_| io::Error::from(ErrorKind::InvalidInput))?;
                    v.resize(offset_from_block_start, 0);
                    self.read_exact(&mut v)?;
                    Ok(asked_seek_offset)
                } else {
                    Err(ErrorKind::InvalidInput.into())
                }
            }
            SeekFrom::End(asked_seek_offset) => {
                let offset_from_end = 0u64
                    .checked_add_signed(-asked_seek_offset)
                    .ok_or(io::Error::from(ErrorKind::InvalidInput))?;
                let mut sum = 0;
                let mut found = None;
                // look for block containing asked_seek_offset from end (.rev())
                for (index, (offset, size)) in
                    self.offsets_and_sizes.iter().copied().enumerate().rev()
                {
                    sum += size;
                    if sum > offset_from_end {
                        // return found info and index
                        found = Some((offset, size, index));
                        break;
                    }
                }

                if sum == offset_from_end {
                    // we seeked to start
                    let (offset, size) = self.offsets_and_sizes[0];
                    found = Some((offset, size, 0));
                }

                if let Some((offset, _size, index)) = found {
                    self.src.seek(SeekFrom::Start(offset))?;
                    self.state = ArchiveEntryDataReaderState::Ready;
                    self.current_offsets_and_sizes_index = index;
                    let mut v = Vec::new();
                    let offset_from_block_start = usize::try_from(sum - offset_from_end)
                        .map_err(|_| io::Error::from(ErrorKind::InvalidInput))?;
                    v.resize(offset_from_block_start, 0);
                    self.read_exact(&mut v)?;

                    Ok(self.offsets_and_sizes.iter().map(|p| p.1).sum())
                } else {
                    Err(ErrorKind::InvalidInput.into())
                }
            }
            SeekFrom::Current(asked_seek_offset) => match self.state {
                ArchiveEntryDataReaderState::InEntryContent(remaining) => {
                    let offset_from_start = self.offsets_and_sizes
                        [..=self.current_offsets_and_sizes_index]
                        .iter()
                        .map(|p| p.1)
                        .sum::<u64>()
                        - remaining;
                    let new_pos = offset_from_start
                        .checked_add_signed(asked_seek_offset)
                        .ok_or(io::Error::from(ErrorKind::InvalidInput))?;
                    self.seek(SeekFrom::Start(new_pos))
                }
                ArchiveEntryDataReaderState::Ready => {
                    let offset_from_start = self.offsets_and_sizes
                        [..self.current_offsets_and_sizes_index]
                        .iter()
                        .map(|p| p.1)
                        .sum::<u64>();
                    let new_pos = offset_from_start
                        .checked_add_signed(asked_seek_offset)
                        .ok_or(io::Error::from(ErrorKind::InvalidInput))?;
                    self.seek(SeekFrom::Start(new_pos))
                }
                ArchiveEntryDataReaderState::Finish => self.seek(SeekFrom::End(asked_seek_offset)),
            },
        }
    }
}

fn get_start_offset_in_src(offsets_and_sizes: &[(u64, u64)]) -> Result<u64, Error> {
    offsets_and_sizes
        .first()
        .copied()
        .map(|p| p.0)
        .ok_or_else(|| {
            Error::WrongReaderState("An entry should have at least 2 offsets in footer".to_owned())
        })
}

fn usize_as_u64(n: usize) -> Result<u64, Error> {
    u64::try_from(n).map_err(|_| Error::WrongWriterState("Unsupported arch".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Empty, Read, Seek, SeekFrom};
    use std::path::Path;

    use crate::{
        Opts, Sha256Hash,
        entry::{ArchiveEntryDataReader, ArchiveEntryDataReaderState, EntryName},
        format::ArchiveEntryBlock,
    };

    const FAKE_CONTENT1: [u8; 4] = [1, 2, 3, 4];
    const FAKE_CONTENT2: [u8; 4] = [5, 6, 7, 8];
    fn create_normal_entry() -> (std::io::Cursor<Vec<u8>>, &'static [(u64, u64)]) {
        // Create several blocks
        let mut buf = Vec::new();
        let id = ArchiveEntryId(0);
        let hash = Sha256Hash::default();

        let mut block = ArchiveEntryBlock::EntryStart::<&[u8]> {
            id,
            name: EntryName::from_arbitrary_bytes(b"foobar").unwrap(),
            opts: Opts,
        };
        block.dump(&mut buf).unwrap();
        let mut block = ArchiveEntryBlock::EntryContent {
            id,
            length: FAKE_CONTENT1.len() as u64,
            opts: Opts,
            data: Some(FAKE_CONTENT1.as_slice()),
        };
        block.dump(&mut buf).unwrap();
        let mut block = ArchiveEntryBlock::EntryContent {
            id,
            length: FAKE_CONTENT2.len() as u64,
            opts: Opts,
            data: Some(FAKE_CONTENT2.as_slice()),
        };
        block.dump(&mut buf).unwrap();

        // std::io::Empty is used because a type with Read is needed
        ArchiveEntryBlock::EndOfEntry::<Empty> {
            id,
            hash,
            opts: Opts,
        }
        .dump(&mut buf)
        .unwrap();

        let offsets = [(0, 0), (28, 4), (54, 4), (80, 0)].as_slice();

        (std::io::Cursor::new(buf), offsets)
    }

    fn create_empty_entry() -> (std::io::Cursor<Vec<u8>>, &'static [(u64, u64)]) {
        // Create several blocks
        let mut buf = Vec::new();
        let id = ArchiveEntryId(0);
        let hash = Sha256Hash::default();

        let mut block = ArchiveEntryBlock::EntryStart::<&[u8]> {
            id,
            name: EntryName::from_arbitrary_bytes(b"empty").unwrap(),
            opts: Opts,
        };
        block.dump(&mut buf).unwrap();

        // std::io::Empty is used because a type with Read is needed
        ArchiveEntryBlock::EndOfEntry::<Empty> {
            id,
            hash,
            opts: Opts,
        }
        .dump(&mut buf)
        .unwrap();

        let offsets = [(0, 0), (22, 0)].as_slice();

        (std::io::Cursor::new(buf), offsets)
    }

    #[test]
    fn blocks_to_file() {
        let (mut data_source, offsets) = create_normal_entry();
        let mut reader = ArchiveEntryDataReader::new(&mut data_source, offsets)
            .expect("BlockToFileReader failed");
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output.len(), FAKE_CONTENT1.len() + FAKE_CONTENT2.len());
        let mut expected_output = Vec::new();
        expected_output.extend(FAKE_CONTENT1);
        expected_output.extend(FAKE_CONTENT2);
        assert_eq!(output, expected_output);
        assert_eq!(reader.state, ArchiveEntryDataReaderState::Finish);
    }

    #[test]
    fn test_seek() {
        let (mut data_source, offsets) = create_normal_entry();
        let mut reader = ArchiveEntryDataReader::new(&mut data_source, offsets)
            .expect("BlockToFileReader failed");
        let mut output = Vec::new();
        reader.seek(SeekFrom::Start(0)).unwrap();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, &[1, 2, 3, 4, 5, 6, 7, 8]);
        output.clear();
        reader.seek(SeekFrom::Start(1)).unwrap();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, &[2, 3, 4, 5, 6, 7, 8]);
        output.clear();
        reader.seek(SeekFrom::Start(1)).unwrap();
        #[allow(clippy::seek_from_current)]
        reader.seek(SeekFrom::Current(0)).unwrap();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, &[2, 3, 4, 5, 6, 7, 8]);
        output.clear();
        reader.seek(SeekFrom::Start(1)).unwrap();
        reader.seek(SeekFrom::Current(-1)).unwrap();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, &[1, 2, 3, 4, 5, 6, 7, 8]);
        output.clear();
        reader.seek(SeekFrom::Start(1)).unwrap();
        reader.seek(SeekFrom::Current(1)).unwrap();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, &[3, 4, 5, 6, 7, 8]);
        output.clear();
        reader.seek(SeekFrom::End(0)).unwrap();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, &[]);
        output.clear();
        assert!(reader.seek(SeekFrom::End(1)).is_err());
        reader.seek(SeekFrom::End(-1)).unwrap();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, &[8]);
        output.clear();
        reader.seek(SeekFrom::End(-2)).unwrap();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, &[7, 8]);
        output.clear();
        reader.seek(SeekFrom::End(-5)).unwrap();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, &[4, 5, 6, 7, 8]);
        output.clear();
        reader.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = [0; 4];
        reader.read_exact(&mut buf).unwrap();
        #[allow(clippy::seek_from_current)]
        reader.seek(SeekFrom::Current(0)).unwrap();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, &[5, 6, 7, 8]);
        output.clear();
        assert!(reader.seek(SeekFrom::End(-9)).is_err());
    }

    #[test]
    fn seek_internal_state_consistency() {
        let (mut data_source, offsets) = create_normal_entry();
        let mut reader = ArchiveEntryDataReader::new(&mut data_source, offsets)
            .expect("Failed to create ArchiveEntryDataReader");

        // Seek to start (offset 0) — should be Ready or just before content reading
        reader.seek(std::io::SeekFrom::Start(0)).unwrap();
        assert!(
            matches!(reader.state, ArchiveEntryDataReaderState::Ready),
            "Expected state Ready after SeekFrom::Start(0), got {:?}",
            reader.state
        );

        // Seek inside first content block (offset 2)
        reader.seek(std::io::SeekFrom::Start(2)).unwrap();
        match &reader.state {
            ArchiveEntryDataReaderState::InEntryContent(remaining) => {
                // remaining should be length of content after offset 2
                assert!(*remaining == 2);
            }
            _ => panic!("Expected InEntryContent state after seek inside content block"),
        }

        // Seek to end (offset equal to total content length, 8 here)
        reader.seek(std::io::SeekFrom::Start(8)).unwrap();
        assert!(
            matches!(
                reader.state,
                ArchiveEntryDataReaderState::Ready | ArchiveEntryDataReaderState::Finish
            ),
            "Expected state Ready or Finish after seeking to end, got {:?}",
            reader.state
        );

        // Seek beyond end (should error)
        assert!(reader.seek(std::io::SeekFrom::Start(9)).is_err());

        // Seek to end with SeekFrom::End(0) should result in Finish or Ready
        reader.seek(std::io::SeekFrom::End(0)).unwrap();
        assert!(
            matches!(
                reader.state,
                ArchiveEntryDataReaderState::Ready | ArchiveEntryDataReaderState::Finish
            ),
            "Expected Ready or Finish after SeekFrom::End(0), got {:?}",
            reader.state
        );

        // Seek backwards inside content using SeekFrom::End(-3)
        reader.seek(std::io::SeekFrom::End(-3)).unwrap();
        match &reader.state {
            ArchiveEntryDataReaderState::InEntryContent(_) => (),
            _ => panic!("Expected InEntryContent after SeekFrom::End(-3)"),
        }

        // Seek to start again and then finish reading all to reach Finish state
        reader.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(reader.state, ArchiveEntryDataReaderState::Finish);
    }

    #[test]
    fn seek_internal_state_consistency_empty_entry() {
        let (mut data_source, offsets) = create_empty_entry();
        let mut reader = ArchiveEntryDataReader::new(&mut data_source, offsets)
            .expect("Failed to create ArchiveEntryDataReader");

        // Seek to start (offset 0) — should be Ready or just before content reading
        reader.seek(std::io::SeekFrom::Start(0)).unwrap();
        assert!(
            matches!(reader.state, ArchiveEntryDataReaderState::Ready),
            "Expected state Ready after SeekFrom::Start(0), got {:?}",
            reader.state
        );

        // Seek to end (offset equal to total content length, 0 here)
        reader.seek(std::io::SeekFrom::Start(0)).unwrap();
        assert!(
            matches!(
                reader.state,
                ArchiveEntryDataReaderState::Ready | ArchiveEntryDataReaderState::Finish
            ),
            "Expected state Ready or Finish after seeking to end, got {:?}",
            reader.state
        );

        // Seek beyond end (should error)
        assert!(reader.seek(std::io::SeekFrom::Start(2)).is_err());

        // Seek to end with SeekFrom::End(0) should result in Finish or Ready
        reader.seek(std::io::SeekFrom::End(0)).unwrap();
        assert!(
            matches!(
                reader.state,
                ArchiveEntryDataReaderState::Ready | ArchiveEntryDataReaderState::Finish
            ),
            "Expected Ready or Finish after SeekFrom::End(0), got {:?}",
            reader.state
        );
    }

    #[test]
    fn entry_name_from_arbitrary_bytes_empty() {
        let res = entryname::EntryName::from_arbitrary_bytes(b"");
        assert!(matches!(
            res,
            Err(entryname::EntryNameError::InvalidPathComponentContent)
        ));
    }

    #[test]
    fn entry_name_from_arbitrary_bytes_nonempty() {
        let name = entryname::EntryName::from_arbitrary_bytes(b"abc").unwrap();
        assert_eq!(name.as_arbitrary_bytes(), b"abc");
    }

    #[test]
    fn entry_name_from_path_normalization() {
        // Should normalize away ParentDir and CurDir
        let path = Path::new("foo/./bar/../baz");
        let name = entryname::EntryName::from_path(path).unwrap();
        assert_eq!(name.as_arbitrary_bytes(), b"foo/baz");
    }

    #[test]
    fn entry_name_from_path_empty() {
        let path = Path::new("");
        let res = entryname::EntryName::from_path(path);
        assert!(matches!(
            res,
            Err(entryname::EntryNameError::InvalidPathComponentContent)
        ));
    }

    #[test]
    fn entry_name_to_pathbuf_roundtrip() {
        let name = entryname::EntryName::from_path("foo/bar").unwrap();
        let pathbuf = name.to_pathbuf().unwrap();
        assert_eq!(pathbuf, Path::new("foo/bar"));
    }

    #[test]
    fn entry_name_forbidden_traversal() {
        // Leading slash is forbidden
        let name = entryname::EntryName::from_arbitrary_bytes(b"/foo");
        assert!(name.is_ok());
        let name = name.unwrap();
        assert!(matches!(
            name.to_pathbuf(),
            Err(entryname::EntryNameError::ForbiddenPathTraversalComponent)
        ));
    }

    #[test]
    fn entry_name_invalid_component() {
        // Contains null byte
        let name = entryname::EntryName::from_arbitrary_bytes(b"foo\0bar").unwrap();
        assert!(matches!(
            name.to_pathbuf(),
            Err(entryname::EntryNameError::InvalidPathComponentContent)
        ));
    }

    #[test]
    fn entry_name_raw_content_to_escaped_string() {
        let name = entryname::EntryName::from_arbitrary_bytes(b"foo/bar%baz").unwrap();
        let s = name.raw_content_to_escaped_string();
        // '%' should be escaped
        assert!(s.contains("%25"));
    }

    #[test]
    fn entry_name_to_pathbuf_escaped_string() {
        let name = entryname::EntryName::from_path("foo/bar.baz").unwrap();
        let s = name.to_pathbuf_escaped_string().unwrap();
        // Should not escape allowed chars
        assert_eq!(s, "foo/bar.baz");
    }

    #[test]
    fn entry_name_dot_and_dotdot_components() {
        // "." and ".." are forbidden as components
        let name = entryname::EntryName::from_arbitrary_bytes(b"foo/./bar").unwrap();
        assert!(matches!(
            name.to_pathbuf(),
            Err(entryname::EntryNameError::InvalidPathComponentContent)
        ));
        let name = entryname::EntryName::from_arbitrary_bytes(b"foo/../bar").unwrap();
        assert!(matches!(
            name.to_pathbuf(),
            Err(entryname::EntryNameError::InvalidPathComponentContent)
        ));
    }
}
