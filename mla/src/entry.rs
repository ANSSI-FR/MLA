use std::io::{ErrorKind, Read, Seek, SeekFrom};

use crate::{errors::Error, format::ArchiveEntryBlock};

/// Represents a unique identifier for an entry in the archive.
/// Used to maintain references to entries while writing an archive.
pub type ArchiveEntryId = u64;

mod entryname {
    use std::{
        ffi::OsStr,
        fmt,
        path::{Component, Path, PathBuf},
    };

    use crate::helpers::mla_percent_escape;

    /// Allowed bytes in `EntryName::to_pathbuf_escaped_string` output. Documented there.
    pub static ENTRY_NAME_PATHBUF_ESCAPED_STRING_ALLOWED_BYTES: [u8; 64] =
        *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";
    /// Allowed bytes in `EntryName::raw_content_to_escaped_string` output. Documented there.
    pub static ENTRY_NAME_RAW_CONTENT_ALLOWED_BYTES: [u8; 63] =
        *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.";

    #[derive(Debug)]
    pub enum EntryNameError {
        ForbiddenPathTraversalComponent,
        InvalidPathComponentContent,
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
        /// Use with caution, arbitrary bytes are stored as is.
        /// See `EntryName::from_path`, `EntryName::as_arbitrary_bytes`
        /// and `EntryName::to_pathbuf`.
        ///
        /// If you want the entry name be used as a file path you may prefer
        /// using `EntryName::from_path`.
        ///
        /// This function returns an `EntryNameError::InvalidPathComponentContent` when given an empty slice.
        pub fn from_arbitrary_bytes(bytes: &[u8]) -> Result<Self, EntryNameError> {
            if bytes.is_empty() {
                Err(EntryNameError::InvalidPathComponentContent)
            } else {
                Ok(Self {
                    name: bytes.to_vec(),
                })
            }
        }

        /// WARNING: you are given bytes controlled by the one who made the entry name.
        /// It may contain arbitrary bytes like slash, backslash, `..`,
        /// `C:\\{}...]`, newline, spaces, carriage return, terminal escape sequences,
        /// Unicode chars like U+0085 or RTLO, HTML, SQL, semicolons, homoglyphs, etc.
        pub fn as_arbitrary_bytes(&self) -> &[u8] {
            self.name.as_slice()
        }

        /// `path` is first normalized by keeping only `Normal`
        /// `std::path::Component`s and popping an eventual previous
        /// component when a `..` is encountered.
        ///
        /// On Windows, `path` is then converted from UTF-16LE to UTF-8 and backslashes are
        /// converted to slash before being serialized inside archive.
        /// On UNIX family, `path` is then serialized as is.
        /// This way, a `Path` P converted with `EntryName::from_path` on an OS and
        /// converted back with `EntryName::to_pathbuf` on
        /// another OS have good chance to have the same meaning.
        /// On Windows, invalid UTF-16 in `path` make this function
        /// return an `Err(EntryNameError::InvalidPathComponentContent)`.
        ///
        /// This function returns an `EntryNameError::InvalidPathComponentContent` when the resulting `EntryName` would be empty.
        pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, EntryNameError> {
            let components = {
                let mut stack = Vec::new();
                for component in path.as_ref().components() {
                    match component {
                        Component::Prefix(_) => (),
                        Component::RootDir => (),
                        Component::CurDir => (),
                        Component::ParentDir => {
                            stack.pop();
                        }
                        Component::Normal(os_str) => {
                            stack.push(normal_component_osstr_to_bytes(os_str)?)
                        }
                    }
                }
                stack
            };
            let name = components.join(&b'/');
            if name.is_empty() {
                Err(EntryNameError::InvalidPathComponentContent)
            } else {
                Ok(Self { name })
            }
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
        /// `PathBuf` may map to same path on OS (eg. Windows case insensitivity).
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
    fn to_pathbuf_os(bytes: &[u8]) -> Result<PathBuf, EntryNameError> {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

        check_os_indep_path_rules(bytes)?;
        Ok(PathBuf::from(OsStr::from_bytes(bytes)))
    }

    #[cfg(target_family = "windows")]
    fn to_pathbuf_os(bytes: &[u8]) -> Result<PathBuf, EntryNameError> {
        check_os_indep_path_rules(bytes)?;
        if bytes.get(1) == Some(&b':') {
            Err(EntryNameError::ForbiddenPathTraversalComponent)
        } else {
            let components = bytes.split(|b| *b == b'/');
            components
                .map(|component| {
                    if is_invalid_os_indep_component(component) || component.contains(&b'\\') {
                        Err(EntryNameError::InvalidPathComponentContent)
                    } else {
                        str::from_utf8(component)
                            .map_err(|_| EntryNameError::InvalidPathComponentContent)
                    }
                })
                .collect::<Result<PathBuf, EntryNameError>>()
        }
    }

    fn to_normal_component_osstr(component: Component) -> Result<&OsStr, EntryNameError> {
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
}

pub use entryname::{
    ENTRY_NAME_PATHBUF_ESCAPED_STRING_ALLOWED_BYTES, ENTRY_NAME_RAW_CONTENT_ALLOWED_BYTES,
    EntryName, EntryNameError,
};

/// Represents an entry in the archive.
pub struct ArchiveEntry<'a, T> {
    pub name: EntryName,
    pub data: ArchiveEntryDataReader<'a, T>,
    pub size: u64,
}

#[derive(PartialEq, Debug)]
enum ArchiveEntryDataReaderState {
    // Remaining size
    InEntryContent(u64),
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
    /// position in `offsets` of the last offset used
    current_offsets_index: usize,
    /// List of offsets of continuous blocks corresponding to where the file can be read
    offsets_in_src: &'a [u64],
}

impl<'a, R: Read + Seek> ArchiveEntryDataReader<'a, R> {
    pub(crate) fn new(
        src: &'a mut R,
        offsets: &'a [u64],
    ) -> Result<ArchiveEntryDataReader<'a, R>, Error> {
        // Set the inner layer at the start of the file
        let start_offset = get_start_offset_in_src(offsets)?;
        src.seek(SeekFrom::Start(start_offset))?;

        // Read file information header
        let id = match ArchiveEntryBlock::from(src)? {
            ArchiveEntryBlock::EntryStart { id, .. } => id,
            _ => {
                return Err(Error::WrongReaderState(
                    "[BlocksToFileReader] A file must start with an EntryStart".to_string(),
                ));
            }
        };

        Ok(ArchiveEntryDataReader {
            src,
            state: ArchiveEntryDataReaderState::Ready,
            id,
            current_offsets_index: 0,
            offsets_in_src: offsets,
        })
    }

    /// Move `self.src` to the next continuous block
    fn move_to_next_block_in_entry(&mut self) -> Result<(), Error> {
        self.current_offsets_index += 1;
        if self.current_offsets_index >= self.offsets_in_src.len() {
            return Err(Error::WrongReaderState(
                "[BlocksToFileReader] No more continuous blocks".to_string(),
            ));
        }
        self.src.seek(SeekFrom::Start(
            self.offsets_in_src[self.current_offsets_index],
        ))?;
        Ok(())
    }

    // inefficient, we walk from start of entry
    fn get_current_position_in_entry(&mut self) -> Result<u64, Error> {
        let offsets_index_at_function_entry = self.current_offsets_index;
        let start_offset = get_start_offset_in_src(self.offsets_in_src)?;
        self.src.seek(SeekFrom::Start(start_offset))?;
        self.current_offsets_index = 0;
        let mut total = 0;
        while self.current_offsets_index < offsets_index_at_function_entry {
            let current_src_offset = self.offsets_in_src[self.current_offsets_index];
            self.src.seek(SeekFrom::Start(current_src_offset))?;
            let content_len = match ArchiveEntryBlock::from(&mut self.src)? {
                ArchiveEntryBlock::EntryStart { .. } => Ok(0),
                ArchiveEntryBlock::EntryContent { length, .. } => Ok(length),
                ArchiveEntryBlock::EndOfEntry { .. } => Err(Error::WrongReaderState(
                    "We shouldn't be at EndOfEntry".to_owned(),
                )),
                ArchiveEntryBlock::EndOfArchiveData => Err(Error::WrongReaderState(
                    "We shouldn't be at EndOfArchiveData".to_owned(),
                )),
            }?;
            total += content_len;
            self.move_to_next_block_in_entry()?;
        }
        let offset_in_content_chunk_at_function_entry = match self.state {
            ArchiveEntryDataReaderState::InEntryContent(remaining) => {
                if let ArchiveEntryBlock::EntryContent { length, .. } =
                    ArchiveEntryBlock::from(&mut self.src)?
                {
                    let offset_in_content_chunk_at_function_entry = length - remaining;
                    // restore position
                    self.src.seek(SeekFrom::Current(u64_as_i64(
                        offset_in_content_chunk_at_function_entry,
                    )?))?;
                    offset_in_content_chunk_at_function_entry
                } else {
                    return Err(Error::WrongReaderState(
                        "We should be in an EntryContent".to_owned(),
                    ));
                }
            }
            ArchiveEntryDataReaderState::Ready => 0,
            ArchiveEntryDataReaderState::Finish => 0,
        };
        total += offset_in_content_chunk_at_function_entry;
        Ok(total)
    }
}

impl<T: Read + Seek> Read for ArchiveEntryDataReader<'_, T> {
    fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
        let (remaining, count) = match self.state {
            ArchiveEntryDataReaderState::Ready => {
                // Start a new block EntryContent
                match ArchiveEntryBlock::from(&mut self.src)? {
                    ArchiveEntryBlock::EntryContent { length, id, .. } => {
                        if id != self.id {
                            self.move_to_next_block_in_entry()?;
                            return self.read(into);
                        }
                        let count = self.src.by_ref().take(length).read(into)?;
                        let count_as_u64 = usize_as_u64(count)?;
                        (length - count_as_u64, count)
                    }
                    ArchiveEntryBlock::EndOfEntry { id, .. } => {
                        if id != self.id {
                            self.move_to_next_block_in_entry()?;
                            return self.read(into);
                        }
                        self.state = ArchiveEntryDataReaderState::Finish;
                        return Ok(0);
                    }
                    ArchiveEntryBlock::EntryStart { id, .. } => {
                        if id != self.id {
                            self.move_to_next_block_in_entry()?;
                            return self.read(into);
                        }
                        return Err(Error::WrongReaderState(
                            "[BlocksToFileReader] Start with a wrong block type".to_string(),
                        )
                        .into());
                    }
                    ArchiveEntryBlock::EndOfArchiveData => {
                        return Err(Error::WrongReaderState(
                            "[BlocksToFileReader] Try to read the end of the archive".to_string(),
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
            self.state = ArchiveEntryDataReaderState::Ready;
        }
        Ok(count)
    }
}

impl<T: Read + Seek> Seek for ArchiveEntryDataReader<'_, T> {
    /// Not really efficient implementation because we don't maintain an index of each entry chunk size. If seeked beyond end of content, places cursor at the end.
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(asked_seek_offset) => {
                // walk each block of our entry from start and get its content length
                let start_offset_in_src = get_start_offset_in_src(self.offsets_in_src)?;
                self.src.seek(SeekFrom::Start(start_offset_in_src))?;
                self.current_offsets_index = 0;
                let mut total_skipped = 0;
                let number_of_chunks = self.offsets_in_src.len();
                // -2 because we don't want the last chunk (EndOfEntry)
                let last_content_chunk_index =
                    number_of_chunks.checked_sub(2).ok_or_else(|| {
                        Error::WrongReaderState(
                            "An entry should have at least 2 offsets in footer".to_owned(),
                        )
                    })?;
                loop {
                    if self.current_offsets_index > last_content_chunk_index {
                        // we don't want to get to the point of reading EndOfEntry
                        self.state = ArchiveEntryDataReaderState::Finish;
                        break;
                    } else {
                        let current_src_offset = self.offsets_in_src[self.current_offsets_index];
                        self.src.seek(SeekFrom::Start(current_src_offset))?;
                        match ArchiveEntryBlock::from(&mut self.src)? {
                            ArchiveEntryBlock::EntryStart { .. } => {
                                self.move_to_next_block_in_entry()?;
                            }
                            ArchiveEntryBlock::EntryContent { length, .. } => {
                                if asked_seek_offset > total_skipped + length {
                                    self.move_to_next_block_in_entry()?;
                                    total_skipped += length;
                                } else {
                                    let remaining_to_skip = asked_seek_offset - total_skipped;
                                    self.src
                                        .seek(SeekFrom::Current(u64_as_i64(remaining_to_skip)?))?;
                                    total_skipped += remaining_to_skip;
                                    let remaining_readable = length - remaining_to_skip;
                                    self.state = if remaining_readable == 0 {
                                        ArchiveEntryDataReaderState::Finish
                                    } else {
                                        ArchiveEntryDataReaderState::InEntryContent(
                                            remaining_readable,
                                        )
                                    };
                                    break;
                                }
                            }
                            ArchiveEntryBlock::EndOfEntry { .. } => {
                                return Err(Error::WrongReaderState(
                                    "We shouldn't be at EndOfEntry".to_owned(),
                                )
                                .into());
                            }
                            ArchiveEntryBlock::EndOfArchiveData => {
                                return Err(Error::WrongReaderState(
                                    "We shouldn't be at EndOfArchiveData".to_owned(),
                                )
                                .into());
                            }
                        }
                    }
                }
                Ok(total_skipped)
            }
            SeekFrom::End(asked_seek_offset) => {
                // manually position ourself at end and call self.seek(SeekFrom::Current(asked_seek_offset))
                let number_of_chunks = self.offsets_in_src.len();
                // -2 because we don't want the last chunk (EndOfEntry)
                let last_content_chunk_index =
                    number_of_chunks.checked_sub(2).ok_or_else(|| {
                        Error::WrongReaderState(
                            "An entry should have at least 2 offsets in footer".to_owned(),
                        )
                    })?;
                let last_content_chunk_offset = self
                    .offsets_in_src
                    .get(last_content_chunk_index)
                    .ok_or_else(|| {
                    Error::WrongReaderState(
                        "An entry should have at least 2 offsets in footer".to_owned(),
                    )
                })?;
                self.src.seek(SeekFrom::Start(*last_content_chunk_offset))?;
                match ArchiveEntryBlock::from(&mut self.src)? {
                    ArchiveEntryBlock::EntryStart { .. } => {
                        assert_eq!(number_of_chunks, 2);
                        if asked_seek_offset > 0 {
                            self.seek(SeekFrom::Start(0))
                        } else {
                            Err(ErrorKind::InvalidInput.into())
                        }
                    }
                    ArchiveEntryBlock::EntryContent { length, .. } => {
                        self.src.seek(SeekFrom::Current(u64_as_i64(length)?))?;
                        self.state = ArchiveEntryDataReaderState::InEntryContent(0);
                        self.current_offsets_index = last_content_chunk_index;
                        self.seek(SeekFrom::Current(asked_seek_offset))
                    }
                    ArchiveEntryBlock::EndOfEntry { .. } => Err(Error::WrongReaderState(
                        "We shouldn't be at EndOfEntry".to_owned(),
                    )
                    .into()),
                    ArchiveEntryBlock::EndOfArchiveData => Err(Error::WrongReaderState(
                        "We shouldn't be at EndOfArchiveData".to_owned(),
                    )
                    .into()),
                }
            }
            SeekFrom::Current(asked_seek_offset) => {
                // inefficient
                let current_position_in_entry = self.get_current_position_in_entry()?;
                // inefficient too, we walk again from start
                let new_position_in_entry = current_position_in_entry
                    .checked_add_signed(asked_seek_offset)
                    .ok_or(ErrorKind::InvalidInput)?;
                self.seek(SeekFrom::Start(new_position_in_entry))
            }
        }
    }
}

fn get_start_offset_in_src(offsets: &[u64]) -> Result<u64, Error> {
    offsets.first().copied().ok_or_else(|| {
        Error::WrongReaderState("An entry should have at least 2 offsets in footer".to_owned())
    })
}

fn usize_as_u64(n: usize) -> Result<u64, Error> {
    u64::try_from(n).map_err(|_| Error::WrongWriterState("Unsupported arch".into()))
}

fn u64_as_i64(n: u64) -> Result<i64, Error> {
    i64::try_from(n).map_err(|_| Error::WrongReaderState("Too big offset asked".into()))
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
    fn create_normal_entry() -> (std::io::Cursor<Vec<u8>>, &'static [u64]) {
        // Create several blocks
        let mut buf = Vec::new();
        let id = 0;
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

        let offsets = [0, 23, 44, 65].as_slice();

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
        reader.seek(SeekFrom::End(1)).unwrap();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, &[]);
        output.clear();
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
