use std::io::{Read, Seek, SeekFrom};

use crate::{errors::Error, format::ArchiveFileBlock};

pub type ArchiveEntryId = u64;

mod entryname {
    use std::{
        ffi::OsStr,
        fmt,
        path::{Component, Path, PathBuf},
    };

    use crate::helpers::mla_percent_escape;

    pub static ENTRY_NAME_PATHBUF_ESCAPED_STRING_ALLOWED_BYTES: [u8; 64] =
        *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";
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

    /// Arbitrary bytes representing an archive entry name
    ///
    /// Every constructor ensures it is not empty
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
        /// `C:\\{}...]`, newline, carriage return, terminal escape sequences,
        /// Unicode chars like U+0085 or RTLO, etc.
        pub fn as_arbitrary_bytes(&self) -> &[u8] {
            self.name.as_slice()
        }

        /// `path` is first normalized by keeping only `std::path::Component::Normal` components.
        /// An `Err(EntryNameError::ForbiddenPathTraversalComponent)` is returned if it contains other components .
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
            type ComponentBytes<'a> = &'a [u8];
            let components = path
                .as_ref()
                .components()
                .map(normal_component_to_bytes)
                .collect::<Result<Vec<ComponentBytes>, EntryNameError>>()?;
            let name = components.join(&b'/');
            if name.is_empty() {
                Err(EntryNameError::InvalidPathComponentContent)
            } else {
                Ok(Self { name })
            }
        }

        /// `EntryName` raw content as bytes escaped with `helpers::mla_percent_escape` with
        /// ASCII alphanumeric chars and ASCII dot as preserved bytes.
        ///
        /// You may want to use `EntryName::to_pathbuf_escaped_string` which has a different encoding than this function.
        /// This function is used by `mlar list --raw-escaped-names`.
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
        /// Please also keep in mind that two different `EntryName` or returned
        /// `PathBuf` may map to same path on OS (eg. Windows case insensitivity).
        ///
        /// The OS may not allow creating files with the returned `PathBuf` if
        /// it contains some forbidden characters (eg. Windows).
        ///
        /// The only OS independent checks performed by this function are
        /// for NUL bytes and for path traversal:
        /// the returned `PathBuf` will only contain `std::path::Component::Normal` components.
        /// Otherwise an `EntryNameError` is returned.
        ///
        /// You may want to perform other checks on the resulting `PathBuf` depending on how it will be used.
        ///
        /// For display or other purpose, you may want to use `EntryName::to_pathbuf_escaped_string`.
        ///
        /// On Windows, this function ensures the underlying `EntryName` bytes are
        /// slash separated properly encoded UTF-8 components containing no backslash.
        /// Otherwise an `Err(EntryNameError::InvalidPathComponentContent)` is returned.
        ///
        /// Details are in `Entries names` section of the `FORMAT.md` specification.
        ///
        /// See `EntryName::from_path`.
        pub fn to_pathbuf(&self) -> Result<PathBuf, EntryNameError> {
            to_pathbuf_os(&self.name)
        }

        /// Escaped String representation of an `EntryName` as a path
        ///
        /// Computed with `self::to_pathbuf()?`, followed by enforcement of
        /// slash as a separator, encoded as UTF-8 bytes and
        /// escaped with `helpers::mla_percent_escape` preserving
        /// ASCII slash, ASCII alphanumeric chars and ASCII dot.
        ///
        /// This differs from `EntryName::raw_content_to_escaped_string` with regards to path restrictions and separator encoding.
        ///
        /// This function is used by `mlar list` by default.
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
            .ok_or(EntryNameError::InvalidPathComponentContent)?
            .as_bytes();
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
            Ok(s) => Ok(s.into_bytes()),
            Err(_) => Err(EntryNameError::InvalidPathComponentContent),
        }
    }

    fn normal_component_to_bytes(component: Component) -> Result<&[u8], EntryNameError> {
        let normal_component_osstr = to_normal_component_osstr(component)?;
        normal_component_osstr_to_bytes(normal_component_osstr)
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

pub struct ArchiveEntry<T: Read> {
    /// File inside a MLA Archive
    pub filename: String,
    pub data: T,
    pub size: u64,
}

#[derive(PartialEq, Debug)]
enum ArchiveEntryDataReaderState {
    // Remaining size
    InFile(usize),
    Ready,
    Finish,
}

pub struct ArchiveEntryDataReader<'a, R: Read + Seek> {
    /// This structure wraps the internals to get back a file's content
    src: &'a mut R,
    state: ArchiveEntryDataReaderState,
    /// id of the File being read
    id: ArchiveEntryId,
    /// position in `offsets` of the last offset used
    current_offset: usize,
    /// List of offsets of continuous blocks corresponding to where the file can be read
    offsets: &'a [u64],
}

impl<'a, R: Read + Seek> ArchiveEntryDataReader<'a, R> {
    pub(crate) fn new(
        src: &'a mut R,
        offsets: &'a [u64],
    ) -> Result<ArchiveEntryDataReader<'a, R>, Error> {
        // Set the inner layer at the start of the file
        src.seek(SeekFrom::Start(offsets[0]))?;

        // Read file information header
        let id = match ArchiveFileBlock::from(src)? {
            ArchiveFileBlock::FileStart { id, .. } => id,
            _ => {
                return Err(Error::WrongReaderState(
                    "[BlocksToFileReader] A file must start with a FileStart".to_string(),
                ));
            }
        };

        Ok(ArchiveEntryDataReader {
            src,
            state: ArchiveEntryDataReaderState::Ready,
            id,
            current_offset: 0,
            offsets,
        })
    }

    /// Move `self.src` to the next continuous block
    fn move_to_next_block(&mut self) -> Result<(), Error> {
        self.current_offset += 1;
        if self.current_offset >= self.offsets.len() {
            return Err(Error::WrongReaderState(
                "[BlocksToFileReader] No more continuous blocks".to_string(),
            ));
        }
        self.src
            .seek(SeekFrom::Start(self.offsets[self.current_offset]))?;
        Ok(())
    }
}

impl<T: Read + Seek> Read for ArchiveEntryDataReader<'_, T> {
    fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
        let (remaining, count) = match self.state {
            ArchiveEntryDataReaderState::Ready => {
                // Start a new block FileContent
                match ArchiveFileBlock::from(&mut self.src)? {
                    ArchiveFileBlock::FileContent { length, id, .. } => {
                        if id != self.id {
                            self.move_to_next_block()?;
                            return self.read(into);
                        }
                        let count = self.src.by_ref().take(length).read(into)?;
                        let length_usize = length as usize;
                        (length_usize - count, count)
                    }
                    ArchiveFileBlock::EndOfFile { id, .. } => {
                        if id != self.id {
                            self.move_to_next_block()?;
                            return self.read(into);
                        }
                        self.state = ArchiveEntryDataReaderState::Finish;
                        return Ok(0);
                    }
                    ArchiveFileBlock::FileStart { id, .. } => {
                        if id != self.id {
                            self.move_to_next_block()?;
                            return self.read(into);
                        }
                        return Err(Error::WrongReaderState(
                            "[BlocksToFileReader] Start with a wrong block type".to_string(),
                        )
                        .into());
                    }
                    ArchiveFileBlock::EndOfArchiveData => {
                        return Err(Error::WrongReaderState(
                            "[BlocksToFileReader] Try to read the end of the archive".to_string(),
                        )
                        .into());
                    }
                }
            }
            ArchiveEntryDataReaderState::InFile(remaining) => {
                let count = self.src.by_ref().take(remaining as u64).read(into)?;
                (remaining - count, count)
            }
            ArchiveEntryDataReaderState::Finish => {
                return Ok(0);
            }
        };
        if remaining > 0 {
            self.state = ArchiveEntryDataReaderState::InFile(remaining);
        } else {
            // remaining is 0 (> never happens thanks to take)
            self.state = ArchiveEntryDataReaderState::Ready;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Empty, Read};

    use crate::{
        Sha256Hash,
        entry::{ArchiveEntryDataReader, ArchiveEntryDataReaderState},
        format::ArchiveFileBlock,
    };

    #[test]
    fn blocks_to_file() {
        // Create several blocks
        let mut buf = Vec::new();
        let id = 0;
        let hash = Sha256Hash::default();

        let mut block = ArchiveFileBlock::FileStart::<&[u8]> {
            id,
            filename: String::from("foobar"),
        };
        block.dump(&mut buf).unwrap();
        let fake_content = vec![1, 2, 3, 4];
        let mut block = ArchiveFileBlock::FileContent {
            id,
            length: fake_content.len() as u64,
            data: Some(fake_content.as_slice()),
        };
        block.dump(&mut buf).unwrap();
        let fake_content2 = vec![5, 6, 7, 8];
        let mut block = ArchiveFileBlock::FileContent {
            id,
            length: fake_content2.len() as u64,
            data: Some(fake_content2.as_slice()),
        };
        block.dump(&mut buf).unwrap();

        // std::io::Empty is used because a type with Read is needed
        ArchiveFileBlock::EndOfFile::<Empty> { id, hash }
            .dump(&mut buf)
            .unwrap();

        let mut data_source = std::io::Cursor::new(buf);
        let offsets = [0];
        let mut reader = ArchiveEntryDataReader::new(&mut data_source, &offsets)
            .expect("BlockToFileReader failed");
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output.len(), fake_content.len() + fake_content2.len());
        let mut expected_output = Vec::new();
        expected_output.extend(fake_content);
        expected_output.extend(fake_content2);
        assert_eq!(output, expected_output);
        assert_eq!(reader.state, ArchiveEntryDataReaderState::Finish);
    }
}
