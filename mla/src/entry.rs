use std::io::{Read, Seek, SeekFrom};

use crate::{errors::Error, format::ArchiveFileBlock};

pub type ArchiveEntryId = u64;

#[derive(Debug)]
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

#[derive(Debug)]
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
