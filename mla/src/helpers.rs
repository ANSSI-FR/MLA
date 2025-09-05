//! Some things you may find useful
use crate::entry::EntryName;
use crate::read_mla_entries_header;

pub use super::layers::traits::{InnerReaderTrait, InnerWriterTrait};

/// Helpers for common operation with MLA Archives
use super::{ArchiveEntryBlock, ArchiveEntryId, ArchiveReader, ArchiveWriter, Error};
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::io::{self, Read, Seek, Write};

/// Escaping function used by MLA, but may be useful for others
///
/// This generic escaping is described in `doc/ENTRY_NAME.md`
pub fn mla_percent_escape(bytes: &[u8], bytes_to_preserve: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(bytes.len() * 3);
    for byte in bytes {
        if bytes_to_preserve.contains(byte) {
            s.push(*byte);
        } else {
            let low_nibble = nibble_to_hex_char(*byte & 0x0F);
            let high_nibble = nibble_to_hex_char((*byte & 0xF0) >> 4);
            s.push(b'%');
            s.push(high_nibble);
            s.push(low_nibble);
        }
    }
    s
}

/// Inverse of `mla_percent_escape`
///
/// This generic unescaping is described in `doc/ENTRY_NAME.md`
pub fn mla_percent_unescape(input: &[u8], bytes_to_allow: &[u8]) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(input.len());
    let mut bytes = input.iter();
    while let Some(b) = bytes.next() {
        if bytes_to_allow.contains(b) {
            result.push(*b);
        } else if *b == b'%' {
            let high_nibble = bytes.next().and_then(|c| hex_char_to_nibble(*c));
            let low_nibble = bytes.next().and_then(|c| hex_char_to_nibble(*c));
            match (high_nibble, low_nibble) {
                (Some(high_nibble), Some(low_nibble)) => {
                    let decoded_byte = (high_nibble << 4) | low_nibble;
                    if bytes_to_allow.contains(&decoded_byte) {
                        return None;
                    }
                    result.push(decoded_byte);
                }
                _ => return None,
            }
        }
    }
    Some(result)
}

#[inline(always)]
fn nibble_to_hex_char(nibble: u8) -> u8 {
    if nibble <= 0x9 {
        b'0' + nibble
    } else {
        b'a' + (nibble - 0xa)
    }
}

#[inline(always)]
fn hex_char_to_nibble(hex_char: u8) -> Option<u8> {
    if hex_char.is_ascii_digit() {
        Some(hex_char - b'0')
    } else if (b'a'..=b'f').contains(&hex_char) {
        Some(hex_char - b'a' + 0xa)
    } else {
        None
    }
}

/// Extract an Archive linearly.
///
/// `export` maps entry names to Write objects, which will receive the
/// corresponding entry's content. If an entry is in the archive but not in
/// `export`, this entry will be silently ignored.
///
/// This is an performant way to extract all elements from an MLA Archive. It
/// avoids seeking for each entry, and for each entry part if entries are
/// interleaved. For an MLA Archive, seeking could be a costly operation, and might
/// involve additional computation and reading a lot of structure around to enable
/// decompression and decryption (eg. getting a whole encrypted block to check its
/// encryption tag).
/// Linear extraction avoids these costs by approximately reading once and only once each byte,
/// and by reducing the amount of seeks.
pub fn linear_extract<W1: InnerWriterTrait, R: InnerReaderTrait, S: BuildHasher>(
    archive: &mut ArchiveReader<R>,
    export: &mut HashMap<&EntryName, W1, S>,
) -> Result<(), Error> {
    // Seek at the beginning
    archive.src.rewind()?;

    // Skip the header, already checked in ArchiveReader::from_config
    read_mla_entries_header(&mut archive.src)?;

    // Use a BufReader to cache, by merging them into one bigger read, small
    // read calls (like the ones on ArchiveEntryBlock reading)
    let mut src = io::BufReader::new(&mut archive.src);

    // Associate an ID in the archive to the corresponding name
    // Do not directly associate to the writer to keep an easier fn API
    let mut id2name: HashMap<ArchiveEntryId, EntryName> = HashMap::new();

    'read_block: loop {
        match ArchiveEntryBlock::from(&mut src)? {
            ArchiveEntryBlock::EntryStart { name, id, opts: _ } => {
                // If the starting file is meant to be extracted, get the
                // corresponding writer
                if export.contains_key(&name) {
                    id2name.insert(id, name.clone());
                }
            }
            ArchiveEntryBlock::EndOfEntry { id, .. } => {
                // Drop the corresponding writer
                id2name.remove(&id);
            }
            ArchiveEntryBlock::EntryContent { length, id, .. } => {
                // Write a block to the corresponding output, if any

                let copy_src = &mut (&mut src).take(length);
                // Is the file considered?
                let mut extracted: bool = false;
                if let Some(entry) = id2name.get(&id)
                    && let Some(writer) = export.get_mut(entry)
                {
                    io::copy(copy_src, writer)?;
                    extracted = true;
                }
                if !extracted {
                    // Exhaust the block to Sink to forward the reader
                    io::copy(copy_src, &mut io::sink())?;
                }
            }
            ArchiveEntryBlock::EndOfArchiveData => {
                // Proper termination
                break 'read_block;
            }
        }
    }
    Ok(())
}

/// Provides a Write interface on an `ArchiveWriter` file
///
/// This interface is meant to be used in situations where length of the data
/// source is unknown, such as a stream. One can then use the `io::copy`
/// facilities to perform multiples block addition in the archive
pub struct StreamWriter<'a, 'b, W: InnerWriterTrait> {
    archive: &'b mut ArchiveWriter<'a, W>,
    file_id: ArchiveEntryId,
}

impl<'a, 'b, W: InnerWriterTrait> StreamWriter<'a, 'b, W> {
    pub fn new(archive: &'b mut ArchiveWriter<'a, W>, file_id: ArchiveEntryId) -> Self {
        Self { archive, file_id }
    }
}

impl<W: InnerWriterTrait> Write for StreamWriter<'_, '_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.archive
            .append_entry_content(self.file_id, buf.len() as u64, buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.archive.flush()
    }
}

#[cfg(test)]
mod tests {
    use crypto::hybrid::generate_keypair_from_seed;
    use rand::SeedableRng;
    use rand::distributions::Standard;
    use rand::prelude::Distribution;
    use rand_chacha::ChaChaRng;

    use super::*;
    use crate::entry::ENTRY_NAME_RAW_CONTENT_ALLOWED_BYTES;
    use crate::tests::build_archive;
    use crate::*;
    use std::io::Cursor;

    // From mla.layers.compress
    const UNCOMPRESSED_DATA_SIZE: u32 = 4 * 1024 * 1024;

    #[test]
    fn full_linear_extract() {
        // Build an archive with 3 files
        let (mla, _sender_key, receiver_key, files) = build_archive(true, true, false, false);

        // Prepare the reader
        let dest = Cursor::new(mla);
        let config = ArchiveReaderConfig::without_signature_verification()
            .with_encryption(&[receiver_key.0.get_decryption_private_key().clone()]);
        let mut mla_read = ArchiveReader::from_config(dest, config).unwrap().0;

        // Prepare writers
        let file_list: Vec<EntryName> = mla_read
            .list_entries()
            .expect("reader.list_entries")
            .cloned()
            .collect();
        let mut export: HashMap<&EntryName, Vec<u8>> =
            file_list.iter().map(|fname| (fname, Vec::new())).collect();
        linear_extract(&mut mla_read, &mut export).expect("Extract error");

        // Check file per file
        for (entry, content) in &files {
            assert_eq!(export.get(entry).unwrap(), content);
        }
    }

    #[test]
    fn one_linear_extract() {
        // Build an archive with 3 files
        let (mla, _sender_key, receiver_key, files) = build_archive(true, true, false, false);

        // Prepare the reader
        let dest = Cursor::new(mla);
        let config = ArchiveReaderConfig::without_signature_verification()
            .with_encryption(&[receiver_key.0.get_decryption_private_key().clone()]);
        let mut mla_read = ArchiveReader::from_config(dest, config).unwrap().0;

        // Prepare writers
        let mut export: HashMap<&EntryName, Vec<u8>> = HashMap::new();
        export.insert(&files[0].0, Vec::new());
        linear_extract(&mut mla_read, &mut export).expect("Extract error");

        // Check file
        assert_eq!(export.get(&files[0].0).unwrap(), &files[0].1);
    }

    #[test]
    /// Linear extraction of a file big enough to use several block
    ///
    /// This test is different from the layers' compress ones:
    /// - in the standard use, between each block, a `Seek` operation is made
    /// - the use of `linear_extract` avoid that repetitive `Seek` usage, as layers are "raw"-read
    ///
    /// Regression test for `brotli-decompressor` 2.3.3 to 2.3.4 (issue #146)
    fn linear_extract_big_file() {
        let file_length = 4 * UNCOMPRESSED_DATA_SIZE as usize;

        // --------- SETUP ----------
        let file = Vec::new();
        // Use a deterministic RNG in tests, for reproducibility. DO NOT DO THIS IS IN ANY RELEASED BINARY!
        let mut rng = ChaChaRng::seed_from_u64(0);
        let (private_key, public_key) = generate_keypair_from_seed([0; 32]);
        let config = ArchiveWriterConfig::with_encryption_without_signature(&[public_key]).unwrap();
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let entry = EntryName::from_arbitrary_bytes(b"my_file").unwrap();
        let data: Vec<u8> = Standard.sample_iter(&mut rng).take(file_length).collect();
        assert_eq!(data.len(), file_length);
        mla.add_entry(entry.clone(), data.len() as u64, data.as_slice())
            .unwrap();

        let dest = mla.finalize().unwrap();

        // --------------------------

        // Prepare the reader
        let dest = Cursor::new(dest);
        let config =
            ArchiveReaderConfig::without_signature_verification().with_encryption(&[private_key]);
        let mut mla_read = ArchiveReader::from_config(dest, config).unwrap().0;

        // Prepare writers
        let mut export: HashMap<&EntryName, Vec<u8>> = HashMap::new();
        export.insert(&entry, Vec::new());
        linear_extract(&mut mla_read, &mut export).expect("Extract error");

        // Check file
        assert_eq!(export.get(&entry).unwrap(), &data);
    }

    #[test]
    fn stream_writer() {
        let file = Vec::new();
        let config = ArchiveWriterConfig::without_encryption_without_signature()
            .unwrap()
            .without_compression();
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let fake_file = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Using write API
        let id = mla
            .start_entry(EntryName::from_arbitrary_bytes(b"my_file").unwrap())
            .unwrap();
        let mut sw = StreamWriter::new(&mut mla, id);
        sw.write_all(&fake_file[..5]).unwrap();
        sw.write_all(&fake_file[5..]).unwrap();
        mla.end_entry(id).unwrap();

        // Using io::copy
        let id = mla
            .start_entry(EntryName::from_arbitrary_bytes(b"my_entry2").unwrap())
            .unwrap();
        let mut sw = StreamWriter::new(&mut mla, id);
        assert_eq!(
            io::copy(&mut fake_file.as_slice(), &mut sw).unwrap(),
            fake_file.len() as u64
        );
        mla.end_entry(id).unwrap();

        let dest = mla.finalize().unwrap();

        // Read the obtained stream
        let buf = Cursor::new(dest.as_slice());
        let mut mla_read = ArchiveReader::from_config(
            buf,
            ArchiveReaderConfig::without_signature_verification().without_encryption(),
        )
        .unwrap()
        .0;
        let mut content1 = Vec::new();
        mla_read
            .get_entry(EntryName::from_arbitrary_bytes(b"my_file").unwrap())
            .unwrap()
            .unwrap()
            .data
            .read_to_end(&mut content1)
            .unwrap();
        assert_eq!(content1.as_slice(), fake_file.as_slice());
        let mut content2 = Vec::new();
        mla_read
            .get_entry(EntryName::from_arbitrary_bytes(b"my_entry2").unwrap())
            .unwrap()
            .unwrap()
            .data
            .read_to_end(&mut content2)
            .unwrap();
        assert_eq!(content2.as_slice(), fake_file.as_slice());
    }

    #[test]
    fn test_escape() {
        assert_eq!(
            b"%2f".as_slice(),
            mla_percent_escape(b"/", &ENTRY_NAME_RAW_CONTENT_ALLOWED_BYTES).as_slice()
        );
        assert_eq!(
            b"/".as_slice(),
            mla_percent_unescape(b"%2f", &ENTRY_NAME_RAW_CONTENT_ALLOWED_BYTES)
                .unwrap()
                .as_slice()
        );
    }
}
