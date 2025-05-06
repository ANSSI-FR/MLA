use crate::layers::traits::InnerReaderTrait;

use super::layers::traits::InnerWriterTrait;
/// Helpers for common operation with MLA Archives
use super::{ArchiveFileBlock, ArchiveFileID, ArchiveReader, ArchiveWriter, Error};
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::io::{self, Read, Seek, Write};

/// Extract an Archive linearly.
///
/// `export` maps filenames to Write objects, which will receives the
/// corresponding file's content. If a file is in the archive but not in
/// `export`, this file will be silently ignored.
///
/// This is an effective way to extract all elements from an MLA Archive. It
/// avoids seeking for each files, and for each files parts if files are
/// interleaved. For an MLA Archive, seeking could be a costly operation, and might
/// involve reading data to `Sink` (seeking in decompression), or involves
/// additional computation (getting a whole encrypted block to check its
/// encryption tag).
/// Linear extraction avoids these costs by reading once and only once each byte,
/// and by reducing the amount of seeks.
pub fn linear_extract<W1: InnerWriterTrait, R: InnerReaderTrait, S: BuildHasher>(
    archive: &mut ArchiveReader<R>,
    export: &mut HashMap<&String, W1, S>,
) -> Result<(), Error> {
    // Seek at the beginning
    archive.src.rewind()?;

    // Use a BufReader to cache, by merging them into one bigger read, small
    // read calls (like the ones on ArchiveFileBlock reading)
    let mut src = io::BufReader::new(&mut archive.src);

    // Associate an ID in the archive to the corresponding filename
    // Do not directly associate to the writer to keep an easier fn API
    let mut id2filename: HashMap<ArchiveFileID, String> = HashMap::new();

    'read_block: loop {
        match ArchiveFileBlock::from(&mut src)? {
            ArchiveFileBlock::FileStart { filename, id } => {
                // If the starting file is meant to be extracted, get the
                // corresponding writer
                if export.contains_key(&filename) {
                    id2filename.insert(id, filename.clone());
                }
            }
            ArchiveFileBlock::EndOfFile { id, .. } => {
                // Drop the corresponding writer
                id2filename.remove(&id);
            }
            ArchiveFileBlock::FileContent { length, id, .. } => {
                // Write a block to the corresponding output, if any

                let copy_src = &mut (&mut src).take(length);
                // Is the file considered?
                let mut extracted: bool = false;
                if let Some(fname) = id2filename.get(&id) {
                    if let Some(writer) = export.get_mut(fname) {
                        io::copy(copy_src, writer)?;
                        extracted = true;
                    }
                };
                if !extracted {
                    // Exhaust the block to Sink to forward the reader
                    io::copy(copy_src, &mut io::sink())?;
                }
            }
            ArchiveFileBlock::EndOfArchiveData => {
                // Proper termination
                break 'read_block;
            }
        }
    }
    Ok(())
}

/// Provides a Write interface on an ArchiveWriter file
///
/// This interface is meant to be used in situations where length of the data
/// source is unknown, such as a stream. One can then use the `io::copy`
/// facilities to perform multiples block addition in the archive
pub struct StreamWriter<'a, 'b, W: InnerWriterTrait> {
    archive: &'b mut ArchiveWriter<'a, W>,
    file_id: ArchiveFileID,
}

impl<'a, 'b, W: InnerWriterTrait> StreamWriter<'a, 'b, W> {
    pub fn new(archive: &'b mut ArchiveWriter<'a, W>, file_id: ArchiveFileID) -> Self {
        Self { archive, file_id }
    }
}

impl<W: InnerWriterTrait> Write for StreamWriter<'_, '_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.archive
            .append_file_content(self.file_id, buf.len() as u64, buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.archive.flush()
    }
}

#[cfg(test)]
mod tests {
    use crypto::hybrid::generate_keypair_from_rng;
    use rand::SeedableRng;
    use rand::distributions::Standard;
    use rand::prelude::Distribution;
    use rand_chacha::ChaChaRng;

    use super::*;
    use crate::tests::build_archive;
    use crate::*;
    use std::io::Cursor;

    // From mla.layers.compress
    const UNCOMPRESSED_DATA_SIZE: u32 = 4 * 1024 * 1024;

    #[test]
    fn full_linear_extract() {
        // Build an archive with 3 files
        let (mla, key, _pubkey, files) = build_archive(None, false);

        // Prepare the reader
        let dest = Cursor::new(mla.into_raw());
        let mut config = ArchiveReaderConfig::new();
        config.add_private_keys(std::slice::from_ref(&key));
        let mut mla_read = ArchiveReader::from_config(dest, config).unwrap();

        // Prepare writers
        let file_list: Vec<String> = mla_read
            .list_files()
            .expect("reader.list_files")
            .cloned()
            .collect();
        let mut export: HashMap<&String, Vec<u8>> =
            file_list.iter().map(|fname| (fname, Vec::new())).collect();
        linear_extract(&mut mla_read, &mut export).expect("Extract error");

        // Check file per file
        for (fname, content) in files.iter() {
            assert_eq!(export.get(fname).unwrap(), content);
        }
    }

    #[test]
    fn one_linear_extract() {
        // Build an archive with 3 files
        let (mla, key, _pubkey, files) = build_archive(None, false);

        // Prepare the reader
        let dest = Cursor::new(mla.into_raw());
        let mut config = ArchiveReaderConfig::new();
        config.add_private_keys(std::slice::from_ref(&key));
        let mut mla_read = ArchiveReader::from_config(dest, config).unwrap();

        // Prepare writers
        let mut export: HashMap<&String, Vec<u8>> = HashMap::new();
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
        // Use a deterministic RNG in tests, for reproductability. DO NOT DO THIS IS IN ANY RELEASED BINARY!
        let mut rng = ChaChaRng::seed_from_u64(0);
        let (private_key, public_key) = generate_keypair_from_rng(&mut rng);
        let mut config = ArchiveWriterConfig::new();
        let layers = Layers::ENCRYPT | Layers::COMPRESS;
        config.set_layers(layers).add_public_keys(&[public_key]);
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let fname = "my_file".to_string();
        let data: Vec<u8> = Standard.sample_iter(&mut rng).take(file_length).collect();
        assert_eq!(data.len(), file_length);
        mla.add_file(&fname, data.len() as u64, data.as_slice())
            .unwrap();

        mla.finalize().unwrap();

        // --------------------------

        // Prepare the reader
        let dest = Cursor::new(mla.into_raw());
        let mut config = ArchiveReaderConfig::new();
        config.add_private_keys(std::slice::from_ref(&private_key));
        let mut mla_read = ArchiveReader::from_config(dest, config).unwrap();

        // Prepare writers
        let mut export: HashMap<&String, Vec<u8>> = HashMap::new();
        export.insert(&fname, Vec::new());
        linear_extract(&mut mla_read, &mut export).expect("Extract error");

        // Check file
        assert_eq!(export.get(&fname).unwrap(), &data);
    }

    #[test]
    fn stream_writer() {
        let file = Vec::new();
        let mut mla = ArchiveWriter::from_config(file, ArchiveWriterConfig::new())
            .expect("Writer init failed");

        let fake_file = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Using write API
        let id = mla.start_file("my_file").unwrap();
        let mut sw = StreamWriter::new(&mut mla, id);
        sw.write_all(&fake_file[..5]).unwrap();
        sw.write_all(&fake_file[5..]).unwrap();
        mla.end_file(id).unwrap();

        // Using io::copy
        let id = mla.start_file("my_file2").unwrap();
        let mut sw = StreamWriter::new(&mut mla, id);
        assert_eq!(
            io::copy(&mut fake_file.as_slice(), &mut sw).unwrap(),
            fake_file.len() as u64
        );
        mla.end_file(id).unwrap();

        mla.finalize().unwrap();

        // Read the obtained stream
        let dest = mla.into_raw();
        let buf = Cursor::new(dest.as_slice());
        let mut mla_read = ArchiveReader::from_config(buf, ArchiveReaderConfig::new()).unwrap();
        let mut content1 = Vec::new();
        mla_read
            .get_file("my_file".to_string())
            .unwrap()
            .unwrap()
            .data
            .read_to_end(&mut content1)
            .unwrap();
        assert_eq!(content1.as_slice(), fake_file.as_slice());
        let mut content2 = Vec::new();
        mla_read
            .get_file("my_file2".to_string())
            .unwrap()
            .unwrap()
            .data
            .read_to_end(&mut content2)
            .unwrap();
        assert_eq!(content2.as_slice(), fake_file.as_slice());
    }
}
