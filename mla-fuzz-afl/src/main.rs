#[cfg(fuzzing)]
use afl::fuzz;
extern crate afl;
use mla::crypto::mlakey::{
    MLADecryptionPrivateKey, MLAEncryptionPublicKey, MLAPrivateKey, MLAPublicKey,
    MLASignatureVerificationPublicKey, MLASigningPrivateKey,
};
use mla::entry::EntryName;
use std::fs::File;
use std::io::{Cursor, Read, Write};

use mla::config::{ArchiveReaderConfig, ArchiveWriterConfig, TruncatedReaderConfig};
use mla::errors::Error;
use mla::{ArchiveReader, ArchiveWriter, TruncatedArchiveReader};

use std::collections::HashMap;

static PUB_KEY: &[u8] = include_bytes!("../../samples/test_mlakey.mlapub");
static PRIV_KEY: &[u8] = include_bytes!("../../samples/test_mlakey.mlapriv");

// FuzzMode enum to select compression/encryption/signature modes
// Each variant corresponds to a different configuration of the archive writer.
#[derive(Debug, Clone, Copy)]
pub enum FuzzMode {
    None = 0,
    Compress = 1,
    Encrypt = 2,
    EncryptSign = 3,
    CompressEncrypt = 4,
    CompressSign = 5,
    CompressEncryptSign = 6,
}

impl FuzzMode {
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(FuzzMode::None),
            1 => Some(FuzzMode::Compress),
            2 => Some(FuzzMode::Encrypt),
            3 => Some(FuzzMode::EncryptSign),
            4 => Some(FuzzMode::CompressEncrypt),
            5 => Some(FuzzMode::CompressSign),
            6 => Some(FuzzMode::CompressEncryptSign),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn to_writer_config(
        &self,
        pub_enc_key: &[MLAEncryptionPublicKey],
        priv_sign_key: &[MLASigningPrivateKey],
    ) -> Result<ArchiveWriterConfig, Error> {
        use FuzzMode::*;

        match self {
            None => Ok(ArchiveWriterConfig::without_encryption_without_signature()?),
            Compress => {
                let cfg = ArchiveWriterConfig::without_encryption_without_signature()?;
                Ok(cfg.with_compression_level(6)?)
            }
            Encrypt => Ok(ArchiveWriterConfig::with_encryption_without_signature(
                pub_enc_key,
            )?),
            EncryptSign => Ok(ArchiveWriterConfig::with_encryption_with_signature(
                pub_enc_key,
                priv_sign_key,
            )?),
            CompressEncrypt => {
                let cfg = ArchiveWriterConfig::with_encryption_without_signature(pub_enc_key)?;
                Ok(cfg.with_compression_level(6)?)
            }
            CompressSign => {
                let cfg = ArchiveWriterConfig::without_encryption_with_signature(priv_sign_key)?;
                Ok(cfg.with_compression_level(6)?)
            }
            CompressEncryptSign => {
                let cfg = ArchiveWriterConfig::with_encryption_with_signature(
                    pub_enc_key,
                    priv_sign_key,
                )?;
                Ok(cfg.with_compression_level(6)?)
            }
        }
    }

    pub fn to_reader_config(
        &self,
        pub_verif_key: &[MLASignatureVerificationPublicKey],
        priv_dec_key: &[MLADecryptionPrivateKey],
    ) -> ArchiveReaderConfig {
        use FuzzMode::*;

        match self {
            None | Compress | CompressSign => {
                // No encryption or only compression - skip encryption, maybe verify signature or skip
                if matches!(self, CompressSign) {
                    // Signature verification only, no encryption
                    ArchiveReaderConfig::with_signature_verification(pub_verif_key)
                        .without_encryption()
                } else {
                    // No encryption and no signature verification
                    ArchiveReaderConfig::without_signature_verification().without_encryption()
                }
            }

            Encrypt | EncryptSign | CompressEncrypt | CompressEncryptSign => {
                // Encrypted archive: must provide keys for decryption and possibly signature verification
                let reader_config = if matches!(self, EncryptSign | CompressEncryptSign) {
                    ArchiveReaderConfig::with_signature_verification(pub_verif_key)
                } else {
                    ArchiveReaderConfig::without_signature_verification()
                };
                reader_config.with_encryption(priv_dec_key)
            }
        }
    }

    pub fn to_truncated_reader_config(
        &self,
        priv_dec_key: &[MLADecryptionPrivateKey],
    ) -> TruncatedReaderConfig {
        use FuzzMode::*;

        if matches!(self, Encrypt | EncryptSign | CompressEncryptSign) {
            TruncatedReaderConfig::without_signature_verification_with_encryption(
                priv_dec_key,
                mla::config::TruncatedReaderDecryptionMode::DataEvenUnauthenticated,
            )
        } else {
            TruncatedReaderConfig::without_signature_verification_without_encryption()
        }
    }
}

struct TestInput {
    config: FuzzMode,
    filenames: Vec<String>,
    // part[0] % filenames.len() -> corresponding file (made for interleaving)
    parts: Vec<Vec<u8>>,
    // Bytes to flip in the buffer; it will fail, but we don't want it to panic
    byteflip: Vec<u32>,
}

// minimal version of MLA serialization
pub trait MLASerialize<W: Write> {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error>;
}

// minimal version of MLA deserialization
pub trait MLADeserialize<R: Read> {
    fn deserialize(src: &mut R) -> Result<Self, Error>
    where
        Self: std::marker::Sized;
}

impl<W: Write> MLASerialize<W> for TestInput {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        let mut total_written = 0u64;

        // Serialize config as 1 byte
        dest.write_all(&[self.config.to_u8()])?;
        total_written += 1;

        // Serialize the number of filenames
        let count = self.filenames.len() as u64;
        dest.write_all(&count.to_le_bytes())?;
        total_written += 8;

        // Serialize each filename
        for name in &self.filenames {
            let bytes = name.as_bytes();
            let len = bytes.len() as u64;
            dest.write_all(&len.to_le_bytes())?;
            dest.write_all(bytes)?;
            total_written += 8 + len;
        }

        // Serialize parts
        let parts_count = self.parts.len() as u64;
        dest.write_all(&parts_count.to_le_bytes())?;
        total_written += 8;

        for part in &self.parts {
            let part_len = part.len() as u64;
            dest.write_all(&part_len.to_le_bytes())?;
            dest.write_all(part)?;
            total_written += 8 + part_len;
        }

        // Serialize byteflip
        let flip_count = self.byteflip.len() as u32;
        dest.write_all(&flip_count.to_le_bytes())?;
        total_written += 4;

        for flip in &self.byteflip {
            dest.write_all(&flip.to_le_bytes())?;
            total_written += 4;
        }

        Ok(total_written)
    }
}

impl<R: Read> MLADeserialize<R> for TestInput {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let mut buf1 = [0u8; 1];
        src.read_exact(&mut buf1)?;
        let config = FuzzMode::from_u8(buf1[0]).ok_or(Error::DeserializationError)?;

        let mut buf8 = [0u8; 8];

        // Read number of filenames
        src.read_exact(&mut buf8)?;
        let num_files = u64::from_le_bytes(buf8) as usize;

        let mut filenames = Vec::with_capacity(num_files);
        for _ in 0..num_files {
            // Read string length
            src.read_exact(&mut buf8)?;
            let str_len = u64::from_le_bytes(buf8) as usize;

            // Read string bytes
            let mut str_buf = vec![0u8; str_len];
            src.read_exact(&mut str_buf)?;
            let string = String::from_utf8(str_buf).map_err(|_| Error::DeserializationError)?;
            filenames.push(string);
        }

        // Read number of parts
        src.read_exact(&mut buf8)?;
        let num_parts = u64::from_le_bytes(buf8) as usize;

        let mut parts = Vec::with_capacity(num_parts);
        for _ in 0..num_parts {
            // Read part length
            src.read_exact(&mut buf8)?;
            let part_len = u64::from_le_bytes(buf8) as usize;

            // Read part bytes
            let mut part_buf = vec![0u8; part_len];
            src.read_exact(&mut part_buf)?;
            parts.push(part_buf);
        }

        // Read number of byteflips (as u32)
        let mut buf4 = [0u8; 4];
        src.read_exact(&mut buf4)?;
        let num_flips = u32::from_le_bytes(buf4) as usize;

        let mut byteflip = Vec::with_capacity(num_flips);
        for _ in 0..num_flips {
            src.read_exact(&mut buf4)?;
            byteflip.push(u32::from_le_bytes(buf4));
        }

        Ok(TestInput {
            config,
            filenames,
            parts,
            byteflip,
        })
    }
}

fn run(data: &mut [u8]) {
    // load public and private keys
    let (pub_enc_key, pub_sig_verif_key) = MLAPublicKey::deserialize_public_key(PUB_KEY)
        .unwrap()
        .get_public_keys();
    let (priv_dec_key, priv_sig_key) = MLAPrivateKey::deserialize_private_key(PRIV_KEY)
        .unwrap()
        .get_private_keys();

    let mut cursor = Cursor::new(&*data);

    let test_case = TestInput::deserialize(&mut cursor).unwrap_or(TestInput {
        config: FuzzMode::None,
        filenames: Vec::new(),
        parts: Vec::new(),
        byteflip: vec![],
    });

    if test_case.filenames.is_empty() || test_case.filenames.len() >= 256 {
        return; // early exit on invalid
    }

    // archive writer configuration
    let archive_config = match test_case
        .config
        .to_writer_config(&[pub_enc_key], &[priv_sig_key])
    {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Invalid config: {e:?}");
            return;
        }
    };

    // Create archive writer buffer
    let mut buf = Vec::new();
    let mut mla = ArchiveWriter::from_config(&mut buf, archive_config).unwrap();

    let mut num2id: HashMap<u8, mla::entry::ArchiveEntryId> = HashMap::new();
    let mut filename2content: HashMap<String, Vec<u8>> = HashMap::new();

    for part in &test_case.parts {
        let num = if part.is_empty() {
            0
        } else {
            part[0] % (test_case.filenames.len() as u8)
        };
        let fname = &test_case.filenames[num as usize];

        let entry_name = match EntryName::from_arbitrary_bytes(fname.as_bytes()) {
            Ok(name) => name,
            Err(_) => {
                continue; // Skip parts with invalid filename
            }
        };

        let id = if let Some(id) = num2id.get(&num) {
            *id
        } else {
            match mla.start_entry(entry_name.clone()) {
                Err(Error::DuplicateFilename) => return,
                Err(err) => panic!("Start block failed {err}"),
                Ok(id) => {
                    num2id.insert(num, id);
                    id
                }
            }
        };

        mla.append_entry_content(id, part.len() as u64, &part[..])
            .expect("Add part failed");

        let content = filename2content.entry(fname.clone()).or_default();
        content.extend(part);
    }

    // Start entries missing from parts (with no content)
    // Also skip invalid entry names
    for (i, fname) in test_case.filenames.iter().enumerate() {
        if !filename2content.contains_key(fname) {
            if let Ok(entry_name) = EntryName::from_arbitrary_bytes(fname.as_bytes()) {
                if let Ok(id) = mla.start_entry(entry_name) {
                    num2id.insert(i as u8, id);
                }
            }
        }
    }

    for id in num2id.values() {
        mla.end_entry(*id).expect("End block failed");
    }

    let dest = mla.finalize().expect("Finalize failed");

    // Parse the created MLA Archive
    let buf = Cursor::new(dest.as_slice());
    let config = test_case
        .config
        .to_reader_config(&[pub_sig_verif_key.clone()], &[priv_dec_key.clone()]);
    let mut mla_read = ArchiveReader::from_config(buf, config).unwrap().0;

    // Check the list of files is correct
    let mut flist: Vec<String> = mla_read
        .list_entries()
        .unwrap()
        .map(|entry_name| entry_name.raw_content_to_escaped_string())
        .collect();
    flist.sort();

    // Read expected filenames, convert to escaped EntryName strings
    let mut tflist: Vec<String> = test_case
        .filenames
        .iter()
        .filter_map(|fname| {
            EntryName::from_arbitrary_bytes(fname.as_bytes())
                .ok()
                .map(|entry| entry.raw_content_to_escaped_string())
        })
        .collect();
    tflist.sort();
    tflist.dedup();

    assert_eq!(flist, tflist);

    // Verify file contents
    let empty = Vec::new();
    for fname in &test_case.filenames {
        let entry_name = match EntryName::from_arbitrary_bytes(fname.as_bytes()) {
            Ok(name) => name,
            Err(_) => continue, // skip invalid entry names
        };

        let mut mla_file = match mla_read.get_entry(entry_name) {
            Ok(Some(file)) => file,
            _ => continue, // skip missing or failed entries
        };

        let expected = filename2content.get(fname).unwrap_or(&empty);
        let mut readback = Vec::new();
        if mla_file.data.read_to_end(&mut readback).is_ok() {
            assert_eq!(readback, *expected);
        }
    }

    // === TruncatedArchiveReader repair test (simulate corruption) ===
    if !test_case.byteflip.is_empty() {
        let mut corrupted = dest.clone();

        // Apply byteflips (XOR with 0xFF)
        for &idx in &test_case.byteflip {
            if let Some(b) = corrupted.get_mut(idx as usize) {
                *b ^= 0xFF;
            }
        }

        // Try to read the corrupted archive with TruncatedArchiveReader
        let truncated_config = test_case.config.to_truncated_reader_config(&[priv_dec_key]);

        match TruncatedArchiveReader::from_config(
            Cursor::new(corrupted.as_slice()),
            truncated_config,
        ) {
            Ok(mut tr) => {
                // We'll try to salvage it into a new buffer
                let mut repaired = Vec::new();
                let out_cfg = ArchiveWriterConfig::without_encryption_without_signature().unwrap();
                let mla_out = ArchiveWriter::from_config(&mut repaired, out_cfg).unwrap();

                match tr.convert_to_archive(mla_out) {
                    Ok(result) => {
                        eprintln!("Repair finished with: {result:?}");

                        // Re-parse the repaired archive to ensure it's valid
                        let reader_cfg = ArchiveReaderConfig::without_signature_verification()
                            .without_encryption();
                        if let Ok((mut recovered_read, _)) =
                            ArchiveReader::from_config(Cursor::new(repaired.as_slice()), reader_cfg)
                        {
                            // Verify recovered file list and contents
                            let mut recovered_list: Vec<String> = recovered_read
                                .list_entries()
                                .unwrap()
                                .map(|entry_name| entry_name.raw_content_to_escaped_string())
                                .collect();
                            recovered_list.sort();

                            for recovered_file in &recovered_list {
                                if tflist.binary_search(recovered_file).is_err() {
                                    // Log and skip unexpected recovered files (possibly corrupted/mangled)
                                    eprintln!(
                                        "Warning: unexpected recovered file: {recovered_file}"
                                    );
                                    continue;
                                }
                            }

                            for fname in &tflist {
                                let entry_name =
                                    match EntryName::from_arbitrary_bytes(fname.as_bytes()) {
                                        Ok(name) => name,
                                        Err(_) => continue, // skip invalid entry names
                                    };

                                let mut mla_file = match recovered_read.get_entry(entry_name) {
                                    Ok(Some(file)) => file,
                                    _ => continue, // skip missing or failed entries
                                };

                                let mut recovered_data = Vec::new();
                                if mla_file.data.read_to_end(&mut recovered_data).is_ok() {
                                    let expected = filename2content.get(fname).unwrap_or(&empty);
                                    assert_eq!(&recovered_data, expected);
                                }
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("Repair failed: {err:?}");
                    }
                }
            }
            Err(e) => {
                // Invalid structure; skip. TruncatedArchiveReader may reject unparseable data
                eprintln!("TruncatedArchiveReader creation failed: {e:?}");
            }
        }
    }
}

#[cfg(fuzzing)]
fn main() {
    fuzz!(|data: &[u8]| {
        let mut buf = data.to_vec();
        run(&mut buf);
    });
}

#[cfg(not(fuzzing))]
fn main() {
    /*
    // Replay a sample:
    //
    // `$ /path/to/fuzz < sample`
    //
    // Or:
    //
    // let mut data = include_bytes!(
    //    "../out/default/crashes/my_crash"
    // ).to_vec();
    // run(&mut data);
     */

    // Avoid dead code on build
    let mut empty = Vec::new();
    run(&mut empty);

    // Produce samples for initialization
    produce_samples();
}

#[allow(dead_code)]
fn produce_samples() {
    const BUFFER_SIZE: usize = 1024 * 1024;

    fn write_sample(filename: &str, input: TestInput) {
        let mut buffer = [0u8; BUFFER_SIZE];
        let mut cursor = Cursor::new(&mut buffer[..]);
        let len = input.serialize(&mut cursor).unwrap();
        let mut file = File::create(filename).unwrap();
        file.write_all(&buffer[..len as usize]).unwrap();
    }

    use crate::FuzzMode;

    // test1: Minimal input, no compression or encryption
    write_sample(
        "in/empty_file",
        TestInput {
            config: FuzzMode::CompressEncrypt,
            filenames: vec![String::from("test1")],
            parts: vec![],
            byteflip: vec![],
        },
    );

    // few_files: Two filenames, multiple parts, no compression or encryption
    write_sample(
        "in/few_files",
        TestInput {
            config: FuzzMode::CompressEncrypt,
            filenames: vec![String::from("test1"), String::from("test2éèà")],
            parts: vec![
                vec![0, 2, 3, 4],
                vec![0, 5, 6],
                vec![1],
                vec![1],
                vec![1, 87, 3, 4, 5, 6],
            ],
            byteflip: vec![],
        },
    );

    // interleaved: two files, parts interleaved, no compression or encryption
    write_sample(
        "in/interleaved",
        TestInput {
            config: FuzzMode::CompressEncrypt,
            filenames: vec![String::from("test1"), String::from("test2")],
            parts: vec![
                vec![0, 2, 3, 4],        // file 0
                vec![1, 5, 6],           // file 1
                vec![1],                 // file 1
                vec![0],                 // file 0
                vec![1, 87, 3, 4, 5, 6], // file 1
            ],
            byteflip: vec![],
        },
    );

    // compress_only: same parts, enable compression mode
    write_sample(
        "in/compress_only",
        TestInput {
            config: FuzzMode::Compress,
            filenames: vec![String::from("test1"), String::from("test2")],
            parts: vec![
                vec![0, 2, 3, 4],
                vec![1, 5, 6],
                vec![1],
                vec![0],
                vec![1, 87, 3, 4, 5, 6],
            ],
            byteflip: vec![],
        },
    );

    // byteflip: same parts, with byte corruption markers, no compression
    write_sample(
        "in/byteflip",
        TestInput {
            config: FuzzMode::None,
            filenames: vec![String::from("test1"), String::from("test2")],
            parts: vec![
                vec![0, 2, 3, 4],
                vec![1, 5, 6],
                vec![1],
                vec![0],
                vec![1, 87, 3, 4, 5, 6],
            ],
            byteflip: vec![20, 30],
        },
    );
}
