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
    Sign = 3,
    EncryptSign = 4,
    CompressEncrypt = 5,
    CompressSign = 6,
    CompressEncryptSign = 7,
}

impl FuzzMode {
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(FuzzMode::None),
            1 => Some(FuzzMode::Compress),
            2 => Some(FuzzMode::Encrypt),
            3 => Some(FuzzMode::Sign),
            4 => Some(FuzzMode::EncryptSign),
            5 => Some(FuzzMode::CompressEncrypt),
            6 => Some(FuzzMode::CompressSign),
            7 => Some(FuzzMode::CompressEncryptSign),
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
        use FuzzMode::{
            Compress, CompressEncrypt, CompressEncryptSign, CompressSign, Encrypt, EncryptSign,
            None, Sign,
        };

        match self {
            None => Ok(ArchiveWriterConfig::without_encryption_without_signature()?),
            Compress => {
                let cfg = ArchiveWriterConfig::without_encryption_without_signature()?;
                Ok(cfg.with_compression_level(6)?)
            }
            Encrypt => Ok(ArchiveWriterConfig::with_encryption_without_signature(
                pub_enc_key,
            )?),
            Sign => Ok(ArchiveWriterConfig::without_encryption_with_signature(
                priv_sign_key,
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
        use FuzzMode::{
            Compress, CompressEncrypt, CompressEncryptSign, CompressSign, Encrypt, EncryptSign,
            None, Sign,
        };

        match self {
            None | Compress => {
                ArchiveReaderConfig::without_signature_verification().without_encryption()
            }
            Sign | CompressSign => {
                ArchiveReaderConfig::with_signature_verification(pub_verif_key).without_encryption()
            }
            Encrypt | CompressEncrypt => {
                ArchiveReaderConfig::without_signature_verification().with_encryption(priv_dec_key)
            }
            EncryptSign | CompressEncryptSign => {
                ArchiveReaderConfig::with_signature_verification(pub_verif_key)
                    .with_encryption(priv_dec_key)
            }
        }
    }

    pub fn to_truncated_reader_config(
        &self,
        priv_dec_key: &[MLADecryptionPrivateKey],
    ) -> TruncatedReaderConfig {
        use FuzzMode::{CompressEncrypt, CompressEncryptSign, Encrypt, EncryptSign};

        match self {
            Encrypt | EncryptSign | CompressEncrypt | CompressEncryptSign => {
                TruncatedReaderConfig::without_signature_verification_with_encryption(
                    priv_dec_key,
                    mla::config::TruncatedReaderDecryptionMode::DataEvenUnauthenticated,
                )
            }
            _ => TruncatedReaderConfig::without_signature_verification_without_encryption(),
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
        total_written = total_written.wrapping_add(1);

        // Serialize the number of filenames
        let count = self.filenames.len() as u64;
        dest.write_all(&count.to_le_bytes())?;
        total_written = total_written.wrapping_add(8);

        // Serialize each filename
        for name in &self.filenames {
            let bytes = name.as_bytes();
            let len = bytes.len() as u64;
            dest.write_all(&len.to_le_bytes())?;
            dest.write_all(bytes)?;
            total_written = total_written.wrapping_add(8).wrapping_add(len);
        }

        // Serialize parts
        let parts_count = self.parts.len() as u64;
        dest.write_all(&parts_count.to_le_bytes())?;
        total_written = total_written.wrapping_add(8);

        for part in &self.parts {
            let part_len = part.len() as u64;
            dest.write_all(&part_len.to_le_bytes())?;
            dest.write_all(part)?;
            total_written = total_written.wrapping_add(8).wrapping_add(part_len);
        }

        // Serialize byteflip
        let flip_count = u32::try_from(self.byteflip.len())
            .expect("Failed to convert byteflip array length to u32");
        dest.write_all(&flip_count.to_le_bytes())?;
        total_written = total_written.wrapping_add(4);

        for flip in &self.byteflip {
            dest.write_all(&flip.to_le_bytes())?;
            total_written = total_written.wrapping_add(4);
        }

        Ok(total_written)
    }
}

impl<R: Read> MLADeserialize<R> for TestInput {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        // Safety limits for untrusted input to avoid huge allocations
        const MAX_FILES: usize = 255;
        const MAX_FILENAME_LEN: usize = 4 * 1024; // 4 KiB
        const MAX_PARTS: usize = 1024;
        const MAX_PART_LEN: usize = 10 * 1024 * 1024; // 10 MiB
        const MAX_BYTEFLIPS: usize = 1024;

        let mut buf1 = [0u8; 1];
        src.read_exact(&mut buf1)?;
        let config = FuzzMode::from_u8(buf1[0]).ok_or(Error::DeserializationError)?;

        let mut buf8 = [0u8; 8];

        // Read number of filenames
        src.read_exact(&mut buf8)?;
        let num_files_u64 = u64::from_le_bytes(buf8);
        let num_files = usize::try_from(num_files_u64).map_err(|_| Error::DeserializationError)?;
        if num_files > MAX_FILES {
            return Err(Error::DeserializationError);
        }

        let mut filenames = Vec::with_capacity(num_files);
        for _ in 0..num_files {
            // Read string length
            src.read_exact(&mut buf8)?;
            let str_len_u64 = u64::from_le_bytes(buf8);
            let str_len = usize::try_from(str_len_u64).map_err(|_| Error::DeserializationError)?;
            if str_len > MAX_FILENAME_LEN {
                return Err(Error::DeserializationError);
            }

            // Read string bytes
            let mut str_buf = vec![0u8; str_len];
            src.read_exact(&mut str_buf)?;
            let string = String::from_utf8(str_buf).map_err(|_| Error::DeserializationError)?;
            filenames.push(string);
        }

        // Read number of parts
        src.read_exact(&mut buf8)?;
        let num_parts_u64 = u64::from_le_bytes(buf8);
        let num_parts = usize::try_from(num_parts_u64).map_err(|_| Error::DeserializationError)?;
        if num_parts > MAX_PARTS {
            return Err(Error::DeserializationError);
        }

        let mut parts = Vec::with_capacity(num_parts);
        for _ in 0..num_parts {
            // Read part length
            src.read_exact(&mut buf8)?;
            let part_len_u64 = u64::from_le_bytes(buf8);
            let part_len =
                usize::try_from(part_len_u64).map_err(|_| Error::DeserializationError)?;
            if part_len > MAX_PART_LEN {
                return Err(Error::DeserializationError);
            }

            // Read part bytes
            let mut part_buf = vec![0u8; part_len];
            src.read_exact(&mut part_buf)?;
            parts.push(part_buf);
        }

        // Read number of byteflips (as u32)
        let mut buf4 = [0u8; 4];
        src.read_exact(&mut buf4)?;
        let num_flips = u32::from_le_bytes(buf4) as usize;
        if num_flips > MAX_BYTEFLIPS {
            return Err(Error::DeserializationError);
        }

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
    // limit data size to avoid OOM
    // 10 Mo max
    if data.len() > 10 * 1024 * 1024 {
        eprintln!("Input too large, skipping");
        return;
    }

    // load public and private keys
    let (pub_enc_key, pub_sig_verif_key) = MLAPublicKey::deserialize_public_key(PUB_KEY)
        .unwrap()
        .get_public_keys();
    let (priv_dec_key, priv_sig_key) = MLAPrivateKey::deserialize_private_key(PRIV_KEY)
        .unwrap()
        .get_private_keys();

    let mut cursor = Cursor::new(&*data);

    // skip invalid inputs
    let test_case = match TestInput::deserialize(&mut cursor) {
        Ok(test_case) => test_case,
        Err(e) => {
            eprintln!("Deserialization failed: {e:?}");
            return;
        }
    };

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
    let mut entry_name2content: HashMap<String, Vec<u8>> = HashMap::new();

    for part in &test_case.parts {
        let num = if part.is_empty() {
            0
        } else {
            part[0]
                .checked_rem(
                    u8::try_from(test_case.filenames.len())
                        .expect("Failed to convert length to u8"),
                )
                .unwrap()
        };
        let name = &test_case.filenames[num as usize];

        let Ok(entry_name) = EntryName::from_arbitrary_bytes(name.as_bytes()) else {
            continue; // Skip parts with invalid filename
        };

        let id = if let Some(id) = num2id.get(&num) {
            *id
        } else {
            match mla.start_entry(entry_name.clone()) {
                Err(Error::DuplicateEntryName) => return,
                Err(err) => panic!("Start block failed {err}"),
                Ok(id) => {
                    num2id.insert(num, id);
                    id
                }
            }
        };

        mla.append_entry_content(id, part.len() as u64, &part[..])
            .expect("Add part failed");

        let content = entry_name2content.entry(name.clone()).or_default();
        content.extend(part);
    }

    // Start entries missing from parts (with no content)
    // Also skip invalid entry names
    for (i, name) in test_case.filenames.iter().enumerate() {
        if !entry_name2content.contains_key(name)
            && let Ok(entry_name) = EntryName::from_arbitrary_bytes(name.as_bytes())
            && let Ok(id) = mla.start_entry(entry_name)
        {
            num2id.insert(
                u8::try_from(i).expect("Failed to convert iterator to u8"),
                id,
            );
        }
    }

    for id in num2id.values() {
        mla.end_entry(*id).expect("End block failed");
    }

    let dest = mla.finalize().expect("Finalize failed");

    // Parse the created MLA Archive
    let buf = Cursor::new(dest.as_slice());
    let config = test_case.config.to_reader_config(
        std::slice::from_ref(&pub_sig_verif_key),
        std::slice::from_ref(&priv_dec_key),
    );
    let mut mla_read = ArchiveReader::from_config(buf, config).unwrap().0;

    // Check the list of files is correct
    let mut actual_entry_names: Vec<String> = mla_read
        .list_entries()
        .unwrap()
        .map(mla::entry::EntryName::raw_content_to_escaped_string)
        .collect();
    actual_entry_names.sort();

    // Read expected filenames, convert to escaped EntryName strings
    let mut expected_entry_names: Vec<String> = test_case
        .filenames
        .iter()
        .filter_map(|name| {
            EntryName::from_arbitrary_bytes(name.as_bytes())
                .ok()
                .map(|entry| entry.raw_content_to_escaped_string())
        })
        .collect();
    expected_entry_names.sort();
    expected_entry_names.dedup();

    assert_eq!(actual_entry_names, expected_entry_names);

    // Verify file contents
    let empty = Vec::new();
    for name in &test_case.filenames {
        let Ok(entry_name) = EntryName::from_arbitrary_bytes(name.as_bytes()) else {
            continue;
        };

        let Ok(Some(mut mla_file)) = mla_read.get_entry(entry_name) else {
            continue;
        };

        let expected = entry_name2content.get(name).unwrap_or(&empty);
        let mut readback = Vec::new();
        if mla_file.data.read_to_end(&mut readback).is_ok() {
            assert_eq!(readback, *expected);
        }
    }

    // === TruncatedArchiveReader `clean-truncated` test (simulate corruption) ===
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
                let mut clean_truncated = Vec::new();
                let out_cfg = ArchiveWriterConfig::without_encryption_without_signature().unwrap();
                let mla_out = ArchiveWriter::from_config(&mut clean_truncated, out_cfg).unwrap();

                match tr.convert_to_archive(mla_out) {
                    Ok(result) => {
                        eprintln!("Repair finished with: {result:?}");

                        // Re-parse the `clean-truncated` archive to ensure it's valid
                        let reader_cfg = ArchiveReaderConfig::without_signature_verification()
                            .without_encryption();
                        if let Ok((mut clean_truncated_read, _)) = ArchiveReader::from_config(
                            Cursor::new(clean_truncated.as_slice()),
                            reader_cfg,
                        ) {
                            // Verify `clean-truncated` entries list and contents
                            let mut clean_truncated_list: Vec<String> = clean_truncated_read
                                .list_entries()
                                .unwrap()
                                .map(mla::entry::EntryName::raw_content_to_escaped_string)
                                .collect();
                            clean_truncated_list.sort();

                            for clean_truncated_file in &clean_truncated_list {
                                if expected_entry_names
                                    .binary_search(clean_truncated_file)
                                    .is_err()
                                {
                                    // Log and skip unexpected `clean-truncated` files (possibly corrupted/mangled)
                                    eprintln!(
                                        "Warning: unexpected `clean-truncated` archive file: {clean_truncated_file}"
                                    );
                                }
                            }

                            for name in &expected_entry_names {
                                let Ok(entry_name) =
                                    EntryName::from_arbitrary_bytes(name.as_bytes())
                                else {
                                    continue;
                                };

                                let Ok(Some(mut mla_file)) =
                                    clean_truncated_read.get_entry(entry_name)
                                else {
                                    continue;
                                };

                                let mut clean_truncated_data = Vec::new();
                                if mla_file.data.read_to_end(&mut clean_truncated_data).is_ok() {
                                    let expected = entry_name2content.get(name).unwrap_or(&empty);

                                    if clean_truncated_data != *expected {
                                        eprintln!(
                                            "Data mismatch after clean truncation for file `{name}`.\nExpected: {expected:02x?}\nRecovered: {clean_truncated_data:02x?}"
                                        );
                                        // Don't panic during clean truncation verification as it is expected to be imperfect
                                    }
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

    fn write_sample(filename: &str, input: &TestInput) {
        let mut buffer = [0u8; BUFFER_SIZE];
        let mut cursor = Cursor::new(&mut buffer[..]);
        let len = input.serialize(&mut cursor).unwrap();
        let mut file = File::create(filename).unwrap();
        file.write_all(&buffer[..usize::try_from(len).expect("Failed to convert length to usize")])
            .unwrap();
    }

    use crate::FuzzMode;

    let filenames = vec![String::from("test1"), String::from("test2")];
    let parts = vec![
        vec![0, 2, 3, 4],
        vec![1, 5, 6],
        vec![1],
        vec![0],
        vec![1, 87, 3, 4, 5, 6],
    ];

    let modes = [
        (FuzzMode::None, "none"),
        (FuzzMode::Compress, "compress"),
        (FuzzMode::Encrypt, "encrypt"),
        (FuzzMode::Sign, "sign"),
        (FuzzMode::EncryptSign, "encrypt_sign"),
        (FuzzMode::CompressEncrypt, "compress_encrypt"),
        (FuzzMode::CompressSign, "compress_sign"),
        (FuzzMode::CompressEncryptSign, "compress_encrypt_sign"),
    ];

    for (mode, name) in &modes {
        write_sample(
            &format!("in/sample_{name}"),
            &TestInput {
                config: *mode,
                filenames: filenames.clone(),
                parts: parts.clone(),
                byteflip: vec![],
            },
        );
    }

    // Also produce a sample with byteflip corruption for each mode
    for (mode, name) in &modes {
        write_sample(
            &format!("in/sample_{name}_byteflip"),
            &TestInput {
                config: *mode,
                filenames: filenames.clone(),
                parts: parts.clone(),
                byteflip: vec![20, 30],
            },
        );
    }
}
