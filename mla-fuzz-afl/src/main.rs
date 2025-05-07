#[cfg(fuzzing)]
use afl::fuzz;
extern crate afl;
use bincode::{Encode, Decode};
use mlakey_parser::{parse_mlakey_privkey, parse_mlakey_pubkey};
use std::fs::File;
use std::io::{self, Cursor, Read, Write};

use mla::config::{ArchiveReaderConfig, ArchiveWriterConfig};
use mla::errors::{Error, FailSafeReadError};
use mla::{ArchiveFailSafeReader, ArchiveFileID, ArchiveReader, ArchiveWriter, Layers};

use std::collections::HashMap;

static PUB_KEY: &[u8] = include_bytes!("../../samples/test_mlakey_pub.pem");
static PRIV_KEY: &[u8] = include_bytes!("../../samples/test_mlakey.pem");

#[derive(Encode, Decode, Debug)]
struct TestInput {
    filenames: Vec<String>,
    // part[0] % filenames.len() -> corresponding file (made for interleaving)
    parts: Vec<Vec<u8>>,
    layers: Layers,
    // Bytes to flip in the buffer; it will fail, but we don't want it to panic
    byteflip: Vec<u32>,
}

fn run(data: &[u8]) {
    // Retrieve the input as a configuration
    // => Lot of failed here, but eventually AFL will be able to bypass it
    // let test_case: TestInput = bincode::decode_from_slice::<TestInput, _>(
    let (test_case, _) = bincode::decode_from_slice::<TestInput, _>(
        data,
        bincode::config::standard()
            .with_limit::< {10 * 1024 * 1024 } >()
            .with_fixed_int_encoding())
        .unwrap_or((TestInput {
            filenames: Vec::new(),
            parts: Vec::new(),
            layers: Layers::EMPTY,
            byteflip: vec![],
        }, 0));
    if test_case.filenames.is_empty() || test_case.filenames.len() >= 256 {
        // Early ret
        return;
    }

    // Load the needed public key
    let public_key = parse_mlakey_pubkey(PUB_KEY).unwrap();

    // Create a MLA Archive
    let mut buf = Vec::new();
    let mut config = ArchiveWriterConfig::new();
    config
        .set_layers(test_case.layers)
        .add_public_keys(&[public_key]);
    let mut mla = ArchiveWriter::from_config(&mut buf, config).unwrap();

    let mut num2id: HashMap<u8, ArchiveFileID> = HashMap::new();
    let mut filename2content: HashMap<String, Vec<u8>> = HashMap::new();
    for part in test_case.parts {
        let num = {
            if part.is_empty() {
                0
            } else {
                part[0] % (test_case.filenames.len() as u8)
            }
        };
        let id = {
            if let Some(id) = num2id.get(&num) {
                *id
            } else {
                let id = match mla.start_file(&test_case.filenames[num as usize]) {
                    Err(Error::DuplicateFilename) => {
                        return;
                    }
                    Err(err) => panic!("Start block failed {}", err),
                    Ok(id) => id,
                };
                num2id.insert(num, id);
                id
            }
        };
        mla.append_file_content(id, part.len() as u64, &part[..])
            .expect("Add part failed");

        let content = {
            let filename = test_case.filenames.get(num as usize).unwrap();
            if let Some(content) = filename2content.get_mut(filename) {
                content
            } else {
                let content = Vec::new();
                filename2content.insert(filename.clone(), content);
                filename2content.get_mut(filename).unwrap()
            }
        };
        content.extend(part);
    }

    for (i, fname) in test_case.filenames.iter().enumerate() {
        if !filename2content.contains_key(fname) {
            num2id.insert(
                i as u8,
                match mla.start_file(fname) {
                    Err(Error::DuplicateFilename) => {
                        return;
                    }
                    Err(err) => panic!("Start block failed {}", err),
                    Ok(id) => id,
                },
            );
        }
    }

    for id in num2id.values() {
        mla.end_file(*id).expect("End block failed");
    }

    mla.finalize().expect("Finalize failed");

    // Parse the created MLA Archive
    let dest = mla.into_raw();
    let buf = Cursor::new(dest.as_slice());
    let private_key = parse_mlakey_privkey(PRIV_KEY).unwrap();
    let mut config = ArchiveReaderConfig::new();
    config.add_private_keys(&[private_key]);
    let mut mla_read = ArchiveReader::from_config(buf, config).unwrap();

    // Check the list of files is correct
    let mut flist: Vec<String> = mla_read.list_files().unwrap().cloned().collect();
    flist.sort();
    #[allow(clippy::iter_cloned_collect)]
    let mut tflist: Vec<String> = test_case.filenames.iter().cloned().collect();
    tflist.sort();
    tflist.dedup();
    assert_eq!(flist, tflist);

    // Get and check file per file
    let empty = Vec::new();
    for fname in &tflist {
        let mut mla_file = mla_read.get_file(fname.clone()).unwrap().unwrap();
        assert_eq!(mla_file.filename, fname.clone());
        let mut buf = Vec::new();
        mla_file.data.read_to_end(&mut buf).unwrap();
        let content = filename2content.get(fname).unwrap_or(&empty);
        assert_eq!(&buf, content);
    }

    // Build FailSafeReader
    let buf = Cursor::new(dest.as_slice());
    let mut config = ArchiveReaderConfig::new();
    let private_key = parse_mlakey_privkey(PRIV_KEY).unwrap();
    config.add_private_keys(&[private_key]);
    let mut mla_fsread = ArchiveFailSafeReader::from_config(buf, config).unwrap();

    // Repair the archive (without any damage, but trigger the corresponding code)
    let dest_w = Vec::new();
    let mut mla_w =
        ArchiveWriter::from_config(dest_w, ArchiveWriterConfig::new()).expect("Writer init failed");
    if let FailSafeReadError::EndOfOriginalArchiveData =
        mla_fsread.convert_to_archive(&mut mla_w).unwrap()
    {
        // Everything runs as expected
    } else {
        panic!();
    }
    // Check the resulting files
    let dest_r = mla_w.into_raw();
    let buf = Cursor::new(dest_r.as_slice());
    let mut mla_read = ArchiveReader::from_config(buf, ArchiveReaderConfig::new()).unwrap();
    for fname in tflist {
        let mut mla_file = mla_read.get_file(fname.clone()).unwrap().unwrap();
        assert_eq!(mla_file.filename, fname.clone());
        let mut buf = Vec::new();
        mla_file.data.read_to_end(&mut buf).unwrap();
        let content = filename2content.get(&fname).unwrap_or(&empty);
        assert_eq!(&buf, content);
    }

    // Byte flip then failread and repair
    let mut changed = false;
    let mut dest_mut = Vec::from(dest.as_slice());
    for index in test_case.byteflip {
        if index >= dest.len() as u32 {
            // Do not byteflip
            continue;
        }
        dest_mut[index as usize] = dest_mut.get(index as usize).unwrap() ^ 0xFF;
        changed = true;
    }
    if !changed {
        return;
    }

    // Try to read
    // Check the resulting files
    let buf = Cursor::new(dest_mut.as_slice());
    let mut config = ArchiveReaderConfig::new();
    let private_key = parse_mlakey_privkey(PRIV_KEY).unwrap();
    config.add_private_keys(&[private_key]);
    let _do_steps = || -> Result<(), Error> {
        let mut mla_read = ArchiveReader::from_config(buf, ArchiveReaderConfig::new())?;
        let flist = mla_read.list_files()?.cloned().collect::<Vec<String>>();
        for fname in flist {
            let mut finfo = match mla_read.get_file(fname)? {
                Some(finfo) => finfo,
                None => continue,
            };
            io::copy(&mut finfo.data, &mut io::sink())?;
        }
        Ok(())
    };
    // Repair
    // Build FailSafeReader
    let buf = Cursor::new(dest_mut.as_slice());
    let mut config = ArchiveReaderConfig::new();
    let private_key = parse_mlakey_privkey(PRIV_KEY).unwrap();
    config.add_private_keys(&[private_key]);
    let mut mla_fsread = {
        if let Ok(mla) = ArchiveFailSafeReader::from_config(buf, config) {
            mla
        } else {
            return;
        }
    };
    // Repair the archive (without any damage, but trigger the corresponding code)
    let dest_w = Vec::new();
    let mut mla_w =
        ArchiveWriter::from_config(dest_w, ArchiveWriterConfig::new()).expect("Writer init failed");
    mla_fsread
        .convert_to_archive(&mut mla_w)
        .expect("End without a FailSafeReadError {}");
}

#[cfg(fuzzing)]
fn main() {
    // Fuzz it!
    fuzz!(|data: &[u8]| {
        run(data);
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
    let data: &'static [u8] = include_bytes!("..");
    run(data);
     */

    // Avoid dead code on build
    run(b"");

    // Produce samples for initialization
    produce_samples();
}

#[allow(dead_code)]
fn produce_samples() {
    let mut f1 = File::create("in/empty_file").unwrap();
    f1.write_all(
        &bincode::serialize(&TestInput {
            filenames: vec![String::from("test1")],
            parts: vec![],
            layers: Layers::EMPTY,
            byteflip: vec![],
        })
        .unwrap(),
    )
    .unwrap();

    let mut f2 = File::create("in/few_files").unwrap();
    f2.write_all(
        &bincode::serialize(&TestInput {
            filenames: vec![String::from("test1"), String::from("test2éèà")],
            parts: vec![
                vec![0, 2, 3, 4],
                vec![0, 5, 6],
                vec![1],
                vec![1],
                vec![1, 87, 3, 4, 5, 6],
            ],
            layers: Layers::DEFAULT,
            byteflip: vec![],
        })
        .unwrap(),
    )
    .unwrap();

    let mut f3 = File::create("in/interleaved").unwrap();
    f3.write_all(
        &bincode::serialize(&TestInput {
            filenames: vec![String::from("test1"), String::from("test2")],
            parts: vec![
                vec![0, 2, 3, 4],
                vec![1, 5, 6],
                vec![1],
                vec![0],
                vec![1, 87, 3, 4, 5, 6],
            ],
            layers: Layers::DEFAULT,
            byteflip: vec![],
        })
        .unwrap(),
    )
    .unwrap();

    let mut f4 = File::create("in/compress_only").unwrap();
    f4.write_all(
        &bincode::serialize(&TestInput {
            filenames: vec![String::from("test1"), String::from("test2")],
            parts: vec![
                vec![0, 2, 3, 4],
                vec![1, 5, 6],
                vec![1],
                vec![0],
                vec![1, 87, 3, 4, 5, 6],
            ],
            layers: Layers::COMPRESS,
            byteflip: vec![],
        })
        .unwrap(),
    )
    .unwrap();

    let mut f5 = File::create("in/byteflip").unwrap();
    f5.write_all(
        &bincode::serialize(&TestInput {
            filenames: vec![String::from("test1"), String::from("test2")],
            parts: vec![
                vec![0, 2, 3, 4],
                vec![1, 5, 6],
                vec![1],
                vec![0],
                vec![1, 87, 3, 4, 5, 6],
            ],
            layers: Layers::DEFAULT,
            byteflip: vec![20, 30],
        })
        .unwrap(),
    )
    .unwrap();
}
