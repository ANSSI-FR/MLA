use assert_cmd::Command;
use assert_fs::fixture::{FileWriteBin, NamedTempFile, TempDir};
use glob;
use permutate::Permutator;
use rand::distributions::{Alphanumeric, Distribution, Standard};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::collections::{HashMap, HashSet};
use std::fs::{metadata, read_dir, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tar::Archive;

const SIZE_FILE1: usize = 10 * 1024 * 1024;
const SIZE_FILE2: usize = 10 * 1024 * 1024;
const UTIL: &str = "mlar";

struct TestFS {
    // Files ordered by names
    files: Vec<NamedTempFile>,
    // Files ordered by their place in the archive
    files_archive_order: Vec<PathBuf>,
}

fn setup() -> TestFS {
    let tmp_file1 = NamedTempFile::new("file1.bin").unwrap();
    let tmp_file2 = NamedTempFile::new("file2.bin").unwrap();
    let tmp_file3 = NamedTempFile::new("file3.bin").unwrap();

    // `file1.bin`: Use only alphanumeric charset to allow for compression
    let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
    let data: Vec<u8> = Alphanumeric
        .sample_iter(&mut rng)
        .take(SIZE_FILE1)
        .map(|c| c as u8)
        .collect();
    tmp_file1.write_binary(data.as_slice()).unwrap();

    // `file2.bin`: Use full charset for bad compression
    let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
    let data: Vec<u8> = Standard.sample_iter(&mut rng).take(SIZE_FILE2).collect();
    tmp_file2.write_binary(data.as_slice()).unwrap();

    // `file3.bin`: tiny file
    tmp_file3.write_binary(b"ABCDEFGHIJ").unwrap();

    let files_archive_order = vec![
        tmp_file1.path().to_path_buf(),
        tmp_file2.path().to_path_buf(),
        tmp_file3.path().to_path_buf(),
    ];
    let mut files = vec![tmp_file1, tmp_file2, tmp_file3];
    files.sort_by(|i1, i2| Ord::cmp(&i1.path(), &i2.path()));

    TestFS {
        files,
        files_archive_order,
    }
}

fn ensure_tar_content(tar_file: &Path, files: &[NamedTempFile]) {
    // Inspect the created TAR file
    let mut arch = Archive::new(File::open(tar_file).unwrap());

    // basename -> expected content
    let mut fname2content = HashMap::new();

    for file in files {
        let mut content = Vec::new();
        File::open(file.path())
            .unwrap()
            .read_to_end(&mut content)
            .unwrap();
        fname2content.insert(file.path().file_name().unwrap(), content);
    }

    for file in arch.entries().unwrap() {
        // Detect I/O error (from `tar-rs` example)
        let mut file = file.unwrap();

        let pbuf = file.header().path().unwrap().to_path_buf();
        let fname = pbuf.file_name().unwrap();

        // Ensure the content is the expected one
        let mut content = Vec::new();
        file.read_to_end(&mut content).unwrap();
        assert_eq!(&content, fname2content.get(fname).unwrap());

        // Prepare for last check: correctness and completeness
        fname2content.remove(fname);
    }
    // Ensure all files have been used
    assert_eq!(fname2content.len(), 0);
}

fn ensure_directory_content(directory: &Path, files: &[NamedTempFile]) {
    // basename -> expected content
    let mut fname2content = HashMap::new();

    for file in files {
        let mut content = Vec::new();
        File::open(file.path())
            .unwrap()
            .read_to_end(&mut content)
            .unwrap();
        fname2content.insert(file.path().file_name().unwrap(), content);
    }

    for entry in glob::glob(&(directory.to_string_lossy() + "/**/*")).unwrap() {
        let entry = entry.unwrap();
        if entry.metadata().unwrap().is_dir() {
            // Ignore directories
            continue;
        }
        let fname = entry.file_name().unwrap();

        // Ensure the content is the expected one
        let mut content = Vec::new();
        File::open(&entry)
            .unwrap()
            .read_to_end(&mut content)
            .unwrap();
        assert_eq!(&content, fname2content.get(fname).unwrap());

        // Prepare for last check: correctness and completeness
        fname2content.remove(fname);
    }
    // Ensure all files have been used
    assert_eq!(fname2content.len(), 0);
}

fn file_list_append_from_dir(dir: &Path, file_list: &mut Vec<String>) {
    for entry in read_dir(dir).unwrap() {
        let new_path = entry.unwrap().path();
        if new_path.is_dir() {
            file_list_append_from_dir(&new_path, file_list);
        } else {
            file_list.push(new_path.to_string_lossy().to_string());
        }
    }
}

#[test]
fn test_create_from_dir() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let ecc_public = Path::new("../samples/test_x25519_pub.pem");
    let ecc_private = Path::new("../samples/test_x25519.pem");

    // Temporary directory to test recursive file addition
    let tmp_dir = TempDir::new().unwrap();
    let mut subfile1_path = tmp_dir.path().join("subfile1");
    let subdir_path = tmp_dir.path().join("subdir");
    let mut subfile2_path = subdir_path.join("subfile2");

    std::fs::write(&mut subfile1_path, "Test1").unwrap();
    std::fs::create_dir(subdir_path).unwrap();
    std::fs::write(&mut subfile2_path, "Test2").unwrap();

    // `mlar create -o output.mla -p samples/test_x25519_pub.pem <tmp_dir>`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("-p")
        .arg(ecc_public);

    cmd.arg(tmp_dir.path());

    let mut file_list: Vec<String> = Vec::new();
    // The exact order of the files in the archive depends on the order of the
    // result of `read_dir` which is plateform and filesystem dependent.
    file_list_append_from_dir(tmp_dir.path(), &mut file_list);

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stderr(file_list.join("\n") + "\n");

    // `mlar list -i output.mla -k samples/test_x25519.pem`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(ecc_private);

    println!("{:?}", cmd);
    let assert = cmd.assert();
    file_list.sort();
    assert.success().stdout(file_list.join("\n") + "\n");
}

#[test]
fn test_create_filelist_stdin() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let ecc_public = Path::new("../samples/test_x25519_pub.pem");
    let ecc_private = Path::new("../samples/test_x25519.pem");

    // Create files
    let testfs = setup();

    // `mlar create -o output.mla -p samples/test_x25519_pub.pem -`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("-p")
        .arg(ecc_public);

    cmd.arg("-");
    println!("{:?}", cmd);

    let mut file_list = String::new();
    for file in &testfs.files {
        file_list.push_str(format!("{}\n", file.path().to_string_lossy()).as_str());
    }
    cmd.write_stdin(String::from(&file_list));
    println!("{:?}", file_list);
    let assert = cmd.assert();
    assert.success().stderr(String::from(&file_list));

    // `mlar list -i output.mla -k samples/test_x25519.pem`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(ecc_private);

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stdout(file_list);
}

#[test]
fn test_create_list_tar() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let tar_file = NamedTempFile::new("output.tar").unwrap();
    let ecc_public = Path::new("../samples/test_x25519_pub.pem");
    let ecc_private = Path::new("../samples/test_x25519.pem");

    // Create files
    let testfs = setup();

    // `mlar create -o output.mla -p samples/test_x25519_pub.pem file1.bin file2.bin file3.bin`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("-p")
        .arg(ecc_public);

    let mut file_list = String::new();
    for file in &testfs.files {
        cmd.arg(file.path());
        file_list.push_str(format!("{}\n", file.path().to_string_lossy()).as_str());
    }

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stderr(String::from(&file_list));

    // `mlar list -i output.mla -k samples/test_x25519.pem`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(ecc_private);

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stdout(file_list);

    // `mlar to-tar -i output.mla -k samples/test_x25519.pem -o output.tar`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("to-tar")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(ecc_private)
        .arg("-o")
        .arg(tar_file.path());

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success();

    // Inspect the created TAR file
    ensure_tar_content(&tar_file.path(), &testfs.files);
}

#[test]
fn test_truncated_repair_list_tar() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let mlar_repaired_file = NamedTempFile::new("repaired.mla").unwrap();
    let tar_file = NamedTempFile::new("output.tar").unwrap();
    let ecc_public = Path::new("../samples/test_x25519_pub.pem");
    let ecc_private = Path::new("../samples/test_x25519.pem");

    // Create files
    let testfs = setup();

    // `mlar create -o output.mla -p samples/test_x25519_pub.pem file1.bin file2.bin file3.bin`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("-p")
        .arg(ecc_public);

    let mut file_list = String::new(); // Sorted by position in archive
    let mut file_list_no_last = String::new(); // Sorted by name
    for file in &testfs.files {
        if file.path() != testfs.files_archive_order.last().unwrap() {
            file_list_no_last.push_str(format!("{}\n", file.path().to_string_lossy()).as_str());
        }
    }
    for path in &testfs.files_archive_order {
        cmd.arg(path);
        file_list.push_str(format!("{}\n", path.to_string_lossy()).as_str());
    }

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stderr(String::from(&file_list));

    // Truncate output.mla
    let mut data = Vec::new();
    File::open(mlar_file.path())
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    File::create(mlar_file.path())
        .unwrap()
        .write_all(&data[..data.len() * 6 / 7])
        .unwrap();

    // `mlar repair -i output.mla -k samples/test_x25519.pem -p samples/test_x25519_pub.pem -o repaired.mla`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("repair")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(ecc_private)
        .arg("-p")
        .arg(ecc_public)
        .arg("-o")
        .arg(mlar_repaired_file.path());

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success();

    // `mlar list -i repaired.mla -k samples/test_x25519.pem`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("-i")
        .arg(mlar_repaired_file.path())
        .arg("-k")
        .arg(ecc_private);

    println!("{:?}", cmd);
    let assert = cmd.assert();
    // Do not consider the last file for test after trunc, as we truncate at
    // 6 / 7 (last file being really small)
    assert.success().stdout(file_list_no_last);

    // `mlar to-tar -i output.mla -k samples/test_x25519.pem -o output.tar`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("to-tar")
        .arg("-i")
        .arg(mlar_repaired_file.path())
        .arg("-k")
        .arg(ecc_private)
        .arg("-o")
        .arg(tar_file.path());

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success();

    // Inspect the created TAR file
    let mut arch = Archive::new(File::open(tar_file.path()).unwrap());

    // basename -> expected content
    let mut fname2content = HashMap::new();

    // Do not consider the last file for test after trunc
    for file in &testfs.files_archive_order[..testfs.files_archive_order.len() - 1] {
        let mut content = Vec::new();
        File::open(file).unwrap().read_to_end(&mut content).unwrap();
        fname2content.insert(file.file_name().unwrap(), content);
    }

    for file in arch.entries().unwrap() {
        // Detect I/O error (from `tar-rs` example)
        let mut file = file.unwrap();

        let pbuf = file.header().path().unwrap().to_path_buf();
        let fname = pbuf.file_name().unwrap();

        // Ensure the extracted content is the same as the expected one, even if
        // truncated (ie, all the bytes must be correct, but the end can be missing)
        let mut content = Vec::new();
        file.read_to_end(&mut content).unwrap();
        assert_eq!(
            &content[..],
            &fname2content.get(fname).unwrap()[..content.len()]
        );
        // Ensure we have at least one byte
        assert_ne!(content.len(), 0);

        // Prepare for last check: correctness and completeness
        fname2content.remove(fname);
    }
    // Ensure all files have been used
    assert_eq!(fname2content.len(), 0);
}

#[test]
fn test_multiple_keys() {
    // Key parsing is common for each subcommands, so test only one: `list`
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let ecc_publics = vec![
        Path::new("../samples/test_x25519_pub.pem"),
        Path::new("../samples/test_x25519_3_pub.pem"),
    ];
    let ecc_privates = vec![
        Path::new("../samples/test_x25519.pem"),
        Path::new("../samples/test_x25519_2.pem"),
    ];

    // Create files
    let testfs = setup();

    // `mlar create -o output.mla -p samples/test_x25519_pub.pem -p samples/test_x25519_3_pub.pem file1.bin file2.bin file3.bin`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("-p")
        .arg(ecc_publics[0])
        .arg("-p")
        .arg(ecc_publics[1]);

    let mut file_list = String::new();
    for file in &testfs.files {
        cmd.arg(file.path());
        file_list.push_str(format!("{}\n", file.path().to_string_lossy()).as_str());
    }

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stderr(String::from(&file_list));

    // Ensure:
    // - we can read with one correct, one bad private key
    // - we can read with only the second correct private key
    // - we cannot read with only a bad private key

    // `mlar list -i output.mla -k samples/test_x25519.pem -k samples/test_x25519_2.pem`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(&ecc_privates[0])
        .arg("-k")
        .arg(&ecc_privates[1]);

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stdout(String::from(&file_list));

    // `mlar list -i output.mla -k samples/test_x25519_3.pem`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(Path::new("../samples/test_x25519_3.pem"));

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stdout(String::from(&file_list));

    // `mlar list -i output.mla -k samples/test_x25519_2.pem`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(&ecc_privates[1]);

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.failure();
}

#[test]
fn test_multiple_compression_level() {
    let mlar_file_q0 = NamedTempFile::new("output_q0.mla").unwrap();
    let mlar_file_q5 = NamedTempFile::new("output_q5.mla").unwrap();
    let tar_file_q0 = NamedTempFile::new("output_q0.tar").unwrap();
    let tar_file_q5 = NamedTempFile::new("output_q5.tar").unwrap();

    // Create files
    let testfs = setup();

    for (dest, compression_level) in &[(mlar_file_q0.path(), "0"), (mlar_file_q5.path(), "5")] {
        // `mlar create -o {dest} -l compress -q {compression_level} file1.bin file2.bin file3.bin`
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("create")
            .arg("-o")
            .arg(dest)
            .arg("-l")
            .arg("compress")
            .arg("-q")
            .arg(compression_level);

        let mut file_list = String::new();
        for file in &testfs.files {
            cmd.arg(file.path());
            file_list.push_str(format!("{}\n", file.path().to_string_lossy()).as_str());
        }

        println!("{:?}", cmd);
        let assert = cmd.assert();
        assert.success().stderr(String::from(&file_list));
    }

    // Hopefully, if compression works, q0 must be smaller than q5
    let q0_size = metadata(mlar_file_q0.path()).unwrap().len();
    let q5_size = metadata(mlar_file_q5.path()).unwrap().len();
    assert!(q5_size < q0_size);

    // Ensure files are correct
    for (src, tar_name) in vec![(mlar_file_q0, &tar_file_q0), (mlar_file_q5, &tar_file_q5)] {
        // `mlar to-tar -i {src} -o {tar_name}`
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("to-tar")
            .arg("-i")
            .arg(src.path())
            .arg("-o")
            .arg(tar_name.path());

        println!("{:?}", cmd);
        let assert = cmd.assert();
        assert.success();
    }
    ensure_tar_content(&tar_file_q0.path(), &testfs.files);
    ensure_tar_content(&tar_file_q5.path(), &testfs.files);
}

#[test]
fn test_convert() {
    // Create an archive with one public key, convert it to use only another key
    // without compression, then verify the size and the content of the archive
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let mlar_file_converted = NamedTempFile::new("convert.mla").unwrap();
    let tar_file = NamedTempFile::new("output.tar").unwrap();
    let ecc_public1 = Path::new("../samples/test_x25519_pub.pem");
    let ecc_private1 = Path::new("../samples/test_x25519.pem");
    let ecc_public2 = Path::new("../samples/test_x25519_2_pub.pem");
    let ecc_private2 = Path::new("../samples/test_x25519_2.pem");

    // Create files
    let testfs = setup();

    // `mlar create -o output.mla -p samples/public_1024.der file1.bin file2.bin file3.bin`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("-p")
        .arg(ecc_public1);

    let mut file_list = String::new();
    for file in &testfs.files {
        cmd.arg(file.path());
        file_list.push_str(format!("{}\n", file.path().to_string_lossy()).as_str());
    }

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stderr(String::from(&file_list));

    // `mlar convert -i output.mla -k samples/private_1024.der -l encrypt -o convert.mla -p samples/public_2048.der`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("convert")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(ecc_private1)
        .arg("-l")
        .arg("encrypt")
        .arg("-o")
        .arg(mlar_file_converted.path())
        .arg("-p")
        .arg(ecc_public2);

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stderr(String::from(&file_list));

    // Hopefully, compressed must be smaller than without compression
    let size_output = metadata(mlar_file.path()).unwrap().len();
    let size_convert = metadata(mlar_file_converted.path()).unwrap().len();
    assert!(size_output < size_convert);

    // `mlar to-tar -i convert.mla -k samples/private_2048.der -o output.tar`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("to-tar")
        .arg("-i")
        .arg(mlar_file_converted.path())
        .arg("-k")
        .arg(ecc_private2)
        .arg("-o")
        .arg(tar_file.path());

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success();

    // Inspect the created TAR file
    ensure_tar_content(&tar_file.path(), &testfs.files);
}

#[test]
fn test_stdio() {
    // Create an archive on stdout, and check it
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let tar_file = NamedTempFile::new("output.tar").unwrap();
    let ecc_public = Path::new("../samples/test_x25519_pub.pem");
    let ecc_private = Path::new("../samples/test_x25519.pem");

    // Create files
    let testfs = setup();

    // `mlar create -o - -p samples/test_x25519_pub.pem file1.bin file2.bin file3.bin`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-o")
        .arg("-")
        .arg("-p")
        .arg(ecc_public);

    let mut file_list = String::new();
    for file in &testfs.files {
        cmd.arg(file.path());
        file_list.push_str(format!("{}\n", file.path().to_string_lossy()).as_str());
    }

    println!("{:?}", cmd);
    let assert = cmd.assert();
    let archive_data = assert.get_output().stdout.clone();
    assert.success().stderr(String::from(&file_list));

    File::create(mlar_file.path())
        .unwrap()
        .write_all(&archive_data)
        .unwrap();
    // `mlar to-tar -i output.mla -k samples/test_x25519.pem -o output.tar`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("to-tar")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(ecc_private)
        .arg("-o")
        .arg(tar_file.path());

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success();

    // Inspect the created TAR file
    ensure_tar_content(&tar_file.path(), &testfs.files);
}

#[test]
fn test_multi_fileorders() {
    // Create several archive with all possible file order. Result should be the same
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let tar_file = NamedTempFile::new("output.tar").unwrap();
    let ecc_public = Path::new("../samples/test_x25519_pub.pem");
    let ecc_private = Path::new("../samples/test_x25519.pem");

    // Create files
    let testfs = setup();
    let path_array: &[&Path] = &[
        testfs.files[0].path(),
        testfs.files[1].path(),
        testfs.files[2].path(),
    ];
    let path_array = [path_array];
    let permutator = Permutator::new(&path_array[..]);

    for list in permutator {
        let set: HashSet<_> = list.iter().collect(); // dedup
        if set.len() != list.len() {
            // Duplicate, avoid
            continue;
        }

        // `mlar create -o output.mla -p samples/test_x25519_pub.pem file1.bin file2.bin file3.bin`
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("create")
            .arg("-o")
            .arg(mlar_file.path())
            .arg("-p")
            .arg(ecc_public);

        let mut file_list = String::new();
        for file in list {
            cmd.arg(file);
            file_list.push_str(format!("{}\n", file.to_string_lossy()).as_str());
        }

        println!("{:?}", cmd);
        let assert = cmd.assert();
        assert.success().stderr(String::from(&file_list));

        // `mlar to-tar -i convert.mla -k samples/test_x25519.pem -o output.tar`
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("to-tar")
            .arg("-i")
            .arg(mlar_file.path())
            .arg("-k")
            .arg(ecc_private)
            .arg("-o")
            .arg(tar_file.path());

        println!("{:?}", cmd);
        let assert = cmd.assert();
        assert.success();

        // Inspect the created TAR file
        ensure_tar_content(&tar_file.path(), &testfs.files);
    }
}

#[test]
fn test_verbose_listing() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let testfs = setup();

    // `mlar create -l -o output.mla
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create").arg("-l").arg("-o").arg(mlar_file.path());

    let mut file_list = String::new();
    for file in &testfs.files {
        cmd.arg(file.path());
        file_list.push_str(format!("{}\n", file.path().to_string_lossy()).as_str());
    }

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stderr(String::from(&file_list));

    // `mlar list -i output.mla`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list").arg("-i").arg(mlar_file.path());

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stdout(file_list);

    // `mlar list -v -i output.mla`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list").arg("-v").arg("-i").arg(mlar_file.path());

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success();

    // `mlar list -vv -i output.mla`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list").arg("-vv").arg("-i").arg(mlar_file.path());

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success();
}

#[test]
fn test_extract() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let mut testfs = setup();

    // `mlar create -l -o output.mla
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create").arg("-l").arg("-o").arg(mlar_file.path());

    let mut file_list = String::new();
    for file in &testfs.files {
        cmd.arg(file.path());
        file_list.push_str(format!("{}\n", file.path().to_string_lossy()).as_str());
    }

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stderr(String::from(&file_list));

    let mut file_list = String::new();
    for file in &testfs.files {
        file_list.push_str(format!("{}\n", file.path().to_string_lossy()).as_str());
    }

    // Test global (with all files)

    // `mlar extract -v -i output.mla -o ouput_dir -g '*'`
    let output_dir = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("extract")
        .arg("-v")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-o")
        .arg(output_dir.path())
        .arg("-g")
        .arg("*");

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stdout(file_list);

    ensure_directory_content(output_dir.path(), &testfs.files);

    // Test linear extraction of all files

    // `mlar extract -v -i output.mla -o ouput_dir`
    let output_dir = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("extract")
        .arg("-v")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-o")
        .arg(output_dir.path());

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert
        .success()
        .stdout("Extracting the whole archive using a linear extraction\n");

    ensure_directory_content(output_dir.path(), &testfs.files);

    // Test extraction of one file explicitly
    // `mlar extract -v -i output.mla -o ouput_dir file1`
    let one_filename = &testfs.files_archive_order[0];
    let mut one_file = Vec::new();
    loop {
        match testfs.files.pop() {
            None => {
                break;
            }
            Some(ntf) => {
                if ntf.path() == one_filename {
                    one_file.push(ntf);
                }
            }
        }
    }
    let output_dir = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("extract")
        .arg("-v")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-o")
        .arg(output_dir.path())
        .arg(one_filename);

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert
        .success()
        .stdout(format!("{}\n", one_filename.to_string_lossy()));

    ensure_directory_content(output_dir.path(), &one_file);

    // Test extraction of one file through glob
    // `mlar extract -v -i output.mla -o ouput_dir -g *1*`
    let output_dir = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("extract")
        .arg("-v")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-o")
        .arg(output_dir.path())
        .arg("-g")
        .arg("*file1*");

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert
        .success()
        .stdout(format!("{}\n", one_filename.to_string_lossy()));

    ensure_directory_content(output_dir.path(), &one_file);
}

#[test]
fn test_cat() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let testfs = setup();

    // `mlar create -l -o output.mla
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create").arg("-l").arg("-o").arg(mlar_file.path());

    let mut file_list = String::new();
    for file in &testfs.files {
        cmd.arg(file.path());
        file_list.push_str(format!("{}\n", file.path().to_string_lossy()).as_str());
    }

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stderr(String::from(&file_list));

    // `mlar cat -i output.mla file1`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("cat")
        .arg("-i")
        .arg(mlar_file.path())
        .arg(&testfs.files_archive_order[2]);

    println!("{:?}", cmd);
    let assert = cmd.assert();

    let mut expected_content = Vec::new();
    File::open(&testfs.files_archive_order[2])
        .unwrap()
        .read_to_end(&mut expected_content)
        .unwrap();
    assert_eq!(assert.success().get_output().stdout, expected_content);
}

#[test]
fn test_keygen() {
    // Gen a keypair, create and list an archive using them
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let output_dir = TempDir::new().unwrap();
    let base_name = output_dir.path().join("key");
    let testfs = setup();

    // `mlar keygen tempdir/key`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("keygen").arg(&base_name);
    cmd.assert().success();

    // `mlar create -p tempdir/key.pub -o output.mla file1 file2 file3`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-p")
        .arg(base_name.with_extension("pub"))
        .arg("-o")
        .arg(mlar_file.path());

    let mut file_list = String::new();
    for file in &testfs.files {
        cmd.arg(file.path());
        file_list.push_str(format!("{}\n", file.path().to_string_lossy()).as_str());
    }

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stderr(String::from(&file_list));

    // `mlar list -k tempdir/key -i output.mla`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("-k")
        .arg(base_name)
        .arg("-i")
        .arg(mlar_file.path());

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stdout(file_list);
}

#[test]
fn test_verbose_info() {
    let ecc_public = Path::new("../samples/test_x25519_pub.pem");
    let ecc_private = Path::new("../samples/test_x25519.pem");
    let ecc_public_2 = Path::new("../samples/test_x25519_2_pub.pem");

    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let testfs = setup();

    // `mlar create -l -o output.mla
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create").arg("-o").arg(mlar_file.path());
    cmd.arg("-l").arg("compress");
    cmd.arg("-l").arg("encrypt");
    cmd.arg("-p").arg(ecc_public);
    cmd.arg("-p").arg(ecc_public_2);

    let mut file_list = String::new();
    for file in &testfs.files {
        cmd.arg(file.path());
        file_list.push_str(format!("{}\n", file.path().to_string_lossy()).as_str());
    }

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stderr(String::from(&file_list));

    // `mlar info -k <key> -i output.mla`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("info")
        .arg("-k")
        .arg(ecc_private)
        .arg("-i")
        .arg(mlar_file.path());

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success().stdout(
        "Format version: 1
Encryption: true
Compression: true
",
    );

    // `mlar info -k <key> -v -i output.mla`
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("info")
        .arg("-k")
        .arg(ecc_private)
        .arg("-v")
        .arg("-i")
        .arg(mlar_file.path());

    println!("{:?}", cmd);
    let assert = cmd.assert();
    assert.success();
}
