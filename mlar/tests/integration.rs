use assert_cmd::Command;
use assert_fs::fixture::{FileWriteBin, NamedTempFile, TempDir};
use mla::entry::EntryName;
use permutate::Permutator;
use rand::SeedableRng;
use rand::distr::{Alphanumeric, Distribution, StandardUniform};
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, metadata, read_dir};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use tar::Archive;

const SIZE_FILE1: usize = 10 * 1024 * 1024;
const SIZE_FILE2: usize = 10 * 1024 * 1024;
const UTIL: &str = "mlar";

fn normalize(path: &Path) -> PathBuf {
    let mut stack = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => (),
            Component::ParentDir => {
                stack.pop();
            }
            Component::Normal(os_str) => stack.push(os_str),
        }
    }
    stack
}

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
        .collect();
    tmp_file1.write_binary(data.as_slice()).unwrap();

    // `file2.bin`: Use full charset for bad compression
    let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
    let data: Vec<u8> = StandardUniform
        .sample_iter(&mut rng)
        .take(SIZE_FILE2)
        .collect();
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

fn file_list_append_from_dir(dir: &Path, file_list: &mut Vec<String>) {
    for entry in read_dir(dir).unwrap() {
        let new_path = entry.unwrap().path();
        if new_path.is_dir() {
            file_list_append_from_dir(&new_path, file_list);
        } else {
            let entry_name = EntryName::from_path(new_path).unwrap();
            let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
            file_list.push(escaped);
        }
    }
}

#[test]
fn test_help() {
    // `mlar --help`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("--help");

    // Ensure the basic help display is working
    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success();
}

#[test]
fn test_create_from_dir() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let public_key = Path::new("../samples/test_mlakey.mlapub");
    let private_key = Path::new("../samples/test_mlakey.mlapriv");

    // Temporary directory with nested structure
    let tmp_dir = TempDir::new().unwrap();
    let entry1_path = tmp_dir.path().join("entry1");
    let subdir_path = tmp_dir.path().join("subdir");
    let entry2_path = subdir_path.join("entry2");

    std::fs::write(&entry1_path, "Test1").unwrap();
    std::fs::create_dir(&subdir_path).unwrap();
    std::fs::write(&entry2_path, "Test2").unwrap();

    // Collect paths from directory into file_list
    let mut file_list: Vec<String> = Vec::new();
    file_list_append_from_dir(tmp_dir.path(), &mut file_list);

    // Prepare expected stderr with " adding: {path}\n"
    let mut expected_stderr = String::new();
    for path in &file_list {
        expected_stderr.push_str(format!(" adding: {path}\n").as_str());
    }

    // `mlar create -o output.mla -p samples/test_mlakey.mlapub <tmp_dir>`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-l")
        .arg("encrypt")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("-p")
        .arg(public_key)
        .arg(tmp_dir.path());

    println!("{cmd:?}");
    cmd.assert().success().stderr(expected_stderr);

    // Sort file list for consistent output
    // The exact order of the files in the archive depends on the order of the
    // result of `read_dir` which is plateform and filesystem dependent.
    file_list.sort();
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let expected_stdout = file_list.join("\n") + "\n";

    // `mlar list -i output.mla -k samples/test_mlakey.mlapriv`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("--skip-signature-verification")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(private_key);

    println!("{cmd:?}");
    cmd.assert().success().stdout(expected_stdout);
}

#[test]
fn test_create_filelist_stdin() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let public_key = Path::new("../samples/test_mlakey.mlapub");
    let private_key = Path::new("../samples/test_mlakey.mlapriv");

    // Create files
    let testfs = setup();

    // Build the stdin file list
    let mut file_list_stdin = String::new();
    for file in &testfs.files {
        file_list_stdin.push_str(format!("{}\n", file.path().to_string_lossy()).as_str());
    }

    // Expected stderr:  adding: <escaped> (<size> bytes)
    let mut expected_stderr = String::new();

    // Expected stdout: plain paths (escaped)
    let mut expected_stdout = String::new();

    for file in &testfs.files {
        let entry_name = EntryName::from_path(file.path()).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();

        expected_stderr.push_str(format!(" adding: {escaped}\n").as_str());
        expected_stdout.push_str(format!("{escaped}\n").as_str());
    }

    // `mlar create -o output.mla -p samples/test_mlakey.mlapub -`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-l")
        .arg("encrypt")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("-p")
        .arg(public_key)
        .arg("--stdin-filepath-list");

    println!("{cmd:?}");
    cmd.write_stdin(file_list_stdin);
    println!("{expected_stderr:?}");

    let assert = cmd.assert();
    assert.success().stderr(expected_stderr);

    // `mlar list -i output.mla -k samples/test_mlakey.mlapriv`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("--skip-signature-verification")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(private_key);

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success().stdout(expected_stdout);
}

#[test]
fn test_create_list_tar() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let tar_file = NamedTempFile::new("output.tar").unwrap();
    let sender_public_key = Path::new("../samples/test_mlakey_archive_v2_sender.mlapub");
    let sender_private_key = Path::new("../samples/test_mlakey_archive_v2_sender.mlapriv");
    let receiver_public_key = Path::new("../samples/test_mlakey_archive_v2_receiver.mlapub");
    let receiver_private_key = Path::new("../samples/test_mlakey_archive_v2_receiver.mlapriv");

    // Create files
    let testfs = setup();

    // `mlar create -o output.mla -p samples/test_mlakey.mlapub file1.bin file2.bin file3.bin`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("-p")
        .arg(receiver_public_key)
        .arg("-k")
        .arg(sender_private_key);

    let mut file_list = String::new(); // For stdout (list)
    let mut expected_stderr = String::new(); // For stderr (create)

    for file in &testfs.files {
        cmd.arg(file.path());

        let entry_name = EntryName::from_path(file.path()).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
        file_list.push_str(format!("{escaped}\n").as_str());
        expected_stderr.push_str(format!(" adding: {escaped}\n").as_str());
    }

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success().stderr(expected_stderr);

    // `mlar list -i output.mla -k samples/test_mlakey.mlapriv`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-p")
        .arg(sender_public_key)
        .arg("-k")
        .arg(receiver_private_key);

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success().stdout(file_list);

    // `mlar to-tar -i output.mla -k samples/test_mlakey.mlapriv -o output.tar`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("to-tar")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-p")
        .arg(sender_public_key)
        .arg("-k")
        .arg(receiver_private_key)
        .arg("-o")
        .arg(tar_file.path());

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success();

    // Inspect the created TAR file
    ensure_tar_content(tar_file.path(), &testfs.files);
}

#[test]
fn test_truncated_clean_truncated_list_tar() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let mlar_clean_truncated_file = NamedTempFile::new("clean_truncated.mla").unwrap();
    let tar_file = NamedTempFile::new("output.tar").unwrap();
    let public_key = Path::new("../samples/test_mlakey.mlapub");
    let private_key = Path::new("../samples/test_mlakey.mlapriv");

    // Create files
    let testfs = setup();

    // Prepare expected outputs:
    // 1. For create command stderr (with prefix)
    let mut file_list = String::new(); // Sorted by position in archive
    // 2. For list command stdout (plain file list, no prefix)
    let mut file_list_no_last_plain = String::new();

    for file in &testfs.files {
        if file.path() != testfs.files_archive_order.last().unwrap() {
            let entry_name = EntryName::from_path(file.path()).unwrap();
            let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
            file_list_no_last_plain.push_str(format!("{escaped}\n").as_str());
        }
    }

    for path in &testfs.files_archive_order {
        let entry_name = EntryName::from_path(path).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
        file_list.push_str(format!(" adding: {escaped}\n").as_str());
    }

    // `mlar create -o output.mla -p samples/test_mlakey.mlapub file1.bin file2.bin file3.bin`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-l")
        .arg("encrypt")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("-p")
        .arg(public_key);

    for path in &testfs.files_archive_order {
        cmd.arg(path);
    }

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success().stderr(file_list);

    // Truncate output.mla to simulate corruption
    let mut data = Vec::new();
    File::open(mlar_file.path())
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    File::create(mlar_file.path())
        .unwrap()
        .write_all(&data[..data.len() * 6 / 7])
        .unwrap();

    // `mlar clean-truncated -i output.mla -k samples/test_mlakey.mlapriv -p samples/test_mlakey.mlapub -o clean_truncated.mla`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("clean-truncated")
        .arg("--skip-signature-verification")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(private_key)
        .arg("--out-pub")
        .arg(public_key)
        .arg("-l")
        .arg("encrypt")
        .arg("-o")
        .arg(mlar_clean_truncated_file.path());

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success();

    // `mlar list -i clean_truncated.mla -k samples/test_mlakey.mlapriv`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("--skip-signature-verification")
        .arg("-i")
        .arg(mlar_clean_truncated_file.path())
        .arg("-k")
        .arg(private_key);

    println!("{cmd:?}");
    let assert = cmd.assert();
    // Expect plain entries list for the `clean-truncated` list, without last truncated file
    // as truncated at 6 / 7, last file being really small
    assert.success().stdout(file_list_no_last_plain);

    // `mlar to-tar -i output.mla -k samples/test_mlakey.mlapriv -o output.tar`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("to-tar")
        .arg("--skip-signature-verification")
        .arg("-i")
        .arg(mlar_clean_truncated_file.path())
        .arg("-k")
        .arg(private_key)
        .arg("-o")
        .arg(tar_file.path());

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success();

    // Inspect the created TAR file
    let mut arch = Archive::new(File::open(tar_file.path()).unwrap());

    // basename -> expected content map
    let mut fname2content = HashMap::new();

    // Do not consider the last file for test after truncation
    for file in &testfs.files_archive_order[..testfs.files_archive_order.len() - 1] {
        let mut content = Vec::new();
        File::open(file).unwrap().read_to_end(&mut content).unwrap();
        fname2content.insert(file.file_name().unwrap().to_owned(), content);
    }

    for file in arch.entries().unwrap() {
        // Detect I/O error (from `tar-rs` example)
        let mut file = file.unwrap();

        let pbuf = file.header().path().unwrap().to_path_buf();
        let fname = pbuf.file_name().unwrap();

        // Ensure the extracted content is correct (partial allowed due to truncation)
        let mut content = Vec::new();
        file.read_to_end(&mut content).unwrap();
        assert_eq!(
            &content[..],
            &fname2content.get(fname).unwrap()[..content.len()]
        );
        // Ensure we have at least one byte
        assert_ne!(content.len(), 0);

        // Remove used files to check completeness
        fname2content.remove(fname);
    }
    // Ensure all expected files have been matched
    assert_eq!(fname2content.len(), 0);
}

#[test]
fn test_clean_truncated_auth_unauth() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let mlar_clean_truncated_file = NamedTempFile::new("clean_truncated.mla").unwrap();
    let public_key = Path::new("../samples/test_mlakey.mlapub");
    let private_key = Path::new("../samples/test_mlakey.mlapriv");

    // Create files
    let testfs = setup();

    for i in 0..3 {
        // Prepare expected outputs for create and list commands
        let entry_name = EntryName::from_path(testfs.files[i].path()).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();

        let create_stderr = format!(" adding: {escaped}\n");
        let list_stdout = format!("{escaped}\n");

        // Create archive with encrypt layer
        // cf. https://github.com/rust-lang/rust/issues/148426
        // TODO: check that warning disappears when issue is fixed
        #[allow(deprecated)]
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("create")
            .arg("-o")
            .arg(mlar_file.path())
            .arg("-l")
            .arg("encrypt")
            .arg("-p")
            .arg(public_key)
            .arg(testfs.files[i].path());

        println!("{cmd:?}");
        let assert = cmd.assert();
        assert.success().stderr(create_stderr.clone());

        // List archive content
        // cf. https://github.com/rust-lang/rust/issues/148426
        // TODO: check that warning disappears when issue is fixed
        #[allow(deprecated)]
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("list")
            .arg("--skip-signature-verification")
            .arg("-i")
            .arg(mlar_file.path())
            .arg("-k")
            .arg(private_key);

        println!("{cmd:?}");
        let assert = cmd.assert();
        assert.success().stdout(list_stdout.clone());

        // Truncate the archive file (~6/7 size)
        let mut data = Vec::new();
        File::open(mlar_file.path())
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        File::create(mlar_file.path())
            .unwrap()
            .write_all(&data[..data.len() * 6 / 7])
            .unwrap();

        // Attempt `clean-truncated` (authenticated)
        // cf. https://github.com/rust-lang/rust/issues/148426
        // TODO: check that warning disappears when issue is fixed
        #[allow(deprecated)]
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("clean-truncated")
            .arg("--skip-signature-verification")
            .arg("-i")
            .arg(mlar_file.path())
            .arg("-k")
            .arg(private_key)
            .arg("--out-pub")
            .arg(public_key)
            .arg("-o")
            .arg(mlar_clean_truncated_file.path())
            .arg("-l")
            .arg("encrypt");

        println!("{cmd:?}");
        let assert = cmd.assert();
        // For file3.bin, `clean-truncated` is expected to fail as the file is really small
        if testfs.files[i]
            .path()
            .to_string_lossy()
            .contains("file3.bin")
        {
            assert.failure();
        } else {
            assert.success();
        }

        // Try to read content from `clean-truncated` archive (authenticated)
        // cf. https://github.com/rust-lang/rust/issues/148426
        // TODO: check that warning disappears when issue is fixed
        #[allow(deprecated)]
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("cat")
            .arg("--skip-signature-verification")
            .arg("-i")
            .arg(mlar_clean_truncated_file.path())
            .arg("-k")
            .arg(private_key)
            .arg(testfs.files[i].path());

        println!("{cmd:?}");
        let assert = cmd.assert();
        let output_auth = assert.get_output();

        // Remove `clean-truncated` file to test unauthenticated `clean-truncated`
        let _ = std::fs::remove_file(mlar_clean_truncated_file.path());

        // Repair allowing unauthenticated data
        // cf. https://github.com/rust-lang/rust/issues/148426
        // TODO: check that warning disappears when issue is fixed
        #[allow(deprecated)]
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("clean-truncated")
            .arg("--allow-unauthenticated-data")
            .arg("--skip-signature-verification")
            .arg("-i")
            .arg(mlar_file.path())
            .arg("-k")
            .arg(private_key)
            .arg("--out-pub")
            .arg(public_key)
            .arg("-o")
            .arg(mlar_clean_truncated_file.path())
            .arg("-l")
            .arg("encrypt");

        println!("{cmd:?}");
        let assert = cmd.assert();
        assert.success();

        // Read content from `clean-truncated` archive (unauthenticated)
        // cf. https://github.com/rust-lang/rust/issues/148426
        // TODO: check that warning disappears when issue is fixed
        #[allow(deprecated)]
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("cat")
            .arg("--skip-signature-verification")
            .arg("-i")
            .arg(mlar_clean_truncated_file.path())
            .arg("-k")
            .arg(private_key)
            .arg(testfs.files[i].path());

        println!("{cmd:?}");
        let assert = cmd.assert();
        let output_unauth = assert.get_output();

        // Output unauthenticated must be longer than the authenticated one
        if testfs.files[i]
            .path()
            .to_string_lossy()
            .contains("file3.bin")
        {
            // for file3, the truncation falls in MLA entries layer magic, thus we cannot `clean-truncated` anything
            assert_eq!(output_unauth.stdout.len(), 0);
            assert_eq!(output_auth.stdout.len(), 0);
        } else {
            // For others, unauthenticated output must be at least as large as authenticated
            assert!(output_unauth.stdout.len() >= output_auth.stdout.len());
        }

        // Authenticated output must match start of unauthenticated output
        assert_eq!(
            output_auth.stdout,
            output_unauth.stdout[..output_auth.stdout.len()]
        );

        // Clean up
        let _ = std::fs::remove_file(mlar_file.path());
        let _ = std::fs::remove_file(mlar_clean_truncated_file.path());
    }
}

#[test]
fn test_multiple_keys() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let public_keys = [
        Path::new("../samples/test_mlakey.mlapub"),
        Path::new("../samples/test_mlakey_3.mlapub"),
    ];
    let private_keys = [
        Path::new("../samples/test_mlakey.mlapriv"),
        Path::new("../samples/test_mlakey_2.mlapriv"),
    ];

    // Create files
    let testfs = setup();

    // Prepare expected stderr (for `create`) with full info lines
    let mut expected_stderr = String::new();
    for file in &testfs.files {
        let entry_name = EntryName::from_path(file.path()).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
        expected_stderr.push_str(format!(" adding: {escaped}\n").as_str());
    }

    // Prepare expected stdout (for `list`) with just file paths, no extra info
    let mut expected_stdout = String::new();
    for file in &testfs.files {
        let entry_name = EntryName::from_path(file.path()).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
        expected_stdout.push_str(format!("{escaped}\n").as_str());
    }

    // Run `mlar create` with compress + encrypt and public keys
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-l")
        .arg("encrypt")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("-p")
        .arg(public_keys[0])
        .arg("-p")
        .arg(public_keys[1]);

    for file in &testfs.files {
        cmd.arg(file.path());
    }

    println!("{cmd:?}");
    cmd.assert().success().stderr(expected_stderr.clone());

    // Run `mlar list` with both private keys
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("--skip-signature-verification")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(private_keys[0])
        .arg("-k")
        .arg(private_keys[1]);

    println!("{cmd:?}");
    cmd.assert().success().stdout(expected_stdout.clone());

    // Run `mlar list` with second private key only
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("--skip-signature-verification")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(public_keys[1].with_extension("mlapriv"));

    println!("{cmd:?}");
    cmd.assert().success().stdout(expected_stdout.clone());

    // Run `mlar list` with wrong private key (should fail)
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("--skip-signature-verification")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(private_keys[1]);

    println!("{cmd:?}");
    cmd.assert().failure();
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
        // cf. https://github.com/rust-lang/rust/issues/148426
        // TODO: check that warning disappears when issue is fixed
        #[allow(deprecated)]
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("create")
            .arg("-o")
            .arg(dest)
            .arg("-l")
            .arg("compress")
            .arg("-q")
            .arg(compression_level);

        let mut expected_stderr = String::new();
        for file in &testfs.files {
            cmd.arg(file.path());

            let entry_name = EntryName::from_path(file.path()).unwrap();
            let escaped = entry_name.to_pathbuf_escaped_string().unwrap();

            expected_stderr.push_str(format!(" adding: {escaped}\n").as_str());
        }

        println!("{cmd:?}");
        let assert = cmd.assert();
        assert.success().stderr(expected_stderr);
    }

    // Hopefully, if compression works, q5 must be smaller than q0
    let q0_size = metadata(mlar_file_q0.path()).unwrap().len();
    let q5_size = metadata(mlar_file_q5.path()).unwrap().len();
    assert!(q5_size < q0_size);

    // Ensure files are correct
    for (src, tar_name) in [(mlar_file_q0, &tar_file_q0), (mlar_file_q5, &tar_file_q5)] {
        // `mlar to-tar -i {src} -o {tar_name}`
        // cf. https://github.com/rust-lang/rust/issues/148426
        // TODO: check that warning disappears when issue is fixed
        #[allow(deprecated)]
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("to-tar")
            .arg("--skip-signature-verification")
            .arg("--accept-unencrypted")
            .arg("-i")
            .arg(src.path())
            .arg("-o")
            .arg(tar_name.path());

        println!("{cmd:?}");
        let assert = cmd.assert();
        assert.success();
    }

    ensure_tar_content(tar_file_q0.path(), &testfs.files);
    ensure_tar_content(tar_file_q5.path(), &testfs.files);
}

#[test]
fn test_convert() {
    // Create an archive with one public key, convert it to use only another key
    // without compression, then verify the size and the content of the archive

    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let mlar_file_converted = NamedTempFile::new("convert.mla").unwrap();
    let tar_file = NamedTempFile::new("output.tar").unwrap();

    let public_key1 = Path::new("../samples/test_mlakey.mlapub");
    let private_key1 = Path::new("../samples/test_mlakey.mlapriv");
    let public_key2 = Path::new("../samples/test_mlakey_2.mlapub");
    let private_key2 = Path::new("../samples/test_mlakey_2.mlapriv");

    // Create files
    let testfs = setup();

    // === Step 1: Create the original archive
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-l")
        .arg("encrypt")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("-p")
        .arg(public_key1);

    let mut create_stderr = String::new();
    for file in &testfs.files {
        cmd.arg(file.path());
        let entry_name = EntryName::from_path(file.path()).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
        create_stderr.push_str(format!(" adding: {escaped}\n").as_str());
    }

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success().stderr(create_stderr.clone());

    // === Step 2: Convert the archive to a new key
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("convert")
        .arg("--skip-signature-verification")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(private_key1)
        .arg("-l")
        .arg("encrypt")
        .arg("-o")
        .arg(mlar_file_converted.path())
        .arg("--out-pub")
        .arg(public_key2);

    println!("{cmd:?}");
    let assert = cmd.assert();

    // Correct expected stderr for `convert`
    let mut convert_stderr = String::new();
    for file in &testfs.files {
        let entry_name = EntryName::from_path(file.path()).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
        convert_stderr.push_str(format!(" converting: {}\n", escaped.replace('/', "%2f")).as_str());
    }

    assert.success().stderr(convert_stderr);

    // === Step 3: Verify that conversion did not compress (size should be bigger)
    let size_output = metadata(mlar_file.path()).unwrap().len();
    let size_convert = metadata(mlar_file_converted.path()).unwrap().len();
    assert!(size_output < size_convert);

    // === Step 4: Extract converted archive to TAR
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("to-tar")
        .arg("--skip-signature-verification")
        .arg("-i")
        .arg(mlar_file_converted.path())
        .arg("-k")
        .arg(private_key2)
        .arg("-o")
        .arg(tar_file.path());

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success();

    // === Step 5: Inspect the created TAR file content
    ensure_tar_content(tar_file.path(), &testfs.files);
}

#[test]
fn test_stdio() {
    // Create an archive on stdout, and check it
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let tar_file = NamedTempFile::new("output.tar").unwrap();
    let public_key = Path::new("../samples/test_mlakey.mlapub");
    let private_key = Path::new("../samples/test_mlakey.mlapriv");

    // Create files
    let testfs = setup();

    // Prepare expected stderr output for create command with  lines
    let mut file_list = String::new();
    for file in &testfs.files {
        let entry_name = EntryName::from_path(file.path()).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
        file_list.push_str(format!(" adding: {escaped}\n").as_str());
    }

    // `mlar create -o - -p samples/test_mlakey.mlapub file1.bin file2.bin file3.bin`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-l")
        .arg("encrypt")
        .arg("-o")
        .arg("-") // output to stdout
        .arg("-p")
        .arg(public_key);

    for file in &testfs.files {
        cmd.arg(file.path());
    }

    println!("{cmd:?}");
    let assert = cmd.assert();
    let archive_data = assert.get_output().stdout.clone();
    assert.success().stderr(file_list);

    // Write archive data to temporary file for further testing
    File::create(mlar_file.path())
        .unwrap()
        .write_all(&archive_data)
        .unwrap();

    // `mlar to-tar -i output.mla -k samples/test_mlakey.mlapriv -o output.tar`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("to-tar")
        .arg("--skip-signature-verification")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-k")
        .arg(private_key)
        .arg("-o")
        .arg(tar_file.path());

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success();

    // Inspect the created TAR file content matches original test files
    ensure_tar_content(tar_file.path(), &testfs.files);
}

#[test]
fn test_multi_fileorders() {
    // Create several archives with all possible file orders. Result should be the same
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let tar_file = NamedTempFile::new("output.tar").unwrap();
    let public_key = Path::new("../samples/test_mlakey.mlapub");
    let private_key = Path::new("../samples/test_mlakey.mlapriv");

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

        // `mlar create -o output.mla -p samples/test_mlakey.mlapub file1.bin file2.bin file3.bin`
        // cf. https://github.com/rust-lang/rust/issues/148426
        // TODO: check that warning disappears when issue is fixed
        #[allow(deprecated)]
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("create")
            .arg("-l")
            .arg("compress")
            .arg("-l")
            .arg("encrypt")
            .arg("-o")
            .arg(mlar_file.path())
            .arg("-p")
            .arg(public_key);

        let mut expected_stderr = String::new();

        for file in list {
            cmd.arg(file);

            let entry_name = EntryName::from_path(file).unwrap();
            let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
            expected_stderr.push_str(format!(" adding: {escaped}\n").as_str());
        }

        println!("{cmd:?}");
        let assert = cmd.assert();
        assert.success().stderr(expected_stderr);

        // `mlar to-tar -i convert.mla -k samples/test_mlakey.mlapriv -o output.tar`
        // cf. https://github.com/rust-lang/rust/issues/148426
        // TODO: check that warning disappears when issue is fixed
        #[allow(deprecated)]
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("to-tar")
            .arg("--skip-signature-verification")
            .arg("-i")
            .arg(mlar_file.path())
            .arg("-k")
            .arg(private_key)
            .arg("-o")
            .arg(tar_file.path());

        println!("{cmd:?}");
        let assert = cmd.assert();
        assert.success();

        // Inspect the created TAR file
        ensure_tar_content(tar_file.path(), &testfs.files);
        let _ = std::fs::remove_file(mlar_file.path());
        let _ = std::fs::remove_file(tar_file.path());
    }
}

#[test]
fn test_verbose_listing() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let testfs = setup();

    // `mlar create -l -o output.mla
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-o")
        .arg(mlar_file.path());

    // Build expected stderr with full " adding: ... (N bytes)" lines
    let mut expected_stderr = String::new();
    for file in &testfs.files {
        cmd.arg(file.path());
        let entry_name = EntryName::from_path(file.path()).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
        expected_stderr.push_str(format!(" adding: {escaped}\n").as_str());
    }

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success().stderr(expected_stderr);

    // `mlar list -i output.mla`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("--skip-signature-verification")
        .arg("--accept-unencrypted")
        .arg("-i")
        .arg(mlar_file.path());

    println!("{cmd:?}");
    let assert = cmd.assert();

    // The list command prints just the names (no INFO prefix), so:
    let mut expected_stdout = String::new();
    for file in &testfs.files {
        let entry_name = EntryName::from_path(file.path()).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
        expected_stdout.push_str(format!("{escaped}\n").as_str());
    }

    assert.success().stdout(expected_stdout);

    // `mlar list -v -i output.mla`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("--skip-signature-verification")
        .arg("--accept-unencrypted")
        .arg("-v")
        .arg("-i")
        .arg(mlar_file.path());

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success();

    // `mlar list -vv -i output.mla`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("--skip-signature-verification")
        .arg("--accept-unencrypted")
        .arg("-vv")
        .arg("-i")
        .arg(mlar_file.path());

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success();
}

#[test]
fn test_extract() {
    // This value should be bigger than FILE_WRITER_POOL_SIZE
    const TEST_MANY_FILES_NB: usize = 5;
    const SIZE_FILE: usize = 10;
    const SEPARATOR: &str = "SEPARATOR";

    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
    let mut files = vec![];
    let mut filenames = vec![];

    // Create many files with random alphanumeric content
    for i in 0..TEST_MANY_FILES_NB {
        let tmp_file = NamedTempFile::new(format!("file{i}.bin")).unwrap();
        let data: Vec<u8> = Alphanumeric.sample_iter(&mut rng).take(SIZE_FILE).collect();
        tmp_file.write_binary(data.as_slice()).unwrap();

        files.push((tmp_file, data));
        filenames.push(format!("file{i}.bin"));
    }

    // Concatenate file data separated by SEPARATOR
    let mut concatenated_data = Vec::new();
    for (idx, (_tmp_file, data)) in files.iter().enumerate() {
        if idx > 0 {
            concatenated_data.extend(SEPARATOR.as_bytes());
        }
        concatenated_data.extend(data);
    }

    // Create archive passing multiple --filenames flags
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("--stdin-data")
        .arg("--stdin-data-separator")
        .arg(SEPARATOR);

    cmd.arg("--stdin-data-entry-names").arg(filenames.join(","));

    cmd.write_stdin(concatenated_data);

    println!("{cmd:?}");
    let assert = cmd.assert();

    assert.success();

    // === 1. Linear extraction ===
    let output_dir = TempDir::new().unwrap();
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("extract")
        .arg("-v")
        .arg("--skip-signature-verification")
        .arg("--accept-unencrypted")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-o")
        .arg(output_dir.path());

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success();

    for (filename, (_tmp_file, original_data)) in filenames.iter().zip(files.iter()) {
        let extracted = fs::read(output_dir.path().join(filename)).unwrap();
        assert_eq!(
            extracted, *original_data,
            "Mismatch in linear extract: {filename}"
        );
    }

    // === 2. Glob extraction ===
    let output_dir = TempDir::new().unwrap();
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("extract")
        .arg("-v")
        .arg("--skip-signature-verification")
        .arg("--accept-unencrypted")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-o")
        .arg(output_dir.path())
        .arg("-g")
        .arg("*");

    println!("{cmd:?}");
    let assert = cmd.assert();
    let output_str = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for filename in &filenames {
        assert!(
            output_str.contains(filename),
            "Missing filename in stdout: {filename}",
        );
    }
    for (filename, (_tmp_file, original_data)) in filenames.iter().zip(files.iter()) {
        let extracted = fs::read(output_dir.path().join(filename)).unwrap();
        assert_eq!(
            extracted, *original_data,
            "Mismatch in glob extract: {filename}"
        );
    }

    // === 3. Single file extraction ===
    let single_file = &filenames[0];
    let single_file_data = &files[0].1;

    let output_dir = TempDir::new().unwrap();
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("extract")
        .arg("-v")
        .arg("--skip-signature-verification")
        .arg("--accept-unencrypted")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-o")
        .arg(output_dir.path())
        .arg(single_file);

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success().stdout(format!("{single_file}\n"));

    let extracted = fs::read(output_dir.path().join(single_file)).unwrap();
    assert_eq!(
        extracted, *single_file_data,
        "Mismatch in single file extract: {single_file}"
    );
}

#[test]
fn test_cat() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let testfs = setup();

    // `mlar create -l compress -o output.mla ...`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-o")
        .arg(mlar_file.path());

    let mut expected_stderr = String::new();
    for file in &testfs.files {
        cmd.arg(file.path());

        let entry_name = EntryName::from_path(file.path()).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
        expected_stderr.push_str(format!(" adding: {escaped}\n").as_str());
    }

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success().stderr(expected_stderr);

    // `mlar cat -i output.mla fileX`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("cat")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("--skip-signature-verification")
        .arg("--accept-unencrypted")
        .arg(normalize(&testfs.files_archive_order[2]));

    println!("{cmd:?}");
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
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let output_dir = TempDir::new().unwrap();
    let base_path = output_dir.path().join("key");
    let priv_path = base_path.with_extension("mlapriv");
    let pub_path = base_path.with_extension("mlapub");
    let testfs = setup();

    // Generate keypair
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("keygen").arg(&base_path);
    cmd.assert().success();

    // Prepare expected stderr for create command
    let mut expected_stderr = String::new();
    for file in &testfs.files {
        let entry_name = EntryName::from_path(file.path()).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
        expected_stderr.push_str(format!(" adding: {escaped}\n").as_str());
    }

    // Prepare expected stdout for list command (just file names)
    let mut expected_stdout = String::new();
    for file in &testfs.files {
        let entry_name = EntryName::from_path(file.path()).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
        expected_stdout.push_str(format!("{escaped}\n").as_str());
    }

    // Create archive using public key
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-l")
        .arg("encrypt")
        .arg("-p")
        .arg(&pub_path)
        .arg("-o")
        .arg(mlar_file.path());

    for file in &testfs.files {
        cmd.arg(file.path());
    }

    println!("{cmd:?}");
    cmd.assert().success().stderr(expected_stderr.clone());

    // List archive contents with private key
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("--skip-signature-verification")
        .arg("-k")
        .arg(&priv_path)
        .arg("-i")
        .arg(mlar_file.path());

    println!("{cmd:?}");
    cmd.assert().success().stdout(expected_stdout.clone());
}

const PRIVATE_KEY_TESTSEED_SHA256: [u8; 32] = [
    171, 203, 214, 39, 195, 210, 188, 152, 227, 36, 24, 90, 1, 205, 194, 21, 203, 119, 153, 203,
    112, 207, 248, 69, 206, 249, 159, 209, 198, 198, 38, 36,
];

const PRIVATE_KEY_TESTSEED2_SHA256: [u8; 32] = [
    17, 3, 32, 197, 51, 208, 40, 91, 226, 177, 99, 168, 223, 174, 41, 231, 253, 62, 61, 176, 248,
    110, 187, 40, 221, 118, 54, 65, 193, 22, 192, 153,
];

#[test]
fn test_keygen_seed() {
    // Gen deterministic keypairs
    let output_dir = TempDir::new().unwrap();
    let base_path = output_dir.path().join("key");
    let priv_path = base_path.with_extension("mlapriv");
    let pub_path = base_path.with_extension("mlapub");

    // `mlar keygen tempdir/key -s TESTSEED`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("keygen").arg(&base_path).arg("-s").arg("TESTSEED");
    cmd.assert().success();

    let mut pkey_testseed = vec![];
    File::open(&priv_path)
        .unwrap()
        .read_to_end(&mut pkey_testseed)
        .unwrap();
    // Check the SHA256, as private key are ~3KB long
    let hash_testseed = Sha256::digest(&pkey_testseed);
    assert_eq!(hash_testseed, PRIVATE_KEY_TESTSEED_SHA256.into());
    let _ = std::fs::remove_file(&priv_path);
    let _ = std::fs::remove_file(&pub_path);

    // `mlar keygen tempdir/key -s TESTSEED2`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("keygen").arg(&base_path).arg("-s").arg("TESTSEED2");
    cmd.assert().success();

    let mut pkey_testseed2 = vec![];
    File::open(&priv_path)
        .unwrap()
        .read_to_end(&mut pkey_testseed2)
        .unwrap();
    // Check the SHA256, as private key are ~3KB long
    let hash_testseed2 = Sha256::digest(&pkey_testseed2);

    assert_eq!(hash_testseed2, PRIVATE_KEY_TESTSEED2_SHA256.into());

    assert_ne!(PRIVATE_KEY_TESTSEED_SHA256, PRIVATE_KEY_TESTSEED2_SHA256);
}

#[test]
fn test_keyderive() {
    /*
    key_parent
    ├──["Child 1"]── key_child1
    │   └──["Child 1"]── key_child1_child1
    └──["Child 2"]── key_child2
    */
    struct Keys {
        parent: Vec<u8>,
        child1: Vec<u8>,
        child2: Vec<u8>,
        child1child1: Vec<u8>,
    }

    let output_dir = TempDir::new().unwrap();
    let key_parent_pfx = output_dir.path().join("key_parent");
    let key_parent_priv = key_parent_pfx.with_extension("mlapriv");
    let key_child1_pfx = output_dir.path().join("key_child1");
    let key_child1_priv = key_child1_pfx.with_extension("mlapriv");
    let key_child2_pfx = output_dir.path().join("key_child2");
    let key_child2_priv = key_child2_pfx.with_extension("mlapriv");
    let key_child1_child1_pfx = output_dir.path().join("key_child1_child1");
    let key_child1_child1_priv = key_child1_child1_pfx.with_extension("mlapriv");

    //---------------- SETUP: Create and fill `keys` --------------
    let mut keys = Keys {
        parent: vec![],
        child1: vec![],
        child2: vec![],
        child1child1: vec![],
    };

    // `mlar keygen tempdir/key_parent`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("keygen").arg(&key_parent_pfx);
    cmd.assert().success();

    keys.parent = fs::read(&key_parent_priv).unwrap();

    // `mlar keyderive tempdir/key_parent tempdir/key_child1 --path "Child 1"`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("keyderive")
        .arg(&key_parent_priv)
        .arg(&key_child1_pfx)
        .arg("-p")
        .arg("Child 1");
    cmd.assert().success();

    keys.child1 = fs::read(&key_child1_priv).unwrap();

    // `mlar keyderive tempdir/key_parent tempdir/key_child2 --path "Child 2"`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("keyderive")
        .arg(&key_parent_priv)
        .arg(&key_child2_pfx)
        .arg("-p")
        .arg("Child 2");
    cmd.assert().success();

    keys.child2 = fs::read(&key_child2_priv).unwrap();

    // `mlar keyderive tempdir/key_child1 tempdir/key_child1_child1 --path "Child 1"`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("keyderive")
        .arg(&key_child1_priv)
        .arg(&key_child1_child1_pfx)
        .arg("-p")
        .arg("Child 1");
    cmd.assert().success();

    keys.child1child1 = fs::read(&key_child1_child1_priv).unwrap();

    //---------------- END OF SETUP -----------------

    // Assert all keys are different
    let v: HashSet<_> = [&keys.parent, &keys.child1, &keys.child2, &keys.child1child1]
        .iter()
        .copied()
        .collect();
    assert_eq!(v.len(), 4);

    // Ensure path is deterministic

    let key_tmp_pfx = output_dir.path().join("key_tmp");
    let key_tmp_priv = key_tmp_pfx.with_extension("mlapriv");
    // `mlar keyderive tempdir/key_parent tempdir/key_tmp --path "Child 2"`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("keyderive")
        .arg(&key_parent_priv)
        .arg(&key_tmp_pfx)
        .arg("-p")
        .arg("Child 2");
    cmd.assert().success();

    assert_eq!(keys.child2, fs::read(&key_tmp_priv).unwrap());

    // Ensure path is transitive

    let key_tmp_2_pfx = output_dir.path().join("key_tmp2");
    let key_tmp_2_priv = key_tmp_2_pfx.with_extension("mlapriv");
    // `mlar keyderive tempdir/key_parent tempdir/key_tmp2 --path "Child 1" --path "Child 1"`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("keyderive")
        .arg(&key_parent_priv)
        .arg(&key_tmp_2_pfx)
        .arg("-p")
        .arg("Child 1")
        .arg("-p")
        .arg("Child 1");
    cmd.assert().success();

    assert_eq!(keys.child1child1, fs::read(&key_tmp_2_priv).unwrap());
}

#[test]
fn test_verbose_info() {
    let public_key = Path::new("../samples/test_mlakey.mlapub");
    let public_key_2 = Path::new("../samples/test_mlakey_2.mlapub");

    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let testfs = setup();

    // `mlar create -l -o output.mla`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create").arg("-o").arg(mlar_file.path());
    cmd.arg("-l").arg("compress");
    cmd.arg("-l").arg("encrypt");
    cmd.arg("-p").arg(public_key);
    cmd.arg("-p").arg(public_key_2);

    // Build expected stderr with full " adding: ... (size bytes)" lines
    let mut expected_stderr = String::new();
    for file in &testfs.files {
        cmd.arg(file.path());
        let entry_name = EntryName::from_path(file.path()).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
        expected_stderr.push_str(format!(" adding: {escaped}\n").as_str());
    }

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success().stderr(expected_stderr);

    // `mlar info -i output.mla`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("info").arg("-i").arg(mlar_file.path());

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success().stdout(
        "Format version: 2
Encryption: true
Signature: false
",
    );

    // `mlar info -v -i output.mla`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("info").arg("-v").arg("-i").arg(mlar_file.path());

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success();
}

#[test]
fn test_no_open_on_encrypt() {
    // Create an unencrypted archive
    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let private_key = Path::new("../samples/test_mlakey.mlapriv");

    // Create files
    let testfs = setup();

    // Prepare expected stderr for create
    let mut expected_stderr = String::new();
    for file in &testfs.files {
        let entry_name = EntryName::from_path(file.path()).unwrap();
        let escaped = entry_name.to_pathbuf_escaped_string().unwrap();
        expected_stderr.push_str(format!(" adding: {escaped}\n").as_str());
    }

    // `mlar create -o output.mla -l compress file1.bin file2.bin file3.bin`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-o")
        .arg(mlar_file.path());

    for file in &testfs.files {
        cmd.arg(file.path());
    }

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success().stderr(expected_stderr);

    // Ensure:
    // - mlar refuses to open the MLA file if a private key is provided

    // `mlar list -i output.mla -k samples/test_mlakey.mlapriv`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("list")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("--skip-signature-verification")
        .arg("-k")
        .arg(private_key);

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.failure();
}

#[test]
fn test_extract_lot_files() {
    // This value should be bigger than FILE_WRITER_POOL_SIZE
    const TEST_MANY_FILES_NB: usize = 1010;
    const SIZE_FILE: usize = 10;
    const SEPARATOR: &str = "SEPARATOR";

    let mlar_file = NamedTempFile::new("output.mla").unwrap();
    let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
    let mut files = vec![];
    let mut filenames = vec![];

    // Create many files with random alphanumeric content
    for i in 0..TEST_MANY_FILES_NB {
        let tmp_file = NamedTempFile::new(format!("{i}")).unwrap();
        let data: Vec<u8> = Alphanumeric.sample_iter(&mut rng).take(SIZE_FILE).collect();
        tmp_file.write_binary(data.as_slice()).unwrap();

        files.push((tmp_file, data));
        filenames.push(format!("{i}"));
    }

    // Concatenate file data separated by SEPARATOR
    let mut concatenated_data = Vec::new();
    for (idx, (_tmp_file, data)) in files.iter().enumerate() {
        if idx > 0 {
            concatenated_data.extend(SEPARATOR.as_bytes());
        }
        concatenated_data.extend(data);
    }

    // Create archive passing multiple --filenames flags
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("--stdin-data")
        .arg("--stdin-data-separator")
        .arg(SEPARATOR);
    cmd.arg("--stdin-data-entry-names").arg(filenames.join(","));

    cmd.arg("-").write_stdin(concatenated_data);

    println!("{cmd:?}");
    let assert = cmd.assert();

    assert.success();

    // === 1. Linear extraction ===
    let output_dir = TempDir::new().unwrap();
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("extract")
        .arg("-v")
        .arg("--skip-signature-verification")
        .arg("--accept-unencrypted")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-o")
        .arg(output_dir.path());

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success();

    for (filename, (_tmp_file, original_data)) in filenames.iter().zip(files.iter()) {
        let extracted = fs::read(output_dir.path().join(filename)).unwrap();
        assert_eq!(
            extracted, *original_data,
            "Mismatch in linear extract: {filename}"
        );
    }

    // === 2. Glob extraction ===
    let output_dir = TempDir::new().unwrap();
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("extract")
        .arg("-v")
        .arg("--skip-signature-verification")
        .arg("--accept-unencrypted")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-o")
        .arg(output_dir.path())
        .arg("-g")
        .arg("*");

    println!("{cmd:?}");
    let assert = cmd.assert();
    let output_str = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for filename in &filenames {
        assert!(
            output_str.contains(filename),
            "Missing filename in stdout: {filename}",
        );
    }
    for (filename, (_tmp_file, original_data)) in filenames.iter().zip(files.iter()) {
        let extracted = fs::read(output_dir.path().join(filename)).unwrap();
        assert_eq!(
            extracted, *original_data,
            "Mismatch in glob extract: {filename}"
        );
    }

    // === 3. Single file extraction ===
    let single_file = &filenames[0];
    let single_file_data = &files[0].1;

    let output_dir = TempDir::new().unwrap();
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("extract")
        .arg("-v")
        .arg("--skip-signature-verification")
        .arg("--accept-unencrypted")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-o")
        .arg(output_dir.path())
        .arg(single_file);

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success().stdout(format!("{single_file}\n"));

    let extracted = fs::read(output_dir.path().join(single_file)).unwrap();
    assert_eq!(
        extracted, *single_file_data,
        "Mismatch in single file extract: {single_file}"
    );
}

#[test]
fn test_stdin() {
    let msg = "echo... echo... echo...";
    let mlar_file = NamedTempFile::new("output.mla").unwrap();

    let output_files = ["default-entry"];

    // `echo "echo... echo... echo..." | mlar create -l -o output.mla --filenames file.txt -`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("--stdin-data")
        .write_stdin(msg);

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success();

    // `mlar extract -v --accept-unencrypted -i output.mla -o output_dir`
    let output_dir = TempDir::new().unwrap();
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("extract")
        .arg("-v")
        .arg("--skip-signature-verification")
        .arg("--accept-unencrypted")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-o")
        .arg(output_dir.path());

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success();

    let extracted_file_path = output_dir.path().join(output_files.first().unwrap());
    let content = fs::read_to_string(&extracted_file_path).unwrap();
    assert_eq!(content, msg);
}

#[test]
fn test_stdin_empty_input() {
    let mlar_file = NamedTempFile::new("output.mla").unwrap();

    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("--stdin-data")
        .arg("--stdin-data-entry-names")
        .arg("empty-entry")
        .write_stdin(""); // empty input

    cmd.assert().success();

    let output_dir = TempDir::new().unwrap();

    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("extract")
        .arg("--accept-unencrypted")
        .arg("--skip-signature-verification")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-o")
        .arg(output_dir.path());

    cmd.assert().success();

    let content = fs::read(output_dir.path().join("empty-entry")).unwrap();
    assert!(content.is_empty(), "Expected empty file, got {content:?}");
}

#[test]
fn test_consecutive_sep_stdin() {
    let sep = "SEP";
    let input: &[&[u8]] = &[
        b"SEP",
        b"\xff\xfe\xad\xde",
        b"SEP",
        b"SEP",
        b"SEP",
        b"echo... echo... echo...",
        b"SEP",
    ];

    let expected_content: &[&[u8]] = &[
        b"",
        b"\xff\xfe\xad\xde",
        b"",
        b"",
        b"echo... echo... echo...",
        b"",
    ];

    let mlar_file = NamedTempFile::new("output.mla").unwrap();

    let output_files = [
        "chunk1.bin",
        "chunk2.bin",
        "chunk3.bin",
        "chunk4.bin",
        "chunk5.bin",
        "chunk6.bin",
    ];

    // `echo -n -e "SEP\xff\xfe\xad\xdeSEPSEPSEPecho... echo... echo...SEP" | mlar create -l -o output.mla --separator SEP -`
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("--stdin-data")
        .arg("--stdin-data-separator")
        .arg(sep)
        .arg("--stdin-data-entry-names")
        .arg(output_files.join(","))
        .write_stdin(input.concat());

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success();

    // `mlar extract -v --accept-unencrypted -i output.mla -o output_dir`
    let output_dir = TempDir::new().unwrap();
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("extract")
        .arg("-v")
        .arg("--skip-signature-verification")
        .arg("--accept-unencrypted")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("-o")
        .arg(output_dir.path());

    println!("{cmd:?}");
    let assert = cmd.assert();
    assert.success();

    for (index, file) in output_files.iter().enumerate() {
        let extracted_file_path = output_dir.path().join(file);
        let content = fs::read(&extracted_file_path).unwrap();
        assert_eq!(content, expected_content[index]);
    }
}

#[test]
fn test_stdin_separator_across_chunks() {
    const SEPARATOR: &str = "SEPARATOR";

    let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
    // 9000 : separator after chunk1
    // 8190 : separator across chunks
    for chunk1_size in [9000, 8190] {
        let mlar_file = NamedTempFile::new("output.mla").unwrap();
        let stdin1 = Alphanumeric
            .sample_iter(&mut rng)
            .take(chunk1_size)
            .collect::<Vec<u8>>();
        let stdin2 = Alphanumeric
            .sample_iter(&mut rng)
            .take(9000)
            .collect::<Vec<u8>>();
        let stdin = [stdin1.as_slice(), SEPARATOR.as_bytes(), stdin2.as_slice()].concat();

        // cf. https://github.com/rust-lang/rust/issues/148426
        // TODO: check that warning disappears when issue is fixed
        #[allow(deprecated)]
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("create")
            .arg("-l")
            .arg("compress")
            .arg("-o")
            .arg(mlar_file.path())
            .arg("--stdin-data")
            .arg("--stdin-data-separator")
            .arg(SEPARATOR);

        cmd.arg("--stdin-data-entry-names").arg("e1,e2");

        cmd.write_stdin(stdin);

        println!("{cmd:?}");
        let assert = cmd.assert();

        assert.success();

        let output_dir = TempDir::new().unwrap();
        // cf. https://github.com/rust-lang/rust/issues/148426
        // TODO: check that warning disappears when issue is fixed
        #[allow(deprecated)]
        let mut cmd = Command::cargo_bin(UTIL).unwrap();
        cmd.arg("extract")
            .arg("-v")
            .arg("--skip-signature-verification")
            .arg("--accept-unencrypted")
            .arg("-i")
            .arg(mlar_file.path())
            .arg("-o")
            .arg(output_dir.path());

        println!("{cmd:?}");
        let assert = cmd.assert();
        assert.success();

        for (name, original_data) in ["e1", "e2"].iter().zip([stdin1, stdin2].iter()) {
            let extracted = fs::read(output_dir.path().join(name)).unwrap();
            assert_eq!(&extracted, original_data, "Mismatch in extract: {name}");
        }
    }
}

#[test]
fn test_stdin_separator_not_in_input_should_fallback_to_single_entry() {
    const SEPARATOR: &str = "SEP";
    let input = b"This is some data that does not contain the separator.";

    let mlar_file = NamedTempFile::new("output.mla").unwrap();

    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("--stdin-data")
        .arg("--stdin-data-separator")
        .arg(SEPARATOR)
        .arg("--stdin-data-entry-names")
        .arg("single_entry_expected") // only one entry will actually be created
        .write_stdin(input)
        .assert()
        .success();
}

#[test]
fn test_missing_entry_names_should_fail() {
    let separator = "SEP";
    let input = b"fooSEPbar";

    let mlar_file = NamedTempFile::new("output.mla").unwrap();

    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("compress")
        .arg("-l")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("--stdin-data")
        .arg("--stdin-data-separator")
        .arg(separator)
        .write_stdin(input)
        .assert()
        .failure();
}

#[test]
fn test_archive_with_missing_file_should_fail() {
    // Create a temp output archive file
    let mlar_file = NamedTempFile::new("output.mla").unwrap();

    // Create a valid temporary input file
    let file1 = NamedTempFile::new("file1.txt").unwrap();
    std::fs::write(&file1, "Test1").unwrap();
    let missing_file_name = "missing_file.bin";

    // === mlar create ===
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    cmd.arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-o")
        .arg(mlar_file.path())
        .arg(file1.path())
        .arg(missing_file_name)
        .assert()
        .failure();
}

#[test]
fn test_archive_with_missing_file_skips_and_succeeds() {
    // Create a temp output archive file
    let mlar_file = NamedTempFile::new("output.mla").unwrap();

    // Create a valid temporary input file
    let file1 = NamedTempFile::new("file1.txt").unwrap();
    std::fs::write(&file1, "Test1").unwrap();
    let file1_name = "file1.txt";
    let missing_file_name = "missing_file.bin";

    // === mlar create ===
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    let output = cmd
        .arg("create")
        .arg("-l")
        .arg("compress")
        .arg("-o")
        .arg(mlar_file.path())
        .arg("--skip-not-found")
        .arg(file1.path())
        .arg(missing_file_name)
        .assert()
        .success()
        .get_output()
        .stderr
        .clone();

    let stderr_str = String::from_utf8_lossy(&output);

    // Check that missing file is explicitly reported
    assert!(
        stderr_str.contains("does not exist"),
        "Expected warning for missing file not found in stderr"
    );
    assert!(
        stderr_str.contains("skipping"),
        "Expected 'skipping' message not found in stderr"
    );
    assert!(
        stderr_str.contains(file1_name),
        "Expected file1 to be reported in stderr"
    );

    // === mlar list ===
    // cf. https://github.com/rust-lang/rust/issues/148426
    // TODO: check that warning disappears when issue is fixed
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin(UTIL).unwrap();
    let output = cmd
        .arg("list")
        .arg("-i")
        .arg(mlar_file.path())
        .arg("--skip-signature-verification")
        .arg("--accept-unencrypted")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout_str = String::from_utf8_lossy(&output);

    // Check that only the valid file is listed
    assert!(
        stdout_str.contains(file1_name),
        "Expected file1 in archive list output"
    );
    assert!(
        !stdout_str.contains(missing_file_name),
        "Missing file should not appear in archive list"
    );
}
