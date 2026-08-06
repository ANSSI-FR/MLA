//! Seed corpus generator for `mla_fuzz`.
//!
//! Generates two types of seeds:
//! - TestInput seeds (via `produce_samples()`) -- for the roundtrip writer->reader path
//! - Raw MLA archive seeds (via `ArchiveWriter`) -- for the parser path
//!
//! Usage: `./generate_seeds <output_dir>`

use std::fs;

use mla::ArchiveWriter;
use mla::config::ArchiveWriterConfig;
use mla::entry::EntryName;
use mla_fuzz::produce_samples;

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "fuzz/mla_fuzz_seed_corpus".to_string());

    fs::create_dir_all(&out_dir).expect("Failed to create output dir");

    // produce_samples() writes to "in/" relative to CWD, so we run it and then move files.
    let _ = fs::remove_dir_all("in");
    produce_samples();

    // Flatten into out_dir (OSS-Fuzz expects a flat corpus).
    if let Ok(entries) = fs::read_dir("in") {
        for entry in entries.flatten() {
            let src = entry.path();
            let dst = format!(
                "{out_dir}/testinput_{}",
                src.file_name().unwrap().to_string_lossy()
            );
            fs::rename(&src, &dst).expect("Failed to move seed");
        }
    }
    let _ = fs::remove_dir_all("in");

    // Generate raw MLA archive seeds (non-encrypted, no signature)
    generate_archive_seed(
        &out_dir,
        "archive_no_compression.mla",
        &[("file1.txt", b"Hello, MLA!")],
        None,
    );
    generate_archive_seed(&out_dir, "archive_empty.mla", &[], None);
    generate_archive_seed(
        &out_dir,
        "archive_multi_file.mla",
        &[
            ("file1.txt", b"Content of file 1"),
            ("file2.txt", b"Content of file 2"),
            ("file3.bin", &[0x00, 0xFF, 0x42, 0x7F, 0x80, 0xAA]),
        ],
        None,
    );
    generate_archive_seed(
        &out_dir,
        "archive_large_name.mla",
        &[(
            "a_very_long_filename_that_tests_entry_name_handling.mla",
            b"data",
        )],
        None,
    );

    // Compressed archive seed -- exercises the compression layer (COMLAAAA)
    generate_archive_seed(
        &out_dir,
        "archive_compressed.mla",
        &[
            ("file1.txt", b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ("file2.txt", b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
        ],
        Some(6),
    );

    println!("Seeds generated in {out_dir}");
}

/// Generate a raw MLA archive seed.
///
/// `compression_level`: `None` disables compression (`.without_compression()`),
/// `Some(level)` sets the compression level via `.with_compression_level(level)`.
fn generate_archive_seed(
    dir: &str,
    filename: &str,
    files: &[(&str, &[u8])],
    compression_level: Option<u32>,
) {
    let mut config = ArchiveWriterConfig::without_encryption_without_signature()
        .expect("Failed to create writer config");
    if let Some(level) = compression_level {
        config = config
            .with_compression_level(level)
            .expect("Failed to set compression level");
    } else {
        config = config.without_compression();
    }

    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::from_config(&mut buf, config).expect("Failed to create writer");

    for (name, content) in files {
        let entry_name =
            EntryName::from_arbitrary_bytes(name.as_bytes()).expect("Failed to create entry name");
        let id = writer
            .start_entry(entry_name)
            .expect("Failed to start entry");
        writer
            .append_entry_content(id, content.len() as u64, *content)
            .expect("Failed to append content");
        writer.end_entry(id).expect("Failed to end entry");
    }

    writer.finalize().expect("Failed to finalize archive");

    fs::write(format!("{dir}/{filename}"), &buf).expect("Failed to write seed file");
}
