use criterion::BenchmarkId;
use criterion::Throughput;
use criterion::{Criterion, criterion_group, criterion_main};

use mla::TruncatedArchiveReader;
use mla::config::{
    ArchiveReaderConfig, ArchiveWriterConfig, TruncatedReaderConfig, TruncatedReaderDecryptionMode,
};
use mla::crypto::mlakey::{MLAPrivateKey, MLAPublicKey, generate_mla_keypair_from_seed};
use mla::entry::EntryName;
use mla::helpers::linear_extract;
use mla::{ArchiveReader, ArchiveWriter};
use rand::SeedableRng;
use rand::distributions::{Alphanumeric, Distribution};
use rand::seq::index::sample;
use rand_chacha::ChaChaRng;
use std::collections::HashMap;
use std::io::{self, Cursor, Read};
use std::time::{Duration, Instant};

const KB: usize = 1024;
const MB: usize = 1024 * KB;

const SIZE_LIST: [usize; 4] = [KB, 64 * KB, MB, 16 * MB];
const SAMPLE_SIZE: usize = 20;
const LAYERS_POSSIBILITIES: [(bool, bool, bool); 8] = [
    (false, false, false), // naked
    (true, false, false),  // compress only
    (false, true, false),  // encrypt only
    (false, false, true),  // signature only
    (true, true, false),   // compress + encrypt
    (true, false, true),   // compress + signature
    (false, true, true),   // encrypt + signature
    (true, true, true),    // compress + encrypt + signature
];

/// Build an archive with `iters` files of `size` bytes each and `layers` enabled
///
/// Files names are `file_{i}`
fn build_archive(
    iters: u64,
    size: u64,
    compression: bool,
    encryption: bool,
    signature: bool,
    privkey: &MLAPrivateKey,
    pubkey: &MLAPublicKey,
) -> (Vec<u8>, ArchiveReaderConfig) {
    // Setup
    let mut rng = ChaChaRng::seed_from_u64(0);
    let file = Vec::new();

    let config = match (encryption, signature) {
        (true, true) => ArchiveWriterConfig::with_encryption_with_signature(
            &[pubkey.get_encryption_public_key().clone()],
            &[privkey.get_signing_private_key().clone()],
        ),
        (true, false) => ArchiveWriterConfig::with_encryption_without_signature(&[pubkey
            .get_encryption_public_key()
            .clone()]),
        (false, true) => ArchiveWriterConfig::without_encryption_with_signature(&[privkey
            .get_signing_private_key()
            .clone()]),
        (false, false) => ArchiveWriterConfig::without_encryption_without_signature(),
    }
    .unwrap();

    let config = if compression {
        config
    } else {
        config.without_compression()
    };

    let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");
    for i in 0..iters {
        let data: Vec<u8> = Alphanumeric
            .sample_iter(&mut rng)
            .take(usize::try_from(size).expect("Failed to convert size to usize"))
            .collect();
        let id = mla
            .start_entry(EntryName::from_path(format!("file_{i}")).unwrap())
            .unwrap();
        mla.append_entry_content(id, data.len() as u64, data.as_slice())
            .unwrap();
        mla.end_entry(id).unwrap();
    }
    let dest = mla.finalize().unwrap();

    // Instantiate the reader
    let config = if signature {
        ArchiveReaderConfig::with_signature_verification(&[pubkey
            .get_signature_verification_public_key()
            .clone()])
    } else {
        ArchiveReaderConfig::without_signature_verification()
    };
    let config = if encryption {
        config.with_encryption(&[privkey.get_decryption_private_key().clone()])
    } else {
        config.without_encryption()
    };
    (dest, config)
}

/// Build an archive with `iters` files of `size` bytes each and `layers` enabled
///
/// Files names are `file_{i}`
fn build_truncated_archive(
    iters: u64,
    size: u64,
    compression: bool,
    encryption: bool,
    signature: bool,
    privkey: &MLAPrivateKey,
    pubkey: &MLAPublicKey,
) -> (Vec<u8>, TruncatedReaderConfig) {
    // Setup
    let mut rng = ChaChaRng::seed_from_u64(0);
    let file = Vec::new();

    let config = match (encryption, signature) {
        (true, true) => ArchiveWriterConfig::with_encryption_with_signature(
            &[pubkey.get_encryption_public_key().clone()],
            &[privkey.get_signing_private_key().clone()],
        ),
        (true, false) => ArchiveWriterConfig::with_encryption_without_signature(&[pubkey
            .get_encryption_public_key()
            .clone()]),
        (false, true) => ArchiveWriterConfig::without_encryption_with_signature(&[privkey
            .get_signing_private_key()
            .clone()]),
        (false, false) => ArchiveWriterConfig::without_encryption_without_signature(),
    }
    .unwrap();

    let config = if compression {
        config
    } else {
        config.without_compression()
    };

    let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");
    for i in 0..iters {
        let data: Vec<u8> = Alphanumeric
            .sample_iter(&mut rng)
            .take(usize::try_from(size).expect("Failed to convert size to usize"))
            .collect();
        let id = mla
            .start_entry(EntryName::from_path(format!("file_{i}")).unwrap())
            .unwrap();
        mla.append_entry_content(id, data.len() as u64, data.as_slice())
            .unwrap();
        mla.end_entry(id).unwrap();
    }
    let dest = mla.finalize().unwrap();

    // Instantiate the reader
    let config = if encryption {
        TruncatedReaderConfig::without_signature_verification_with_encryption(
            &[privkey.get_decryption_private_key().clone()],
            TruncatedReaderDecryptionMode::OnlyAuthenticatedData,
        )
    } else {
        TruncatedReaderConfig::without_signature_verification_without_encryption()
    };
    (dest, config)
}

/// Wrapper on `build_archive` returning an already instantiated `ArchiveReader`
fn build_archive_reader<'a>(
    iters: u64,
    size: u64,
    compression: bool,
    encryption: bool,
    signature: bool,
    privkey: &MLAPrivateKey,
    pubkey: &MLAPublicKey,
) -> ArchiveReader<'a, io::Cursor<Vec<u8>>> {
    let (dest, config) = build_archive(
        iters,
        size,
        compression,
        encryption,
        signature,
        privkey,
        pubkey,
    );
    let buf = Cursor::new(dest);
    ArchiveReader::from_config(buf, config).unwrap().0
}

fn layers_to_config(
    (compression, encryption, signature): (bool, bool, bool),
    privkey: &MLAPrivateKey,
    pubkey: &MLAPublicKey,
) -> ArchiveWriterConfig {
    let config = match (encryption, signature) {
        (true, true) => ArchiveWriterConfig::with_encryption_with_signature(
            &[pubkey.get_encryption_public_key().clone()],
            &[privkey.get_signing_private_key().clone()],
        ),
        (true, false) => ArchiveWriterConfig::with_encryption_without_signature(&[pubkey
            .get_encryption_public_key()
            .clone()]),
        (false, true) => ArchiveWriterConfig::without_encryption_with_signature(&[privkey
            .get_signing_private_key()
            .clone()]),
        (false, false) => ArchiveWriterConfig::without_encryption_without_signature(),
    }
    .unwrap();
    if compression {
        config
    } else {
        config.without_compression()
    }
}

/// Benchmark with all layers' permutations different block size
///
/// The archive is not reset between iterations, only between benchs.
/// Data is only appended as block for the same file.
/// As a result, some addition might take longer (on layer boundaries), but with
/// enough samples it ends as outliers
///
/// Big blocks (> 4MB) are also use to force the use of several blocks inside boundaries
pub fn writer_multiple_layers_multiple_block_size(c: &mut Criterion) {
    // Setup
    let mut rng = ChaChaRng::seed_from_u64(0);
    let (privkey, pubkey) = generate_mla_keypair_from_seed([0; 32]);

    let mut group = c.benchmark_group("writer_multiple_layers_multiple_block_size");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(SAMPLE_SIZE);
    for size in SIZE_LIST {
        group.throughput(Throughput::Bytes(size as u64));

        let data: Vec<u8> = Alphanumeric.sample_iter(&mut rng).take(size).collect();

        for (compression, encryption, signature) in &LAYERS_POSSIBILITIES {
            // Create an archive
            let file = Vec::new();

            let mut mla = ArchiveWriter::from_config(
                file,
                layers_to_config((*compression, *encryption, *signature), &privkey, &pubkey),
            )
            .expect("Writer init failed");

            let id = mla
                .start_entry(EntryName::from_path("file").unwrap())
                .unwrap();
            group.bench_with_input(
                BenchmarkId::new(
                    format!("compression: {compression}, encryption: {encryption}, signature: {signature}"),
                    size,
                ),
                &size,
                |b, &_size| {
                    b.iter(|| mla.append_entry_content(id, data.len() as u64, data.as_slice()));
                },
            );
        }
    }
    group.finish();
}

/// Benchmark the layer Compress only, using different block size
///
/// It should be noted the Throughput obtained depends on the data received and
/// do not represent the size of the emitted data.
/// Additional tests should be done to measure the compression gain between
/// the different levels
pub fn multiple_compression_quality(c: &mut Criterion) {
    let size = 256 * KB;

    let mut rng = ChaChaRng::seed_from_u64(0);

    let mut group = c.benchmark_group("multiple_compression_quality");
    group.measurement_time(Duration::from_secs(10));
    for quality in 1..=11 {
        group.throughput(Throughput::Bytes(size as u64));

        let data: Vec<u8> = Alphanumeric.sample_iter(&mut rng).take(size).collect();

        // Create an archive
        let file = Vec::new();
        let config = ArchiveWriterConfig::without_encryption_without_signature()
            .unwrap()
            .with_compression_level(quality)
            .unwrap();
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let id = mla
            .start_entry(EntryName::from_path("file").unwrap())
            .unwrap();
        group.bench_with_input(
            BenchmarkId::new(format!("CompressionLevel {quality}"), size),
            &size,
            |b, &_size| {
                b.iter(|| mla.append_entry_content(id, data.len() as u64, data.as_slice()));
            },
        );
    }
    group.finish();
}

/// Create an archive with a file of `iters`*`size` bytes using `layers` and
/// measure the time needed to read it
///
/// This function is used to measure only the read time without the cost of
/// creation nor file getting
fn read_one_file_by_chunk(
    iters: u64,
    size: u64,
    compression: bool,
    encryption: bool,
    signature: bool,
    privkey: &MLAPrivateKey,
    pubkey: &MLAPublicKey,
) -> Duration {
    // Prepare data
    let mut mla_read = build_archive_reader(
        1,
        size * iters,
        compression,
        encryption,
        signature,
        privkey,
        pubkey,
    );

    // Get the file (costly as `seek` are implied)
    let subfile = mla_read
        .get_entry(EntryName::from_path("file_0").unwrap())
        .unwrap()
        .unwrap();

    // Read iters * size bytes
    let start = Instant::now();
    let mut src = subfile.data;
    for _i in 0..iters {
        io::copy(&mut (&mut src).take(size), &mut io::sink()).unwrap();
    }
    start.elapsed()
}

/// Benchmark the read speed depending on layers enabled and read size
pub fn reader_multiple_layers_multiple_block_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("reader_multiple_layers_multiple_block_size");
    group.sample_size(SAMPLE_SIZE);

    let (privkey, pubkey) = generate_mla_keypair_from_seed([0; 32]);

    for size in SIZE_LIST {
        group.throughput(Throughput::Bytes(size as u64));

        for (compression, encryption, signature) in &LAYERS_POSSIBILITIES {
            group.bench_function(
                BenchmarkId::new(
                    format!("compression: {compression}, encryption: {encryption}, signature: {signature}"),
                    size,
                ),
                {
                    let privkey = privkey.clone();
                    let pubkey = pubkey.clone();
                    move |b| {
                        b.iter_custom(|iters| {
                            read_one_file_by_chunk(iters, size as u64, *compression, *encryption, *signature, &privkey, &pubkey)
                        });
                    }
                },
            );
        }
    }
    group.finish();
}

/// Create an archive with a `iters` files of `size` bytes using `layers` and
/// measure the time needed to read them (in a random order)
///
/// This function is used to measure only the `get_file` + read time without the
/// cost of archive creation
fn iter_read_multifiles_random(
    iters: u64,
    size: u64,
    compression: bool,
    encryption: bool,
    signature: bool,
    privkey: &MLAPrivateKey,
    pubkey: &MLAPublicKey,
) -> Duration {
    let mut mla_read = build_archive_reader(
        iters,
        size,
        compression,
        encryption,
        signature,
        privkey,
        pubkey,
    );

    let mut rng = ChaChaRng::seed_from_u64(0);
    // Measure the time needed to get and read a file
    let start = Instant::now();
    for i in sample(
        &mut rng,
        usize::try_from(iters).expect("Failed to convert length to usize"),
        usize::try_from(iters).expect("Failed to convert amount to usize"),
    )
    .iter()
    {
        let subfile = mla_read
            .get_entry(EntryName::from_path(format!("file_{i}")).unwrap())
            .unwrap()
            .unwrap();
        let mut src = subfile.data;
        io::copy(&mut (&mut src).take(size), &mut io::sink()).unwrap();
    }
    start.elapsed()
}

/// This benchmark measures the time needed to randomly pick a file and read it
///
/// This pattern should represent one of the common use of the library
pub fn reader_multiple_layers_multiple_block_size_multifiles_random(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_size_decompress_multifiles_random");
    group.sample_size(SAMPLE_SIZE);

    let (privkey, pubkey) = generate_mla_keypair_from_seed([0; 32]);

    for size in SIZE_LIST {
        group.throughput(Throughput::Bytes(size as u64));

        for (compression, encryption, signature) in &LAYERS_POSSIBILITIES {
            let privkey = privkey.clone();
            let pubkey = pubkey.clone();
            group.bench_function(
                BenchmarkId::new(
                    format!("compression: {compression}, encryption: {encryption}, signature: {signature}"),
                    size,
                ),
                move |b| {
                    b.iter_custom(|iters| {
                        iter_read_multifiles_random(
                            iters,
                            size as u64,
                            *compression,
                            *encryption,
                            *signature,
                            &privkey,
                            &pubkey,
                        )
                    });
                },
            );
        }
    }
    group.finish();
}

/// Create an archive with a `iters` files of `size` bytes using `layers` and
/// measure the time needed to read them (linearly)
///
/// This function is used to measure only `linear_extract` time without the cost
/// of archive creation
fn iter_decompress_multifiles_linear(
    iters: u64,
    size: u64,
    compression: bool,
    encryption: bool,
    signature: bool,
    privkey: &MLAPrivateKey,
    pubkey: &MLAPublicKey,
) -> Duration {
    let mut mla_read = build_archive_reader(
        iters,
        size,
        compression,
        encryption,
        signature,
        privkey,
        pubkey,
    );

    let fnames: Vec<EntryName> = mla_read.list_entries().unwrap().cloned().collect();
    // Measure the time needed to get and read a file
    // Prepare output
    let mut export: HashMap<&EntryName, io::Sink> =
        fnames.iter().map(|fname| (fname, io::sink())).collect();
    let start = Instant::now();
    linear_extract(&mut mla_read, &mut export).unwrap();
    start.elapsed()
}

/// This benchmark measures the time needed in a "linear extraction"
/// It can be compared to the "randomly pick" extraction
///
/// The full extraction is a common pattern of use of the library. This
/// benchmark helps measuring the gain of using `linear_extract`.
pub fn reader_multiple_layers_multiple_block_size_multifiles_linear(c: &mut Criterion) {
    let mut group =
        c.benchmark_group("reader_multiple_layers_multiple_block_size_multifiles_linear");
    group.sample_size(SAMPLE_SIZE);

    let (privkey, pubkey) = generate_mla_keypair_from_seed([0; 32]);

    for size in SIZE_LIST {
        group.throughput(Throughput::Bytes(size as u64));

        for (compression, encryption, signature) in &LAYERS_POSSIBILITIES {
            let privkey = privkey.clone();
            let pubkey = pubkey.clone();
            group.bench_function(
                BenchmarkId::new(
                    format!("compression: {compression}, encryption: {encryption}, signature: {signature}"),
                    size,
                ),
                move |b| {
                    b.iter_custom(|iters| {
                        iter_decompress_multifiles_linear(
                            iters,
                            size as u64,
                            *compression,
                            *encryption,
                            *signature,
                            &privkey,
                            &pubkey,
                        )
                    });
                },
            );
        }
    }
    group.finish();
}

/// Create an archive then repair it.
///
/// Return the time taken by the repair operation
fn repair_archive(
    iters: u64,
    size: u64,
    compression: bool,
    encryption: bool,
    signature: bool,
    privkey: &MLAPrivateKey,
    pubkey: &MLAPublicKey,
) -> Duration {
    let (data, config) = build_truncated_archive(
        iters,
        size,
        compression,
        encryption,
        signature,
        privkey,
        pubkey,
    );
    let buf = Cursor::new(data);
    let dest = Vec::new();

    // No need to truncate the data, repair the whole file
    let mut mla_repair = TruncatedArchiveReader::from_config(buf, config).unwrap();
    // Avoid any layers to speed up writing, as this is not the measurement target
    let writer_config = ArchiveWriterConfig::without_encryption_without_signature()
        .unwrap()
        .without_compression();
    let mla_output = ArchiveWriter::from_config(dest, writer_config).unwrap();

    let start = Instant::now();
    // Measure the convert_to_archive time
    mla_repair.convert_to_archive(mla_output).unwrap();
    start.elapsed()
}

/// This benchmark measures the time needed to repair an archive depending on the
/// enabled layers.
///
/// Only one-size is used, as the archive must be big enough to be representative
pub fn failsafe_multiple_layers_repair(c: &mut Criterion) {
    let size = 4 * MB as u64;
    let mut group = c.benchmark_group("failsafe_multiple_layers_repair");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(size));

    let (privkey, pubkey) = generate_mla_keypair_from_seed([0; 32]);

    for (compression, encryption, signature) in &LAYERS_POSSIBILITIES {
        let privkey = privkey.clone();
        let pubkey = pubkey.clone();
        group.bench_function(
            BenchmarkId::new(
                format!(
                    "compression: {compression}, encryption: {encryption}, signature: {signature}"
                ),
                size,
            ),
            move |b| {
                b.iter_custom(|iters| {
                    repair_archive(
                        iters,
                        size,
                        *compression,
                        *encryption,
                        *signature,
                        &privkey,
                        &pubkey,
                    )
                });
            },
        );
    }
}

criterion_group!(
    benches,
    writer_multiple_layers_multiple_block_size,
    reader_multiple_layers_multiple_block_size,
    reader_multiple_layers_multiple_block_size_multifiles_random,
    reader_multiple_layers_multiple_block_size_multifiles_linear,
    failsafe_multiple_layers_repair,
    // Was used to determine the best default compression quality ratio
    //
    // multiple_compression_quality,
);
criterion_main!(benches);
