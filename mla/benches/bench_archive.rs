use criterion::{Criterion, criterion_group, criterion_main};

use criterion::BenchmarkId;
use criterion::Throughput;

use mla::TruncatedArchiveReader;
use mla::config::{ArchiveReaderConfig, ArchiveWriterConfig};
use mla::crypto::mlakey::{HybridPublicKey, generate_keypair_from_seed};
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
const SAMPLE_SIZE_SMALL: usize = 20;
const LAYERS_POSSIBILITIES: [(bool, bool); 4] =
    [(false, false), (true, false), (false, true), (true, true)];

/// Build an archive with `iters` files of `size` bytes each and `layers` enabled
///
/// Files names are `file_{i}`
fn build_archive(
    iters: u64,
    size: u64,
    compression: bool,
    encryption: bool,
) -> (Vec<u8>, ArchiveReaderConfig) {
    // Setup
    let mut rng = ChaChaRng::seed_from_u64(0);
    let (private_key, public_key) = generate_keypair_from_seed([0; 32]);
    let file = Vec::new();
    // Create the initial archive with `iters` files of `size` bytes
    let config = if encryption {
        ArchiveWriterConfig::with_public_keys(&[public_key])
    } else {
        ArchiveWriterConfig::without_encryption()
    };
    let config = if compression {
        config
    } else {
        config.without_compression()
    };
    let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");
    for i in 0..iters {
        let data: Vec<u8> = Alphanumeric
            .sample_iter(&mut rng)
            .take(size as usize)
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
    let config = ArchiveReaderConfig::with_private_keys(&[private_key]);
    (dest, config)
}

/// Wrapper on `build_archive` returning an already instancied `ArchiveReader`
fn build_archive_reader<'a>(
    iters: u64,
    size: u64,
    compression: bool,
    encryption: bool,
) -> ArchiveReader<'a, io::Cursor<Vec<u8>>> {
    let (dest, config) = build_archive(iters, size, compression, encryption);
    let buf = Cursor::new(dest);
    ArchiveReader::from_config(buf, config).unwrap()
}

fn layers_to_config(
    (compression, encryption): &(bool, bool),
    public_key: &HybridPublicKey,
) -> ArchiveWriterConfig {
    let config = if *encryption {
        ArchiveWriterConfig::with_public_keys(&[public_key.clone()])
    } else {
        ArchiveWriterConfig::without_encryption()
    };
    if *compression {
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
    // Use a deterministic RNG in tests, for reproductability. DO NOT DO THIS IS IN ANY RELEASED BINARY!
    let mut rng = ChaChaRng::seed_from_u64(0);
    let (_private_key, public_key) = generate_keypair_from_seed([0; 32]);

    let mut group = c.benchmark_group("writer_multiple_layers_multiple_block_size");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(SAMPLE_SIZE_SMALL);
    for size in SIZE_LIST.iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        let data: Vec<u8> = Alphanumeric.sample_iter(&mut rng).take(*size).collect();

        for (compression, encryption) in &LAYERS_POSSIBILITIES {
            // Create an archive
            let file = Vec::new();

            let mut mla = ArchiveWriter::from_config(
                file,
                layers_to_config(&(*compression, *encryption), &public_key),
            )
            .expect("Writer init failed");

            let id = mla
                .start_entry(EntryName::from_path("file").unwrap())
                .unwrap();
            group.bench_with_input(
                BenchmarkId::new(
                    format!("compression: {compression}, encryption: {encryption}"),
                    size,
                ),
                size,
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
/// Additionnals tests should be done to measure the compression gain between
/// the different levels
pub fn multiple_compression_quality(c: &mut Criterion) {
    let size = 256 * KB;

    // Setup
    // Use a deterministic RNG in tests, for reproductability. DO NOT DO THIS IS IN ANY RELEASED BINARY!
    let mut rng = ChaChaRng::seed_from_u64(0);

    let mut group = c.benchmark_group("multiple_compression_quality");
    group.measurement_time(Duration::from_secs(10));
    for quality in 1..=11 {
        group.throughput(Throughput::Bytes(size as u64));

        let data: Vec<u8> = Alphanumeric.sample_iter(&mut rng).take(size).collect();

        // Create an archive
        let file = Vec::new();
        let config = ArchiveWriterConfig::without_encryption()
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
fn read_one_file_by_chunk(iters: u64, size: u64, compression: bool, encryption: bool) -> Duration {
    // Prepare data
    let mut mla_read = build_archive_reader(1, size * iters, compression, encryption);

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
    // Reduce the number of sample to avoid taking too much time
    group.sample_size(SAMPLE_SIZE_SMALL);

    for size in SIZE_LIST.iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        for (compression, encryption) in &LAYERS_POSSIBILITIES {
            group.bench_function(
                BenchmarkId::new(
                    format!("compression: {compression}, encryption: {encryption}"),
                    size,
                ),
                move |b| {
                    b.iter_custom(|iters| {
                        read_one_file_by_chunk(iters, *size as u64, *compression, *encryption)
                    })
                },
            );
        }
    }
    group.finish();
}

/// Create an archive with a `iters` files of `size` bytes using `layers` and
/// measure the time needed to read them (in a random order)
///
/// This function is used to measure only the get_file + read time without the
/// cost of archive creation
fn iter_read_multifiles_random(
    iters: u64,
    size: u64,
    compression: bool,
    encryption: bool,
) -> Duration {
    let mut mla_read = build_archive_reader(iters, size, compression, encryption);

    let mut rng = ChaChaRng::seed_from_u64(0);
    // Measure the time needed to get and read a file
    let start = Instant::now();
    for i in sample(&mut rng, iters as usize, iters as usize).iter() {
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
    let mut group = c.benchmark_group("chunk_size_decompress_mutilfiles_random");
    // Reduce the number of sample to avoid taking too much time
    group.sample_size(SAMPLE_SIZE_SMALL);
    for size in SIZE_LIST.iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        for (compression, encryption) in &LAYERS_POSSIBILITIES {
            group.bench_function(
                BenchmarkId::new(
                    format!("compression: {compression}, encryption: {encryption}"),
                    size,
                ),
                move |b| {
                    b.iter_custom(|iters| {
                        iter_read_multifiles_random(iters, *size as u64, *compression, *encryption)
                    })
                },
            );
        }
    }
    group.finish();
}

/// Create an archive with a `iters` files of `size` bytes using `layers` and
/// measure the time needed to read them (linearyly)
///
/// This function is used to measure only `linear_extract` time without the cost
/// of archive creation
fn iter_decompress_multifiles_linear(
    iters: u64,
    size: u64,
    compression: bool,
    encryption: bool,
) -> Duration {
    let mut mla_read = build_archive_reader(iters, size, compression, encryption);

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
    // Reduce the number of sample to avoid taking too much time
    group.sample_size(SAMPLE_SIZE_SMALL);
    for size in SIZE_LIST.iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        for (compression, encryption) in &LAYERS_POSSIBILITIES {
            group.bench_function(
                BenchmarkId::new(
                    format!("compression: {compression}, encryption: {encryption}"),
                    size,
                ),
                move |b| {
                    b.iter_custom(|iters| {
                        iter_decompress_multifiles_linear(
                            iters,
                            *size as u64,
                            *compression,
                            *encryption,
                        )
                    })
                },
            );
        }
    }
    group.finish();
}

/// Create an archive then repair it.
///
/// Return the time taken by the repair operation
fn repair_archive(iters: u64, size: u64, compression: bool, encryption: bool) -> Duration {
    let (data, config) = build_archive(iters, size, compression, encryption);
    let buf = Cursor::new(data);
    let dest = Vec::new();

    // No need to truncate the data, repair the whole file
    let mut mla_repair = TruncatedArchiveReader::from_config(buf, config).unwrap();
    // Avoid any layers to speed up writing, as this is not the measurement target
    let writer_config = ArchiveWriterConfig::without_encryption().without_compression();
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
    // Reduce the number of sample to avoid taking too much time
    group.sample_size(10);
    group.throughput(Throughput::Bytes(size));

    for (compression, encryption) in &LAYERS_POSSIBILITIES {
        group.bench_function(
            BenchmarkId::new(
                format!("compression: {compression}, encryption: {encryption}"),
                size,
            ),
            move |b| b.iter_custom(|iters| repair_archive(iters, size, *compression, *encryption)),
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
