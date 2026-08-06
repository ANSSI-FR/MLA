#![no_main]

use libfuzzer_sys::{fuzz_mutator, fuzz_target, fuzzer_mutate};
use mla_fuzz::run;

fuzz_target!(|data: &[u8]| {
    run(data);
});

/// Copy `out` into `data` (clamped to `max_size`) and return the new size.
fn install_out(data: &mut [u8], out: Vec<u8>, max_size: usize) -> usize {
    let new_size = out.len().min(max_size);
    data[..new_size].copy_from_slice(&out[..new_size]);
    new_size
}

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    if size >= 8 && &data[..8] == b"MLAFAAAA" {
        let out = mla_oss_fuzz::mutator::mutate_archive(&data[..size], max_size, seed);
        install_out(data, out, max_size)
    } else if seed.is_multiple_of(3) {
        // Promote to archive: ~33% of non-archive inputs are replaced with a
        // fresh archive generated from the default model. The high rate ensures
        // archive coverage even when the corpus is dominated by TestInput seeds.
        let out = mla_oss_fuzz::mutator::mutate_archive(&[], max_size, seed);
        install_out(data, out, max_size)
    } else {
        let new_size = fuzzer_mutate(data, size, max_size);
        // Clamp first byte to 0-7 (TestInput FuzzMode). This keeps TestInput
        // inputs valid but prevents natural promotion to the archive path
        // (byte 0x4D 'M' is out of range). Promotion is handled explicitly
        // by the seed % 3 branch above.
        if new_size > 0 {
            data[0] %= 8;
        }
        new_size
    }
});
