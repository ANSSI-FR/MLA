#![no_main]

use libfuzzer_sys::{fuzz_mutator, fuzz_target, fuzzer_mutate};
use mla_fuzz::run;

fuzz_target!(|data: &[u8]| {
    run(data);
});

fn install_out(data: &mut [u8], out: Vec<u8>, max_size: usize) -> usize {
    let new_size = out.len().min(max_size);
    data[..new_size].copy_from_slice(&out[..new_size]);
    new_size
}

// The corpus mixes two input families: raw MLA archives (parser path) and
// TestInput structs (writer/reader roundtrip). The model-based mutator only
// understands archives, so archives are model-mutated, TestInputs fall back
// to byte mutation, and ~1/3 of non-archive rounds are promoted to fresh
// archives. With 16 TestInput and 5 archive seeds, that rate brings the two
// paths to near-parity
fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    if size >= 8 && &data[..8] == b"MLAFAAAA" {
        let out = mla_oss_fuzz::mutator::mutate_archive(&data[..size], max_size, seed);
        install_out(data, out, max_size)
    } else if seed.is_multiple_of(3) {
        // Promote to a fresh archive built from the default model
        let out = mla_oss_fuzz::mutator::mutate_archive(&[], max_size, seed);
        install_out(data, out, max_size)
    } else {
        let new_size = fuzzer_mutate(data, size, max_size);
        // Clamp to a valid FuzzMode (0-7) so byte-mutated inputs stay
        // TestInputs instead of drifting toward 'M' (archive magic)
        if new_size > 0 {
            data[0] %= 8;
        }
        new_size
    }
});
