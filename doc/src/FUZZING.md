Fuzzing
-

## AFL-based Fuzzing

A fuzzing scenario made with [afl.rs](https://github.com/rust-fuzz/afl.rs) is available in mla-fuzz-afl.
The scenario is capable of:
* Creating archives with interleaved files, and different layers enabled
* Reading them to check their content
* Repairing the archive without truncation, and verifying it
* Altering the archive raw data, and ensuring reading it does not panic (but only fail)
* Repairing the altered archive, and ensuring the recovery does not fail (only reports detected errors)

To launch it:
1. Generate initial samples (automatically created when running without stdin):
```sh
cd mla-fuzz-afl
mkdir -p in out
cargo run
```
This will create sample files in `in/` directory.

2. Build and launch AFL:
```sh
cargo afl build
cargo afl fuzz -i in -o out target/debug/mla-fuzz-afl
```

If you have found crashes, try to replay them with either:
* Peruvian rabbit mode of AFL: `cargo afl run -i - -o out -C ../target/debug/mla-fuzz-afl`
* Direct replay: `../target/debug/mla-fuzz-afl < out/crashes/crash_id`
* Debugging: uncomment the "Replay sample" part of `mla-fuzz-afl/src/main.rs`, and add `dbg!()` when it is needed

Warning: The stability is quite low, likely due to the process used for the scenario (deserialization from the data provided by AFL) and variability of inner algorithms, such as `brotli`. Crashes, if any, might not be reproducible or due to the `mla-fuzz-afl` inner working, which is a bit complex (and therefore likely buggy). One can comment irrelevant parts in `mla-fuzz-afl/src/main.rs` to ensure a better experience.

## OSS-Fuzz (libFuzzer) Fuzzing

An OSS-Fuzz-compatible libFuzzer harness is available in fuzz/. The fuzzing logic is shared with the AFL-based fuzzer through the `mla-fuzz/` crate.

The `run()` entry point dispatches between two paths based on the input's first bytes:

- **TestInput roundtrip path**: input starts with a byte 0-7 (`FuzzMode`), serialized as a `TestInput` struct. Exercises the writer->reader roundtrip (archive creation, interleaved files, layers, truncation repair, alteration).
- **Raw archive parser path**: input starts with `MLAFAAAA` magic. Exercises `ArchiveReader::from_config` -> `list_entries` -> `get_hash` -> `get_entry` -> `seek` -> `read_to_end` on untrusted bytes. Decompressed output is capped at 64 MB per read (two reads per entry) and 128 MB aggregate soft cap to prevent OOM via decompression bombs. Note: the truncated-reader repair path (`CompressionLayerTruncatedReader`) is exercised only through the TestInput byteflip/repair flow, not this dispatch.

### OSS-Fuzz Integration

The OSS-Fuzz configuration files for MLA integration are located in the OSS-Fuzz repository under:

```text
projects/mla/
├── Dockerfile      # Docker build configuration
├── build.sh       # Fuzzer build script
└── project.yaml   # Project metadata
```

The fuzz target is defined in:

```text
fuzz/fuzz_targets/mla_fuzz.rs
```

### Local Testing (Basic)

For quick development without ASan instrumentation:

All commands below are expected to be run from the root of the MLA repository.

Build the fuzz target:

```sh
cargo build --manifest-path fuzz/Cargo.toml --profile fuzzing --bin mla_fuzz
```

Run the fuzzer:

```sh
./target/fuzzing/mla_fuzz
```

Run the fuzzer against the seed corpus with the dictionary:

```sh
./target/fuzzing/mla_fuzz \
    -dict=fuzz/mla_fuzz.dict \
    fuzz/mla_fuzz_seed_corpus/
```

Replay a specific input:

```sh
./target/fuzzing/mla_fuzz path/to/input
```

### Local Testing with ASan

To test with AddressSanitizer and **coverage instrumentation** enabled (matching
OSS-Fuzz behavior), you need:
- Rust nightly with ASan support
- clang/clang++ with ASan support (set `CC=clang CXX=clang++`)

The `RUSTFLAGS` below include the SanitizerCoverage flags that give libFuzzer
coverage feedback. **Coverage is required** -- without it libFuzzer reports
`WARNING: no interesting inputs were found` and cannot guide mutations; it can
only stumble on crashes by luck.

Run from the workspace root:

```sh
export CC=clang
export CXX=clang++
# SanitizerCoverage flags on the Rust side give libFuzzer coverage feedback.
# LTO is disabled in the `fuzzing` profile (lto=false) so sancov-module's
# per-crate __sancov_gen_* symbols link cleanly (cargo-fuzz#384).
export RUSTFLAGS="--cfg fuzzing -Zsanitizer=address -Cdebug-assertions=on -Coverflow-checks=on -Cdebuginfo=1 -Cforce-frame-pointers -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares -Ccodegen-units=1"
export CFLAGS="-fsanitize=address -fsanitize-address-use-after-scope"
export CXXFLAGS="-fsanitize=address -fsanitize-address-use-after-scope"

cargo build --locked --manifest-path fuzz/Cargo.toml --target x86_64-unknown-linux-gnu --profile fuzzing --bin mla_fuzz
./target/x86_64-unknown-linux-gnu/fuzzing/mla_fuzz
```

Do **not** add `-fno-sanitize-coverage` to `CFLAGS`/`CXXFLAGS`: recent clang
rejects the bare flag ("unknown argument"). The libFuzzer C++ runtime keeps the
standard OSS-Fuzz instrumentation; the Rust crates get coverage (via `RUSTFLAGS`).

**Note:** The `fuzzing` profile disables symbol stripping (`strip=false`) which is
required for ASan to work correctly. Using the standard `release` profile will strip
symbols and cause "BAD BUILD: does not seem to be compiled with ASan" errors.

The simplest full-ASan setup is via OSS-Fuzz:

```sh
python3 infra/helper.py run_fuzzer mla mla_fuzz
```

### Testing with OSS-Fuzz

To test MLA integration with OSS-Fuzz locally, first clone the OSS-Fuzz repository:

```sh
git clone https://github.com/google/oss-fuzz.git
cd oss-fuzz
```

The MLA project files are already present in the OSS-Fuzz repository at `projects/mla/`. Ensure they reference the correct branch:

- Dockerfile clones https://github.com/ANSSI-FR/MLA
- project.yaml defines the project metadata
- build.sh contains the build script

Build the OSS-Fuzz image:

```sh
python3 infra/helper.py build_image mla
```

Build the fuzzers:

```sh
python3 infra/helper.py build_fuzzers mla
```

Validate the build by checking the fuzzers execute without errors:

```sh
python3 infra/helper.py check_build mla
```

Run the fuzz target:

```sh
python3 infra/helper.py run_fuzzer mla mla_fuzz
```

Crash reports stay in the OSS-Fuzz tracker, where project maintainers have
full access (`file_github_issue: False` in `project.yaml`); they are not
mirrored as public GitHub issues.

### Custom Mutator

Without a custom mutator, libFuzzer wastes most runs on `Deserialization
Error`: raw byte mutations almost never produce valid `TestInput` structs or
valid `MLAFAAAA`-prefixed archives. A custom mutator solves this with a
model-based approach. The dispatch between the two paths above lives in
`fuzz/fuzz_targets/mla_fuzz.rs`: archives are mutated through the model,
non-archive inputs fall back to byte mutation with the first byte clamped
to a valid `FuzzMode`, and about one third of non-archive rounds are
replaced with a fresh archive from the default model. With 16 `TestInput`
and 5 archive seeds, that rate brings the two paths to near-parity. The
archive mutation logic lives in `fuzz/src/mutator.rs`.

### Mutator Unit Tests

The mutator has unit tests that verify magic preservation (including when
re-mutating an already-valid archive), above-80% validity, and max-size
compliance. These tests are cheap (under 2s) and do not require libFuzzer:

```sh
cargo test --manifest-path fuzz/Cargo.toml --lib
```

**Note:** `cargo test --all` will launch the `mla_fuzz` binary as a libFuzzer
harness and start fuzzing indefinitely. To run the full test suite without
triggering the fuzzer, exclude the `mla-oss-fuzz` package:

```sh
cargo test --all --exclude mla-oss-fuzz --release
```

### Long-Running Fuzzing

For long runs on multi-core machines, use libFuzzer fork mode. Each worker
runs in a subprocess, so crashes (including SIGSEGV from stack overflows) are
recorded as reproducers without stopping the master:

```sh
./target/fuzzing/mla_fuzz -fork=4 -max_total_time=3600
```

### Technical Details

**Multi-crate Workspace Consideration:**

MLA uses a Rust workspace with multiple crates (`mla`, `mla-fuzz`,
`mla-oss-fuzz`). Two things must hold for libFuzzer to receive coverage
feedback:

1. **Coverage instrumentation must be present.** The SanitizerCoverage flags
   (`-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-*`) must be passed
   to the Rust crates via `RUSTFLAGS`. Without them, libFuzzer emits
   `WARNING: no interesting inputs were found so far. Is the code instrumented
   for coverage?`, reports `INITED` with no `cov:` field, and adds zero new
   units. The fuzzer is then blind: it can still detect crashes (panics,
   SIGSEGV, OOM), but any find is accidental rather than coverage-guided.

2. **LTO must be disabled for the fuzz build.** `sancov-module` emits a
   per-crate constructor `__sancov_gen_<N>`. With LTO (`lto = true`, which the
   `release` profile enables and `fuzzing` inherits), crate merging turns these
   into undefined references at link time:
   `rust-lld: error: undefined symbol: __sancov_gen_.1599` (referenced by
   `asan.module_dtor`). This is a known cargo-fuzz issue ([#384]) and is NOT
   caused by the coverage flags themselves or by the multi-crate workspace.
   The `fuzzing` profile sets `lto = false` to resolve it.

   [#384]: https://github.com/rust-fuzz/cargo-fuzz/issues/384

**Why not just use `cargo fuzz build`?**

`cargo fuzz build` injects the SanitizerCoverage flags automatically, but it
builds with the `release` profile, which has `lto = true` in this workspace.
That triggers the `__sancov_gen_*` link error described above. To use
`cargo-fuzz` locally you must set `lto = false` on the `release` profile (or a
cargo-fuzz-compatible profile), which is undesirable for production release
builds. The direct `cargo build --profile fuzzing` approach used by `build.sh`
avoids this: the `fuzzing` profile is dedicated to fuzzing and can safely keep
`lto = false` without affecting the production `release` profile.

The `build.sh` script in `projects/mla/`:
- Uses `/rust/bin/cargo` directly (bypassing the OSS-Fuzz wrapper that rewrites
  `RUSTFLAGS`) and adds the SanitizerCoverage flags to `RUSTFLAGS` explicitly.
- Leaves the C/C++ flags untouched: recent clang rejects the bare
  `-fno-sanitize-coverage` flag ("unknown argument"), so the libFuzzer C++
  runtime keeps the standard OSS-Fuzz `-fsanitize=fuzzer-no-link`
  (light instrumentation, harmless).
- Builds with the `fuzzing` profile (`lto = false`, `strip = false`) which is
  defined in both `Cargo.toml` (workspace root) and `fuzz/Cargo.toml`.
- Produces: `target/x86_64-unknown-linux-gnu/fuzzing/mla_fuzz` (ASan + coverage).

This workflow reproduces the environment used by OSS-Fuzz and can help diagnose
build, linker, sanitizer, or environment-specific issues.

### Seed Corpus and Dictionary

A seed corpus and a libFuzzer dictionary are provided to help the fuzzer discover
interesting inputs quickly:

- `fuzz/mla_fuzz_seed_corpus/`: 21 pre-generated seeds (16 TestInput + 5 raw MLA archives)
- `fuzz/mla_fuzz.dict`: dictionary with MLA format magic constants and tokens

To regenerate the seed corpus (e.g. after changing the MLA format or `TestInput`):

```sh
cargo run --manifest-path fuzz/Cargo.toml --profile fuzzing --bin generate_seeds
```

This overwrites `fuzz/mla_fuzz_seed_corpus/` with fresh seeds. The generator is an
auto-discovered binary in `fuzz/src/bin/generate_seeds.rs`; it is not a fuzz target
and is excluded from OSS-Fuzz builds (`build.sh` builds only `--bin mla_fuzz`).

In OSS-Fuzz, `build.sh` packages the seed corpus as `$OUT/mla_fuzz_seed_corpus.zip`
and the dictionary as `$OUT/mla_fuzz.dict`, following the standard OSS-Fuzz naming
convention.

### Coverage and known gaps

The fuzz target exercises all layer combinations (compression, encryption,
signature), hashing, and re-parsing of corrupted archives with `ArchiveReader`
and `TruncatedArchiveReader`. Reads are both sequential and random-access:
seeks to the start, the end, and an offset inside the entry (half the bytes
read), which also goes through the intra-block resynchronization paths.
Fuzzing `ArchiveWriter` against corrupted streams and the `mlar-upgrader` v1
reader is not covered by this target.
