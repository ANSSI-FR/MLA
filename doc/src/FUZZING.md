Fuzzing
-

## AFL-based Fuzzing

A fuzzing scenario made with [afl.rs](https://github.com/rust-fuzz/afl.rs) is available in `mla-fuzz-afl`.
The scenario is capable of:
* Creating archives with interleaved files, and different layers enabled
* Reading them to check their content
* Repairing the archive without truncation, and verifying it
* Altering the archive raw data, and ensuring reading it does not panic (but only fail)
* Repairing the altered archive, and ensuring the recovery doesn't fail (only reports detected errors)

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
* Debugging: uncomment the "Replay sample" part of `mla-fuzz-afl/src/main.rs`, and add `dbg!()` when it's needed

Warning: The stability is quite low, likely due to the process used for the scenario (deserialization from the data provided by AFL) and variability of inner algorithms, such as brotli. Crashes, if any, might not be reproducible or due to the `mla-fuzz-afl` inner working, which is a bit complex (and therefore likely buggy). One can comment irrelevant parts in `mla-fuzz-afl/src/main.rs` to ensure a better experience.
Fuzzing
-

## AFL-based Fuzzing

A fuzzing scenario made with [afl.rs](https://github.com/rust-fuzz/afl.rs) is available in `mla-fuzz-afl`.
The scenario is capable of:
* Creating archives with interleaved files, and different layers enabled
* Reading them to check their content
* Repairing the archive without truncation, and verifying it
* Altering the archive raw data, and ensuring reading it does not panic (but only fail)
* Repairing the altered archive, and ensuring the recovery doesn't fail (only reports detected errors)

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
* Debugging: uncomment the "Replay sample" part of `mla-fuzz-afl/src/main.rs`, and add `dbg!()` when it's needed

Warning: The stability is quite low, likely due to the process used for the scenario (deserialization from the data provided by AFL) and variability of inner algorithms, such as brotli. Crashes, if any, might not be reproducible or due to the `mla-fuzz-afl` inner working, which is a bit complex (and therefore likely buggy). One can comment irrelevant parts in `mla-fuzz-afl/src/main.rs` to ensure a better experience.

## OSS-Fuzz (libFuzzer) Fuzzing

An OSS-Fuzz-compatible libFuzzer harness is available in `fuzz/`. The fuzzing logic is shared with the AFL-based fuzzer through the `mla-fuzz/` crate.

### OSS-Fuzz Integration

The OSS-Fuzz configuration files are located in:

```text
fuzz/oss-fuzz/
├── build.sh
└── project.yaml
````

The fuzz target is defined in:

```text
fuzz/fuzz_targets/mla_fuzz.rs
```

### Local Testing

All commands below are expected to be run from the root of the MLA repository.

Install `cargo-fuzz` if needed:

```sh
cargo install cargo-fuzz
```

Build the fuzz target:

```sh
cargo fuzz build -O
```

Run the fuzzer:

```sh
cargo fuzz run mla_fuzz
```

Run the fuzzer against an existing corpus:

```sh
cargo fuzz run mla_fuzz corpus/
```

Replay a specific input:

```sh
cargo fuzz run mla_fuzz path/to/input
```

### Testing with OSS-Fuzz

To reproduce the OSS-Fuzz build environment locally, clone the OSS-Fuzz repository:

```sh
git clone https://github.com/google/oss-fuzz.git
cd oss-fuzz
```

Create a project directory and copy the OSS-Fuzz configuration files:

```sh
mkdir -p projects/mla
cp /path/to/MLA/fuzz/oss-fuzz/* projects/mla/
```

Build the OSS-Fuzz image:

```sh
python3 infra/helper.py build_image mla
```

Build the fuzzers:

```sh
python3 infra/helper.py build_fuzzers mla
```

Run the fuzz target:

```sh
python3 infra/helper.py run_fuzzer mla mla_fuzz
```

This workflow reproduces the environment used by OSS-Fuzz and can help diagnose build, linker, sanitizer, or environment-specific issues that do not appear when running `cargo fuzz` directly.
