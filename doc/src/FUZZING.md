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
This will create sample files in in/ directory.

2. Build and launch AFL:
```sh
cargo afl build
cargo afl fuzz -i in -o out target/debug/mla-fuzz-afl
```

If you have found crashes, try to replay them with either:
* Peruvian rabbit mode of AFL: cargo afl run -i - -o out -C ../target/debug/mla-fuzz-afl
* Direct replay: ../target/debug/mla-fuzz-afl < out/crashes/crash_id
* Debugging: uncomment the "Replay sample" part of mla-fuzz-afl/src/main.rs, and add dbg!() when it is needed

Warning: The stability is quite low, likely due to the process used for the scenario (deserialization from the data provided by AFL) and variability of inner algorithms, such as brotli. Crashes, if any, might not be reproducible or due to the mla-fuzz-afl inner working, which is a bit complex (and therefore likely buggy). One can comment irrelevant parts in mla-fuzz-afl/src/main.rs to ensure a better experience.

## OSS-Fuzz (libFuzzer) Fuzzing

An OSS-Fuzz-compatible libFuzzer harness is available in fuzz/. The fuzzing logic is shared with the AFL-based fuzzer through the mla-fuzz/ crate.

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

Note: The OSS-Fuzz integration uses a dedicated branch add-oss-fuzz in the MLA repository which contains the necessary fuzzing infrastructure.

### Local Testing (Basic)

For quick development without ASan instrumentation:

All commands below are expected to be run from the root of the MLA repository.

Build the fuzz target:

```sh
cd fuzz
cargo build --profile fuzzing --bins
```

Run the fuzzer:

```sh
./target/x86_64-unknown-linux-gnu/fuzzing/mla_fuzz
```

Run the fuzzer against an existing corpus:

```sh
./target/x86_64-unknown-linux-gnu/fuzzing/mla_fuzz corpus/
```

Replay a specific input:

```sh
./target/x86_64-unknown-linux-gnu/fuzzing/mla_fuzz path/to/input
```

### Local Testing with ASan

To test with AddressSanitizer enabled (matching OSS-Fuzz behavior), you need:
- Rust nightly with ASan support
- clang with ASan support
- libstdc++ with ASan support

Run from the workspace root:

```sh
cd fuzz
# Set the same flags as OSS-Fuzz build.sh
# Note: These are the flags used in projects/mla/build.sh
export RUSTFLAGS="--cfg fuzzing -Zsanitizer=address -Cdebuginfo=1 -Cforce-frame-pointers"
export CFLAGS="-fsanitize=address -fsanitize-address-use-after-scope -fno-sanitize-coverage"
export CXXFLAGS="-fsanitize=address -fsanitize-address-use-after-scope -fno-sanitize-coverage -stdlib=libc++"

cargo build --profile fuzzing --bins
./target/x86_64-unknown-linux-gnu/fuzzing/mla_fuzz
```

**Note:** The `fuzzing` profile disables symbol stripping (`strip=false`) which is
required for ASan to work correctly. Using the standard `release` profile will strip
symbols and cause "BAD BUILD: does not seem to be compiled with ASan" errors.

**Easiest method:** The simplest way to test with full ASan support is via OSS-Fuzz:

```sh
python3 infra/helper.py run_fuzzer mla mla_fuzz
```

### Testing with OSS-Fuzz

To test MLA integration with OSS-Fuzz locally, first clone the OSS-Fuzz repository and the MLA repository with the add-oss-fuzz branch:

```sh
git clone https://github.com/google/oss-fuzz.git
cd oss-fuzz
```

The MLA project files are already present in the OSS-Fuzz repository at projects/mla/. Ensure they reference the correct branch:

- Dockerfile clones from: https://github.com/ANSSI-FR/MLA with branch add-oss-fuzz
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

### Technical Details

**Multi-crate Workspace Consideration:**

MLA uses a Rust workspace with multiple crates (`mla`, `mla-fuzz`, `mla-oss-fuzz`, etc.). This structure can cause issues with OSS-Fuzz default configuration because:

1. `cargo-fuzz` 0.13.2 automatically adds ASAN coverage instrumentation flags (`-Cpasses=sancov-module`, `-Cllvm-args=-sanitizer-coverage-*`)
2. Each crate in the workspace generates its own coverage symbols (`__sancov_gen_.*`)
3. When linking multiple crates together with ASAN, symbol conflicts occur (undefined reference to `__sancov_gen_.*`)

**Solution Implemented:**

The `build.sh` script in `projects/mla/` addresses this by:
- Using `/rust/bin/cargo` directly instead of the OSS-Fuzz wrapper (`/usr/local/bin/cargo`)
- Defining custom `RUSTFLAGS` without coverage instrumentation: `--cfg fuzzing -Zsanitizer=address -Cdebuginfo=1 -Cforce-frame-pointers`
- Disabling coverage in C/C++ flags: `-fno-sanitize-coverage`
- Building with a custom `fuzzing` profile that disables symbol stripping: `cargo build --manifest-path fuzz/Cargo.toml --target x86_64-unknown-linux-gnu --profile fuzzing --bins`
- The fuzzer binary is produced at: `target/x86_64-unknown-linux-gnu/fuzzing/mla_fuzz`

The `fuzzing` profile (defined in both `Cargo.toml` at workspace root and `fuzz/Cargo.toml`)
inherits from `release` but sets `strip = false` to preserve symbols required by ASan.

This produces a working fuzzer binary with `AddressSanitizer` enabled but without the
coverage instrumentation that causes symbol conflicts.

**Note:** This approach differs from using `cargo fuzz build` which would provide
additional features (automatic corpus management, etc.), but the standard `cargo-fuzz`
approach currently does not work with MLA's multi-crate workspace structure due to
symbol conflicts. The OSS-Fuzz infrastructure handles corpus management and coverage
separately at runtime, so this direct cargo build approach is fully supported.

This workflow reproduces the environment used by OSS-Fuzz and can help diagnose
build, linker, sanitizer, or environment-specific issues.
