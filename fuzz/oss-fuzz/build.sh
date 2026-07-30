#!/bin/bash -eu
# Build script for MLA OSS-Fuzz integration
#
# NOTE ON CARGO COMMAND:
# We use /rust/bin/cargo (the actual Rust cargo binary) instead of just 'cargo'
# because /usr/local/bin/cargo in the base-builder-rust image is an OSS-Fuzz
# wrapper script that intercepts commands and can modify RUSTFLAGS.
#
# NOTE ON COVERAGE FLAGS:
# cargo-fuzz (version 0.13.2 released on 2026-06-10) automatically adds ASAN coverage
# instrumentation flags (-Cpasses=sancov-module, -Cllvm-args=-sanitizer-coverage-*)
# when building. These flags cause __sancov_gen_.* symbol conflicts when linking
# multiple crates together with ASAN (each crate generates its own coverage symbols).
#
# MLA is a workspace with multiple crates (mla, mla-fuzz, mla-oss-fuzz), so we get
# these conflicts. Other single-crate projects don't have this issue.
#
# SOLUTION:
# We bypass cargo-fuzz entirely by using /rust/bin/cargo build directly with
# our own RUSTFLAGS that don't include coverage instrumentation.
# This produces a working fuzzer binary that uses libfuzzer-sys.
#
# NOTE: This is NOT a degraded solution. OSS-Fuzz does not require cargo-fuzz.
# The OSS-Fuzz infrastructure handles corpus management and coverage separately
# at runtime (via the runner). Many Rust projects in OSS-Fuzz use direct cargo
# build with libfuzzer-sys. This approach is fully supported and recommended for
# multi-crate workspaces where cargo-fuzz's coverage instrumentation causes
# symbol conflicts.
#
# Using 'cargo fuzz build' would provide built-in corpus management, but it
# currently doesn't work due to the symbol conflict issue, and is not required
# for OSS-Fuzz integration.

cd $SRC/MLA

# Disable sanitizer coverage in C/C++ flags to prevent symbol conflicts
export CFLAGS="$CFLAGS -fno-sanitize-coverage"
export CXXFLAGS="$CXXFLAGS -fno-sanitize-coverage"

# Set RUSTFLAGS for ASAN without coverage instrumentation
# --cfg fuzzing: Enables fuzzing-specific configuration in Rust crates
# -Zsanitizer=address: Enables AddressSanitizer
# -Cdebuginfo=1: Includes debug info (required for OSS-Fuzz stack traces)
# -Cforce-frame-pointers: Forces frame pointers (required for OSS-Fuzz)
export RUSTFLAGS="--cfg fuzzing -Zsanitizer=address -Cdebuginfo=1 -Cforce-frame-pointers"

# Build the fuzzer using the real cargo binary, not the OSS-Fuzz wrapper
/rust/bin/cargo build --manifest-path fuzz/Cargo.toml --target x86_64-unknown-linux-gnu --release --bins

# Copy the compiled fuzzer binary to the output directory
cp target/x86_64-unknown-linux-gnu/release/mla_fuzz "$OUT/"
