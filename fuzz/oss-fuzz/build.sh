#!/bin/bash -eu

# OSS-Fuzz already uses Docker to build the fuzzers, so we don't need to clone the repository or copy files. Instead, we can directly build the fuzzer using cargo-fuzz.
# They use this image gcr.io/oss-fuzz-base/base-builder-rust, which is based on Debian and has Rust and cargo-fuzz pre-installed. It also sets up the environment for building and running Rust fuzzers.

# Build the fuzzer using cargo-fuzz
cd $SRC/MLA
cargo fuzz build -O

# Copy the fuzzer binary to the output directory
cp target/x86_64-unknown-linux-gnu/release/mla_fuzz "$OUT/"
