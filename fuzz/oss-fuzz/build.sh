#!/bin/bash -eu
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# /rust/bin/cargo bypasses the OSS-Fuzz wrapper that rewrites RUSTFLAGS, so
# the SanitizerCoverage flags are added explicitly (libFuzzer is blind
# without them). LTO must stay disabled: it breaks sancov-module linking
# (cargo-fuzz#384, cf. the `fuzzing` profile). Do NOT add GCC's bare
# `-fno-sanitize-coverage` to CFLAGS/CXXFLAGS: recent clang rejects it, and
# the OSS-Fuzz CFLAGS already give the C++ runtime -fsanitize=fuzzer-no-link
#
# Build only the fuzz target (--bin mla_fuzz), not generate_seeds. The latter
# is a dev-only seed generator (fuzz/src/bin/generate_seeds.rs), not a fuzz
# target. Seeds are pre-generated and committed in fuzz/mla_fuzz_seed_corpus/

cd $SRC/MLA

export RUSTFLAGS="--cfg fuzzing -Zsanitizer=address -Cdebuginfo=1 -Cforce-frame-pointers -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares -Ccodegen-units=1"

/rust/bin/cargo build --manifest-path fuzz/Cargo.toml --target x86_64-unknown-linux-gnu --profile fuzzing --bin mla_fuzz

cp target/x86_64-unknown-linux-gnu/fuzzing/mla_fuzz "$OUT/"

# Package seed corpus as a zip (OSS-Fuzz convention: <fuzzer>_seed_corpus.zip)
# and copy the dictionary (<fuzzer>.dict). libFuzzer auto-discovers both at startup
if compgen -G "fuzz/mla_fuzz_seed_corpus/*" > /dev/null; then
    zip -j "$OUT/mla_fuzz_seed_corpus.zip" fuzz/mla_fuzz_seed_corpus/*
fi
cp fuzz/mla_fuzz.dict "$OUT/mla_fuzz.dict"
