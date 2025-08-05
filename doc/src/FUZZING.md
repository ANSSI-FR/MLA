Fuzzing
-

A fuzzing scenario made with [afl.rs](https://github.com/rust-fuzz/afl.rs) is available in `mla-fuzz-afl`.
The scenario is capable of:
* Creating archives with interleaved files, and different layers enabled
* Reading them to check their content
* Repairing the archive without truncation, and verifying it
* Altering the archive raw data, and ensuring reading it does not panic (but only fail)
* Repairing the altered archive, and ensuring the recovery doesn't fail (only reports detected errors)

To launch it:
1. produce initial samples by uncommenting `produce_samples()` in `mla-fuzz-afl/src/main.rs`
```sh
cd mla-fuzz-afl
# ... uncomment `produces_samples()` ...
mkdir in
mkdir out
cargo run
```
2. build and launch AFL
```sh
cargo afl build
cargo afl fuzz -i in -o out ../target/debug/mla-fuzz-afl
```

If you have found crashes, try to replay them with either:
* Peruvian rabbit mode of AFL: `cargo afl run -i - -o out -C ../target/debug/mla-fuzz-afl`
* Direct replay: `../target/debug/mla-fuzz-afl < out/crashes/crash_id`
* Debugging: uncomment the "Replay sample" part of `mla-fuzz-afl/src/main.rs`, and add `dbg!()` when it's needed

:warning: The stability is quite low, likely due to the process used for the scenario (deserialization from the data provided by AFL) and variability of inner algorithms, such as brotli. Crashes, if any, might not be reproducible or due to the `mla-fuzz-afl` inner working, which is a bit complex (and therefore likely buggy). One can comment irrelevant parts in `mla-fuzz-afl/src/main.rs` to ensure a better experience.
