# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2026-11-09

### Added/Changed

- Final v1 release: branch frozen, no security fixes, migrate archives to v2 with `mlar-upgrader`
- Pin rust toolchain to 1.98.1, update CI
- Vendor dependencies for offline builds
- Statically link windows msvc binaries against the CRT
- Release profile: opt-level 3 (backported from the main branch)
- Documentation improvements (repair and compression details, layers and main documentation)
- Remove the bench workflow, the Python bindings workflow and the dependabot config
- Python bindings: not buildable from this branch (root vendored dependencies), use the PyPI wheels or the main branch
- C bindings: regenerate `mla.h`; `MLAStatus` is now a 64-bit based enum (C23, with `typedef` fallback) and the unused `MLA_STATUS_RAND_ERROR` is removed
- Fix clippy 1.98 warnings on all targets (pedantic and nursery lints)
- `SHA256SUMS`: signed with the release manager GPG key (Ed25519, fingerprint `FF5A 2354 5CBA DD41 8D9F  674F B11A EB48 F579 6F65`, on keys.openpgp.org)

### Fixed

- Fix #226: repair a compressed archive losing data on truncated compressed streams
- Reject corrupted archives instead of panicking or aborting on integer underflow (reported by Matthieu Buffet): compression and archive footer lengths larger than the available bytes, and encrypted streams truncated inside the last authentication tag (read and seek paths)
- Validate the compression footer SizesInfo before use: reject empty or short compressed block size lists, and cap the brotli input buffer to prevent a multi-GB allocation on a forged block size

## [1.4.0] - 2023-10-02

### Added/Changed

- Code cleaning
- Bump dependencies
- Benchmarking: reduce the number of test case per test, add new scenarios
- Explicitely ask for `zeroize` and `static_secrets` feature in `x25519-dalek`

### Fixed

- FailSafe Reader: drastically improve performance
- Fix a Brotli-decompressor regression ([following a minor update](https://github.com/ANSSI-FR/MLA/pull/163)) and add corresponding tests

## [1.3.0] - 2022-08-22

### Thanks

- [Jean-Baptiste Galet](https://github.com/jbgalet)
- [@sashaconway](https://github.com/sashaconway)

### Added/Changed

- Introduce `"send"` feature, to provide `ArchiveWriter` with `Send` bound ([#120](https://github.com/ANSSI-FR/MLA/issues/120))
- Enable `x25519-dalek`'s `"u64_backend"` feature by default, to have a default working compilation
- Bump dependencies
- Dependencies: disable default features
- Code cleaning

### Fixed

- Internalize `StaticSecret` generation, due to [dependency issue](https://github.com/ANSSI-FR/MLA/pull/112)
- Tests: use `rand_chacha::ChaCha8Rng` (reliable accross achitectures) instead of `StdRng`
- Tests: fix a bug [due to a wrong assumption](https://github.com/ANSSI-FR/MLA/pull/112)
- Typo in comments
- CI: testing with different features

## [1.2.0] - 2021-09-28

### Thanks

- [Matthieu Buffet](https://github.com/mtth-bfft)
- [Olivier Dembour](https://github.com/alex-sector)

### Added/Changed

- C/CPP bindings now support partial writes and error codes
- Bump dependencies

## [1.1.1] - 2021-05-31

- Bump dependencies

## [1.1.0] - 2021-01-26

### Thanks

- [Matthieu Buffet](https://github.com/mtth-bfft)

### Added/Changed

- C/CPP bindings (for archive writing), and associated tests
- MLA releases (through the CI), including:
  * `.h` and `.hpp` headers. There are generated, but provided to ease the use of bindings without the Rust toolchain;
  * `libmla.a` for Linux x86-64 bits;
  * `mla.lib` (static), `mla.dll` + `mla.dll.lib` (dynamic), `mla.pdb` (symbols) for Windows i686 and x86_64, in *release* and *debug* targets.

### Fixed

- Force `aes-ctr` and `aes` version, to avoid breaking changes
- Fix [an issue](https://github.com/ANSSI-FR/MLA/issues/63) which may occurs in archive with more than 2^32 bits data

## [1.0.1] - 2020-09-14

### Thanks

- [Jean-Baptiste Galet](https://github.com/jbgalet)

### Added/Changed

- Publish previously internal structures:
  - `ArchiveFooter`
  - `ArchiveHeader`
  - `ArchivePersistentConfig` fields
  - `CompressionLayerReader.sizes_info`
  - `EncryptionPersistentConfig.multi_recipient`
  - `FileInfo`
  - `layers` module
  - `MultiRecipientPersistent`
  - `SizesInfo`
- Bump dependencies:
  - `x25519-dalek`: 0 to 1
- Code cleaning
- Minor memory footprint reduction
- Introduce `MultiRecipientPersistent.count_keys()`: amount of recipients
