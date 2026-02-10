# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased [2.0.0] - 2026-02-FIXME

### Added/Changed since 1.3.0

- MLA2 is now the default; it is **incompatible** with MLA1. MLA1 enters **low maintenance mode**
- Hybrid traditional/post-quantum encryption using **X25519 + ML-KEM1024**
- Archive signing using hybrid traditional/post-quantum signatures
- Switched to **Rust 2024 edition**
- Key commitment support for AES-GCM
- New archive format, enabling improved cryptographic and performance characteristics
- Cryptographic layer reworked to **protect against truncation attacks**
- Redesigned API for improved **simplicity, safety, and stability over time**
- Support for **authenticated truncated archive reading**
- Support for **seeking inside archive entries**
- Comprehensive documentation overhaul
- Published the **MLA Book**, a comprehensive guide and reference for MLA usage and concepts
- Introduced `mlar-upgrader`: a tool to **upgrade MLA1 archives to MLA2 format**
- Bumped dependencies as part of pre-alpha maintenance: `brotli`, `clap`, `rand`, and others via Dependabot (April 2025)
- GitHub Actions workflows updated to **use pinned versions** for CI security
- Minor documentation corrections and CI improvements merged ahead of alpha release
- Added support for a shared-secret decryption advanced use case

### Fixed since 1.3.0

- Fixed incomplete recovery for truncated archives (#226)

### Added/Changed since 2.0.0-beta

- Added a migration guide ( doc/src/MIGRATION.md )
- Improved trust thanks to MLA security assessment (#465)
- Improved release transparency thanks to GitHub artifact attestation and reproducible builds

### Fixed since 2.0.0-beta

- Fixed incomplete memory zeroization (#465)

## [2.0.0-beta] – 2025-12-20

### Added / Changed

**Breaking changes**

- TLV-based options: introduce a TLV structure for `KeyOpts` and archive-level `Opts`
- Key format improvements: support alternative key-format line separators
- Signature compatibility: replace `ed25519ph` usage with `ed25519` for better compatibility

---

- Mark some public items (enum, struct) as non exhaustive to enable future additions without breaking existing code
- Documentation: improved security section and examples; MLA Book and docs refreshed
- CLI and tooling: `mlar` and `mlar-upgrader` enhancements:
  - Optimized read/write
  - Improved error handling
- Build & CI: 
  - Specify toolchain for releases
  - Remove macos-13 x86_64 support due to obsolescence
  - Deliver Windows 7 builds using tier 3 target 
- Dependencies: 
  - Removed unneeded deps (e.g., `humansize`, direct `kem` dependency)
  - Switched `ml-kem` to a maintained version
- Clippy fixes including pedantic mode
- [Advanced use case] HSM / shared-secret decryption: add an option to decrypt archives using a shared secret

### Fixed

- Fix stdin handling as input
- Backported truncated compression-layer fix from v1 where applicable
- Documentation: fix math environment for GFM and KaTeX conversion for GitHub Pages
- Fix `with_encryption_accept_unencrypted` behaviour

## [2.0.0-alpha] – 2025-08-01

### Added/Changed

- MLA2 is now the default; it is **incompatible** with MLA1. MLA1 enters **low maintenance mode**
- Hybrid traditional/post-quantum encryption using **X25519 + ML-KEM1024**
- Archive signing using hybrid traditional/post-quantum signatures
- Switched to **Rust 2024 edition**
- Key commitment support for AES-GCM
- New archive format, enabling improved cryptographic and performance characteristics
- Cryptographic layer reworked to **protect against truncation attacks**
- Redesigned APIs and CLI for improved **simplicity, safety, and semver compatibility**
- Support for **authenticated truncated archive reading**
- Support for **seeking inside archive entries**
- Comprehensive documentation overhaul
- Published the **MLA Book**, a comprehensive guide and reference for MLA usage and concepts
- Introduced `mlar-upgrader`: a tool to **upgrade MLA1 archives to MLA2 format**
- Bumped dependencies as part of pre-alpha maintenance: `brotli`, `clap`, `rand`, and others via Dependabot (April 2025)
- GitHub Actions workflows updated to **use pinned versions** for increased CI/CD security
- Minor documentation corrections and CI improvements merged ahead of alpha release

### Fixed

- Minor doc and CI fixes improving build stability

## [1.4.0] - 2023-10-02

### Added/Changed

- Code cleaning
- Bump dependencies
- Benchmarking: reduce the number of test case per test, add new scenarios
- Explicitly ask for `zeroize` and `static_secrets` feature in `x25519-dalek`

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
