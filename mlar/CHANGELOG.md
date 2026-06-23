# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-16

### Added/Changed since 1.3.0

- MLA2 is now the default; it is **incompatible** with MLA1. MLA1 enters **low maintenance mode**
- Hybrid traditional/post-quantum encryption using **X25519 + ML-KEM1024**
- Archive signing using hybrid traditional/post-quantum signatures
- New archive format, enabling improved cryptographic and performance characteristics
- Cryptographic layer reworked to **protect against truncation attacks**
- Redesigned CLI for improved **simplicity, safety, and semver compatibility**
- Support for **authenticated truncated archive reading**
- Create archive from **stdin** input
- **Mark-of-the-Web (MotW)** propagation support
- Introduced `mlar-upgrader`: a tool to **upgrade MLA1 archives to MLA2 format**
- Added support for a shared-secret decryption advanced use case

### Fixed since 1.3.0

- Limit dependencies by linking statically MSVC builds for Windows
- Fixed inappropriate default privileges on private key files

### Added/Changed since 2.0.0-beta

- Added a migration guide ( doc/src/MIGRATION.md )
- Improved trust thanks to MLA security assessment (#465)
- Improved release transparency thanks to GitHub artifact attestation and reproducible builds
- Replace `-l` option with less error prone `--unencrypted` `--unsigned` and `--uncompressed`

### Fixed since 2.0.0-beta

- Fixed inappropriate default privileges on private key files

## [2.0.0-beta] – 2025-12-20

### Added / Changed

- Adapted `mlar` and `mlar-upgrader` to the TLV-based `KeyOpts`/`Opts` format
- Added and hardened `stdin`-based creation
- Improved CLI ergonomics
- Better error handling
- Optimize read/write paths with BufReader/BufWriter where appropriate
- [Advanced use case] HSM / shared-secret decryption: add an option to decrypt archives using a shared secret

### Fixed

- Limit dependencies by linking statically MSVC builds for Windows

## [2.0.0-alpha] – 2025-08-01

### Added/Changed

- MLA2 is now the default; it is **incompatible** with MLA1. MLA1 enters **low maintenance mode**
- Hybrid traditional/post-quantum encryption using **X25519 + ML-KEM1024**
- Archive signing using hybrid traditional/post-quantum signatures
- Switched to **Rust 2024 edition**
- New archive format, enabling improved cryptographic and performance characteristics
- Cryptographic layer reworked to **protect against truncation attacks**
- Redesigned APIs and CLI for improved **simplicity, safety, and semver compatibility**
- Support for **authenticated truncated archive reading**
- Create archive from **stdin** input
- **Mark-of-the-Web (MotW)** propagation support
- Introduced `mlar-upgrader`: a tool to **upgrade MLA1 archives to MLA2 format**

### Fixed

## [1.3.0] - 2023-10-06

### Thanks

- [Jean-Baptiste Galet](https://github.com/jbgalet)

### Added/Changed

- Bump dependencies
- Code cleaning
- Add more integration & CLI tests
- Behavior change: to avoid mistake, do not open unencrypted archive if a key is provided
- Add [key derivation capabilities](https://github.com/ANSSI-FR/MLA/pull/155)

### Fixed

- Reduce the number of call to `open`/`close` on linear extraction

## [1.2.0] - 2021-10-01

### Thanks

- [Nicolas Bordes](https://github.com/NicsTr)

### Added/Changed

- Recursive file-adding capability
- Bump dependencies

## [1.1.1] - 2021-03-04

### Added/Changed

- Bump dependencies
  - In particular, update `mla` to running state, including a fix for [an issue](https://github.com/ANSSI-FR/MLA/issues/63) which may occurs in archive with more than 2^32 bits data


## [1.1.0] - 2020-09-14

### Thanks

- [sashaconway](https://github.com/sashaconway)
- [Jean-Baptiste Galet](https://github.com/jbgalet)

### Added/Changed

- Switch from `ed25519_parser` to `curve25519-parser`: X25519 keys parsing capabilities
- `mlar to-tar`:
  - Support for `-` output
  - Sorted files
- New command, `mlar info`, to get an overview of an archive
- Typos
- Bump dependencies:
  - `x25519-dalek`: 0 to 1
  - `hex`: 0.3 to 0.4
  - `assert_cmd`: 0.12 to 1.0 (dev)
  - `assert_fs`: 0.13 to 1.0 (dev)
  - `mla`: running state
