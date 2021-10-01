# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
