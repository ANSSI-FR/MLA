# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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