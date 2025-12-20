# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0-beta] – 2025-12-20

### Added / Changed

- API adjustments according to MLA updates
- Improve documentation, usage, examples and tests

### Fixed

- Fix Windows debugging and stack sizes for some debug scenarios

## [2.0.0-alpha] – 2025-08-01

### Added/Changed

- Redesigned APIs and CLI for improved **simplicity, safety, and semver compatibility**

### Fixed

### Previous relevant entries

## [1.2.0] - 2021-09-28

### Added/Changed

- C/CPP bindings now support partial writes and error codes

## [1.1.0] - 2021-01-26

### Added/Changed

- C/CPP bindings (for archive writing), and associated tests
- MLA releases (through the CI), including:
  * `.h` and `.hpp` headers, generated but provided to ease use without Rust toolchain
  * Static and dynamic libraries for Linux and Windows targets