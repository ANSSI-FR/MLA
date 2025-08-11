# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] – 2025‑08‑07

### Added / Changed

- Split `MLAFile` class into `MLAReader` and `MLAWriter` classes for clarity, cleaner error handling and better Pythonic API.
- Added `mla.pyi` stub file to improve developer experience and support better type checking.

### Fixed

## [0.4.0] – 2025‑08‑01

### Added / Changed

- Major refactor and upgrade of Python bindings using `pyO3`:
  - Updated for compatibility with redesigned Rust APIs and signature handling.
  - Aligned with Python 3.13 support and safety across threads.
  - Improved integration with archive configuration and key signature verification.
- Python bindings version bumped and aligned with MLA versioning.

### Fixed

- Updated thread‑safety guarantees and memory handling across Rust↔Python FFI.

### Previous relevant entries

## [0.1.0] – 2021‑01‑26

### Added / Changed

- Python bindings (for archive writing and reading), and associated tests
