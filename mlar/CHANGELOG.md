# Change Log

## 1.1.0

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