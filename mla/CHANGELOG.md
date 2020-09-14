# Change Log

## 1.0.1

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