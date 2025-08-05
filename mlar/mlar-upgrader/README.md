# MLA v1 to v2 Archive Migration Tool

`mlar-upgrader` is a CLI utility for upgrading [MLA](https://github.com/ANSSI-FR/MLA) archives from version 1 to version 2. It reads a legacy MLA v1 archive, optionally decrypts it using provided private keys, and writes a new MLA v2 archive, optionally re-encrypting it with specified MLA v2 public keys.

## Features

- Supports reading encrypted MLA v1 archives (ED25519 private key in PEM/DER format).
- Supports writing encrypted MLA v2 archives (via MLA public keys).
- Handles entry name conversion and metadata preservation.
- Validates and finalizes output archive for compatibility with MLA v2 consumers.

## Usage

```sh
mlar-upgrader -i <v1_archive> -o <v2_archive> [options]
```

This tool is written in Rust and uses recent Rust language features. It is strongly recommended to use the latest stable version of rustc for successful compilation.

### Examples

```sh
# upgrade a cleartext archive
mlar-upgrader -i archive_v1.mla -o archive_v2.mla

# upgrade and decrypt with a private key
mlar-upgrader -i archive_v1.mla -k key.mlapriv -o archive_v2.mla

# upgrade, decrypt with a private key, and re-encrypt with MLA 2 public key
mlar-upgrader -i archive_v1.mla -k key.mlapriv -p receiver.mlapub -o archive_v2.mla
```
