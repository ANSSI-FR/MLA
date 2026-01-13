# Migration guide from older MLA versions

This guide can help you upgrade code through breaking changes from one MLA version to the next. For a detailed list of all changes, see the [CHANGELOG](https://github.com/ANSSI-FR/MLA/blob/main/CHANGELOG.md).

## from 1.* to 2.0.0

### Deprecation of MLA 1

- MLA 2 is now the default and is incompatible with MLA 1.
- MLA 1 enters low maintenance mode (no new features, only critical bug fixes).

### Generate new keys

MLA 2 introduces a new archive format and new cryptography. You must generate new keys:

```sh
mlar keygen sender
mlar keygen receiver
```

Note: if you don't need signatures for mlar archive creation, use `--unsigned` otherwise it will try to sign by default and fail if no private key is specified. For reading with mlar, If you understand the associated risks, you can skip signature verification using the `--skip-signature-verification` flag.

### Upgrade your archives

`mlar-upgrader` is a CLI utility for upgrading [MLA](https://github.com/ANSSI-FR/MLA) archives from version 1 to version 2. It reads a legacy MLA v1 archive, optionally decrypts it using provided private keys, and writes a new MLA v2 archive, optionally re-encrypting it with specified MLA v2 public keys.

Full documentation: [mlar-upgrader usage](https://github.com/ANSSI-FR/MLA/tree/main/mlar/mlar-upgrader#usage).

### mlar utility

`mlar repair` command got renamed to `mlar clean-truncated`. It also got fixed regarding to [issue #226](https://github.com/ANSSI-FR/MLA/issues/226).

### API

MLA 2 introduces signifiant API changes for archive creation, encryption and signature handling, see [quick API usage](https://docs.rs/mla/2.0.0-beta/mla/#quick-api-usage).

### Bindings

#### C/C++

MLA 2 introduces signifiant API changes for archive creation, encryption and signature handling. Updated examples to read and write an MLA on Linux and Windows [can be found here](https://github.com/ANSSI-FR/MLA/tree/main/bindings/C#examples).

Full documentation: [MLA's C/C++ API](https://github.com/ANSSI-FR/MLA/tree/main/bindings/C#api).

#### Python

MLA 2 introduces one major change in the Python bindings: `MLAFile` split: this class got split into `MLAReader` and `MLAWriter`, see [usage example](https://github.com/ANSSI-FR/MLA/tree/main/bindings/python#usage-example).

Also, MLA 2 now includes stub files (`.pyi`) for better IDE support (type checking, autocompletion).
