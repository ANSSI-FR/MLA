# MLA C/C++ Bindings

This project provides C and C++ bindings for MLA.

## How-to

The latest versions of the libraries are available in the [Releases section](https://github.com/ANSSI-FR/MLA/releases).

Each release provides:

- `.h` and `.hpp` headers — generated automatically for easy integration, no Rust toolchain required.
- `libmla.a` for Linux (x86-64)
- `mla.lib` (static), `mla.dll` + `mla.dll.lib` (dynamic), and `mla.pdb` (debug symbols) for Windows (i686 and x86_64), in both *Release* and *Debug* builds.

---

## Build from source

You can also compile the libraries manually using the Rust toolchain.

### 1. Generate C/C++ bindings

Install `cbindgen` if it's not already installed:

```sh
cargo install cbindgen

# Generate the C header
cbindgen --config cbindgen_c.toml

# Generate the C++ header
cbindgen --config cbindgen_cpp.toml
```

### 2. Install a target toolchain

```sh
# Add the Windows MSVC target as an example
rustup target add x86_64-pc-windows-msvc
```

### 3. Compile

```sh
# Debug build for Windows MSVC target
cargo build --target x86_64-pc-windows-msvc

# Release build for Windows MSVC target
cargo build --release --target x86_64-pc-windows-msvc
```

#### Linking notes for Windows

If you are linking your own application against `mla.lib` (the static library), you must also link against `ntdll.lib`.

To build or link properly on Windows:

- Make sure the appropriate linker is available.
- Install the **Microsoft Visual Studio Build Tools** (with C++ components).
- Use a **Developer Command Prompt for Visual Studio** to ensure the environment is correctly configured.

## Examples

### Writing an MLA

- Linux: [tests/linux-gcc-g++/create.c](tests/linux-gcc-g++/create.c)
- Windows: [tests/windows-msvc/src/write.c](tests/windows-msvc/src/write.c)

### Reading an MLA

- Linux: [tests/linux-gcc-g++/open.c](tests/linux-gcc-g++/open.c)
- Windows: [tests/windows-msvc/src/read.c](tests/windows-msvc/src/read.c)

## API

The API is available in [mla.h](mla.h) and [mla.hpp](mla.hpp).

### Writer config creation

- `create_mla_writer_config_with_encryption_with_signature(...)`
- `create_mla_writer_config_with_encryption_without_signature(...)`
- `create_mla_writer_config_without_encryption_with_signature(...)`
- `create_mla_writer_config_without_encryption_without_signature(...)`

### Reader config creation

- `create_mla_reader_config(...)`

Provide private keys for decryption and public keys for signature verification.

### Compression

- `mla_writer_config_set_compression_level(hConfig, level)`

Valid levels: 1 (fastest) to 11 (best), 6 is default.

### Archive writing

- `mla_archive_new(...)`
- `mla_archive_start_entry_with_path_as_name(...)`
- `mla_archive_file_append(...)`
- `mla_archive_file_close(...)`
- `mla_archive_close(...)`

### Archive reading

- `mla_archive_open(...)`
- `mla_archive_list_entries(...)`
- `mla_archive_open_entry_by_name(...)`
- `mla_archive_file_read(...)`
- `mla_archive_file_close(...)`
- `mla_archive_close(...)`

### Error handling

All functions return `MLAStatus`. Use `MLA_STATUS(MLA_STATUS_SUCCESS)` to check for success.

### Guidelines

- Encryption and signing are explicit; choose your config accordingly.
- Output/input is managed via user-provided callbacks for writing, flushing, and reading.
- Handles are used for configs, archives, and files.
- Both writer and reader APIs are available.

---

## Tests

See the [tests](tests) directory for more usage examples.
Tests are run by CI and can be run locally using the provided `Makefile` and Visual Studio projects.

---

## Caveat

MLA bindings for C currently do **not** support the `Send` feature; handles and objects are **not** thread-safe.
