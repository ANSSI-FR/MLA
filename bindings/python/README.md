# MLA Python Bindings

Python bindings for the MLA (Multi-Layer Archive) format, enabling secure, compressed, and signed archives from Python.

## Installation

Install from PyPI:

```sh
pip install mla-archive
```

Or build from source:

**Install maturin:**  
   `maturin` is a tool for building and publishing Rust-based Python packages.  
   You can install it via pip:

   ```sh
   pip install maturin
   ```

   Or, if you prefer, via cargo:

   ```sh
   cargo install maturin
   ```

**Build the Python wheel:**

   ```sh
   maturin build --release
   ```

   This creates a `.whl` file in the `target/wheels/` directory.

**(Alternative) Install directly into your current Python environment:**

   ```sh
   maturin develop
   ```

   This builds and installs the package for development.

## Usage Example

```python
import mla

# --- Writing ---
config = mla.WriterConfig.without_encryption_without_signature()
with mla.MLAFile("example.mla", "w", config) as archive:
    archive[mla.EntryName("hello.txt")] = b"Hello, MLA!"
    archive[mla.EntryName("data.bin")] = b"\x00\x01\x02"

# --- Reading ---
sig_cfg = mla.SignatureConfig.without_signature_verification()
config = mla.ReaderConfig.without_encryption(sig_cfg)
with mla.MLAFile("example.mla", "r", config) as archive:
    print(archive[mla.EntryName("hello.txt")])  # b'Hello, MLA!'
    for name in archive.keys():
        print(name.raw_content_to_escaped_string(), len(archive[name]))
```

## Features

- Create and extract MLA archives from Python
- Support for compression, encryption, and signatures (if enabled in the archive)
- Simple dictionary-like API for file access
- Compatible with archives created by the Rust `mlar` CLI

## API

- `mla.MLAFile(path, mode)` — Open an archive for reading (`"r"`) or writing (`"w"`)
- `archive[name] = data` — Add a file (write mode)
- `archive[name]` — Read a file (read mode)
- `archive.finalize()` — Finalize and close the archive (write mode)
- Iteration: `for name in archive: ...`

See [tests](tests) for more usage examples.

## Testing

Run the test suite with:

```sh
pytest
```
