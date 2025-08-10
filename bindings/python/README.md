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

def main() -> None:
    # --- Writing ---
    config: mla.WriterConfig = mla.WriterConfig.without_encryption_without_signature()
    with mla.MLAWriter("example.mla", config) as archive:
        archive[mla.EntryName("hello.txt")] = b"Hello, MLA!"
        archive[mla.EntryName("data.bin")] = b"\x00\x01\x02"
    print("Archive written: example.mla")

    # --- Reading ---
    sig_cfg: mla.SignatureConfig = mla.SignatureConfig.without_signature_verification()
    config: mla.ReaderConfig = mla.ReaderConfig.without_encryption(sig_cfg)
    with mla.MLAReader("example.mla", config) as archive:
        for name in archive.keys():
            # name is of type EntryName
            print(f"{name.raw_content_to_escaped_string()}: {archive[name].decode('utf-8')}")

if __name__ == "__main__":
    main()
```

## Features

- Create and extract MLA archives from Python
- Support for compression, encryption, and signatures (if enabled in the archive)
- Simple dictionary-like API for file access
- Compatible with archives created by the Rust `mlar` CLI

## API

- `mla.MLAReader(path, config)` — Open an archive for reading
- `mla.MLAWriter(path, config)` — Open an archive for writing
- `archive[name] = data` — Add a file (write mode)
- `archive[name]` — Read a file (read mode)
- `archive.finalize()` — Finalize and close the archive (write mode)
- Iteration: `for name in archive: ...`

See [tests](tests) for more usage examples.

## Type stub files

The MLA Python bindings include type stub files (`.pyi`) to provide static type information for tools like `mypy`, IDEs, and linters.

- The bindings expose a native extension module `mla.mla` along with the top-level `mla` package.
- To support static analysis, there are stub files both for the top-level package (`mla/__init__.pyi`) and the native submodule (`mla/mla.pyi`).
- These stubs allow type checkers to understand the full API surface, since compiled native modules lack introspectable Python signatures.
- When developing or modifying the bindings, ensure all `.pyi` files are kept alongside their respective Python or compiled modules so tools can locate them.
- To verify your stubs correctly match the runtime API (with `mypy` as an example), use:

```sh
python3 -m mypy.stubtest mla
```

## Testing

Run the test suite with:

```sh
pytest
```