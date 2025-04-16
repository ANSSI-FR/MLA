# MLA Python Bindings

This project provides Python bindings for the MLA format.

## How-to

The last version of the wheel is available in at [pypi.org/mla-archive](https://pypi.org/project/mla-archive/).

One can also compile them using the Rust toolchain:

```sh
# Install the appropriate target toolchain
# For instance, with rustup:
rustup add target ...
# Compile the Debug version
cargo build --target ...
# Compile the Release version
cargo build --release --target ...
```

## Example

* Creating a new MLA (from [this file](tests/test_mla.py))

```python
import mla
import tempfile

from mla import MLAFile, MLAError

# Test data
FILES = {
    "file1": b"DATA1",
    "file2": b"DATA_2",
}

def basic_archive():
    "Create a temporary archive and return its path"
    fname = tempfile.mkstemp(suffix=".mla")[1]
    archive = MLAFile(fname, "w")
    for name, data in FILES.items():
        archive[name] = data
    archive.finalize()
    return fname
```

## API

Both writer and reader API are available.

## Tests

The bindings are [tested](tests). These tests might also provides some example of use.

They are launched by the CI.
One can locally launch them using `pytest`.
