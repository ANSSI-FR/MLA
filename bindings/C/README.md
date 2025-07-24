# MLA C/CPP Bindings

This project provides C and CPP bindings for the MLA format.

## How-to

The last version of libraries are available in the [Release section](https://github.com/ANSSI-FR/MLA/releases).

It provides:
* `.h` and `.hpp` headers. There are generated, but provided to ease the use of bindings without the Rust toolchain;
* `libmla.a` for Linux x86-64 bits
* `mla.lib` (static), `mla.dll` + `mla.dll.lib` (dynamic), `mla.pdb` (symbols) for Windows i686 and x86_64, in *release* and *debug* targets

One can also compile them using the Rust toolchain:

```sh
# Install cbindgen
cargo install cbindgen
# Generate the .h header
cbindgen --config cbindgen_c.toml
# Generate the .hpp header
cbindgen --config cbindgen_cpp.toml
# Install the appropriate target toolchain
# For instance, with rustup:
rustup add target ...
# Compile the Debug version
cargo build --target ...
# Compile the Release version
cargo build --release --target ...
```

Notes: when linking with `mla.lib`, `ntdll.lib` is also needed.

## Example

* Creating a new MLA (from [this file](tests/linux-gcc-g++/create.c) - Windows example [here](tests/windows-msvc/src/main.c))

```C
// Called to out Archive content to the actual output
static int32_t callback_write(const uint8_t* pBuffer, uint32_t length, void *context, uint32_t *pBytesWritten)
{
    size_t res = fwrite(pBuffer, 1, length, (FILE*)context);
    *pBytesWritten = (uint32_t)res;
    if (ferror(context))
    {
        return errno;
    }
    return 0;
}

// Called to flush the actual output
static int32_t callback_flush(void *context)
{
    if (fflush((FILE*)context) != 0)
    {
        return errno;
    }
    return 0;
}

[...]

// Open the output file
FILE* f = fopen("test.mla", "w");

// Create a configuration for the archive writer
MLAStatus status;
MLAWriterConfigHandle hConfig = NULL;
status = create_mla_writer_config_with_public_keys(&hConfig, szPubkey, 1);
// Error code can be obtained with MLA_STATUS
if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
{
    fprintf(stderr, " [!] Config creation failed with code %" PRIX64 "\n", (uint64_t)status);
    return (int)status;
}

// For the sake of readability, checks are now omitted

// Add a recipient

// Create the archive writer
// `callback_write` and `callback_flush` will received whatever context is given to `mla_archive_new`
// Here, this is `f`, the output file descriptor
MLAArchiveHandle hArchive = NULL;
status = mla_archive_new(&hConfig, &callback_write, &callback_flush, f, &hArchive);

// Start a new file in the archive
// hFile will be used to identify this file inside the archive
MLAArchiveFileHandle hFile = NULL;
status = mla_archive_start_entry_with_path_as_name(hArchive, "test.txt", &hFile);

// Append some content
status = mla_archive_file_append(hArchive, hFile, (const uint8_t*)"Hello, World!\n", (uint32_t)strlen("Hello, World!\n"));

// Finalize the file inside the archive
status = mla_archive_file_close(hArchive, &hFile);

// Finalize the archive
status = mla_archive_close(&hArchive);

// Clean-up
fclose(f);
```

## API

The API is available in [mla.h](mla.h) and [mla.hpp](mla.hpp).

For now, only the writer API is available.

### Guidelines

* If one wants an archive without encryption, they must explicitly ask for it (ie. default is encrypted)
* Statuses and handles are separated, to avoid confusion and the use of a variable for two distinct purposes. As a result, each API always returns a `MLAStatus`, and could take or give handles through arguments
* Output writing is delegated to the library user, through callbacks. That way, she can manage how and when flushing and  actual writes are made (buffering, writing to an external HTTP server...)

## Tests

The bindings are [tested](tests). These tests might also provides some example of use.

They are launched by the CI.
One can locally launch them using the available `Makefile` and Visual Studio projects.

## Caveat

MLA bindings for C currently does not support the `Send` feature, so its handles and objects are not safe to use across multiple threads. Thread safety cannot be guaranteed at this time.