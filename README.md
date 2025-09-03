[![Build & test](https://github.com/ANSSI-FR/MLA/workflows/Build%20&%20test/badge.svg)](https://github.com/ANSSI-FR/MLA/actions)
[![Cargo MLA](https://img.shields.io/badge/crates.io-mla-red)](
https://crates.io/crates/mla)
[![Documentation MLA](https://img.shields.io/badge/docs.rs-mla-blue)](
https://docs.rs/mla)
[![Cargo MLAR](https://img.shields.io/badge/crates.io-mlar-red)](
https://crates.io/crates/mlar)
[![PyPI - Version](https://img.shields.io/pypi/v/mla-archive?label=PyPI%20%7C%20mla-archive)](https://pypi.org/project/mla-archive/)

# Multi Layer Archive (MLA)

MLA is an archive file format with the following features:

* Support for traditional and post-quantum encryption hybridation with asymmetric keys (HPKE with AES256-GCM and a KEM based on an hybridation of X25519 and post-quantum ML-KEM 1024)
* Support for traditional and post-quantum signing hybridation
* Support for compression (based on [`rust-brotli`](https://github.com/dropbox/rust-brotli/))
* Streamable archive creation:
  * An archive can be built even over a data-diode
  * An entry can be added through chunks of data, without initially knowing the final size
  * Entry chunks can be interleaved (one can add the beginning of an entry, start a second one, and then continue adding the first entry's parts)
* Architecture agnostic and portable to some extent (written entirely in Rust)
* Archive reading is seekable, even if compressed or encrypted. An entry can be accessed in the middle of the archive without reading from the beginning
* If truncated, archives can be repaired to some extent. Two modes are available:
  * Authenticated repair (default): only authenticated (as in AEAD, there is no signature verification) encrypted chunks of data are retrieved
  * Unauthenticated repair: authenticated and unauthenticated encrypted chunks of data are retrieved. Use at your own risk.
* Arguably less prone to bugs, especially while parsing an untrusted archive (Rust safety)

# Repository

This repository contains:

* `mla`: the Rust library implementing MLA reader and writer
* `mlar`: a Rust cli utility wrapping `mla` for common actions (create, list, extract...)
* `doc` : documentation related to MLA (e.g. format specification, cryptography)
  * [MLA book](https://anssi-fr.github.io/MLA)
* `bindings` : bindings for other languages
* `samples` : test assets
* `mla-fuzz-afl` : a Rust utility to fuzz `mla`
* `.github`: Continuous Integration needs

# Quick command-line usage

Here are some commands to use ``mlar`` in order to work with archives in MLA format.

```sh
# Generate MLA key pairs.
mlar keygen sender
mlar keygen receiver

# Create an archive with some files.
mlar create -k sender.mlapriv -p receiver.mlapub -o my_archive.mla /boot/./grub/locale/en@quot.mo /etc/security/../issue ../file.txt

# List the content of the archive.
# Note that order may vary, root dir are stripped,
# paths are normalized and listing is encoded as described in
# `doc/src/ENTRY_NAME.md` (hence the percent in output).
# This outputs:
# ``
# etc/issue
# boot/grub/locale/en%40quot.mo
# file.txt
# ``
mlar list -k receiver.mlapriv -p sender.mlapub -i my_archive.mla

# Extract the content of the archive into a new directory.
# In this example, this creates two files:
# extracted_content/etc/issue and extracted_content/etc/os-release
mlar extract -k receiver.mlapriv -p sender.mlapub -i my_archive.mla -o extracted_content

# Display the content of a file in the archive
mlar cat -k receiver.mlapriv -p sender.mlapub -i my_archive.mla etc/os-release

# Convert the archive into a long-term format, primarily for archival purposes.
# Below operation also removes encryption and applies
# the highest (but slowest) compression level.
mlar convert -k receiver.mlapriv -p sender.mlapub -i my_archive.mla -o longterm.mla -l compress -q 11

# Create an archive with multiple recipients and without signature nor compression
mlar create -l encrypt -p archive.mlapub -p client1.mlapub -o my_archive.mla ...

# List an archive containing an entry with a name that cannot be interpreted as path.
# This outputs:
# `c%3a%2f%00%3b%e2%80%ae%0ac%0dd%1b%5b1%3b31ma%3cscript%3eevil%5c..%2f%d8%01%c2%85%e2%88%95`
# corresponding to an entry name containing: ASCII chars, c:, /, .., \,
# NUL, RTLO, newline, terminal escape sequence, carriage return,
# HTML, surrogate code unit, U+0085 weird newline, fake unicode slash.
# Please note that some of these characters may appear in a valid path.
mlar list -k samples/test_mlakey_archive_v2_receiver.mlapriv -p samples/test_mlakey_archive_v2_sender.mlapub -i samples/archive_weird.mla --raw-escaped-names

# Get its content.
# This displays:
# `' OR 1=1`
mlar cat -k samples/test_mlakey_archive_v2_receiver.mlapriv -p samples/test_mlakey_archive_v2_sender.mlapub -i samples/archive_weird.mla --raw-escaped-names c%3a%2f%00%3b%e2%80%ae%0ac%0dd%1b%5b1%3b31ma%3cscript%3eevil%5c..%2f%d8%01%c2%85%e2%88%95

# Create an archive of a web file, without compression, without encryption and without signature
curl https://raw.githubusercontent.com/ANSSI-FR/MLA/refs/heads/main/LICENSE.md | mlar create -l -o my_archive.mla --stdin-data

# Create an archive of a web file and arbitrary byte string, without compression, without encryption and without signature (chosen separator should not be present in the two entries)
(curl https://raw.githubusercontent.com/ANSSI-FR/MLA/refs/heads/main/LICENSE.md; echo "SEPARATOR"; echo -n "All Hail MLA") | mlar create -l -o my_archive.mla --stdin-data --stdin-data-separator "SEPARATOR" --stdin-data-entry-names great_license.md,hello.txt

# Create an archive passing the file list on stdin (not data)
echo -n -e "/etc/issue\n/etc/os-release" | mlar create -l -o my_archive.mla --stdin-file-list
```

`mlar` can be obtained:

* through Cargo: `cargo install mlar`
* using the [latest release](https://github.com/ANSSI-FR/MLA/releases) for supported operating systems
  * The released binaries are built with `opt-level = 3`, enabling great performance

For even higher performance, you can build a native-optimized binary (not portable), for example on a Linux machine:

```bash
RUSTFLAGS="-Ctarget-cpu=native" cargo build --release --target x86_64-unknown-linux-musl
```

Note: Native builds are optimized for your machine's CPU and **are not portable**. Use them only when running on the same machine you build on.

# API usage

See [https://docs.rs/mla](https://docs.rs/mla/2.0.0-alpha/mla/index.html)

# Using MLA with others languages

Bindings are available for:

* [C/C++](bindings/C/README.md)
* [Python](bindings/python/README.md)

## Security

* Please keep in mind, it is generally not safe to extract in a place where at least one ancestor is writable by others (symbolic link attacks).
* Even if encrypted with an authenticated cipher, if you receive an unsigned archive, it may have been crafted by anyone having your public key and thus can contain arbitrary data.
* Read API documentation and mlar help before using their functionalities. They sometimes provide important security warnings. `doc/src/ENTRY_NAME.md` is also of particular interest.
* mlar escapes entry names on output to avoid security issues.
* Except for symbolic link attacks, mlar will not extract outside given output directory.

## FAQ

**Is `MLAArchiveWriter` `Send`?**

By default, `MLAArchiveWriter` is not `Send`. If the inner writable type is also `Send`, one can enable the feature `send` for `mla` in `Cargo.toml`, such as:

```toml
[dependencies]
mla = { version = "...", default-features = false, features = ["send"]}
```

**Was a new format really required?**

As existing archive formats are numerous, probably not.

But to the best of the authors' knowledge, none of them support the aforementioned
features (but, of course, are better suitable for others purposes).

For instance (from the understanding of the author):

* `tar` format needs to know the size of files before adding them, and is not
  seekable
* `zip` format could lose information about files if the footer is removed
* `7zip` format requires to rebuild the entire archive while adding files to it
  (not streamable). It is also quite complex, and so harder to audit / trust
  when unpacking unknown archive
* `journald` format is not streamable. Also, one writer / multiple reader is
  not needed here, thus releasing some constraints `journald` format has
* any archive + `age`: [age](https://age-encryption.org/) does not, as of MLA 2.0 release, support post quantum encryption nor signatures.
* Backup formats are generally written to avoid things such as duplication,
  hence their need to keep bigger structures in memory, or not being 
  streamable

Tweaking these formats would likely have resulted in similar properties. The
choice has been made to keep a better control over what the format is capable 
of, and to (try to) KISS.

## Performance

One can evaluate the performance through embedded benchmark, based on [Criterion](https://github.com/bheisler/criterion.rs).

Several scenarios are already embedded, such as:
* File addition, with different size and layer configurations
* File addition, varying the compression quality
* File reading, with different size and layer configurations
* Random file read, with different size and layer configurations
* Linear archive extraction, with different size and layer configurations

On an "Intel(R) Core(TM) i7-1255U CPU @ 2.60GHz":
```sh
$ cargo bench
...
multiple_layers_multiple_block_size/compression: true, encryption: true, signature: true/1048576
                        time:   [7.0850 ms 7.1179 ms 7.1586 ms]
                        thrpt:  [139.69 MiB/s 140.49 MiB/s 141.14 MiB/s]
...
chunk_size_decompress_multifiles_random/compression: true, encryption: true, signature: true/1048576
                        time:   [11.285 ms 11.494 ms 11.663 ms]
                        thrpt:  [85.745 MiB/s 87.005 MiB/s 88.616 MiB/s]
...
reader_multiple_layers_multiple_block_size_multifiles_linear/compression: true, encryption: true, signature: true/1048576
                        time:   [4.6197 ms 4.6383 ms 4.6604 ms]
                        thrpt:  [214.58 MiB/s 215.60 MiB/s 216.47 MiB/s]
...
```

Criterion.rs documentation explains how to get back HTML reports, compare results, etc.

### AES-NI support

As described in the [aes crate documentation](https://docs.rs/aes/0.8.4/aes/index.html#x86x86_64-intrinsics-aes-ni), this crate uses **runtime detection** on `i686` and `x86_64` targets to check if AES-NI is available. If AES-NI is not detected, it automatically falls back to a constant-time software implementation.

# Contributing

We appreciate your help! To contribute, please read our [contributing instructions](.github/CONTRIBUTING.md).
