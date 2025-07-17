[![Build & test](https://github.com/ANSSI-FR/MLA/workflows/Build%20&%20test/badge.svg)](https://github.com/ANSSI-FR/MLA/actions)
[![Cargo MLA](https://img.shields.io/badge/crates.io-mla-red)](
https://crates.io/crates/mla)
[![Documentation MLA](https://img.shields.io/badge/docs.rs-mla-blue)](
https://docs.rs/mla)
[![Cargo MLAR](https://img.shields.io/badge/crates.io-mlar-red)](
https://crates.io/crates/mlar)

Multi Layer Archive (MLA)
=

MLA is an archive file format with the following features:

* Support for traditional and post-quantum encryption hybridation with asymmetric keys (HPKE with AES256-GCM and a KEM based on an hybridation of X25519 and post-quantum ML-KEM 1024)
* Support for compression (based on [`rust-brotli`](https://github.com/dropbox/rust-brotli/))
* Streamable archive creation:
  * An archive can be built even over a data-diode
  * An entry can be added through chunks of data, without initially knowing the final size
  * Entry chunks can be interleaved (one can add the beginning of an entry, start a second one, and then continue adding the first entry's parts)
* Architecture agnostic and portable to some extent (written entirely in Rust)
* Archive reading is seekable, even if compressed or encrypted. An entry can be accessed in the middle of the archive without reading from the beginning
* If truncated, archives can be repaired to some extent. Two modes are available:
  * Authenticated repair (default): only authenticated encrypted chunks of data are retrieved
  * Unauthenticated repair: authenticated and unauthenticated encrypted chunks of data are retrieved. Use at your own risk.
* Arguably less prone to bugs, especially while parsing an untrusted archive (Rust safety)

Repository
=

This repository contains:

* `mla`: the Rust library implementing MLA reader and writer
* `mlar`: a Rust cli utility wrapping `mla` for common actions (create, list, extract...)
* `doc` : advanced documentation related to MLA (e.g. format specification)
* `bindings` : bindings for other languages
* `samples` : test assets
* `mla-fuzz-afl` : a Rust utility to fuzz `mla`
* `.github`: Continuous Integration needs

Quick command-line usage
=

Here are some commands to use ``mlar`` in order to work with archives in MLA format.

```sh
# Generate an MLA key pair {key, key.pub}
mlar keygen key

# Create an archive with some files, using the public key
mlar create -p key.pub -o my_archive.mla /etc/./os-release /etc/security/../issue ../file.txt

# Create an archive of a web file and utf-8 string, without encryption
(curl https://raw.githubusercontent.com/ANSSI-FR/MLA/refs/heads/master/README.md; echo "SEP"; echo "All Hail MLA!") | mlar create -l -o my_archive.mla --separator "SEP" --filenames great_readme.md -

# List the content of the archive, using the private key.
# Note that order may vary, root dir are stripped,
# paths are normalized and listing is encoded as described in
# `doc/ESCAPING.md`.
# This outputs:
# ```
# etc/issue
# etc/os%2drelease
# file.txt
# ```
mlar list -k key -i my_archive.mla

# Extract the content of the archive into a new directory.
# In this example, this creates two files:
# extracted_content/etc/issue and extracted_content/etc/os-release
mlar extract -k key -i my_archive.mla -o extracted_content

# Display the content of a file in the archive
mlar cat -k key -i my_archive.mla etc/os-release

# Convert the archive to a long-term one, removing encryption and using the best
# and slower compression level
mlar convert -k key -i my_archive.mla -o longterm.mla -l compress -q 11

# Create an archive with multiple recipient
mlar create -p archive.pub -p client1.pub -o my_archive.mla ...

# List an archive containing an entry with a name that cannot be interpreted as path.
# This outputs:
# `c%3a%2f%00%3b%e2%80%ae%0ac%0dd%1b%5b1%3b31ma%3cscript%3eevil%5c..%2f%d8%01%c2%85%e2%88%95`
# corresponding to an entry name containing: ASCII chars, c:, /, .., \,
# NUL, RTLO, newline, terminal escape sequence, carriage return,
# HTML, surrogate code unit, U+0085 weird newline, fake unicode slash.
# Please note that some of these characters may appear in valid a path.
mlar list -k test_mlakey.priv -i archive_weird.mla --raw-escaped-names

# Get its content.
# This displays:
# `' OR 1=1`
mlar cat -k test_mlakey.priv -i archive_weird.mla --raw-escaped-names c%3a%2f%00%3b%e2%80%ae%0ac%0dd%1b%5b1%3b31ma%3cscript%3eevil%5c..%2f%d8%01%c2%85%e2%88%95
```

`mlar` can be obtained:

* through Cargo: `cargo install mlar`
* using the [latest release](https://github.com/ANSSI-FR/MLA/releases) for supported operating systems


API usage
=

See [https://docs.rs/mla](https://docs.rs/mla)

Using MLA with others languages
=

Bindings are available for:

* [C/CPP](bindings/C/README.md)
* [Python](bindings/python/README.md)

Security
-

* There is currently no signature mechanism implemented: an encrypted archive may have been crafted by anyone having your public key and thus can contain arbitrary data.
* Please keep in mind, it is generally not safe to extract in a place where at least one ancestor is writable by others (symbolic link attacks).
* Read API documentation and mlar help before using their functionnalities. They sometimes provide important security warnings. `doc/ENTRY_NAME.md` is also of particular interest.
* mlar escapes entry names on output to avoid security issues.
* Except for symbolic link attacks, mlar will not extract outside given output directory.

FAQ
-

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
* `journald` format is not streamable. Also, one writter / multiple reader is
  not needed here, thus releasing some constraints `journald` format have
* any archive + `age`: [age](https://age-encryption.org/) does not yet support post quantum encryption
* Backup formats are generally written to avoid things such as duplication,
  hence their need to keep bigger structures in memory, or not being 
  streamable

Tweaking these formats would likely have resulted in similar properties. The
choice has been made to keep a better control over what the format is capable 
of, and to (try to) KISS.

Performance
-

One can evaluate the performance through embedded benchmark, based on [Criterion](https://github.com/bheisler/criterion.rs).

Several scenarios are already embedded, such as:
* File addition, with different size and layer configurations
* File addition, varying the compression quality
* File reading, with different size and layer configurations
* Random file read, with different size and layer configurations
* Linear archive extraction, with different size and layer configurations

On an "Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz":
```sh
$ cd mla/
$ cargo bench
...
multiple_layers_multiple_block_size/Layers ENCRYPT | COMPRESS | DEFAULT/1048576                                                                           
                        time:   [28.091 ms 28.259 ms 28.434 ms]
                        thrpt:  [35.170 MiB/s 35.388 MiB/s 35.598 MiB/s]
...
chunk_size_decompress_mutilfiles_random/Layers ENCRYPT | COMPRESS | DEFAULT/4194304                                                                          
                        time:   [126.46 ms 129.54 ms 133.42 ms]
                        thrpt:  [29.980 MiB/s 30.878 MiB/s 31.630 MiB/s]
...
linear_vs_normal_extract/LINEAR / Layers DEBUG | EMPTY/2097152                        
                        time:   [145.19 us 150.13 us 153.69 us]
                        thrpt:  [12.708 GiB/s 13.010 GiB/s 13.453 GiB/s]
...
```

Criterion.rs documentation explains how to get back HTML reports, compare results, etc.

The AES-NI extension is enabled in the compilation toolchain for the supported architectures, leading to massive performance gain for the encryption layer, especially in reading operations. Because the crate `aesni` statically enables it, it might lead to errors if the user's architecture does not support it. It could be disabled at the compilation time, or by commenting the associated section in `.cargo/config`.

# Contributing

We appreciate your help! To contribute, please read our [contributing instructions](.github/CONTRIBUTING.md).
