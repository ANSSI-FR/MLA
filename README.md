[![Build & test](https://github.com/ANSSI-FR/MLA/workflows/Build%20&%20test/badge.svg)](https://github.com/ANSSI-FR/MLA/actions)
[![Cargo MLA](https://img.shields.io/badge/crates.io-mla-red)](
https://crates.io/crates/mla)
[![Documentation MLA](https://img.shields.io/badge/docs.rs-mla-blue)](
https://docs.rs/mla)
[![Cargo Curve25519-Parser](https://img.shields.io/badge/crates.io-curve25519_parser-red)](
https://crates.io/crates/curve25519-parser)
[![Documentation Curve25519-Parser](https://img.shields.io/badge/docs.rs-curve25519_parser-blue)](
https://docs.rs/curve25519-parser)
[![Cargo MLAR](https://img.shields.io/badge/crates.io-mlar-red)](
https://crates.io/crates/mlar)

Multi Layer Archive (MLA)
=

MLA is an archive file format with the following features:

* Support for compression (based on [`rust-brotli`](https://github.com/dropbox/rust-brotli/))
* Support for authenticated encryption with asymmetric keys (AES256-GCM with an ECIES schema over Curve25519, based on [Rust-Crypto](https://github.com/RustCrypto) `aes-ctr` and [DalekCryptography](https://github.com/dalek-cryptography) `x25519-dalek`)
* Effective, architecture agnostic and portable (written entirely in Rust)
* Small memory footprint during archive creation
* Streamable archive creation:
  * An archive can be built even over a data-diode
  * A file can be added through chunks of data, without initially knowing the final size
  * File chunks can be interleaved (one can add the beginning of a file, start a second one, and then continue adding the first file's parts)
* Archive files are seekable, even if compressed or encrypted. A file can be accessed in the middle of the archive without reading from the beginning
* If truncated, archives can be repaired. Files which were still in the archive, and the beginning of the ones for which the end is missing, will be recovered
* Arguably less prone to bugs, especially while parsing an untrusted archive (Rust safety)

Repository
=

This repository contains:

* `mla`: the Rust library implementing MLA reader and writer
* `mlar`: a Rust utility wrapping `mla` for common actions (create, list, extract, ...)
* `curve25519-parser`: a Rust library for parsing DER/PEM public and private Ed25519 keys and X25519 keys (as made by `openssl`)
* `mla-fuzz-afl` : a Rust utility to fuzz `mla`
* `bindings` : bindings for other languages
* `.github`: Continuous Integration needs

Quick command-line usage
=

Here are some commands to use ``mlar`` in order to work with archives in MLA format.

```sh
# Generate an X25519 key pair {key, key.pub} (OpenSSL could also be used)
mlar keygen key

# Create an archive with some files, using the public key
mlar create -p key.pub -o my_archive.mla /etc/os-release /etc/issue

# List the content of the archive, using the private key
mlar list -k key -i my_archive.mla

# Extract the content of the archive into a new directory
# In this example, this creates two files:
# extracted_content/etc/issue and extracted_content/etc/os-release
mlar extract -k key -i my_archive.mla -o extracted_content

# Display the content of a file in the archive
mlar cat -k key -i my_archive.mla /etc/os-release

# Convert the archive to a long-term one, removing encryption and using the best
# and slower compression level
mlar convert -k key -i my_archive.mla -o longterm.mla -l compress -q 11

# Create an archive with multiple recipient
mlar create -p archive.pub -p client1.pub -o my_archive.mla ...
```

`mlar` can be obtained:

* through Cargo: `cargo install mlar`
* using the [latest release](https://github.com/ANSSI-FR/MLA/releases) for supported operating systems


Quick API usage
=

* Create an archive, with compression and encryption:
```rust
use curve25519_parser::parse_openssl_25519_pubkey;
use mla::config::ArchiveWriterConfig;
use mla::ArchiveWriter;

const PUB_KEY: &[u8] = include_bytes!("samples/test_x25519_pub.pem");

fn main() {
    // Load the needed public key
    let public_key = parse_openssl_25519_pubkey(PUB_KEY).unwrap();

    // Create an MLA Archive - Output only needs the Write trait
    let mut buf = Vec::new();
    // Default is Compression + Encryption, to avoid mistakes
    let mut config = ArchiveWriterConfig::default();
    // The use of multiple public keys is supported
    config.add_public_keys(&vec![public_key]);
    // Create the Writer
    let mut mla = ArchiveWriter::from_config(&mut buf, config).unwrap();

    // Add a file
    mla.add_file("filename", 4, &[0, 1, 2, 3][..]).unwrap();

    // Complete the archive
    mla.finalize().unwrap();
}
```
* Add files part per part, in a "concurrent" fashion:
```rust
...
// A file is tracked by an id, and follows this API's call order:
// 1. id = start_file(filename);
// 2. append_file_content(id, content length, content (impl Read))
// 2-bis. repeat 2.
// 3. end_file(id)

// Start a file and add content
let id_file1 = mla.start_file("fname1").unwrap();
mla.append_file_content(id_file1, file1_part1.len() as u64, file1_part1.as_slice()).unwrap();
// Start a second file and add content
let id_file2 = mla.start_file("fname2").unwrap();
mla.append_file_content(id_file2, file2_part1.len() as u64, file2_part1.as_slice()).unwrap();
// Add a file as a whole
mla.add_file("fname3", file3.len() as u64, file3.as_slice()).unwrap();
// Add new content to the first file
mla.append_file_content(id_file1, file1_part2.len() as u64, file1_part2.as_slice()).unwrap();
// Mark still opened files as finished
mla.end_file(id_file1).unwrap();
mla.end_file(id_file2).unwrap();
```
* Read files from an archive
```rust
use curve25519_parser::parse_openssl_25519_privkey;
use mla::config::ArchiveReaderConfig;
use mla::ArchiveReader;
use std::io;

const PRIV_KEY: &[u8] = include_bytes!("samples/test_x25519_archive_v1.pem");
const DATA: &[u8] = include_bytes!("samples/archive_v1.mla");

fn main() {
    // Get the private key
    let private_key = parse_openssl_25519_privkey(PRIV_KEY).unwrap();

    // Specify the key for the Reader
    let mut config = ArchiveReaderConfig::new();
    config.add_private_keys(&[private_key]);

    // Read from buf, which needs Read + Seek
    let buf = io::Cursor::new(DATA);
    let mut mla_read = ArchiveReader::from_config(buf, config).unwrap();

    // Get a file
    let mut file = mla_read
        .get_file("simple".to_string())
        .unwrap() // An error can be raised (I/O, decryption, etc.)
        .unwrap(); // Option(file), as the file might not exist in the archive

    // Get back its filename, size, and data
    println!("{} ({} bytes)", file.filename, file.size);
    let mut output = Vec::new();
    std::io::copy(&mut file.data, &mut output).unwrap();

    // Get back the list of files in the archive:
    for fname in mla_read.list_files().unwrap() {
        println!("{}", fname);
    }
}
```

:warning: Filenames are `String`s, which may contain path separator (`/`, `\`, `..`, etc.). Please consider this while using the API, to avoid path traversal issues.

Using MLA with others languages
=

Bindings are available for:

* [C/CPP](bindings/C/README.md)

Design
=

As the name spoils it, an MLA archive is made of several, independent, layers. The following section introduces the design ideas behind MLA. Please refer to [FORMAT.md](FORMAT.md) for a more formal description.

Layers
-

Each layer acts as a *Unix PIPE*, taking bytes in input and outputting in the next
layer.
A layer is made of:

* a `Writer`, implementing the `Write` trait. It is responsible for emitting bytes while creating a new archive
* a `Reader`, implementing both `Read` and `Seek` traits. It is responsible for reading bytes while reading an archive
* a `FailSafeReader`, implementing only the `Read` trait. It is responsible for reading bytes while repairing an archive

Layers are made with the *repairable* property in mind. Reading them must never need information from the footer, but a footer can be used to optimize the reading. For example, accessing a file inside the archive can be optimized using the footer to seek to the file beginning, but it is still possible to get information by reading the whole archive until the file is found.

Layers are optional, but their order is enforced. Users can choose to enable or disable them.
Current order is the following:

1. *File storage abstraction (not a layer)*
1. Raw layer (mandatory)
1. Compression layer
1. Encryption layer
1. Position layer (mandatory)
1. *Stored bytes*

Overview
-

```
+----------------+-------------------------------------------------------------------------------------------------------------+
| Archive Header |                                                                                                             | => Final container (File / Buffer / etc.)
+------------------------------------------------------------------------------------------------------------------------------+
                 +-------------------------------------------------------------------------------------------------------------+
                 |                                                                                                             | => Raw layer
                 +-------------------------------------------------------------------------------------------------------------+
                 +-----------+---------+------+---------+------+---------------------------------------------------------------+
                 | E. header | Block 1 | TAG1 | Block 2 | TAG2 | Block 3 | TAG3 | ...                                          | => Encryption layer
                 +-----------+---------+------+---------+------+---------------------------------------------------------------+
                             |         |      |         |      |         |      |                                              |
                             +-------+--      --+-------       -----------      ----+---------+------+---------+ +-------------+
                             | Blk 1 |          | Blk 2                             | Block 3 | ...  | Block n | |    Footer   | => Compression Layer
                             +-------+--      --+-------       -----------      ----+---------+------+---------+ +-------------+
                            /         \                                                             /           \
                           /           \                                                           /             \
                          /             \                                                         /               \
                         +-----------------------------------------------------------------------------------------+
                         |                                                                                         |             => Position layer
                         +-----------------------------------------------------------------------------------------+
                         +-------------+-------------+-------------+-------------+-----------+-------+-------------+
                         | File1 start | File1 data1 | File2 start | File1 data2 | File1 end |  ...  | Files index |             => Files information and content
                         +-------------+-------------+-------------+-------------+-----------+-------+-------------+
```

Layers description
-

### Raw Layer

Implemented in `RawLayer*` (i.e. `RawLayerWriter`, `RawLayerReader` and `RawLayerFailSafeReader`).

This is the simplest layer. It is required to provide an API between layers and
final output worlds. It is also used to keep the position of data's start.

### Position Layer

Implemented in `PositionLayer*`.

Similar to the `RawLayer`, this is a very simple, utility, layer. It keeps
track of how many bytes have been written to the sub-layers.

For instance, it is required by the file storage layer to keep track of the
position in the flow of files, for indexing purpose.

### Encryption Layer

Implemented in `EncryptionLayer*`.

This layer encrypts data using the symmetric authenticated encryption with associated data (AEAD) algorithm *AES-GCM 256*, and encrypts the symmetric key using an ECIES schema based on *Curve25519*.

The ECIES schema is extended to support multiple public keys: a public key is generated and then used to perform `n` Diffie-Hellman exchanges with the `n` users public keys. The generated public key is also recorded in the header (to let the user replay the DH exchange). Once derived according to ECIES, we get `n` keys. These keys are then used to encrypt a common key `k`, and the resulting `n` ciphertexts are stored in the layer header.
This key `k` will later be used for the symmetric encryption of the archive.

In addition to the key, a nonce (8 bytes) is also generated per archive. A fixed associated data is used.

The generation uses `OsRng` from crate `rand`, that uses `getrandom()` from crate `getrandom`. `getrandom` provides implementations for many systems, listed [here](https://docs.rs/getrandom/0.1.14/getrandom/).
On Linux it uses the `getrandom()` syscall and falls back on `/dev/urandom`.
On Windows it uses the `RtlGenRandom` API (available since Windows XP/Windows Server 2003).

In order to be "better safe than sorry", a `ChaChaRng` is seeded from the
bytes generated by `OsRng` in order to build a CSPRNG(Cryptographically Secure PseudoRandom Number Generator). This `ChaChaRng` provides the actual bytes used in keys and nonces generations.

The layer data is then made of several encrypted blocks, each with a constant size except for the last one. Each block is encrypted with an IV including the base nonce and a counter. This construction is close to the [STREAM](https://github.com/miscreant/meta/wiki/STREAM) one, except for the `last_block` bit. The choice has been made not to use it, because:
* At the time of writing, the archive writer does not know that the current block is the last one. Therefore, it cannot use a specific IV. To circumvent it, a dummy footer block has to be added at the end, leading to additional complexity for last block detection
* In STREAM, the `last_block` bit is used to prevent undetected truncation. In MLA, it is already the role of the `EndOfArchiveData` tag at the file layer level

Thus, to seek-and-read at a given position, the layer decrypts the block containing this position, and verifies the tag before returning the decrypted data. 

The authors decided to use elliptic curve over RSA, because:
* No ready-for-production Rust-based libraries have been found at the date of writing
* A security-audited Rust library already exists for Curve25519
* Curve25519 is widely used and [respects several criteria](https://safecurves.cr.yp.to/)
* Common arguments, such as the ones of [Trail of bits](https://blog.trailofbits.com/2019/07/08/fuck-rsa/)

AES-GCM is used because it is one of the most commonly used AEAD algorithms and using one avoids a whole class of attacks. In addition, it lets us rely on hardware acceleration (like AES-NI) to keep reasonable performance.

External cryptographic libraries have been reviewed:
* RustCrypto AES-GCM, reviewed by [NCC Group](https://research.nccgroup.com/wp-content/uploads/2020/02/NCC_Group_MobileCoin_RustCrypto_AESGCM_ChaCha20Poly1305_Implementation_Review_2020-02-12_v1.0.pdf)
* Dalek cryptography library, reviewed by [Quarkslab](https://blog.quarkslab.com/security-audit-of-dalek-libraries.html)


### Compression Layer

Implemented in `CompressionLayer*`.

This layer is based on the Brotli compression algorithm ([RFC 7932](https://tools.ietf.org/html/rfc7932)).
Each 4MB of cleartext data is stored in a separately compressed chunk.

This algorithm, used with a *window* of size 1, is able to read each chunk and
stop when 4MB of cleartext has been obtained. It is then reset, and starts
decompressing the next chunk.

To speed up the decompression, and to make the layer seekable, a footer is used. It
saves the compressed size. Knowing the decompressed size, a seek at a cleartext
position can be performed by seeking to the beginning of the correct compressed
block, then decompressing the first bytes until the desired position is reached.

The footer is also used to allow for a wider *window*, enabling faster
decompression. Finally, it also records the size of the last block, to compute the
frontier between compressed data and the footer.

The 4MB size is a trade-off between a better compression (higher value) and faster seeking (smaller value). It has been chosen based on benchmarking of representative data. Better compression can also be achieved by setting the compression quality parameter to a higher value (leading to a slower process).

File storage
-

Files are saved as series of archive-file blocks. A first special type of block
indicates the start of a file, along with its filename and a file ID. A second special type of
block indicates the end of the current file.

Blocks contain file data, prepended with the current block size and the corresponding file ID. Even if the
format handles streaming files, the size of a file chunk must be known before
writing it. The file ID enables blocks from different files to be interleaved.



The file-ending block marks the end of data for a given file, and includes its
full content SHA256. Thus, the integrity of files can be checked, even on repair
operations.

The layer footer contains for each file its size, its ending block offset and an index of its block locations. Block location index enables direct access. The ending block offset enables fast hash retrieval and the file size eases the conversion to formats needing the size of the file before the data, such as Tar.





If this footer is unavailable, the archive is read from the beginning to recover
file information.


API Guidelines
-

The archive format provides, for each file:
* a filename, which is an unicode String
* data, which are a stream of bytes

A few metadata are also computed, such as:
* the file size
* the SHA256 hash of the content

No additional metadata (permissions, ownership, etc.) are present, and would probably not be added unless very strong arguments are given. The goal is to keep the file format simple enough, and to leave the complexity to the code using it. Things such as permissions, ownership, etc. are hard to guarantee over several OSes and filesystems; and lead to higher complexity, for example in tar. For the same reasons, `/` or `\` do not have any significance in filename; it is up to the user to choose how to handle them (are there namespaces? directories in Windows style? etc.).

If one still wants to have associated metadata for its own use case, the recommended way is to embed an additional file in the archive containing the needed metadata.

Additionally, the file format is expected to change slightly in the future, to keep an easier backward compatibility, or, at least, version conversion, and simple support.

The API provided by the library is then very simple:
* Add a file
* Start / Add file chunk / End
* List files in the archive (unordered)
* Get a file
* Get a file hash

As the need for a less general API might appear, helpers are available in `mla::helpers`, such as:
* `StreamWriter`: Provides a `Write` interface on a `ArchiveWriter` file (could be used when even file chunk sizes are not known, likely with `io::copy`)
* `linear_extract`: Extract an Archive linearly. Faster way to extract a whole archive, by reducing the amount of costly `seek` operations


Is a new format really required?
-

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
* any archive + `age`: [age](https://age-encryption.org/) could be used jointly with an archive format to provide encryption, but would likely lack integration with the inner archive format
* Backup formats are generally written to avoid things such as duplication,
  hence their need to keep bigger structures in memory, or their not being 
  streamable

Tweaking these formats would likely have resulted in similar properties. The
choice has been made to keep a better control over what the format is capable 
of, and to (try to) KISS.

Testing
=

The repository contains:

* unit tests (for `mla` and `curve25519-parser`), testing separately expected behaviors
* integration tests (for `mlar`), testing common scenarios, such as `create`->`list`->`to-tar`, or `create`->truncate->`repair`
* benchmarking scenarios (for `mla`)
* [AFL](https://lcamtuf.coredump.cx/afl/) scenario (for `mla`)
* A [committed archive in format v1](samples/archive_v1.mla), to ensure backward readability over time

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

Fuzzing
-

A fuzzing scenario made with [afl.rs](https://github.com/rust-fuzz/afl.rs) is available in `mla-fuzz-afl`.
The scenario is capable of:
* Creating archives with interleaved files, and different layers enabled
* Reading them to check their content
* Repairing the archive without truncation, and verifying it
* Altering the archive raw data, and ensuring reading it does not panic (but only fail)
* Repairing the altered archive, and ensuring the recovery doesn't fail (only reports detected errors)

To launch it:
1. produce initial samples by uncommenting `produce_samples()` in `mla-fuzz-afl/src/main.rs`
```sh
cd mla-fuzz-afl
# ... uncomment `produces_samples()` ...
mkdir in
mkdir out
cargo run
```
2. build and launch AFL
```sh
cargo afl build
cargo afl run -i in -o out ../target/debug/mla-fuzz-afl
```

If you have found crashes, try to replay them with either:
* Peruvian rabbit mode of AFL: `cargo afl run -i - -o out -C ../target/debug/mla-fuzz-afl`
* Direct replay: `../target/debug/mla-fuzz-afl < out/crashes/crash_id`
* Debugging: uncomment the "Replay sample" part of `mla-fuzz-afl/src/main.rs`, and add `dbg!()` when it's needed

:warning: The stability is quite low, likely due to the process used for the scenario (deserialization from the data provided by AFL) and variability of inner algorithms, such as brotli. Crashes, if any, might not be reproducible or due to the `mla-fuzz-afl` inner working, which is a bit complex (and therefore likely buggy). One can comment unrelevant parts in `mla-fuzz-afl/src/main.rs` to ensure a better experience.
