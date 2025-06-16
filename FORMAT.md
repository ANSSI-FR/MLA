Versioning
=

Relation between the MLA version and the file format version:

| MLA Version | Supported file format |
|-------------|-----------------------|
| 2.0         | 2                     |

MLA file format v2
=

This document introduces the MLA file format in its current version, v2.
For a more comprehensive introduction of the ideas behind it, please refer to [README.md](README.md).

Structures marked with #[bincode] below are encoded with [bincode](https://docs.rs/bincode/2.0.0/bincode/index.html) in version 2 with fixed-size integer encoding in little endian.

MLA Header
-

```rust
struct MLA {
    // MLA magic
    magic: [u8; 3] = b"MLA",
    // Current file format version
    #[little_endian]
    format_version: u32 = 2,
    #[bincode]
    struct ArchivePersistentConfig {
        // bitfield indicating which Layer is enabled
        // - ENCRYPT = 0b0000_0001;
        // - COMPRESS = 0b0000_0010;
        layers_enabled: Layers,
        // Optional field, if "encrypt" layer is enabled
        encrypt: Option<struct EncryptionPersistentConfig {
            // HPKE with multi recipient
            recipients: Vec<struct HybridRecipientEncapsulatedKey {
                /// "Ciphertext" for ML-KEM 1024
                ct_ml: [u8; 1568],
                /// "Ciphertext" for DH-KEM (actually an ECC ephemeral public key)
                ct_ecc: [u8; 32],
                /// Wrapped (encrypted) version of the main shared secret
                /// - Algorithm: AES-256-GCM
                /// - Key: per-recipient hybrid shared secret
                /// - Nonce: per-recipient
                wrapped_ss: [u8; 32],
                /// Associated tag
                tag: [u8; 16],
            }>,
            key_commitment: struct KeyCommitmentAndTag {
                key_commitment: [u8; 64],
                tag: [u8; 16],
            }
        }>,
    },
    data: [u8],
}
```

The content of the `data` field then depend on what layers are enabled, in the following order:
1. Encryption layer
2. Compression layer
3. Actual archive entries

### Example

For example, on [samples/archive_v2.mla](samples/archive_v2.mla):
* `4d 4c 41`: `magic`
* `02 00 00 00`: `format_version`, set to 2 for archive format v2
* `03`: `layers`, with `ENCRYPT | COMPRESS = 0b11`, i.e. Encryption and Compression layers are enabled
* `01`: `EncryptionPersistentConfig` is present, as expected because the corresponding layer ("encrypt") is enabled
* `01 00 00 00 00 00 00 00` : there is one recipient
* `a6 (.. 1568-bytes length ..) b8`: `recipients[0].mlkem_encapsulated_key`
* `37 (.. 32-bytes length ..) 00`: `recipients[0].ecc_encapsulated_key`
* `41 (.. 32-bytes length ..) b3`: `recipients[0].encrypted_shared_secret`
* `83 (.. 16-bytes length ..) 51`: `recipients[0].encrypted_shared_secret_tag`
* `08 (.. 64-bytes length ..) df`: `encrypted_key_commitment`
* `f3 (.. 16-bytes length ..) 26`: `encrypted_key_commitment_tag`
* `a3 until EOF`: `data`

Encryption layer
-

From the information in the header, the cryptographic material is recovered as described in `CRYPTO.md`. This enables decrypting following content.

`data` is a contiguous list of:
```rust
struct DataBlock {
    encrypted_content: [u8; 128 * 1024],
    tag: [u8; 16],
}
```

followed by one:
```rust
struct FinalBlock {
    encrypted_content: [u8; 10],
    tag: [u8; 16],
}
```

The last `DataBlock` is an exception: `encrypted_content` might be smaller. Its size is then `((data.len() - sizeof(FinalBlock)) % sizeof(DataBlock)) - 16`.

To protect from a truncation attack, before using an archive, it must be checked that `FinalBlock.tag` is correct and that `msg_final` is `FINALBLOCK`.

Formats for DER keys (thus PEM keys too) are documented in comments of functions `parse_mlakey_privkey_der` and `parse_mlakey_pubkey_der`.

### Example

For example, with the private key [samples/test_mlakey_archive_v2.der](samples/test_mlakey_archive_v2.der):
* The MLA private key ASN.1 DER encoded data is a X25519 private key followed by a ML-KEM 1024 private key
* MLA private key X25519 part: `5d 58 a8 7c 9c 69 ba 67 4a f9 d3 89 23 76 c9 5e d8 eb 08 cf 09 cd 61 5c 07 28 99 c3 79 45 96 a9`
* MLA private key `mlkem_dk` (`dk_pke||ek||h||z`) part: `21 f0 (.. 3168-bytes length ..) de 3e`

This gives with [samples/archive_v2.mla](samples/archive_v2.mla): 
* `ecc_shared_secret`: `40 1c 7f b9 ba 4a d3 7c 5a 8f a9 7a 6f b4 02 57 22 d6 e9 b2 66 2c 02 cd eb d0 f4 81 0c 14 16 00`
* `mlkem_shared_secret`: `6a 92 fa 89 e2 30 57 19 eb 39 52 46 24 06 de 65 30 61 b8 f6 bb 6e 61 63 3c b3 99 d5 f6 a3 95 d0`
* `combined_shared_secret`: `ec f2 64 11 18 2e 19 0a 3e da bf 55 51 5f 51 0e 85 ed 3c 66 78 59 f5 7d 78 44 b9 96 41 a1 57 1f`
* `Per-Recipient Hybrid KEM HPKE base_nonce`: `cb 7e 1d 35 29 c1 92 a2 71 03 6c 71`
* `Per-Recipient Hybrid KEM HPKE key`: `8c 22 67 a9 65 4b d4 c1 45 42 6b e9 4e f1 94 93 d5 e8 ae 83 c2 dd 65 62 a3 82 fa d0 b9 95 d1 79`
* `Per-Recipient Hybrid KEM decapsulated key`: `41 14 54 34 3b 09 a9 cd df d7 f0 83 46 63 35 dc f4 89 4b 12 46 06 81 68 6d 1f d0 0e 11 63 3a b3` 
* `Multi-Recipient Hybrid KEM HPKE base_nonce`: `df d3 f3 74 d1 0e b9 1f 31 ba 6c 09`
* `Multi-Recipient Hybrid KEM HPKE key`: `8a a1 b7 a7 ad 5d 8d 07 ae 97 27 93 d5 5b 45 d9 ed dc b3 30 91 93 88 ce f1 19 63 78 0d 32 b0 0b`

These last two elements are those with which HPKE is setup to do AES-256-GCM decryption of the rest of the archive.

* Now, the decryption process can be started. `data` length (`27273=29044-(sizeof(header)=1745)-(sizeof(FinalBlock)=26)`) being smaller than `sizeof(DataBlock)`, the `encrypted_content` is 27257-bytes long. The corresponding tag is `2e .. 16` (which corresponds to the last 16-bytes of `data` before the `FinalBlock` ).

The first decrypted bytes are `9b ff ff 3f 67 54 af 01 03 e7 35 a9 87 88 82 3e ...`.

In the next section, `data` is now the decrypted content (as if the encryption layer was absent).

Compression
-

```rust
struct CompressionLayer {
    // Compressed data, explained below
    compressed_data: [u8],
    // Footer
    #[bincode]
    sizes_info: struct SizesInfo {
        /// Ordered list of chunk compressed sizes; only set at initialization
        compressed_sizes: Vec<u32>,
        /// Last block uncompressed size
        last_block_size: u32,
    }
    // Size of the serialized `sizes_info`
    #[little_endian]
    sizes_info_length: u32
}
```

The compression layer footer information is retrieved by first reading the value of `sizes_info_length` at the end of `data`, then reading `sizes_info_length`-bytes at the end of `data` minus 4 bytes.

`compressed_data` is a concatenation of `compressed_block_i` blocks of size `compressed_sizes[i]`.

A `compressed_block_i` is a [brotli compressed](https://tools.ietf.org/html/rfc7932) block. Its uncompressed data size is `4 * 1024 * 1024`-bytes, except for the last block (`last_block_size`).  This format already brings necessary data for decompression, such as the quality level used.

The resulting data is the concatenation of all decompressed `compressed_block_i`.

### Example

For example, on [samples/archive_v2.mla](samples/archive_v2.mla), after decryption:
* Reading from the end of `data` leads to `sizes_info_length = 24`
* The corresponding `SizesInfo` is:
```rust
SizesInfo {
    compressed_sizes: [
        13333,
        259,
        13637,
    ],
    last_block_size: 3209403,
}
```

It indeed corresponds to the size of `data`: `data.len() = 27257 = 13333 + 259 + 13637 + 24 + 4`. The decompressed size is then `decompressed.len() = 2 * (4 * 1024 * 1024) + 3209403`.

* Each block can now be decompressed

The first decompressed bytes are `00 00 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 73 69 6d 70 6c 65 01 00 00 00 00 00 00 00 00`.

In the next section, `data` is now the decompressed content (as if the compression layer was absent).

Entries names
-

```rust
#[bincode]
struct EntryName {
    name: Vec<u8>
}
````

Each archive Entry as an associated name. An EntryName is a nonempty sequence of bytes (maximum length of 65536). It may be interpreted as arbitrary bytes or as a file path.
If it is to be interpreted as a file path, the underlying bytes must consist of ASCII slash separated components and not begin with a slash.
The rules for each component are:
* must not be empty
* must not contain any ASCII NUL byte
* must not be ASCII dot
* must not be two ASCII dots

If it is to be interpreted as a Windows file path, in addition to previous rules:
* No byte should be an ASCII backslash (separators are represented by an ASCII slash).
* The eventual second byte of the whole path should not be an ASCII colon (`:`).
* Every component must be encoded as UTF-8.

Even if respecting these rules, the OS may see the resulting path as invalid.

Actual archive entries data
-

```rust
struct ArchiveContent {
    // Data content, explained below
    entry_data: [u8]
    // Footer
    #[bincode]
    struct ArchiveFooter {
        // EntryName -> Corresponding EntryInfo
        entries_info: Vec<(EntryName, struct EntryInfo {
            // Offsets of continuous chunks of `ArchiveEntryBlock`
            offsets: Vec<u64>,
            // Size of the `entry_data`, in bytes
            size: u64,
            // Offset of the ArchiveEntryBlock::EndOfEntry
            eof_offset: u64,
        })>,
    },
    // Size of the serialized `ArchiveFooter`
    #[little_endian]
    archive_footer_length: u64
}
```

The archive footer information is optionaly retrieved by first reading the value of `archive_footer_length` at the end of `data`, then reading `archive_footer_length`-bytes at the end of `data` minus 8 bytes.

`entry_data` is the concatenation of all `ArchiveEntryBlock`s. Each block starts with a `u8` corresponding to the block type:
```rust
enum ArchiveEntryBlockType {
    EntryStart = 0x00,
    EntryContent = 0x01,

    EndOfArchiveData = 0xFE,
    EndOfEntry = 0xFF,
}
```

Then, depending on the block type:
```rust
struct EntryStart {
    // entry unique ID in the archive
    #[little_endian]
    id: u64,
    // entry name
    name: EntryName
}

struct EntryContent {
    // entry unique ID in the archive
    #[little_endian]
    id: u64,
    // Length of the block_data
    #[little_endian]
    length: u64,
    // Content
    block_data: [u8; length]
}

struct EndOfEntry {
    // Entry unique ID in the archive
    #[little_endian]
    id: u64,
    // SHA-256 of the entry content
    hash: [u8; 32]
}

struct EndOfArchiveData {}
```

An entry `entry_i` in the archive always starts with an `EntryStart`, giving its name and unique ID.

Let `content_i` be the content of `entry_i`. It starts empty.

Each time a `EntryContent` is encountered, the corresponding `block_data` is appended to `content_i`.

Once the `EndOfEntry` for `entry_i` is reached, the entry is completely read. Its content SHA-256 hash can be verified with the `EndOfEntry.hash`.

Between the last `EndOfEntry` block and the beginning of the `ArchiveFooter`, there is the only `EndOfArchiveData` block. It is used in the repair process, to correctly separate the actual archive data from the footer.

As blocks from different entries can be interleaved, the `entries_info.offsets` are the offsets in `entry_data` of blocks for the same entry.

For instance, if the blocks are:
```
Off0: [EntryStart ID 1]
Off1: [EntryStart ID 2]
Off2: [EntryContent ID 1]
Off3: [EntryContent ID 1]
Off4: [EntryContent ID 2]
Off5: [EndOfEntry ID 1]
...
```

The `offsets` for the entry with ID 1 will be ̀`Off0`, `Off2`, `Off5`.
Additionally, for faster `hash` retrieval, `entries_info.eof_offset` is the offset of the `EndOfEntry` block for the corresponding entry. In this example, `eof_offset = Off5` for ID 1.

Finally, the `entries_info.size` is the size in bytes of the corresponding entry content.

For reproducibility, the `entries_info` `Vec` is sorted by entry name (lexicographically by bytes values) before being serialized.

### Example

For example, on [samples/archive_v2.mla](samples/archive_v2.mla), after decryption and decompression:
* Reading from the end of `data` leads to `archive_footer_length = 18444`
* The corresponding `ArchiveFooter` is (observed order may be different if deserialized into a HashMap):
```rust
ArchiveFooter {
    entries_info: {
        "big": EntryInfo {
            offsets: [
                1074403,
            ],
            size: 10485760,
            eof_offset: 11560200,
        },
        "file_0": EntryInfo {
            offsets: [
                337,
                19122,
                1074362,
            ],
            size: 4096,
            eof_offset: 1074362,
        },
        ...
        "simple": EntryInfo {
                        offsets: [
                            0,
                        ],
                        size: 256,
                        eof_offset: 296,
                    },
    }
}
```

Let's start reading the first entry of the archive. For easier reading, here is an excerpt of the first 400 bytes of `data`:
```
0000  00 00 00 00 00 00 00 00 00 06 00 00 00 00 00 00   ................
0010  00 73 69 6d 70 6c 65 01 00 00 00 00 00 00 00 00   .simple.........
0020  00 01 00 00 00 00 00 00 00 01 02 03 04 05 06 07   ................
0030  08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17   ................
0040  18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27   ........ !"#$%&'
0050  28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37   ()*+,-./01234567
0060  38 39 3a 3b 3c 3d 3e 3f 40 41 42 43 44 45 46 47   89:;<=>?@ABCDEFG
0070  48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57   HIJKLMNOPQRSTUVW
0080  58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65 66 67   XYZ[\]^_`abcdefg
0090  68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77   hijklmnopqrstuvw
00a0  78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87   xyz{|}~.........
00b0  88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97   ................
00c0  98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7   ................
00d0  a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7   ................
00e0  b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7   ................
00f0  c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7   ................
0100  d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7   ................
0110  e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7   ................
0120  f8 f9 fa fb fc fd fe ff ff 00 00 00 00 00 00 00   ................
0130  00 40 af f2 e9 d2 d8 92 2e 47 af d4 64 8e 69 67   .@.......G..d.ig
0140  49 71 58 78 5f bd 1d a8 70 e7 11 02 66 bf 94 48   IqXx_...p...f..H
0150  80 00 01 00 00 00 00 00 00 00 06 00 00 00 00 00   ................
0160  00 00 66 69 6c 65 5f 30 00 02 00 00 00 00 00 00   ..file_0........
0170  00 06 00 00 00 00 00 00 00 66 69 6c 65 5f 31 00   .........file_1.
0180  03 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00   ................
```

* `00`: mark a `EntryStart` block
* `00 00 00 00 00 00 00 00`: entry ID is 0
* `06 00 00 00 00 00 00 00`: name length, in bytes, is 6
* `73 69 6d 70 6c 65`: the name is "simple"
* `01`: mark a `EntryContent` block
* `00 00 00 00 00 00 00 00`: corresponding entry ID is 0 (ie, the entry "simple")
* `00 01 00 00 00 00 00 00`: this block contains 0x100 bytes of data
* `00 .. (256-bytes long) .. ff`: actual 256 first bytes of "simple"
* `ff`: mark a `EndOfEntry` block
* `00 00 00 00 00 00 00 00`: entry ID is 0. The entry "simple" has been fully recovered
* `40 .. (32-bytes long) .. 80`: SHA256 hash of the entry "simple" content, ie `SHA256(00 01 02 .. FE FF)`

Here, the entry "simple" has been fully recovered. If one continues, there are:
* A `EntryStart` block for the entry "file_0" with ID 1
* A `EntryStart` block for the entry "file_1" with ID 2
* A `EntryStart` block with ID 3 for a name of length 6, incomplete in the excerpt
