Versioning
=

Relation between the MLA version and the file format version:

| MLA Version | Supported file format |
|-------------|-----------------------|
| 1.0         | 1                     |

MLA file format v1
=

This document introduces the MLA file format in its current version, v1.
For a more comprehensive introduction of the ideas behind it, please refer to [README.md](README.md).

Please refer to the code for the detail of structures.

MLA Header
-

```rust
struct MLA {
    // MLA magic
    magic: [u8; 3] = b"MLA",
    // Current file format version
    #[little_endian]
    format_version: u32 = 1,
    #[bincode]
    struct ArchivePersistentConfig {
        // bitfield indicating which Layer is enabled
        // - ENCRYPT = 0b0000_0001;
        // - COMPRESS = 0b0000_0010;
        layers_enabled: Layers,
        // Optional field, if "encrypt" layer is enabled
        encrypt: Option<
            struct EncryptionPersistentConfig {
                // ECIES with multi recipient
                multi_recipient: struct MultiRecipientPersistent {
                    /// Ephemeral public key
                    public: [u8; 32],
                    encrypted_keys: Vec<struct KeyAndTag {
                        // Encrypted Key, for each one recipient
                        key: [u8; 32],
                        // Associated tag
                        tag: [u8; 16],
                    }>,
                },
                // nonce generated per-archive and used in the encryption process
                nonce: [u8; 8],
            }
        >,
    },
    data: [u8],
}
```

The content of the `data` field then depend on what layers are enabled, in the following order:
1. Encryption layer
2. Compression layer
3. Actual archive files data

### Example

For example, on `samples/archive_v1.mla`:
* `4d 4c 41`: `magic`
* `01 00 00 00`: `format_version`, set to 1 for archive format v1
* `03`: `layers`, with `ENCRYPT | COMPRESS = 0b11`, ie Encryption and Compression layers are enabled
* `01`: `EncryptionPersistentConfig` is present, as expected because the corresponding layer ("encrypt") is enabled
* `97 (.. 32-bytes length ..) 5a`: `multi_recipient.public`
* `01 00 00 00 00 00 00 00`: one `KeyAndTag` in `multi_recipient.encrypted_keys`
* `99 (.. 32-bytes long ..) 59`: `encrypted_keys[0].key`
* `34 (.. 16-bytes long ..) 7d`: `encrypted_keys[0].tag`
* `0e (.. 8-bytes long ..) f4`: `nonce`
* `56 until EOF`: `data`

Encryption layer
-

From the information in the header, the `nonce` is recovered.

To recover the decryption key `kd`, using:
* a candidate Ed25519 key-pair `cpub`, `cpriv`
* the ephemeral public key in the archive `apub = multi_recipient.public`
* registered recipient number `i` (from `multi_recipient.encrypted_keys`): `key_i` and associated `tag_i`

The following operations are made:
1. Derives the Diffie-Hellman key `dhkey = HKDF(SHA-256, D-H(cpriv, apub), "KEY DERIVATION")`
2. For each possible recipient:
    1. Decrypt and compute tag: `possible_key, tag = AES-GCM-256(dhkey, nonce="ECIES NONCE0", associated_data="").decrypt(key_i)`
    2. Compare the resulting tag `tag` with `tag_i`. If they are the same, `kd = possible_key`

Once the decryption key `kd` and `nonce` have been retrieved, `data` can be decrypted.

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

Each content `content_i` (and associated `db_tag_i`) of `DataBlock` number `i` is decrypted through `msg_i, tag_i = AES-GCM-256(kd, nonce=(nonce . u32.as_big_endian(i)), associated_data="")`.

The block is then verified by comparing `tag_i` with `db_tag_i`.

The concatenation of `msg_i` forms the inner `data`.

`FinalBlock` is decrypted through `msg_final, tag_final = AES-GCM-256(kd, nonce=(nonce . u32.as_big_endian(i)), associated_data="FINALAAD")`. To protect from a truncation attack, before using an archive, it must be checked that `tag_final` equals to `FinalBlock.tag` value and that `msg_final` is `FINALBLOCK`.

### Example

For example, on `samples/archive_v1.mla` with the private key `samples/testpub25519.pem`:
* The ASN1 data contained in `testpub25519.pem` is a 32-bytes long key `asn1_key = 34 .. CE`
* This corresponds to a private Ed25519 key `cpriv = clamping(SHA-256(asn1_key))`, with `clamping` being the operation of twiddling a few bits (`scalar[0] &= 0xf8`, `scalar[31] &= 0x7f`, `scalar[31] |= 0x40`).

`cpriv = f0 6d f7 24 61 4b 61 3a 4b 88 f6 04 dd 6e 30 a1 4d e5 89 63 69 69 c6 51 67 a8 3d ea 9c cb c6 4b`

* Computing `dhkey` results in `dhkey = d3 11 3e 86 98 6f 84 9e ed 8f 42 7a 7b dd f8 e0 5f 43 f0 47 f1 3c 6d 19 11 b5 5e d8 e9 36 09 47`
* Decrypting the corresponding key leads to the correct tag (`34 .. 7d`), the obtained `kd = msg` is then valid.

`kd = b7 fc 48 ec c3 90 12 3a a7 1b c6 9d 10 74 36 de bf 27 aa 68 0e 6c c8 10 cb 9c a1 ce 6e ba d2 22`

* Now, the decryption process can be started. `data` length (28509) being smaller than `sizeof(DataBlock)`, the `encrypted_content` is 28493-bytes long. The corresponding tag is `83 .. dd` (which corresponds to the last 16-bytes of `data`, also corresponding here to the last 16-byte of the archive).

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

For example, on [samples/archive_v1.mla](samples/archive_v1.mla), after decryption:
* Reading from the end of `data` leads to `sizes_info_length = 24`
* The corresponding `SizesInfo` is:
```rust
SizesInfo {
    compressed_sizes: [
        13333,
        259,
        14873,
    ],
    last_block_size: 3209399,
}
```

It indeed corresponds to the size of `data`: `data.len() = 28493 = 13333 + 259 + 14873 + 24 + 4`. The decompressed size is then `decompressed.len() = 2 * (4 * 1024 * 1024) + 3209399`.

* Each block can now be decompressed

The first decompressed bytes are `00 00 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 73 69 6d 70 6c 65 01 00 00 00 00 00 00 00 00`.

In the next section, `data` is now the decompressed content (as if the compression layer was absent).

Actual archive files data
-

```rust
struct ArchiveContent {
    // Data content, explained below
    file_data: [u8]
    // Footer
    #[bincode]
    struct ArchiveFooter {
        // Filename -> Corresponding FileInfo
        files_info: HashMap<String, struct FileInfo {
            // Offsets of continuous chunks of `ArchiveFileBlock`
            offsets: Vec<u64>,
            // Size of the file, in bytes
            size: u64,
            // Offset of the ArchiveFileBlock::EndOfFile
            eof_offset: u64,
        }>,
    },
    // Size of the serialized `ArchiveFooter`
    #[little_endian]
    archive_footer_length: u32
}
```

The archive footer information is retrieved by first reading the value of `archive_footer_length` at the end of `data`, then reading `archive_footer_length`-bytes at the end of `data` minus 4 bytes.

`file_data` is the concatenation of all `ArchiveFileBlock`s. Each block starts with a `u8` corresponding to the block type:
```rust
enum ArchiveFileBlockType {
    FileStart = 0x00,
    FileContent = 0x01,

    EndOfArchiveData = 0xFE,
    EndOfFile = 0xFF,
}
```

Then, depending on the block type:
```rust
struct FileStart {
    // File uniq ID in the archive
    #[little_endian]
    id: u64,
    // Length of the filename
    #[little_endian]
    length: u64,
    // UTF-8 encoded filename
    filename: [u8; length]
}

struct FileContent {
    // File uniq ID in the archive
    #[little_endian]
    id: u64,
    // Length of the block_data
    #[little_endian]
    length: u64,
    // Content
    block_data: [u8; length]
}

struct EndOfFile {
    // File uniq ID in the archive
    #[little_endian]
    id: u64,
    // SHA-256 of the file content
    hash: [u8; 32]
}

struct EndOfArchiveData {}
```

A file `file_i` in the archive always starts with a `FileStart`, giving its filename and uniq ID.
Let `content_i` be the content of `file_i`. It starts empty.

Each time a `FileContent` is encountered, the corresponding `block_data` is appended to `content_i`.

Once the `EndOfFile` for `file_i` is reached, the file is completely read. Its content SHA-256 hash can be verified with the `EndOfFile.hash`.

Between the last `EndOfFile` block and the beginning of the `ArchiveFooter`, there is the only `EndOfArchiveData` block. It is used in the repair process, to correctly separate the actual archive data from the footer.

As blocks from different files can be interleaved, the `files_info.offsets` corresponds to offsets in `file_data` of blocks for the same file.

For instance, if the blocks are:
```
Off0: [FileStart ID 1]
Off1: [FileStart ID 2]
Off2: [FileContent ID 1]
Off3: [FileContent ID 1]
Off4: [FileContent ID 2]
Off5: [EndOfFile ID 1]
...
```

The `offsets` for the file with ID 1 will be ̀`Off0`, `Off2`, `Off5`.
Additionally, for faster `hash` retrieval, `files_info.eof_offset` is the offset of the `EndOfFile` block for the corresponding file. In this example, `eof_offset = Off5` for ID 1.

Finally, the `files_info.size` is the size in bytes of the corresponding file content.

### Example

For example, on [samples/archive_v1.mla](samples/archive_v1.mla), after decryption and decompression:
* Reading from the end of `data` leads to `archive_footer_length = 18444`
* The corresponding `ArchiveFooter` is:
```rust
ArchiveFooter {
    files_info: {
        "file_190": FileInfo {
            offsets: [
                4977,
                9812,
                794561,
                1066572,
            ],
            size: 4096,
            eof_offset: 1066572,
        },
        "file_38": FileInfo {
            offsets: [
                1239,
                17260,
                174249,
                1072804,
            ],
            size: 4096,
            eof_offset: 1072804,
        },
        ...
        "simple": FileInfo {
                        offsets: [
                            0,
                        ],
                        size: 256,
                        eof_offset: 296,
                    },
        ...
    }
}
```

Let's start reading the first file of the archive. For easier reading, here is an excerpt of the first 400 bytes of `data`:
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

* `00`: mark a `FileStart` block
* `00 00 00 00 00 00 00 00`: file ID is 0
* `06 00 00 00 00 00 00 00`: filename length, in bytes, is 6
* `73 69 6d 70 6c 65`: the filename is "simple"
* `01`: mark a `FileContent` block
* `00 00 00 00 00 00 00 00`: corresponding file ID is 0 (ie, the file "simple")
* `00 01 00 00 00 00 00 00`: this block contains 0x100 bytes of data
* `00 .. (256-bytes long) .. ff`: actual 256 first bytes of "simple"
* `ff`: mark a `EndOfFile` block
* `00 00 00 00 00 00 00 00`: file ID is 0. The file "simple" has been fully recovered
* `40 .. (32-bytes long) .. 80`: SHA256 hash of the file "simple" content, ie `SHA256(00 01 02 .. FE FF)`

Here, the file "simple" has been fully recovered. If one continues, there are:
* A `FileStart` block for the file "file_0" with ID 1
* A `FileStart` block for the file "file_1" with ID 2
* A `FileStart` block with ID 3 for a filename of length 6, incomplete in the excerpt
