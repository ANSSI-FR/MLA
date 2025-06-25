# MLA FORMAT

Relation between the MLA library version and the file format version:

| MLA Version | Supported file format |
|-------------|-----------------------|
| 2.X         | 2                     |
| 1.X         | 1                     |

This document introduces the MLA file format in its current version, 2.
For a more comprehensive introduction of the ideas behind it, please refer to [README.md](README.md).

## Types and their serialization format

* Integers are unsigned and serialized as bytes in little endian. They are called u64 for 64 bits integers, u32 for 32 bits ones, u16 for 16 bits ones and u8 for 8 bits ones. Serialization length in bytes are: 8 for u64, 4 for u32, 2 for u16 and 1 for u8.
* `Vec<T>` is a sequence of elements of type `T`. It is serialized with its length in number of elements (not necessarily bytes) as a u64 and the sequence of serialized elements of type `T`.
* `Opts` represents MLA options. It is serialized with a tag of value 0 as a u8 if no option is present. Otherwise it is serialized with a tag of value 1 as u8 followed by a yet unspecified Vec<u8>. Multiple fields in this file format are of type `Opts` for future proofing reasons, but no option is defined at the moment. For future proofing, implementers of this file format version must still handle the tag of value 1 and read the `Vec<u8>` even if not using this values. Thus, if an option is specified in the future, pre-dating implementations will be able to work with new archives containing the optional value.
* `Tail<T>` is a `T` followed by its `tail_length` length in bytes as a u64. This enables extracting the `T` when reading from the end. Note that a `Tail<Vec<T>>` contains two lengths which may differ in units and always differ in values as `Tail`'s length includes `Vec`'s serialization of its own length. For example, serialization of a `Tail<Vec<u16>>` containing 0 and 1, leads to `02 00 00 00 00 00 00 00 00 00 01 00 0c 00 00 00 00 00 00 00`. As a second example, serialization of `Tail<Vec<u8>>` containing 0 and 1, leads to `02 00 00 00 00 00 00 00 00 01 0a 00 00 00 00 00 00 00`.

## MLA Header

* An MLA file begins with the `mla_header_magic` ASCII magic: "MLAFAAAA".
* `mla_header_magic` is followed by the `format_version` format version number as a u32.
* `format_version` is followed by an `header_options` field of type `Opts`.
* `header_options` is followed by archive content `archive_content`, described below.
* `archive_content` is followed by an `footer_options` field of type `Tail<Opts>` to enable determining `archive_content`'s end when reading from the end of the MLA file.
* `footer_options` is followed by the `footer_magic` ASCII magic "EMLAAAAA", terminating the archive.

`archive_content` consists of a serialized MLA entries layer documented below, transformed with zero or more layers, documented below too. A layer consists of a u64 layer magic followed by its data. Layer order plays an important security role, so the signature layer has to be above the encryption layer which has to be above the compression layer. This must be enforced by writers and readers. Readers should ensure users explicitly choose if they allow an archive without signature or without encryption.

## Signature layer

* The layer `signature_layer_magic` ASCII magic is "SIGMLAAA".
* `signature_layer_magic` is followed by an `signature_header_options` of type `Opts`.
* `signature_header_options` is followed by `sig_inner_layer`, consisting of the inner layer bytes.
* `sig_inner_layer` is followed by `signature_footer_options` of type `Tail<Opts>`.
* `signature_footer_options` is followed by `signature_data` serialized as a `Tail<Vec<u8>>` which content is described below.

`signature_data` is a `Vec<u8>` whose content bytes consist of a sequence of `SignatureDataWHdr`. A `SignatureDataWHdr` is a `signature_method_id` u16, followed by a `signature_data` sequence of bytes depending of the tag value. For the moment, there are two valid `signature_method_id`: 0 and 1. 0 maps to `MLAEd25519SigMethod`, 1 maps to `MLAMLDSA87SigMethod`. These methods are described in `doc/CRYPTO.md`. Their input starts and includes `mla_header_magic`, up to and including `sig_inner_layer`.  In the current version, for the signature layer to be considered verified, the reader must verify that at least one `SignatureDataWHdr` of each `signature_method_id` is verified.

## Encryption layer

The layer `encryption_layer_magic` ASCII magic is "ENCMLAAA".
`encryption_layer_magic` is followed by `encryption_header_options` of type `Opts`.
`encryption_header_options` is followed by a `encryption_method_id` u16, described below.
`encryption_method_id` is followed by `encryption_metadata`, a sequence of bytes described below.
`encryption_metadata` is followed by `encrypted_inner_layer`, a sequence of bytes described below.
`encrypted_inner_layer` is followed by one `encryption_footer_options` of type `Tail<Opts>`.

The only `encryption_method_id` valid `encryption_method_id` for the moment is 0. It is the encryption method described in `CRYPTO.md`.

`encryption_metadata` depends on the previous `encryption_method_id` value. For `encryption_method_id` 0, `encryption_metadata` is a `Vec<PerRecipientEncapsulatedKey>` followed by a `KeyCommitmentAndTag`.

A `PerRecipientEncapsulatedKey` is an `mlkem1024_encapsulated_s` field followed by an `ed25519_encapsulated_s` field, followed by an `m0_encrypted_ss` field and a `prkem_tag` field. As described in more detail in `CRYPTO.md`, `m0_encrypted_ss` is the AES-256-GCM encrypted `global_secret`. The AES key used to encrypt this `global_secret` is recovered from `mlkem1024_encapsulated_s` and `ed25519_encapsulated_s`. `prkem_tag` is the GCM tag associated with `m0_encrypted_ss`.

`mlkem1024_encapsulated_s` is a sequence of 1568 bytes corresponding to the ciphertext output of ML-KEM.Encaps as described in FIPS 203. `ed25519_encapsulated_s` is a sequence of 32 bytes corresponding to the output of the X25519 as described in RFC 7748. `m0_encrypted_ss` is a 32 bytes sequence. `prkem_tag` is a 16 bytes sequence.

`KeyCommitmentAndTag` is the key commitment described in `CRYPTO.md`. It is a 64-bytes ciphertext followed by a 16-bytes tag.

`encrypted_inner_layer` is the AES-256-GCM encrypted inner layer with the `global_secret` key. `encrypted_inner_layer` is a sequence of `M0EncryptedChunk` followed by one `M0FinalEncryptedChunk`. Each `M0EncryptedChunk` has an `encrypted_content` (128*1024)-bytes field (last `M0EncryptedChunk` may be smaller) followed by a `tag` 16-bytes field. `encrypted_content` is the inner_layer encrypted chunk, and `tag` its GCM tag. `M0FinalEncryptedChunk` has a 10-bytes `encrypted_content` field followed by a 16-bytes `tag`.

The last `M0EncryptedChunk`'s `encrypted_content` size is the remainder of inner layer size divided by (128*1024).

To protect from a truncation attack, before using an archive, it must be checked that the `tag` of the `M0FinalEncryptedChunk` is correct and that its decrypted `encrypted_content` is the ASCII `FINALBLOCK`.

## Compression layer

The layer `compression_layer_magic` ASCII magic is "COMLAAAA".
`compression_layer_magic` if followed by `compression_header_options` of type `Opts`.
`compression_header_options` is followed by `compressed_data`, a sequence of bytes explained below.
`compressed_data` is followed by `compression_footer_options` of type `Tail<Opts>`.
`compressed_footer_options` is followed by `sizes_info` of type `Tail<SizesInfo>`, where `SizesInfo` is explained below.

The inner layer, is split in `4 * 1024 * 1024`-bytes chunks, except for the last chunk which may be smaller. Each chunk is compressed with [brotli](https://tools.ietf.org/html/rfc7932). The resulting size of each compressed chunk is recorded in `sizes_info`. `SizesInfo` has a first field `compressed_sizes`, which is a `Vec<u32>` corresponding to an ordered list of compressed chunk sizes and a second field `last_block_uncompresed_size` as a u32 indicating the uncompressed size of last inner layer chunk.

`compressed_data` is the concatenation of each compressed chunk.

The compression layer footer information can be retrieved by first reading the value of `sizes_info.tail_length` at the end of the layer, then reading the preceding `sizes_info.tail_length`-bytes.

## MLA entries layer

The layer `entries_layer_magic` ASCII magic is "MLAENAAA".
`entries_layer_magic` is followed by `entries_header_options` of type `Opts`.
`entries_header_options` is followed by `entries_data`, a sequence of bytes described below.
`entries_data` is followed by `entries_footer` of type `Tail<EntriesFooter>`, where `EntriesFooter` is described below.
`entries_footer` is followed by `entries_footer_options` of type `Tail<Opts>`.

`entries_data` is a succession of `ArchiveEntryBlock` of different type. An `ArchiveEntryBlock` begins with an `ArchiveEntryBlockType` u8 determining the type of `ArchiveEntryBlock`:
* 0x00 means `EntryStart`
* 0x01 means `EntryContentChunk`
* 0xFE means `EndOfArchiveData`
* 0xFF means `EndOfEntry`

If the `ArchiveEntryBlockType` is `EntryStart`, it is followed by an `ArchiveEntryId` u64, an `EntryName` and an `entry_start_options` of type `Opts`. An `EntryName` is a `Vec<u8>` described in `doc/ENTRY_NAME.md`.

If the `ArchiveEntryBlockType` is `EntryContentChunk`, it is followed by an `ArchiveEntryId`, a `content_options` of type `Opts` and a `Vec<u8>` `entry_content_data`.

If the `ArchiveEntryBlockType` is `EndOfEntry`, it is followed by an `ArchiveEntryId`, a `end_options` of type `Opts` and a `hash` serialized as 32 u8.

If the `ArchiveEntryBlockType` is `EndOfArchiveData`, it is followed by nothing.

`EntriesFooter` is a `Vec<EntryNameInfoMapElt>`. An `EntryNameInfoMapElt` is an `EntryName` followed by an `entry_blocks_offsets` which is a `Vec<EntryBlockOffset>` explained after, followed by an `entry_size` as u64. `entry_size` is the whole size of the content of the entry with the corresponding `EntryName`. For reproducibility, the `EntriesFooter` `Vec` is sorted by entry name (lexicographically by bytes values) before being serialized.

`EntryBlockOffset` is a u64 indicating at which offset from the begining of the MLA entries layer an `ArchiveEntryBlock` can be found for the given `EntryName`. All `EntryBlockOffset`s for each entry are recorded in `entry_blocks_offsets` and they are so in ascending order of offset.

### Explainations

An archive entry `entry_i` in the archive always starts with an `EntryStart`, giving its name and unique ID i.

`entry_i` content is the concatenation of all `EntryContentChunk`s `entry_content_data` fields with `ArchiveEntryId` value `i`.

Once the `EndOfEntry` for `entry_i` is reached, the entry is completely read. Its content SHA-256 hash can be verified with the `EndOfEntry.hash`.

Between the last `EndOfEntry` block and `entries_footer`, there is the only `EndOfArchiveData` block. It is used when trying to read a truncated archive, to correctly separate the actual archive data from the footer.

As blocks from different entries can be interleaved, the `entry_block_offsets` for an entry are the offsets in `entries_data` of its blocks.

For instance, if the blocks are:
```
Off0: [EntryStart ID 1]
Off1: [EntryStart ID 2]
Off2: [EntryContentChunk ID 1]
Off3: [EntryContentChunk ID 1]
Off4: [EntryContentChunk ID 2]
Off5: [EndOfEntry ID 1]
...
```

The `offsets` for the entry with ID 1 will be `Off0`, `Off2`, `Off3` and `Off5`.
