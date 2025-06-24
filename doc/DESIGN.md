Design
=

As the name spoils it, an MLA is made of several, independent, layers. The following section introduces the design ideas behind MLA. Please refer to [FORMAT.md](FORMAT.md) for a more formal description.

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

This layer encrypts data as explained in `CRYPTO.md` and `FORMAT.md`.

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


