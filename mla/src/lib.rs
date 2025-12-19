//! Multi Layer Archive (MLA)
//!
//! MLA is an archive file format with the following features:
//!
//! * Support for traditional and post-quantum encryption hybridation with asymmetric keys (HPKE with AES256-GCM and a KEM based on an hybridation of X25519 and post-quantum ML-KEM 1024)
//! * Support for traditional and post-quantum signature hybridation
//! * Support for compression (based on [`rust-brotli`](https://github.com/dropbox/rust-brotli/))
//! * Streamable archive creation:
//!   * An archive can be built even over a data-diode
//!   * An entry can be added through chunks of data, without initially knowing the final size
//!   * Entry chunks can be interleaved (one can add the beginning of an entry, start a second one, and then continue adding the first entry's parts)
//! * Architecture agnostic and portable to some extent (written entirely in Rust)
//! * Archive reading is seekable, even if compressed or encrypted. An entry can be accessed in the middle of the archive without reading from the beginning
//! * If truncated, archives can be `clean-truncated` in order to recover its content to some extent. Two modes are available:
//!   * Authenticated recover (default): only authenticated (as in AEAD, there is no signature verification) encrypted chunks of data are retrieved
//!   * Unauthenticated recover: authenticated and unauthenticated encrypted chunks of data are retrieved. Use at your own risk.
//! * Arguably less prone to bugs, especially while parsing an untrusted archive (Rust safety)
//!
//! Repository
//! =
//!
//! The MLA repository contains:
//!
//! * `mla`: the Rust library implementing MLA reader and writer
//! * `mlar`: a Rust cli utility wrapping `mla` for common actions (create, list, extract...)
//! * `doc` : advanced documentation related to MLA (e.g. format specification)
//! * `bindings` : bindings for other languages
//! * `samples` : test assets
//! * `mla-fuzz-afl` : a Rust utility to fuzz `mla`
//! * `.github`: Continuous Integration needs
//!
//! Quick API usage
//! =
//!
//! * Create an archive, with compression and encryption:
//! ```rust
//! use mla::ArchiveWriter;
//! use mla::config::ArchiveWriterConfig;
//! use mla::crypto::mlakey::{MLAPrivateKey, MLAPublicKey};
//! use mla::entry::EntryName;
//! // for encryption
//! const RECEIVER_PUB_KEY: &[u8] =
//!     include_bytes!("../../samples/test_mlakey_archive_v2_receiver.mlapub");
//! // for signing
//! const SENDER_PRIV_KEY: &[u8] =
//!     include_bytes!("../../samples/test_mlakey_archive_v2_sender.mlapriv");
//!
//! fn main() {
//!     // For encryption, load the needed receiver public key
//!     let (pub_enc_key, _pub_sig_verif_key) = MLAPublicKey::deserialize_public_key(RECEIVER_PUB_KEY)
//!         .unwrap()
//!         .get_public_keys();
//!     // For signing, load the needed sender private key
//!     let (_priv_dec_key, priv_sig_key) = MLAPrivateKey::deserialize_private_key(SENDER_PRIV_KEY)
//!         .unwrap()
//!         .get_private_keys();
//!     // In production, you may want to zeroize the real `SENDER_PRIV_KEY` or
//!     // associated temporary values of its `Read` implementation here.
//!     // Create an MLA Archive - Output only needs the Write trait.
//!     // Here, a Vec is used but it would tipically be a `File` or a network socket.
//!     let mut buf = Vec::new();
//!     // The use of multiple keys is supported
//!     let config =
//!         ArchiveWriterConfig::with_encryption_with_signature(&[pub_enc_key], &[priv_sig_key])
//!             .unwrap();
//!     // Create the Writer
//!     let mut mla = ArchiveWriter::from_config(&mut buf, config).unwrap();
//!     // Add a file
//!     // This creates an entry named "a/filename" (without first "/"), See `EntryName::from_path`
//!     mla.add_entry(
//!         EntryName::from_path("/a/filename").unwrap(),
//!         4,
//!         &[0, 1, 2, 3][..],
//!     )
//!     .unwrap();
//!     // Complete the archive
//!     mla.finalize().unwrap();
//! }
//! ```
//! * Add entries part per part, in a "concurrent" fashion:
//! ```rust
//! use mla::ArchiveWriter;
//! use mla::config::ArchiveWriterConfig;
//! use mla::crypto::mlakey::{MLAPrivateKey, MLAPublicKey};
//! use mla::entry::EntryName;
//!
//! // for encryption
//! const RECEIVER_PUB_KEY: &[u8] =
//!     include_bytes!("../../samples/test_mlakey_archive_v2_receiver.mlapub");
//! // for signing
//! const SENDER_PRIV_KEY: &[u8] =
//!     include_bytes!("../../samples/test_mlakey_archive_v2_sender.mlapriv");
//!
//! fn main() {
//!     // For encryption, load the needed receiver public key
//!     let (pub_enc_key, _pub_sig_verif_key) = MLAPublicKey::deserialize_public_key(RECEIVER_PUB_KEY)
//!         .unwrap()
//!         .get_public_keys();
//!     // For signing, load the needed sender private key
//!     let (_priv_dec_key, priv_sig_key) = MLAPrivateKey::deserialize_private_key(SENDER_PRIV_KEY)
//!         .unwrap()
//!         .get_private_keys();
//!     // In production, you may want to zeroize the real `SENDER_PRIV_KEY` or
//!     // associated temporary values of its `Read` implementation here.
//!
//!     // Create an MLA Archive - Output only needs the Write trait
//!     let mut buf = Vec::new();
//!     let config =
//!         ArchiveWriterConfig::with_encryption_with_signature(&[pub_enc_key], &[priv_sig_key])
//!             .unwrap();
//!
//!     // Create the Writer
//!     let mut mla = ArchiveWriter::from_config(&mut buf, config).unwrap();
//!
//!     // An entry is tracked by an id, and follows this API's call order:
//!     // 1. id = start_entry(entry_name);
//!     // 2. append_entry_content(id, content length, content (impl Read))
//!     // 2-bis. repeat 2.
//!     // 3. end_entry(id)
//!
//!     // Start an entry and add content
//!     let id_entry1 = mla
//!         .start_entry(EntryName::from_path("name1").unwrap())
//!         .unwrap();
//!     let entry1_part1 = vec![11, 12, 13, 14];
//!     mla.append_entry_content(
//!         id_entry1,
//!         entry1_part1.len() as u64,
//!         entry1_part1.as_slice(),
//!     )
//!     .unwrap();
//!
//!     // Start a second entry and add content
//!     let id_entry2 = mla
//!         .start_entry(EntryName::from_path("name2").unwrap())
//!         .unwrap();
//!     let entry2_part1 = vec![21, 22, 23, 24];
//!     mla.append_entry_content(
//!         id_entry2,
//!         entry2_part1.len() as u64,
//!         entry2_part1.as_slice(),
//!     )
//!     .unwrap();
//!
//!     // Add an entry as a whole
//!     let entry3 = vec![31, 32, 33, 34];
//!     mla.add_entry(
//!         EntryName::from_path("name3").unwrap(),
//!         entry3.len() as u64,
//!         entry3.as_slice(),
//!     )
//!     .unwrap();
//!
//!     // Add new content to the first entry
//!     let entry1_part2 = vec![15, 16, 17, 18];
//!     mla.append_entry_content(
//!         id_entry1,
//!         entry1_part2.len() as u64,
//!         entry1_part2.as_slice(),
//!     )
//!     .unwrap();
//!
//!     // Mark still opened entries as finished
//!     mla.end_entry(id_entry1).unwrap();
//!     mla.end_entry(id_entry2).unwrap();
//!
//!     // Complete the archive
//!     mla.finalize().unwrap();
//! }
//! ```
//! * Read entries from an archive
//! ```rust
//! use mla::ArchiveReader;
//! use mla::config::ArchiveReaderConfig;
//! use mla::crypto::mlakey::{MLAPrivateKey, MLAPublicKey};
//! use mla::entry::EntryName;
//! use std::io;
//!
//! const DATA: &[u8] = include_bytes!("../../samples/archive_v2.mla");
//! // for decryption
//! const RECEIVER_PRIV_KEY: &[u8] =
//!     include_bytes!("../../samples/test_mlakey_archive_v2_receiver.mlapriv");
//! // for signature verification
//! const SENDER_PUB_KEY: &[u8] = include_bytes!("../../samples/test_mlakey_archive_v2_sender.mlapub");
//!
//! fn main() {
//!     // For decryption, load the needed receiver private key
//!     let (priv_dec_key, _priv_sig_key) = MLAPrivateKey::deserialize_private_key(RECEIVER_PRIV_KEY)
//!         .unwrap()
//!         .get_private_keys();
//!     // For signature verification, load the needed sender public key
//!     let (_pub_enc_key, pub_sig_verif_key) = MLAPublicKey::deserialize_public_key(SENDER_PUB_KEY)
//!         .unwrap()
//!         .get_public_keys();
//!
//!     // Specify the key for the Reader
//!     let config = ArchiveReaderConfig::with_signature_verification(&[pub_sig_verif_key])
//!         .with_encryption(&[priv_dec_key]);
//!
//!     // Read from buf, which needs Read + Seek
//!     let buf = io::Cursor::new(DATA);
//!     let mut mla_read = ArchiveReader::from_config(buf, config).unwrap().0;
//!
//!     // Get a file
//!     let mut entry = mla_read
//!         .get_entry(EntryName::from_path("simple").unwrap()) // or EntryName::from_arbitrary_bytes if name is not representing a file path
//!         .unwrap() // An error can be raised (I/O, decryption, etc.)
//!         .unwrap(); // Option(entry), as the entry might not exist in the archive
//!
//!     // Get back its name, size, and data
//!     // display name interpreted as file path and escape to avoid
//!     // issues with terminal escape sequences for example
//!     println!(
//!         "{} ({} bytes)",
//!         entry.name.to_pathbuf_escaped_string().unwrap(),
//!         entry.get_size()
//!     );
//!     let mut output = Vec::new();
//!     std::io::copy(&mut entry.data, &mut output).unwrap();
//!
//!     // Get back the list of entries names in the archive without
//!     // interpreting them as file paths, so no need to unwrap as
//!     // it cannot fail. ASCII slash is encoded too.
//!     for entry_name in mla_read.list_entries().unwrap() {
//!         println!("{}", entry_name.raw_content_to_escaped_string());
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::convert::TryFrom;
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
#[macro_use]
extern crate bitflags;
use crypto::hybrid::MLAEncryptionPublicKey;
use layers::compress::COMPRESSION_LAYER_MAGIC;
use layers::encrypt::ENCRYPTION_LAYER_MAGIC;
use layers::strip_head_tail::StripHeadTailReader;
use layers::traits::InnerReaderTrait;

pub mod entry;
use entry::{
    ArchiveEntry, ArchiveEntryDataReader, ArchiveEntryId, EntryName, deserialize_entry_name,
    serialize_entry_name,
};

mod base64;

/// As the name spoils it, an MLA is made of several, independent, layers. The following section introduces the design ideas behind MLA. Please refer to [FORMAT.md](FORMAT.md) for a more formal description.
///
/// Layers
/// -
///
/// Each layer acts as a *Unix PIPE*, taking bytes in input and outputting in the next
/// layer.
/// A layer is made of:
///
/// * a `Writer`, implementing the `Write` trait. It is responsible for emitting bytes while creating a new archive
/// * a `Reader`, implementing both `Read` and `Seek` traits. It is responsible for reading bytes while reading an archive
/// * a `TruncatedReader`, implementing only the `Read` trait. It is responsible for reading bytes when cleaning a truncated archive (`clean-truncated` operation)
///
/// Layers are made with the *recoverable* property in mind. Reading them must never need information from the footer, but a footer can be used to optimize the reading. For example, accessing a file inside the archive can be optimized using the footer to seek to the file beginning, but it is still possible to get information by reading the whole archive until the file is found.
///
/// Layers are optional, but their order is enforced. Users can choose to enable or disable them.
/// Current order is the following:
///
/// 1. *File storage abstraction (not a layer)*
/// 1. Raw layer (mandatory)
/// 1. Compression layer
/// 1. Encryption layer
/// 1. Position layer (mandatory)
/// 1. *Stored bytes*
///
/// Overview
/// -
///
/// ```text
/// +----------------+-------------------------------------------------------------------------------------------------------------+
/// | Archive Header |                                                                                                             | => Final container (File / Buffer / etc.)
/// +------------------------------------------------------------------------------------------------------------------------------+
///                  +-------------------------------------------------------------------------------------------------------------+
///                  |                                                                                                             | => Raw layer
///                  +-------------------------------------------------------------------------------------------------------------+
///                  +-----------+---------+------+---------+------+---------------------------------------------------------------+
///                  | E. header | Block 1 | TAG1 | Block 2 | TAG2 | Block 3 | TAG3 | ...                                          | => Encryption layer
///                  +-----------+---------+------+---------+------+---------------------------------------------------------------+
///                              |         |      |         |      |         |      |                                              |
///                              +-------+--      --+-------       -----------      ----+---------+------+---------+ +-------------+
///                              | Blk 1 |          | Blk 2                             | Block 3 | ...  | Block n | |    Footer   | => Compression Layer
///                              +-------+--      --+-------       -----------      ----+---------+------+---------+ +-------------+
///                             /         \                                                             /           \
///                            /           \                                                           /             \
///                           /             \                                                         /               \
///                          +-----------------------------------------------------------------------------------------+
///                          |                                                                                         |             => Position layer
///                          +-----------------------------------------------------------------------------------------+
///                          +-------------+-------------+-------------+-------------+-----------+-------+-------------+
///                          | File1 start | File1 data1 | File2 start | File1 data2 | File1 end |  ...  | Files index |             => Files information and content
///                          +-------------+-------------+-------------+-------------+-----------+-------+-------------+
/// ```
///
/// Layers description
/// -
///
/// ### Raw Layer
///
/// Implemented in `RawLayer*` (i.e. `RawLayerWriter`, `RawLayerReader` and `RawLayerTruncatedReader`).
///
/// This is the simplest layer. It is required to provide an API between layers and
/// final output worlds. It is also used to keep the position of data's start.
///
/// ### Position Layer
///
/// Implemented in `PositionLayer*`.
///
/// Similar to the `RawLayer`, this is a very simple, utility, layer. It keeps
/// track of how many bytes have been written to the sub-layers.
///
/// For instance, it is required by the file storage layer to keep track of the
/// position in the flow of files, for indexing purpose.
///
/// ### Encryption Layer
///
/// Implemented in `EncryptionLayer*`.
///
/// This layer encrypts data using the symmetric authenticated encryption with associated data (AEAD) algorithm *AES-GCM 256*, and encrypts the symmetric key using an ECIES schema based on *Curve25519*.
///
/// The ECIES schema is extended to support multiple public keys: a public key is generated and then used to perform `n` Diffie-Hellman exchanges with the `n` users public keys. The generated public key is also recorded in the header (to let the user replay the DH exchange). Once derived according to ECIES, we get `n` keys. These keys are then used to encrypt a common key `k`, and the resulting `n` ciphertexts are stored in the layer header.
/// This key `k` will later be used for the symmetric encryption of the archive.
///
/// In addition to the key, a nonce (8 bytes) is also generated per archive. A fixed associated data is used.
///
/// The generation uses `OsRng` from crate `rand`, that uses `getrandom()` from crate `getrandom`. `getrandom` provides implementations for many systems, listed [here](https://docs.rs/getrandom/0.1.14/getrandom/).
/// On Linux it uses the `getrandom()` syscall and falls back on `/dev/urandom`.
/// On Windows it uses the `RtlGenRandom` API (available since Windows XP/Windows Server 2003).
///
/// In order to be "better safe than sorry", a `ChaChaRng` is seeded from the
/// bytes generated by `OsRng` in order to build a CSPRNG (Cryptographically Secure Pseudo Random Number Generator). This `ChaChaRng` provides the actual bytes used in keys and nonces generations.
///
/// The layer data is then made of several encrypted blocks, each with a constant size except for the last one. Each block is encrypted with an IV including the base nonce and a counter. This construction is close to the [STREAM](https://github.com/miscreant/meta/wiki/STREAM) one, except for the `last_block` bit. The choice has been made not to use it, because:
/// * At the time of writing, the archive writer does not know that the current block is the last one. Therefore, it cannot use a specific IV. To circumvent it, a dummy footer block has to be added at the end, leading to additional complexity for last block detection
/// * In STREAM, the `last_block` bit is used to prevent undetected truncation. In MLA, it is already the role of the `EndOfArchiveData` tag at the file layer level
///
/// Thus, to seek-and-read at a given position, the layer decrypts the block containing this position, and verifies the tag before returning the decrypted data.
///
/// The authors decided to use elliptic curve over RSA, because:
/// * No ready-for-production Rust-based libraries have been found at the date of writing
/// * A security-audited Rust library already exists for Curve25519
/// * Curve25519 is widely used and [respects several criteria](https://safecurves.cr.yp.to/)
/// * Common arguments, such as the ones of [Trail of bits](https://blog.trailofbits.com/2019/07/08/fuck-rsa/)
///
/// AES-GCM is used because it is one of the most commonly used AEAD algorithms and using one avoids a whole class of attacks. In addition, it lets us rely on hardware acceleration (like AES-NI) to keep reasonable performance.
///
/// External cryptographic libraries have been reviewed:
/// * Rust Crypto AES-GCM, reviewed by [NCC Group](https://research.nccgroup.com/wp-content/uploads/2020/02/NCC_Group_MobileCoin_RustCrypto_AESGCM_ChaCha20Poly1305_Implementation_Review_2020-02-12_v1.0.pdf)
/// * Dalek cryptography library, reviewed by [Quarkslab](https://blog.quarkslab.com/security-audit-of-dalek-libraries.html)
///
///
/// ### Compression Layer
///
/// Implemented in `CompressionLayer*`.
///
/// This layer is based on the Brotli compression algorithm ([RFC 7932](https://tools.ietf.org/html/rfc7932)).
/// Each 4MB of cleartext data is stored in a separately compressed chunk.
///
/// This algorithm, used with a *window* of size 1, is able to read each chunk and
/// stop when 4MB of cleartext has been obtained. It is then reset, and starts
/// decompressing the next chunk.
///
/// To speed up the decompression, and to make the layer seekable, a footer is used. It
/// saves the compressed size. Knowing the decompressed size, a seek at a cleartext
/// position can be performed by seeking to the beginning of the correct compressed
/// block, then decompressing the first bytes until the desired position is reached.
///
/// The footer is also used to allow for a wider *window*, enabling faster
/// decompression. Finally, it also records the size of the last block, to compute the
/// frontier between compressed data and the footer.
///
/// The 4MB size is a trade-off between a better compression (higher value) and faster seeking (smaller value). It has been chosen based on benchmarking of representative data. Better compression can also be achieved by setting the compression quality parameter to a higher value (leading to a slower process).
///
/// File storage
/// -
///
/// Files are saved as series of archive-file blocks. A first special type of block
/// indicates the start of a file, along with its entry name and an entry ID. A second special type of
/// block indicates the end of the current file.
///
/// Blocks contain file data, prepended with the current block size and the corresponding file ID. Even if the
/// format handles streaming files, the size of a file chunk must be known before
/// writing it. The file ID enables blocks from different files to be interleaved.
///
///
///
/// The file-ending block marks the end of data for a given file, and includes its
/// full content SHA256. Thus, the integrity of files can be checked, even on recover
/// operations.
///
/// The layer footer contains for each file its size, its ending block offset and an index of its block locations. Block location index enables direct access. The ending block offset enables fast hash retrieval and the file size eases the conversion to formats needing the size of the file before the data, such as Tar.
///
///
///
///
///
/// If this footer is unavailable, the archive is read from the beginning to recover
/// file information.
pub(crate) mod layers;
use crate::crypto::mlakey::{MLASignatureVerificationPublicKey, MLASigningPrivateKey};
use crate::layers::compress::{
    CompressionLayerReader, CompressionLayerTruncatedReader, CompressionLayerWriter,
};
use crate::layers::encrypt::{
    EncryptionLayerReader, EncryptionLayerTruncatedReader, EncryptionLayerWriter,
};
use crate::layers::position::PositionLayerWriter;
use crate::layers::raw::{RawLayerReader, RawLayerTruncatedReader, RawLayerWriter};
use crate::layers::signature::{
    SIGNATURE_LAYER_MAGIC, SignatureLayerReader, SignatureLayerTruncatedReader,
    SignatureLayerWriter,
};
use crate::layers::traits::{
    InnerWriterTrait, InnerWriterType, LayerReader, LayerTruncatedReader, LayerWriter,
};
pub mod errors;
use crate::errors::{Error, TruncatedReadError};

pub mod config;
use crate::config::{ArchiveReaderConfig, ArchiveWriterConfig, TruncatedReaderConfig};

pub mod crypto;
use crate::crypto::hash::{HashWrapperReader, HashWrapperWriter, Sha256Hash};
use sha2::{Digest, Sha256, Sha512};

mod format;
pub mod helpers;
use format::ArchiveHeader;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

// -------- Constants --------

const MLA_MAGIC: &[u8; 8] = b"MLAFAAAA";
const MLA_FORMAT_VERSION: u32 = 2;
const END_MLA_MAGIC: &[u8; 8] = b"EMLAAAAA";
/// Maximum number of UTF-8 bytes allowed in an entry name (not characters).
/// Set to 1024 bytes to stay safely within common `PATH_MAX` limits on Linux,
/// FreeBSD, OpenBSD, and NetBSD. Windows supports longer paths via special prefixes,
/// but for maximum portability, we adopt this conservative limit.
const ENTRY_NAME_MAX_SIZE: u64 = 1024;

const ENTRIES_LAYER_MAGIC: &[u8; 8] = b"MLAENAAA";

const EMPTY_OPTS_SERIALIZATION: &[u8; 1] = &[0];
const EMPTY_TAIL_OPTS_SERIALIZATION: &[u8; 9] = &[0, 1, 0, 0, 0, 0, 0, 0, 0];

#[derive(Debug)]
struct Opts;

impl Opts {
    fn from_reader(mut src: impl Read) -> Result<Self, Error> {
        let discriminant = u8::deserialize(&mut src)?;
        match discriminant {
            0 => (),
            1 => {
                let mut n = [0; 8];
                src.read_exact(&mut n)?;
                let n = u64::from_le_bytes(n);
                let mut v = Vec::new();
                src.take(n).read_to_end(&mut v)?;
                // no action implemented for the moment, hence no further use
            }
            _ => return Err(Error::DeserializationError),
        }
        Ok(Opts)
    }

    #[allow(clippy::unused_self)]
    fn dump(&mut self, mut src: impl Write) -> Result<u64, Error> {
        // No option for the moment
        src.write_all(EMPTY_OPTS_SERIALIZATION)?;
        Ok(1)
    }
}

// -------- MLA Format Footer --------

struct ArchiveFooter {
    /// `EntryName` -> Corresponding `EntryInfo`
    entries_info: HashMap<EntryName, EntryInfo>,
}

impl ArchiveFooter {
    /// Footer:
    /// ```ascii-art
    /// [entries_info][entries_info length]
    /// ```
    /// Performs zero-copy serialization of a footer
    fn serialize_into<W: Write>(
        mut dest: W,
        entries_info: &HashMap<EntryName, ArchiveEntryId>,
        ids_info: &HashMap<ArchiveEntryId, EntryInfo>,
    ) -> Result<(), Error> {
        // Combine `entries_info` and `ids_info` to ArchiveFooter.entries_info,
        // avoiding copies (only references)
        let mut tmp = Vec::new();
        for (k, i) in entries_info {
            let v = ids_info.get(i).ok_or_else(|| {
                Error::WrongWriterState(
                    "[ArchiveFooter seriliaze] Unable to find the ID".to_string(),
                )
            })?;
            tmp.push((k, v));
        }
        tmp.sort_by_key(|(k, _)| *k);

        tmp.len().serialize(&mut dest)?;
        let mut footer_serialization_length = 8;
        for (k, i) in tmp {
            footer_serialization_length += serialize_entry_name(k, &mut dest)?;
            footer_serialization_length += i.serialize(&mut dest)?;
        }
        (footer_serialization_length + 1).serialize(&mut dest)?; // +1 for tag indicating index presence
        Ok(())
    }

    /// Parses and instantiates a footer from serialized data
    pub fn deserialize_from<R: Read + Seek>(mut src: R) -> Result<Option<ArchiveFooter>, Error> {
        let index_present = u8::deserialize(&mut src)?;
        if index_present == 1 {
            // Read entries_info
            let n = u64::deserialize(&mut src)?;
            let entries_info = (0..n)
                .map(|_| {
                    let name = deserialize_entry_name(&mut src)?;
                    let info = EntryInfo::deserialize(&mut src)?;
                    Ok::<_, Error>((name, info))
                })
                .collect::<Result<HashMap<_, _>, Error>>()?;

            Ok(Some(ArchiveFooter { entries_info }))
        } else {
            Ok(None)
        }
    }
}

// -------- Writer --------

/// Tags used in each `ArchiveEntryBlock` to indicate the type of block that follows
#[derive(Debug)]
enum ArchiveEntryBlockType {
    EntryStart,
    EntryContent,

    EndOfArchiveData,
    EndOfEntry,
}

impl<W: Write> MLASerialize<W> for ArchiveEntryBlockType {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        let byte: u8 = match self {
            ArchiveEntryBlockType::EntryStart => 0,
            ArchiveEntryBlockType::EntryContent => 1,
            ArchiveEntryBlockType::EndOfArchiveData => 0xFE,
            ArchiveEntryBlockType::EndOfEntry => 0xFF,
        };
        byte.serialize(dest)
    }
}

impl<R: Read> MLADeserialize<R> for ArchiveEntryBlockType {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let serialized_block_type = u8::deserialize(src)?;
        match serialized_block_type {
            0 => Ok(ArchiveEntryBlockType::EntryStart),
            1 => Ok(ArchiveEntryBlockType::EntryContent),
            0xFE => Ok(ArchiveEntryBlockType::EndOfArchiveData),
            0xFF => Ok(ArchiveEntryBlockType::EndOfEntry),
            _ => Err(Error::WrongBlockSubFileType),
        }
    }
}

use format::ArchiveEntryBlock;

#[derive(Debug, Clone)]
enum ArchiveWriterState {
    /// Initialized, with files opened
    OpenedFiles {
        ids: Vec<ArchiveEntryId>,
        hashes: HashMap<ArchiveEntryId, Sha256>,
    },
    /// File finalized, no more change allowed
    Finalized,
}

impl ArchiveWriterState {
    /// Wrap a `impl Read` with hash updating, corresponding to the file identified by `id`
    fn wrap_with_hash<R: Read>(
        &mut self,
        id: ArchiveEntryId,
        src: R,
    ) -> Result<HashWrapperReader<'_, R>, Error> {
        let hash = match self {
            ArchiveWriterState::OpenedFiles { hashes, .. } => match hashes.get_mut(&id) {
                Some(hash) => hash,
                None => {
                    return Err(Error::WrongWriterState(
                        "[wrap_with_hash] Unable to find the ID".to_string(),
                    ));
                }
            },
            ArchiveWriterState::Finalized => {
                return Err(Error::WrongWriterState(
                    "[wrap_with_hash] Wrong state".to_string(),
                ));
            }
        };

        Ok(HashWrapperReader::new(src, hash))
    }
}

/// Used to check whether the current state is the one expected
/// ```text
/// check_state!(self.state, ArchiveWriterState::XXX)
/// ```
macro_rules! check_state {
    ( $x:expr, $y:ident ) => {{
        match $x {
            ArchiveWriterState::$y { .. } => (),
            _ => {
                return Err(Error::WrongArchiveWriterState {
                    current_state: format!("{:?}", $x).to_string(),
                    expected_state: format! {"{}", "ArchiveWriterState::$y"}.to_string(),
                });
            }
        }
    }};
}

/// Used to check whether the current state is `OpenedFiles`, with the expected file opened
/// ```text
/// check_state_file_opened!(self.state, file_id)
/// ```
macro_rules! check_state_file_opened {
    ( $x:expr, $y:expr ) => {{
        match $x {
            ArchiveWriterState::OpenedFiles { ids, hashes } => {
                if !ids.contains($y) || !hashes.contains_key($y) {
                    return Err(Error::WrongArchiveWriterState {
                        current_state: format!("{:?}", $x).to_string(),
                        expected_state: "ArchiveWriterState with id $y".to_string(),
                    });
                }
            }
            _ => {
                return Err(Error::WrongArchiveWriterState {
                    current_state: format!("{:?}", $x).to_string(),
                    expected_state: "ArchiveWriterState with id $y".to_string(),
                });
            }
        }
    }};
}

/// Use this to write an archive
///
/// See crate root documentation for example usage.
///
/// Don't forget to call `ArchiveWriter::finalize`
pub struct ArchiveWriter<'a, W: 'a + InnerWriterTrait> {
    /// MLA Archive format writer
    ///
    ///
    /// Internals part:
    ///
    /// Destination: use a Box to be able to dynamically changes layers
    dest: Box<PositionLayerWriter<'a, W>>,
    /// Internal state
    state: ArchiveWriterState,
    /// Entry name -> Corresponding `ArchiveEntryID`
    ///
    /// This is done to keep a quick check for entry name existence
    entries_info: HashMap<EntryName, ArchiveEntryId>,
    /// ID -> Corresponding `EntryInfo`
    ///
    /// File chunks identify their relative file using the `ArchiveEntryID`.
    /// `entries_info` and `ids_info` could have been merged into a single `HashMap`
    /// String -> `EntryInfo`, at the cost of an additional `HashMap` `ArchiveEntryID` ->
    /// String, thus increasing memory footprint.
    /// These hashmaps are actually merged at the last moment, on footer
    /// serialization
    ids_info: HashMap<ArchiveEntryId, EntryInfo>,
    /// Next file id to use
    next_id: ArchiveEntryId,
    /// Current file being written (for continuous block detection)
    current_id: ArchiveEntryId,
}

// This is an unstable feature for now (`Vec.remove_item`), use a function
// instead to keep stable compatibility
fn vec_remove_item<T: std::cmp::PartialEq>(vec: &mut Vec<T>, item: &T) -> Option<T> {
    let pos = vec.iter().position(|x| *x == *item)?;
    Some(vec.remove(pos))
}

impl<W: InnerWriterTrait> ArchiveWriter<'_, W> {
    /// Create an `ArchiveWriter` from config.
    pub fn from_config(dest: W, config: ArchiveWriterConfig) -> Result<Self, Error> {
        let dest: InnerWriterType<W> = Box::new(RawLayerWriter::new(dest));

        let archive_header = ArchiveHeader {
            format_version_number: MLA_FORMAT_VERSION,
        };
        let mut archive_header_hash = Sha512::new();
        let mut dest = HashWrapperWriter::new(dest, &mut archive_header_hash);
        archive_header.serialize(&mut dest)?;
        let mut dest = dest.into_inner();

        // Enable layers depending on user option
        dest = match config.signature {
            Some(signature_config) => Box::new(SignatureLayerWriter::new(
                dest,
                signature_config,
                archive_header_hash,
            )?),
            None => dest,
        };
        dest = match config.encryption {
            Some(encryption_config) => {
                Box::new(EncryptionLayerWriter::new(dest, &encryption_config)?)
            }
            None => dest,
        };
        dest = match config.compression {
            Some(cfg) => Box::new(CompressionLayerWriter::new(dest, &cfg)?),
            None => dest,
        };

        // Upper layer must be a PositionLayer
        let mut final_dest = Box::new(PositionLayerWriter::new(dest));
        final_dest.reset_position();

        // Write the magic
        final_dest.write_all(ENTRIES_LAYER_MAGIC)?;
        let _ = Opts.dump(&mut final_dest)?;

        // Build initial archive
        Ok(ArchiveWriter {
            dest: final_dest,
            state: ArchiveWriterState::OpenedFiles {
                ids: Vec::new(),
                hashes: HashMap::new(),
            },
            entries_info: HashMap::new(),
            ids_info: HashMap::new(),
            next_id: ArchiveEntryId(0),
            current_id: ArchiveEntryId(0),
        })
    }

    /// Create an `ArchiveWriter` with a default config (encryption, signature and compression with default level).
    ///
    /// Do not mix up keys. If `A` sends an archive to `B`,
    /// `encryption_public_keys` must contain
    /// `B`'s encryption public key and
    /// `signing_private_keys` must contain `A`'s signature private key.
    ///
    /// Returns `ConfigError::EncryptionKeyIsMissing` if `encryption_public_keys` is empty.
    /// Returns `ConfigError::PrivateKeyNotSet` if `signing_private_keys` is empty.
    pub fn new(
        dest: W,
        encryption_public_keys: &[MLAEncryptionPublicKey],
        signing_private_keys: &[MLASigningPrivateKey],
    ) -> Result<Self, Error> {
        let config = ArchiveWriterConfig::with_encryption_with_signature(
            encryption_public_keys,
            signing_private_keys,
        )?;
        Self::from_config(dest, config)
    }

    /// Finalize an archive (appends footer, finalize compression, truncation protection, etc.).
    ///
    /// Must be done to use `ArchiveReader` then.
    pub fn finalize(mut self) -> Result<W, Error> {
        // Check final state (empty ids, empty hashes)
        check_state!(self.state, OpenedFiles);
        match &mut self.state {
            ArchiveWriterState::OpenedFiles { ids, hashes } => {
                if !ids.is_empty() || !hashes.is_empty() {
                    return Err(Error::WrongWriterState(
                        "[Finalize] At least one file is still open".to_string(),
                    ));
                }
            }
            ArchiveWriterState::Finalized => {
                // Never happens, due to `check_state!`
                return Err(Error::WrongWriterState(
                    "[Finalize] State have changes inside finalize".to_string(),
                ));
            }
        }
        self.state = ArchiveWriterState::Finalized;

        // Mark the end of the data

        // Use std::io::Empty as a readable placeholder type
        ArchiveEntryBlock::EndOfArchiveData::<std::io::Empty> {}.dump(&mut self.dest)?;

        self.dest.write_all(&[1])?; // We always keep an index for the moment
        ArchiveFooter::serialize_into(&mut self.dest, &self.entries_info, &self.ids_info)?;

        self.dest.write_all(EMPTY_TAIL_OPTS_SERIALIZATION)?; // No option for the moment

        // Recursive call
        let mut final_dest = self.dest.finalize()?;
        final_dest.write_all(EMPTY_TAIL_OPTS_SERIALIZATION)?; // No option for the moment
        final_dest.write_all(END_MLA_MAGIC)?;
        Ok(final_dest)
    }

    /// Add the current offset to the corresponding list if the file id is not
    /// the current one, ie. if blocks are not continuous
    fn record_offset_and_size_in_index(
        &mut self,
        id: ArchiveEntryId,
        size: u64,
    ) -> Result<(), Error> {
        let offset = self.dest.position();
        match self.ids_info.get_mut(&id) {
            Some(file_info) => file_info.offsets_and_sizes.push((offset, size)),
            None => {
                return Err(Error::WrongWriterState(
                    "[mark_continuous_block] Unable to find the ID".to_string(),
                ));
            }
        }
        self.current_id = id;
        Ok(())
    }

    /// Start a new entry in archive without giving content for the moment.
    ///
    /// Returns an Id that must be kept to be able to append data to this entry.
    ///
    /// See `ArchiveWriter::append_entry_content` and `ArchiveWriter::end_entry`.
    pub fn start_entry(&mut self, name: EntryName) -> Result<ArchiveEntryId, Error> {
        check_state!(self.state, OpenedFiles);

        if self.entries_info.contains_key(&name) {
            return Err(Error::DuplicateEntryName);
        }

        // Create ID for this file
        let id = self.next_id;
        self.next_id = ArchiveEntryId(self.next_id.0 + 1);
        self.current_id = id;
        self.entries_info.insert(name.clone(), id);

        // Save the current position
        self.ids_info.insert(
            id,
            EntryInfo {
                offsets_and_sizes: vec![(self.dest.position(), 0)],
            },
        );
        // Use std::io::Empty as a readable placeholder type
        ArchiveEntryBlock::EntryStart::<std::io::Empty> {
            name,
            id,
            opts: Opts,
        }
        .dump(&mut self.dest)?;

        match &mut self.state {
            ArchiveWriterState::OpenedFiles { ids, hashes } => {
                ids.push(id);
                hashes.insert(id, Sha256::default());
            }
            ArchiveWriterState::Finalized => {
                // Never happens, due to `check_state!`
                return Err(Error::WrongWriterState(
                    "[StartFile] State have changes inside start_file".to_string(),
                ));
            }
        }
        Ok(id)
    }

    /// Appends data to an entry started with `ArchiveWriter::start_entry`.
    ///
    /// Can be called multiple times to append data to the same entry.
    /// Can be interleaved with other calls writing data for other entries.
    pub fn append_entry_content<U: Read>(
        &mut self,
        id: ArchiveEntryId,
        size: u64,
        src: U,
    ) -> Result<(), Error> {
        check_state_file_opened!(&self.state, &id);

        if size == 0 {
            // Avoid creating 0-sized block
            return Ok(());
        }

        self.record_offset_and_size_in_index(id, size)?;
        let src = self.state.wrap_with_hash(id, src)?;

        ArchiveEntryBlock::EntryContent {
            id,
            length: size,
            data: Some(src),
            opts: Opts,
        }
        .dump(&mut self.dest)
    }

    /// Mark an entry as terminated and record its Sha256 hash.
    pub fn end_entry(&mut self, id: ArchiveEntryId) -> Result<(), Error> {
        check_state_file_opened!(&self.state, &id);

        let hash = match &mut self.state {
            ArchiveWriterState::OpenedFiles { ids, hashes } => {
                let hash = hashes.remove(&id).ok_or_else(|| {
                    Error::WrongWriterState("[EndFile] Unable to retrieve the hash".to_string())
                })?;
                vec_remove_item(ids, &id);
                hash.finalize().into()
            }
            ArchiveWriterState::Finalized => {
                // Never happens, due to `check_state_file_opened!`
                return Err(Error::WrongWriterState(
                    "[EndFile] State have changes inside end_file".to_string(),
                ));
            }
        };

        self.record_offset_and_size_in_index(id, 0)?;
        // Use std::io::Empty as a readable placeholder type
        ArchiveEntryBlock::EndOfEntry::<std::io::Empty> {
            id,
            hash,
            opts: Opts,
        }
        .dump(&mut self.dest)?;

        Ok(())
    }

    /// Helper calling `start_entry`, `append_entry_content` and `end_entry` one after the other.
    pub fn add_entry<U: Read>(&mut self, name: EntryName, size: u64, src: U) -> Result<(), Error> {
        let id = self.start_entry(name)?;
        self.append_entry_content(id, size, src)?;
        self.end_entry(id)
    }

    /// Flushes data to the destination `Writer` `W`.
    /// Calls flush on the destination too.
    pub fn flush(&mut self) -> io::Result<()> {
        self.dest.flush()
    }
}

trait MLASerialize<W: Write> {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error>;
}

trait MLADeserialize<R: Read> {
    fn deserialize(src: &mut R) -> Result<Self, Error>
    where
        Self: std::marker::Sized;
}

impl<W: Write> MLASerialize<W> for u8 {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        dest.write_all(&[*self])?;
        Ok(1)
    }
}

impl<W: Write> MLASerialize<W> for u64 {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        dest.write_all(&self.to_le_bytes())?;
        Ok(8)
    }
}

impl<R: Read> MLADeserialize<R> for u64 {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let mut n = [0; 8];
        src.read_exact(&mut n)
            .map_err(|_| Error::DeserializationError)?;
        Ok(u64::from_le_bytes(n))
    }
}

impl<W: Write> MLASerialize<W> for usize {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        let u64self = u64::try_from(*self).map_err(|_| Error::SerializationError)?;
        dest.write_all(&u64self.to_le_bytes())?;
        Ok(8)
    }
}

impl<W: Write> MLASerialize<W> for u32 {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        dest.write_all(&self.to_le_bytes())?;
        Ok(4)
    }
}

impl<R: Read> MLADeserialize<R> for u32 {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let mut n = [0; 4];
        src.read_exact(&mut n)
            .map_err(|_| Error::DeserializationError)?;
        Ok(u32::from_le_bytes(n))
    }
}

impl<W: Write> MLASerialize<W> for u16 {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        dest.write_all(&self.to_le_bytes())?;
        Ok(2)
    }
}

impl<R: Read> MLADeserialize<R> for u16 {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let mut n = [0; 2];
        src.read_exact(&mut n)
            .map_err(|_| Error::DeserializationError)?;
        Ok(u16::from_le_bytes(n))
    }
}

impl<R: Read> MLADeserialize<R> for u8 {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let mut n = [0; 1];
        src.read_exact(&mut n)
            .map_err(|_| Error::DeserializationError)?;
        Ok(u8::from_le_bytes(n))
    }
}

impl<W: Write, A: MLASerialize<W>, B: MLASerialize<W>> MLASerialize<W> for (A, B) {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        let mut serialization_length = self.0.serialize(dest)?;
        serialization_length += self.1.serialize(dest)?;
        Ok(serialization_length)
    }
}

impl<W: Write, T: MLASerialize<W>> MLASerialize<W> for Vec<T> {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        let u64len = u64::try_from(self.len()).map_err(|_| Error::SerializationError)?;
        let mut serialization_length = u64len.serialize(dest)?;
        serialization_length += self.as_slice().serialize(dest)?;
        Ok(serialization_length)
    }
}

impl<W: Write, T: MLASerialize<W>> MLASerialize<W> for &[T] {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        let mut serialization_length = 0;
        for e in *self {
            serialization_length += e.serialize(dest)?;
        }
        Ok(serialization_length)
    }
}

impl<R: Read, T: MLADeserialize<R>> MLADeserialize<R> for Vec<T> {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let n = u64::deserialize(src)?;
        let v: Result<Vec<T>, Error> = (0..n).map(|_| T::deserialize(src)).collect();
        v
    }
}

impl<R: Read, const N: usize> MLADeserialize<R> for [u8; N] {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let mut a = [0; N];
        for e in &mut a {
            *e = u8::deserialize(src)?;
        }
        Ok(a)
    }
}

impl<R: Read, T1: MLADeserialize<R>, T2: MLADeserialize<R>> MLADeserialize<R> for (T1, T2) {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        Ok((T1::deserialize(src)?, T2::deserialize(src)?))
    }
}

// -------- Reader --------

#[cfg_attr(test, derive(PartialEq, Eq, Debug, Clone))]
pub(crate) struct EntryInfo {
    /// Entry information to save in the footer
    ///
    /// Offsets of chunks of `ArchiveEntryBlock`
    offsets_and_sizes: Vec<(u64, u64)>,
}

impl<W: Write> MLASerialize<W> for EntryInfo {
    fn serialize(&self, mut dest: &mut W) -> Result<u64, Error> {
        self.offsets_and_sizes.serialize(&mut dest)
    }
}

impl<R: Read> MLADeserialize<R> for EntryInfo {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let offsets_and_sizes = MLADeserialize::deserialize(src)?;

        Ok(Self { offsets_and_sizes })
    }
}

fn read_layer_magic<R: Read>(src: &mut R) -> Result<[u8; 8], Error> {
    let mut buf = [0; 8];
    src.read_exact(&mut buf)?;
    Ok(buf)
}

/// Use this to read an archive
pub struct ArchiveReader<'a, R: 'a + InnerReaderTrait> {
    /// MLA Archive format Reader
    //
    /// Source
    src: Box<dyn 'a + LayerReader<'a, R>>,
    /// Metadata (from footer if any)
    metadata: Option<ArchiveFooter>,
}

fn read_mla_entries_header(mut src: impl Read) -> Result<(), Error> {
    // Read the magic
    let mut magic = [0u8; 8];
    src.read_exact(&mut magic)?;
    if magic != *ENTRIES_LAYER_MAGIC {
        return Err(Error::WrongMagic);
    }
    read_mla_entries_header_skip_magic(src)
}

fn read_mla_entries_header_skip_magic(mut src: impl Read) -> Result<(), Error> {
    let _ = Opts::from_reader(&mut src)?; // No option handled at the moment
    Ok(())
}

impl<'b, R: 'b + InnerReaderTrait> ArchiveReader<'b, R> {
    /// Create an `ArchiveReader`.
    pub fn from_config(
        mut src: R,
        config: ArchiveReaderConfig,
    ) -> Result<(Self, Vec<MLASignatureVerificationPublicKey>), Error> {
        // Make sure we read the archive header from the start
        src.rewind()?;

        // Read Archive Header while hashing it
        let mut archive_header_hash = Sha512::new();
        let mut src = HashWrapperReader::new(src, &mut archive_header_hash);
        ArchiveHeader::deserialize(&mut src)?;

        // Pin the current position (after header) as the new 0
        let mut raw_src = Box::new(RawLayerReader::new(src.into_inner()));
        raw_src.reset_position()?;
        let mut src: Box<dyn 'b + LayerReader<'b, R>> = raw_src;

        // Read and strip tail (end magic, tail options)
        let end_magic_position = src.seek(SeekFrom::End(-8))?;
        let end_magic = read_layer_magic(&mut src)?;
        if &end_magic != END_MLA_MAGIC {
            return Err(Error::WrongEndMagic);
        }
        src.seek(SeekFrom::End(-16))?;
        let mla_footer_options_length = u64::deserialize(&mut src)?;
        let mla_tail_len = mla_footer_options_length + 16;
        let inner_len = end_magic_position + 8;
        src.seek(SeekFrom::Start(0))?;
        src = Box::new(StripHeadTailReader::new(
            src,
            0,
            mla_tail_len,
            inner_len,
            0,
        )?);

        // Enable layers depending on user option. Order is relevant

        // Read first layer magic while updating hash
        let mut src = HashWrapperReader::new(src, &mut archive_header_hash);
        let mut magic = read_layer_magic(&mut src)?;
        let mut src = src.into_inner();
        let accept_unencrypted = config.accept_unencrypted;

        // check signature first if any

        // The following var lets us ensure the encryption persistent config we use is the one read during signature verification
        // This is cool because it contains the key commitment.
        // Thus the authentication of the AEAD can protect us if the source we read from is manipulated after signature verification.
        let mut signed_persistent_encryption_config = None;
        let mut keys_with_valid_signatures = Vec::new();

        if magic == SIGNATURE_LAYER_MAGIC {
            let (sig_layer, new_keys_with_valid_signatures, read_persistent_encryption_config) =
                SignatureLayerReader::new_skip_magic(
                    src,
                    &config.signature_reader_config,
                    archive_header_hash,
                )?;
            signed_persistent_encryption_config = read_persistent_encryption_config;
            keys_with_valid_signatures = new_keys_with_valid_signatures;
            src = Box::new(sig_layer);
            src.initialize()?;
            magic = read_layer_magic(&mut src)?;
        } else if config.signature_reader_config.signature_check {
            return Err(Error::SignatureVerificationAskedButNoSignatureLayerFound);
        }

        if &magic == ENCRYPTION_LAYER_MAGIC {
            src = Box::new(EncryptionLayerReader::new_skip_magic(
                src,
                config.encrypt,
                signed_persistent_encryption_config,
            )?);
            src.initialize()?;
            magic = read_layer_magic(&mut src)?;
        } else if !accept_unencrypted {
            return Err(Error::EncryptionAskedButNotMarkedPresent);
        }

        if &magic == COMPRESSION_LAYER_MAGIC {
            src = Box::new(CompressionLayerReader::new_skip_magic(src)?);
            src.initialize()?;
        }

        // read `entries_footer_options`
        src.seek(SeekFrom::End(-8))?;
        let entries_footer_options_length = u64::deserialize(&mut src)?;
        // skip reading them as there are none for the moment

        // Read the eventual index in footer
        let entries_footer_length_offset_from_end =
            (-16i64) // -8 for Tail<Opts>'s length, -8 for `Tail<EntriesIndex>`'s length field
                .checked_sub_unsigned(entries_footer_options_length)
                .ok_or(Error::DeserializationError)?;
        // Read the index length
        src.seek(SeekFrom::End(entries_footer_length_offset_from_end))?;
        let entries_footer_length = u64::deserialize(&mut src)?;
        // Prepare for deserialization
        let start_of_entries_footer_from_current = (-8i64)
            .checked_sub_unsigned(entries_footer_length)
            .ok_or(Error::DeserializationError)?;
        src.seek(SeekFrom::Current(start_of_entries_footer_from_current))?;
        let metadata = ArchiveFooter::deserialize_from(&mut src)?;

        // Reset the position for further uses
        src.rewind()?;

        read_mla_entries_header(&mut src)?;

        Ok((ArchiveReader { src, metadata }, keys_with_valid_signatures))
    }

    /// Return an iterator on the name of each entry in the archive.
    ///
    /// Order is not relevant, and may change.
    pub fn list_entries(&self) -> Result<impl Iterator<Item = &EntryName>, Error> {
        if let Some(ArchiveFooter { entries_info, .. }) = &self.metadata {
            Ok(entries_info.keys())
        } else {
            Err(Error::MissingMetadata)
        }
    }

    /// Get the hash recorded in the archive footer for an entry content.
    pub fn get_hash(&mut self, name: &EntryName) -> Result<Option<Sha256Hash>, Error> {
        if let Some(ArchiveFooter { entries_info }) = &self.metadata {
            // Get file relative information
            let Some(file_info) = entries_info.get(name) else {
                return Ok(None);
            };

            // Set the inner layer at the start of the EoE tag
            let eoe_offset = file_info
                .offsets_and_sizes
                .last()
                .ok_or(Error::DeserializationError)?
                .0;
            self.src.seek(SeekFrom::Start(eoe_offset))?;

            // Return the file hash
            match ArchiveEntryBlock::from(&mut self.src)? {
                ArchiveEntryBlock::EndOfEntry { hash, .. } => Ok(Some(hash)),
                _ => Err(Error::WrongReaderState(
                    "[ArchiveReader] last offset must point to a EndOfEntry".to_string(),
                )),
            }
        } else {
            Err(Error::MissingMetadata)
        }
    }

    /// Get an archive entry.
    ///
    /// If no entry is found with given `name`, returns `Ok(None)`.
    /// If found, return `Ok(Some(e))` where e is an `ArchiveEntry`, letting you read its content and size.
    /// Returns an `Err` on error...
    pub fn get_entry(
        &mut self,
        name: EntryName,
    ) -> Result<Option<ArchiveEntry<'_, impl InnerReaderTrait>>, Error> {
        if let Some(ArchiveFooter { entries_info }) = &self.metadata {
            // Get file relative information
            let Some(file_info) = entries_info.get(&name) else {
                return Ok(None);
            };
            if file_info.offsets_and_sizes.is_empty() {
                return Err(Error::WrongReaderState(
                    "[ArchiveReader] A file must have at least one offset".to_string(),
                ));
            }

            // Instantiate the file representation
            let reader = ArchiveEntryDataReader::new(&mut self.src, &file_info.offsets_and_sizes)?;
            Ok(Some(ArchiveEntry { name, data: reader }))
        } else {
            Err(Error::MissingMetadata)
        }
    }
}

// This code is very similar with MLAArchiveReader

/// Use this to convert a truncated archive to one that can be opened with `ArchiveReader`, eventually loosing some content and security or performance properties.
pub struct TruncatedArchiveReader<'a, R: 'a + Read> {
    /// MLA Archive format Reader for eventually truncated archives
    //
    /// Source
    src: Box<dyn 'a + LayerTruncatedReader<'a, R>>,
}

// Size of the `clean-truncated` file blocks
const CACHE_SIZE: usize = 8 * 1024 * 1024; // 8MB

/// Used to update the error state only if it was `NoError`
/// ```text
/// update_error!(error_var, TruncatedReadError::...)
/// ```
macro_rules! update_error {
    ( $x:ident = $y:expr ) => {
        #[allow(clippy::single_match)]
        match $x {
            TruncatedReadError::NoError => {
                $x = $y;
            }
            _ => {}
        }
    };
}

impl<'b, R: 'b + Read> TruncatedArchiveReader<'b, R> {
    /// Create a `TruncatedArchiveReader` with given config.
    pub fn from_config(mut src: R, config: TruncatedReaderConfig) -> Result<Self, Error> {
        ArchiveHeader::deserialize(&mut src)?;

        // Enable layers depending on user option. Order is relevant
        let mut src: Box<dyn 'b + LayerTruncatedReader<'b, R>> =
            Box::new(RawLayerTruncatedReader::new(src));
        let accept_unencrypted = config.accept_unencrypted;
        let truncated_decryption_mode = config.truncated_decryption_mode;
        let mut magic = read_layer_magic(&mut src)?;
        if magic == SIGNATURE_LAYER_MAGIC {
            src = Box::new(SignatureLayerTruncatedReader::new_skip_magic(src)?);
            magic = read_layer_magic(&mut src)?;
        }
        if &magic == ENCRYPTION_LAYER_MAGIC {
            src = Box::new(EncryptionLayerTruncatedReader::new_skip_magic(
                src,
                config.encrypt,
                None,
                truncated_decryption_mode,
            )?);
            magic = read_layer_magic(&mut src)?;
        } else if !accept_unencrypted {
            return Err(Error::EncryptionAskedButNotMarkedPresent);
        }
        if &magic == COMPRESSION_LAYER_MAGIC {
            src = Box::new(CompressionLayerTruncatedReader::new_skip_magic(src)?);
            magic = read_layer_magic(&mut src)?;
        }

        if &magic != ENTRIES_LAYER_MAGIC {
            return Err(Error::DeserializationError);
        }

        // Read the magic
        read_mla_entries_header_skip_magic(&mut src)?;

        Ok(Self { src })
    }

    /// Best-effort conversion of the current archive to a correct
    /// one. On success, returns the reason conversion terminates (ideally,
    /// `EndOfOriginalArchiveData`)
    #[allow(clippy::cognitive_complexity)]
    pub fn convert_to_archive<W: InnerWriterTrait>(
        &mut self,
        mut output: ArchiveWriter<W>,
    ) -> Result<TruncatedReadError, Error> {
        let mut error = TruncatedReadError::NoError;

        // Associate an id retrieved from the archive to recover, to the
        // corresponding output file id
        let mut id_truncated2id_output: HashMap<ArchiveEntryId, ArchiveEntryId> = HashMap::new();
        // Associate an id retrieved from the archive to corresponding entry name
        let mut id_truncated2entryname: HashMap<ArchiveEntryId, EntryName> = HashMap::new();
        // List of IDs from the archive already fully added
        let mut id_truncated_done = Vec::new();
        // Associate an id retrieved from the archive with its ongoing Hash
        let mut id_truncated2hash: HashMap<ArchiveEntryId, Sha256> = HashMap::new();

        'read_block: loop {
            match ArchiveEntryBlock::from(&mut self.src) {
                Err(Error::IOError(err)) => {
                    if let std::io::ErrorKind::UnexpectedEof = err.kind() {
                        update_error!(error = TruncatedReadError::UnexpectedEOFOnNextBlock);
                        break;
                    }
                    update_error!(error = TruncatedReadError::IOErrorOnNextBlock(err));
                    break;
                }
                Err(err) => {
                    update_error!(error = TruncatedReadError::ErrorOnNextBlock(err));
                    break;
                }
                Ok(block) => {
                    match block {
                        ArchiveEntryBlock::EntryStart { name, id, opts: _ } => {
                            if let Some(_id_output) = id_truncated2id_output.get(&id) {
                                update_error!(error = TruncatedReadError::ArchiveEntryIDReuse(id));
                                break 'read_block;
                            }
                            if id_truncated_done.contains(&id) {
                                update_error!(
                                    error = TruncatedReadError::ArchiveEntryIDAlreadyClosed(id)
                                );
                                break 'read_block;
                            }

                            id_truncated2entryname.insert(id, name.clone());
                            let id_output = match output.start_entry(name.clone()) {
                                Err(Error::DuplicateEntryName) => {
                                    update_error!(
                                        error = TruncatedReadError::EntryNameReuse(
                                            name.raw_content_to_escaped_string()
                                        )
                                    );
                                    break 'read_block;
                                }
                                Err(err) => {
                                    return Err(err);
                                }
                                Ok(id) => id,
                            };
                            id_truncated2id_output.insert(id, id_output);
                            id_truncated2hash.insert(id, Sha256::default());
                        }
                        ArchiveEntryBlock::EntryContent { length, id, .. } => {
                            let id_output = if let Some(id_output) = id_truncated2id_output.get(&id)
                            {
                                *id_output
                            } else {
                                update_error!(
                                    error = TruncatedReadError::ContentForUnknownFile(id)
                                );
                                break 'read_block;
                            };

                            if id_truncated_done.contains(&id) {
                                update_error!(
                                    error = TruncatedReadError::ArchiveEntryIDAlreadyClosed(id)
                                );
                                break 'read_block;
                            }
                            let entry = id_truncated2entryname.get(&id).expect(
                                "`id_truncated2entryname` not more sync with `id_truncated2id_output`",
                            );
                            let hash = id_truncated2hash.get_mut(&id).expect(
                                "`id_truncated2hash` not more sync with `id_truncated2id_output`",
                            );

                            // Limit the reader to at most the file's content
                            let src = &mut (&mut self.src).take(length);

                            // `Read` trait normally guarantees that if an error is returned by `.read()`, no data
                            // has been read
                            //
                            // It must then be equivalent to
                            // - call `n` times the API for 1 byte looking for the first fail
                            // - call the API for `n` bytes, possibly returning a first bunch of bytes then a failure
                            //
                            // The second method is used to reduced the calls' count when recovering large files.
                            // Being equivalent to the first method, it should extracts as many bytes as possible
                            // from the potentially broken stream.
                            //
                            // Note: some `Read` implementation does not respect this contract, as it might be
                            // subject to different interpretation

                            // This buffer is used to reduced the resulting file fragmentation by aggregating `read` results
                            let mut buf = vec![0; CACHE_SIZE];
                            'content: loop {
                                let mut next_write_pos = 0;
                                'buf_fill: loop {
                                    match src.read(&mut buf[next_write_pos..]) {
                                        Ok(read) => {
                                            if read == 0 {
                                                // EOF
                                                break 'buf_fill;
                                            }
                                            next_write_pos += read;
                                        }
                                        Err(err) => {
                                            // Stop reconstruction
                                            output.append_entry_content(
                                                id_output,
                                                next_write_pos as u64,
                                                &buf[..next_write_pos],
                                            )?;
                                            update_error!(
                                                error = TruncatedReadError::ErrorInFile(
                                                    err,
                                                    entry.raw_content_to_escaped_string()
                                                )
                                            );
                                            break 'read_block;
                                        }
                                    }
                                    // Cache full
                                    if next_write_pos >= CACHE_SIZE {
                                        break 'buf_fill;
                                    }
                                }
                                output.append_entry_content(
                                    id_output,
                                    next_write_pos as u64,
                                    &buf[..next_write_pos],
                                )?;
                                hash.update(&buf[..next_write_pos]);
                                if next_write_pos < CACHE_SIZE {
                                    // EOF
                                    break 'content;
                                }
                            }
                        }
                        ArchiveEntryBlock::EndOfEntry {
                            id,
                            hash,
                            opts: Opts,
                        } => {
                            let id_output = if let Some(id_output) = id_truncated2id_output.get(&id)
                            {
                                *id_output
                            } else {
                                update_error!(error = TruncatedReadError::EOFForUnknownFile(id));
                                break 'read_block;
                            };

                            if id_truncated_done.contains(&id) {
                                update_error!(
                                    error = TruncatedReadError::ArchiveEntryIDAlreadyClosed(id)
                                );
                                break 'read_block;
                            }
                            if let Some(hash_archive) = id_truncated2hash.remove(&id) {
                                let computed_hash = hash_archive.finalize();
                                if computed_hash.as_slice() != hash {
                                    update_error!(
                                        error = TruncatedReadError::HashDiffers {
                                            expected: Vec::from(computed_hash.as_slice()),
                                            obtained: Vec::from(&hash[..]),
                                        }
                                    );
                                    break 'read_block;
                                }
                            } else {
                                // Synchronisation error
                                update_error!(
                                    error = TruncatedReadError::TruncatedReadInternalError
                                );
                                break 'read_block;
                            }

                            output.end_entry(id_output)?;
                            id_truncated_done.push(id);
                        }
                        ArchiveEntryBlock::EndOfArchiveData => {
                            // Expected end
                            update_error!(error = TruncatedReadError::EndOfOriginalArchiveData);
                            break 'read_block;
                        }
                    }
                }
            }
        }

        let mut unfinished_files = Vec::new();

        // Clean-up files still opened
        for (id_truncated, id_output) in id_truncated2id_output {
            if id_truncated_done.contains(&id_truncated) {
                // File is OK
                continue;
            }

            let entry = id_truncated2entryname
                .get(&id_truncated)
                .expect("`id_truncated2entryname` not more sync with `id_truncated2id_output`");
            output.end_entry(id_output)?;

            unfinished_files.push(entry.clone());
        }

        // Report which files are not completed, if any
        if !unfinished_files.is_empty() {
            error = TruncatedReadError::UnfinishedEntries {
                names: unfinished_files,
                stopping_error: Box::new(error),
            };
        }

        output.finalize()?;
        Ok(error)
    }
}

/// Extract information from MLA Header
pub mod info;

#[cfg(test)]
pub(crate) mod tests {
    use crate::config::TruncatedReaderDecryptionMode;
    use crate::crypto::mlakey::{MLAPrivateKey, MLAPublicKey, generate_mla_keypair_from_seed};

    use super::*;
    use crypto::hybrid::generate_keypair_from_seed;
    use rand::distributions::{Distribution, Standard};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;
    #[cfg(feature = "send")]
    use static_assertions;
    #[cfg(feature = "send")]
    use std::fs::File;
    use std::io::{Cursor, Empty, Read};

    #[test]
    fn read_dump_header() {
        let header = ArchiveHeader {
            format_version_number: MLA_FORMAT_VERSION,
        };
        let mut buf = Vec::new();
        header.serialize(&mut buf).unwrap();
        println!("{buf:?}");

        let header_rebuild = ArchiveHeader::deserialize(&mut buf.as_slice()).unwrap();
        assert_eq!(header_rebuild.format_version_number, MLA_FORMAT_VERSION);
    }

    #[test]
    fn dump_block() {
        let mut buf = Vec::new();
        let id = ArchiveEntryId(0);
        let hash = Sha256Hash::default();

        // std::io::Empty is used because a type with Read is needed
        ArchiveEntryBlock::EntryStart::<Empty> {
            id,
            name: EntryName::from_path("foobaré.exe").unwrap(),
            opts: Opts,
        }
        .dump(&mut buf)
        .unwrap();

        let fake_content = vec![1, 2, 3, 4];
        let mut block = ArchiveEntryBlock::EntryContent {
            id,
            length: fake_content.len() as u64,
            data: Some(fake_content.as_slice()),
            opts: Opts,
        };
        block.dump(&mut buf).unwrap();

        // std::io::Empty is used because a type with Read is needed
        ArchiveEntryBlock::EndOfEntry::<Empty> {
            id,
            hash,
            opts: Opts,
        }
        .dump(&mut buf)
        .unwrap();

        println!("{buf:?}");
    }

    #[test]
    fn new_mla() {
        let file = Vec::new();
        // Use a deterministic RNG in tests, for reproducibility. DO NOT DO THIS IS IN ANY RELEASED BINARY!
        let (private_key, public_key) = generate_keypair_from_seed([0; 32]);
        let config = ArchiveWriterConfig::with_encryption_without_signature(&[public_key]).unwrap();
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let fake_file = vec![1, 2, 3, 4];
        mla.add_entry(
            EntryName::from_path("my_file").unwrap(),
            fake_file.len() as u64,
            fake_file.as_slice(),
        )
        .unwrap();
        let fake_file = vec![5, 6, 7, 8];
        let fake_entry2 = vec![9, 10, 11, 12];
        let id = mla
            .start_entry(EntryName::from_path("my_entry2").unwrap())
            .unwrap();
        mla.append_entry_content(id, fake_file.len() as u64, fake_file.as_slice())
            .unwrap();
        mla.append_entry_content(id, fake_entry2.len() as u64, fake_entry2.as_slice())
            .unwrap();
        mla.end_entry(id).unwrap();

        let dest = mla.finalize().unwrap();
        let buf = Cursor::new(dest.as_slice());
        let config =
            ArchiveReaderConfig::without_signature_verification().with_encryption(&[private_key]);
        let mut mla_read = ArchiveReader::from_config(buf, config).unwrap().0;

        let mut file = mla_read
            .get_entry(EntryName::from_path("my_file").unwrap())
            .unwrap()
            .unwrap();
        let mut rez = Vec::new();
        file.data.read_to_end(&mut rez).unwrap();
        assert_eq!(rez, vec![1, 2, 3, 4]);
        // Explicit drop here, because otherwise mla_read.get_entry() cannot be
        // recall. It is not detected by the NLL analysis
        drop(file);
        let mut entry2 = mla_read
            .get_entry(EntryName::from_path("my_entry2").unwrap())
            .unwrap()
            .unwrap();
        let mut rez2 = Vec::new();
        entry2.data.read_to_end(&mut rez2).unwrap();
        assert_eq!(rez2, vec![5, 6, 7, 8, 9, 10, 11, 12]);
    }

    #[test]
    fn new_encryption_only_mla() {
        let file = Vec::new();
        // Use a deterministic RNG in tests, for reproducibility. DO NOT DO THIS IS IN ANY RELEASED BINARY!
        let (private_key, public_key) = generate_keypair_from_seed([0; 32]);
        let config = ArchiveWriterConfig::with_encryption_without_signature(&[public_key])
            .unwrap()
            .without_compression();
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let fake_file = vec![1, 2, 3, 4];
        mla.add_entry(
            EntryName::from_path("my_file").unwrap(),
            fake_file.len() as u64,
            fake_file.as_slice(),
        )
        .unwrap();
        let fake_file = vec![5, 6, 7, 8];
        let fake_entry2 = vec![9, 10, 11, 12];
        let id = mla
            .start_entry(EntryName::from_path("my_entry2").unwrap())
            .unwrap();
        mla.append_entry_content(id, fake_file.len() as u64, fake_file.as_slice())
            .unwrap();
        mla.append_entry_content(id, fake_entry2.len() as u64, fake_entry2.as_slice())
            .unwrap();
        mla.end_entry(id).unwrap();

        let dest = mla.finalize().unwrap();
        let buf = Cursor::new(dest.as_slice());
        let config =
            ArchiveReaderConfig::without_signature_verification().with_encryption(&[private_key]);
        let mut mla_read = ArchiveReader::from_config(buf, config).unwrap().0;

        let mut file = mla_read
            .get_entry(EntryName::from_path("my_file").unwrap())
            .unwrap()
            .unwrap();
        let mut rez = Vec::new();
        file.data.read_to_end(&mut rez).unwrap();
        assert_eq!(rez, vec![1, 2, 3, 4]);
        // Explicit drop here, because otherwise mla_read.get_entry() cannot be
        // recall. It is not detected by the NLL analysis
        drop(file);
        let mut entry2 = mla_read
            .get_entry(EntryName::from_path("my_entry2").unwrap())
            .unwrap()
            .unwrap();
        let mut rez2 = Vec::new();
        entry2.data.read_to_end(&mut rez2).unwrap();
        assert_eq!(rez2, vec![5, 6, 7, 8, 9, 10, 11, 12]);
    }

    #[test]
    fn new_naked_mla() {
        let file = Vec::new();
        // Use a deterministic RNG in tests, for reproducibility. DO NOT DO THIS IS IN ANY RELEASED BINARY!
        let config = ArchiveWriterConfig::without_encryption_without_signature()
            .unwrap()
            .without_compression();
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let fake_file = vec![1, 2, 3, 4];
        mla.add_entry(
            EntryName::from_path("my_file").unwrap(),
            fake_file.len() as u64,
            fake_file.as_slice(),
        )
        .unwrap();
        let fake_file = vec![5, 6, 7, 8];
        let fake_entry2 = vec![9, 10, 11, 12];
        let id = mla
            .start_entry(EntryName::from_path("my_entry2").unwrap())
            .unwrap();
        mla.append_entry_content(id, fake_file.len() as u64, fake_file.as_slice())
            .unwrap();
        mla.append_entry_content(id, fake_entry2.len() as u64, fake_entry2.as_slice())
            .unwrap();
        mla.end_entry(id).unwrap();

        let dest = mla.finalize().unwrap();
        let buf = Cursor::new(dest.as_slice());
        let config = ArchiveReaderConfig::without_signature_verification().without_encryption();
        let mut mla_read = ArchiveReader::from_config(buf, config).unwrap().0;

        let mut file = mla_read
            .get_entry(EntryName::from_path("my_file").unwrap())
            .unwrap()
            .unwrap();
        let mut rez = Vec::new();
        file.data.read_to_end(&mut rez).unwrap();
        assert_eq!(rez, vec![1, 2, 3, 4]);
        // Explicit drop here, because otherwise mla_read.get_entry() cannot be
        // recall. It is not detected by the NLL analysis
        drop(file);
        let mut entry2 = mla_read
            .get_entry(EntryName::from_path("my_entry2").unwrap())
            .unwrap()
            .unwrap();
        let mut rez2 = Vec::new();
        entry2.data.read_to_end(&mut rez2).unwrap();
        assert_eq!(rez2, vec![5, 6, 7, 8, 9, 10, 11, 12]);
    }

    #[test]
    fn new_compression_only_mla() {
        let file = Vec::new();
        // Use a deterministic RNG in tests, for reproducibility. DO NOT DO THIS IS IN ANY RELEASED BINARY!
        let config = ArchiveWriterConfig::without_encryption_without_signature().unwrap();
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let fake_file = vec![1, 2, 3, 4];
        mla.add_entry(
            EntryName::from_path("my_file").unwrap(),
            fake_file.len() as u64,
            fake_file.as_slice(),
        )
        .unwrap();
        let fake_file = vec![5, 6, 7, 8];
        let fake_entry2 = vec![9, 10, 11, 12];
        let id = mla
            .start_entry(EntryName::from_path("my_entry2").unwrap())
            .unwrap();
        mla.append_entry_content(id, fake_file.len() as u64, fake_file.as_slice())
            .unwrap();
        mla.append_entry_content(id, fake_entry2.len() as u64, fake_entry2.as_slice())
            .unwrap();
        mla.end_entry(id).unwrap();

        let dest = mla.finalize().unwrap();
        let buf = Cursor::new(dest.as_slice());
        let config = ArchiveReaderConfig::without_signature_verification().without_encryption();
        let mut mla_read = ArchiveReader::from_config(buf, config).unwrap().0;

        let mut file = mla_read
            .get_entry(EntryName::from_path("my_file").unwrap())
            .unwrap()
            .unwrap();
        let mut rez = Vec::new();
        file.data.read_to_end(&mut rez).unwrap();
        assert_eq!(rez, vec![1, 2, 3, 4]);
        // Explicit drop here, because otherwise mla_read.get_entry() cannot be
        // recall. It is not detected by the NLL analysis
        drop(file);
        let mut entry2 = mla_read
            .get_entry(EntryName::from_path("my_entry2").unwrap())
            .unwrap()
            .unwrap();
        let mut rez2 = Vec::new();
        entry2.data.read_to_end(&mut rez2).unwrap();
        assert_eq!(rez2, vec![5, 6, 7, 8, 9, 10, 11, 12]);
    }

    #[test]
    fn new_sig_mla() {
        let file = Vec::new();
        // Use a deterministic RNG in tests, for reproducibility. DO NOT DO THIS IS IN ANY RELEASED BINARY!
        let (private_key, public_key) = generate_mla_keypair_from_seed([0; 32]);
        let config = ArchiveWriterConfig::without_encryption_with_signature(&[private_key
            .get_signing_private_key()
            .clone()])
        .unwrap();
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let fake_file = vec![1, 2, 3, 4];
        mla.add_entry(
            EntryName::from_path("my_file").unwrap(),
            fake_file.len() as u64,
            fake_file.as_slice(),
        )
        .unwrap();
        let fake_file = vec![5, 6, 7, 8];
        let fake_entry2 = vec![9, 10, 11, 12];
        let id = mla
            .start_entry(EntryName::from_path("my_entry2").unwrap())
            .unwrap();
        mla.append_entry_content(id, fake_file.len() as u64, fake_file.as_slice())
            .unwrap();
        mla.append_entry_content(id, fake_entry2.len() as u64, fake_entry2.as_slice())
            .unwrap();
        mla.end_entry(id).unwrap();

        let dest = mla.finalize().unwrap();
        let buf = Cursor::new(dest.as_slice());
        let config = ArchiveReaderConfig::with_signature_verification(&[public_key
            .get_signature_verification_public_key()
            .clone()])
        .without_encryption();
        let mut mla_read = ArchiveReader::from_config(buf, config).unwrap().0;

        let mut file = mla_read
            .get_entry(EntryName::from_path("my_file").unwrap())
            .unwrap()
            .unwrap();
        let mut rez = Vec::new();
        file.data.read_to_end(&mut rez).unwrap();
        assert_eq!(rez, vec![1, 2, 3, 4]);
        // Explicit drop here, because otherwise mla_read.get_entry() cannot be
        // recall. It is not detected by the NLL analysis
        drop(file);
        let mut entry2 = mla_read
            .get_entry(EntryName::from_path("my_entry2").unwrap())
            .unwrap()
            .unwrap();
        let mut rez2 = Vec::new();
        entry2.data.read_to_end(&mut rez2).unwrap();
        assert_eq!(rez2, vec![5, 6, 7, 8, 9, 10, 11, 12]);
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn build_archive(
        compression: bool,
        encryption: bool,
        signature: bool,
        interleaved: bool,
    ) -> (
        Vec<u8>,
        (MLAPrivateKey, MLAPublicKey),
        (MLAPrivateKey, MLAPublicKey),
        Vec<(EntryName, Vec<u8>)>,
    ) {
        let (written_archive, sender_keys, receiver_keys, entries_content, _, _) =
            build_archive2(compression, encryption, signature, interleaved);
        (written_archive, sender_keys, receiver_keys, entries_content)
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn build_archive2(
        compression: bool,
        encryption: bool,
        signature: bool,
        interleaved: bool,
    ) -> (
        Vec<u8>,
        (MLAPrivateKey, MLAPublicKey),
        (MLAPrivateKey, MLAPublicKey),
        Vec<(EntryName, Vec<u8>)>,
        HashMap<EntryName, ArchiveEntryId>,
        HashMap<ArchiveEntryId, EntryInfo>,
    ) {
        // Build an archive with 3 files
        let file = Vec::new();
        // Use a deterministic RNG in tests, for reproducibility. DO NOT DO THIS IS IN ANY RELEASED BINARY!
        let (sender_private_key, sender_public_key) = generate_mla_keypair_from_seed([0; 32]);
        let (receiver_private_key, receiver_public_key) = generate_mla_keypair_from_seed([1; 32]);
        let config = if encryption {
            if signature {
                ArchiveWriterConfig::with_encryption_with_signature(
                    &[receiver_public_key.get_encryption_public_key().clone()],
                    &[sender_private_key.get_signing_private_key().clone()],
                )
            } else {
                ArchiveWriterConfig::with_encryption_without_signature(&[receiver_public_key
                    .get_encryption_public_key()
                    .clone()])
            }
        } else if signature {
            ArchiveWriterConfig::without_encryption_with_signature(&[sender_private_key
                .get_signing_private_key()
                .clone()])
        } else {
            ArchiveWriterConfig::without_encryption_without_signature()
        }
        .unwrap();
        let config = if compression {
            config
        } else {
            config.without_compression()
        };
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let entry1 = EntryName::from_arbitrary_bytes(b"my_entry1").unwrap();
        let entry2 = EntryName::from_arbitrary_bytes(b"my_entry2").unwrap();
        let entry3 = EntryName::from_arbitrary_bytes(b"my_entry3").unwrap();
        let fake_file_part1 = vec![1, 2, 3];
        let fake_file_part2 = vec![4, 5, 6, 7, 8];
        let mut fake_entry1 = Vec::new();
        fake_entry1.extend_from_slice(fake_file_part1.as_slice());
        fake_entry1.extend_from_slice(fake_file_part2.as_slice());
        let fake_entry2 = vec![9, 10, 11, 12];
        let fake_entry3 = vec![13, 14, 15];

        if interleaved {
            // Interleaved writes, expected result is:
            // [File1 start]
            // [File1 content 1 2 3]
            // [File2 start]
            // [File2 content 9 10 11 12]
            // [File3 start]
            // [File3 content 13 14 15]
            // [File3 end]
            // [File1 content 4 5 6 7 8]
            // [File1 end]
            // [File2 end]
            let id_entry1 = mla.start_entry(entry1.clone()).unwrap();
            mla.append_entry_content(
                id_entry1,
                fake_file_part1.len() as u64,
                fake_file_part1.as_slice(),
            )
            .unwrap();
            let id_entry2 = mla.start_entry(entry2.clone()).unwrap();
            mla.append_entry_content(id_entry2, fake_entry2.len() as u64, fake_entry2.as_slice())
                .unwrap();
            mla.add_entry(
                entry3.clone(),
                fake_entry3.len() as u64,
                fake_entry3.as_slice(),
            )
            .unwrap();
            mla.append_entry_content(
                id_entry1,
                fake_file_part2.len() as u64,
                fake_file_part2.as_slice(),
            )
            .unwrap();
            mla.end_entry(id_entry1).unwrap();
            mla.end_entry(id_entry2).unwrap();
        } else {
            mla.add_entry(
                entry1.clone(),
                fake_entry1.len() as u64,
                fake_entry1.as_slice(),
            )
            .unwrap();
            mla.add_entry(
                entry2.clone(),
                fake_entry2.len() as u64,
                fake_entry2.as_slice(),
            )
            .unwrap();
            mla.add_entry(
                entry3.clone(),
                fake_entry3.len() as u64,
                fake_entry3.as_slice(),
            )
            .unwrap();
        }
        let entries_info = mla.entries_info.clone();
        let ids_info = mla.ids_info.clone();
        let written_archive = mla.finalize().unwrap();

        (
            written_archive,
            (sender_private_key, sender_public_key),
            (receiver_private_key, receiver_public_key),
            vec![
                (entry1, fake_entry1),
                (entry2, fake_entry2),
                (entry3, fake_entry3),
            ],
            entries_info,
            ids_info,
        )
    }

    #[test]
    fn interleaved_files() {
        // Build an archive with 3 interleaved files
        let (mla, _sender_key, receiver_key, files) = build_archive(true, true, false, true);

        let buf = Cursor::new(mla.as_slice());
        let config = ArchiveReaderConfig::without_signature_verification()
            .with_encryption(&[receiver_key.0.get_decryption_private_key().clone()]);
        let mut mla_read = ArchiveReader::from_config(buf, config).unwrap().0;

        for (entry, content) in files {
            let mut file = mla_read.get_entry(entry).unwrap().unwrap();
            let mut rez = Vec::new();
            file.data.read_to_end(&mut rez).unwrap();
            assert_eq!(rez, content);
        }
    }

    #[test]
    fn mla_all_layer_combinations() {
        // Deterministic keys for reproducibility
        let (privkey, pubkey) = generate_mla_keypair_from_seed([42; 32]);

        // All combinations: (compress, encrypt, sign)
        let combinations = [
            (false, false, false), // naked
            (true, false, false),  // compress only
            (false, true, false),  // encrypt only
            (false, false, true),  // signature only
            (true, true, false),   // compress + encrypt
            (true, false, true),   // compress + signature
            (false, true, true),   // encrypt + signature
            (true, true, true),    // compress + encrypt + signature
        ];

        for (compress, encrypt, sign) in combinations {
            let mut config = match (encrypt, sign) {
                (true, true) => ArchiveWriterConfig::with_encryption_with_signature(
                    &[pubkey.get_encryption_public_key().clone()],
                    &[privkey.get_signing_private_key().clone()],
                )
                .unwrap(),
                (true, false) => ArchiveWriterConfig::with_encryption_without_signature(&[pubkey
                    .get_encryption_public_key()
                    .clone()])
                .unwrap(),
                (false, true) => ArchiveWriterConfig::without_encryption_with_signature(&[privkey
                    .get_signing_private_key()
                    .clone()])
                .unwrap(),
                (false, false) => {
                    ArchiveWriterConfig::without_encryption_without_signature().unwrap()
                }
            };
            if !compress {
                config = config.without_compression();
            }

            // Write archive
            let file = Vec::new();
            let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");
            let data = vec![1, 2, 3, 4, 5];
            mla.add_entry(
                EntryName::from_path("testfile").unwrap(),
                data.len() as u64,
                data.as_slice(),
            )
            .unwrap();
            let archive = mla.finalize().unwrap();

            // Read archive
            let buf = Cursor::new(archive);
            let reader_config = match (encrypt, sign) {
                (true, true) => ArchiveReaderConfig::with_signature_verification(&[pubkey
                    .get_signature_verification_public_key()
                    .clone()])
                .with_encryption(&[privkey.get_decryption_private_key().clone()]),
                (true, false) => ArchiveReaderConfig::without_signature_verification()
                    .with_encryption(&[privkey.get_decryption_private_key().clone()]),
                (false, true) => ArchiveReaderConfig::with_signature_verification(&[pubkey
                    .get_signature_verification_public_key()
                    .clone()])
                .without_encryption(),
                (false, false) => {
                    ArchiveReaderConfig::without_signature_verification().without_encryption()
                }
            };
            let mut mla_read = ArchiveReader::from_config(buf, reader_config).unwrap().0;
            let mut file = mla_read
                .get_entry(EntryName::from_path("testfile").unwrap())
                .unwrap()
                .unwrap();
            let mut out = Vec::new();
            file.data.read_to_end(&mut out).unwrap();
            assert_eq!(
                out,
                vec![1, 2, 3, 4, 5],
                "Failed for combination compress={compress}, encrypt={encrypt}, sign={sign}"
            );
        }
    }

    #[test]
    fn list_and_read_files() {
        // Build an archive with 3 files
        let (mla, _sender_key, receiver_key, files) = build_archive(true, true, false, false);

        let buf = Cursor::new(mla.as_slice());
        let config = ArchiveReaderConfig::without_signature_verification()
            .with_encryption(&[receiver_key.0.get_decryption_private_key().clone()]);
        let mut mla_read = ArchiveReader::from_config(buf, config).unwrap().0;

        // Check the list of files is correct
        let mut sorted_list: Vec<EntryName> = mla_read.list_entries().unwrap().cloned().collect();
        sorted_list.sort();
        assert_eq!(
            sorted_list,
            files.iter().map(|(x, _y)| x.clone()).collect::<Vec<_>>(),
        );

        // Get and check file per file, not in the writing order
        for (entry, content) in files.iter().rev() {
            let mut mla_file = mla_read.get_entry(entry.clone()).unwrap().unwrap();
            assert_eq!(mla_file.name, entry.clone());
            let mut buf = Vec::new();
            mla_file.data.read_to_end(&mut buf).unwrap();
            assert_eq!(&buf, content);
        }
    }

    #[test]
    fn convert_truncated() {
        // Build an archive with 3 files
        let (dest, _sender_key, receiver_key, files) = build_archive(true, true, false, false);

        // Prepare the truncated reader
        let config = TruncatedReaderConfig::without_signature_verification_with_encryption(
            &[receiver_key.0.get_decryption_private_key().clone()],
            TruncatedReaderDecryptionMode::OnlyAuthenticatedData,
        );
        let mut mla_fsread = TruncatedArchiveReader::from_config(dest.as_slice(), config).unwrap();

        // Prepare the writer
        let mut dest_w = Vec::new();
        let config = ArchiveWriterConfig::with_encryption_without_signature(&[receiver_key
            .1
            .get_encryption_public_key()
            .clone()])
        .unwrap();
        let mla_w = ArchiveWriter::from_config(&mut dest_w, config).expect("Writer init failed");

        // Conversion
        match mla_fsread.convert_to_archive(mla_w).unwrap() {
            TruncatedReadError::EndOfOriginalArchiveData => {
                // We expect to end with the final tag - all files have been
                // read and we stop on the tag before the footer
            }
            status => {
                panic!("Unexpected status: {status}");
            }
        }

        // New archive can now be checked
        let buf2 = Cursor::new(dest_w.as_slice());
        let config = ArchiveReaderConfig::without_signature_verification()
            .with_encryption(&[receiver_key.0.get_decryption_private_key().clone()]);
        let mut mla_read = ArchiveReader::from_config(buf2, config).unwrap().0;

        // Check the list of files is correct
        let mut sorted_list: Vec<EntryName> = mla_read.list_entries().unwrap().cloned().collect();
        sorted_list.sort();
        assert_eq!(
            sorted_list,
            files.iter().map(|(x, _y)| x.clone()).collect::<Vec<_>>(),
        );

        // Get and check file per file, not in the writing order
        for (entry, content) in files.iter().rev() {
            let mut mla_file = mla_read.get_entry(entry.clone()).unwrap().unwrap();
            assert_eq!(mla_file.name, entry.clone());
            let mut buf = Vec::new();
            mla_file.data.read_to_end(&mut buf).unwrap();
            assert_eq!(&buf, content);
        }
    }

    #[test]
    fn convert_trunc_truncated() {
        for interleaved in &[false, true] {
            // Build an archive with 3 files, without compressing to truncate at the correct place
            let (dest, _sender_key, receiver_key, files, entries_info, ids_info) =
                build_archive2(false, true, false, *interleaved);
            // Truncate the resulting file (before the footer, hopefully after the header), and prepare the truncated reader
            let footer_size = {
                let mut cursor = Cursor::new(Vec::new());
                ArchiveFooter::serialize_into(&mut cursor, &entries_info, &ids_info).unwrap();
                usize::try_from(cursor.position())
                    .expect("Failed to convert cursor position to usize")
            };

            for remove in &[1, 10, 30, 50, 70, 95, 100] {
                let config = TruncatedReaderConfig::without_signature_verification_with_encryption(
                    &[receiver_key.0.get_decryption_private_key().clone()],
                    TruncatedReaderDecryptionMode::DataEvenUnauthenticated,
                );
                let mut mla_fsread = TruncatedArchiveReader::from_config(
                    &dest[..dest.len() - footer_size - remove],
                    config,
                )
                .expect("Unable to create");

                // Prepare the writer
                let mut dest_w = Vec::new();
                let config_w =
                    ArchiveWriterConfig::with_encryption_without_signature(&[receiver_key
                        .1
                        .get_encryption_public_key()
                        .clone()])
                    .expect("Writer init failed");
                let mla_w = ArchiveWriter::from_config(&mut dest_w, config_w).unwrap();

                // Conversion
                let _status = mla_fsread.convert_to_archive(mla_w).unwrap();

                // New archive can now be checked
                let buf2 = Cursor::new(dest_w.as_slice());
                let config = ArchiveReaderConfig::without_signature_verification()
                    .with_encryption(&[receiver_key.0.get_decryption_private_key().clone()]);
                let mut mla_read = ArchiveReader::from_config(buf2, config).unwrap().0;

                // Check *the start of* the files list is correct
                let expected = files.iter().map(|(x, _y)| x.clone()).collect::<Vec<_>>();
                let mut file_list = mla_read
                    .list_entries()
                    .unwrap()
                    .cloned()
                    .collect::<Vec<_>>();
                file_list.sort();
                assert_eq!(
                    file_list[..],
                    expected[..file_list.len()],
                    "File lists not equal {} interleaving and {} bytes removed",
                    if *interleaved { "with" } else { "without" },
                    remove
                );

                // Get and check file per file, not in the writing order
                for (entry, content) in files.iter().rev() {
                    // The file may be missing
                    let Some(mut mla_file) = mla_read.get_entry(entry.clone()).unwrap() else {
                        continue;
                    };
                    // If the file is present, ensure there are bytes and the first
                    // bytes are the same
                    assert_eq!(mla_file.name, entry.clone());
                    let mut buf = Vec::new();
                    mla_file.data.read_to_end(&mut buf).unwrap();
                    assert_ne!(
                        buf.len(),
                        0,
                        "Read 0 bytes from entry {} {} interleaving and {} bytes removed",
                        mla_file.name.raw_content_to_escaped_string(),
                        if *interleaved { "with" } else { "without" },
                        remove
                    );
                    assert_eq!(&buf[..], &content[..buf.len()]);
                }
            }
            // /!\ This test doesn't ensure the code is doing the best effort; it only check the result is correct.
        }
    }

    #[test]
    fn avoid_duplicate_entryname() {
        let buf = Vec::new();
        let config = ArchiveWriterConfig::without_encryption_without_signature()
            .unwrap()
            .without_compression();
        let mut mla = ArchiveWriter::from_config(buf, config).unwrap();
        mla.add_entry(
            EntryName::from_path("Test").unwrap(),
            4,
            vec![1, 2, 3, 4].as_slice(),
        )
        .unwrap();
        assert!(
            mla.add_entry(
                EntryName::from_path("Test").unwrap(),
                4,
                vec![1, 2, 3, 4].as_slice()
            )
            .is_err()
        );
        assert!(
            mla.start_entry(EntryName::from_path("Test").unwrap())
                .is_err()
        );
    }

    #[test]
    fn check_file_size() {
        // Build an archive with 3 non-interleaved files and another with
        // interleaved files
        for interleaved in &[false, true] {
            let (dest, _sender_key, receiver_key, files, entries_info, ids_info) =
                build_archive2(true, true, false, *interleaved);

            for (entry, data) in &files {
                let id = entries_info.get(entry).unwrap();
                let size: u64 = ids_info
                    .get(id)
                    .unwrap()
                    .offsets_and_sizes
                    .iter()
                    .map(|p| p.1)
                    .sum();
                assert_eq!(size, data.len() as u64);
            }

            let buf = Cursor::new(dest.as_slice());
            let config = ArchiveReaderConfig::without_signature_verification()
                .with_encryption(&[receiver_key.0.get_decryption_private_key().clone()]);
            let mut mla_read = ArchiveReader::from_config(buf, config).unwrap().0;

            for (entry, data) in &files {
                let mla_file = mla_read.get_entry(entry.clone()).unwrap().unwrap();
                assert_eq!(mla_file.get_size(), data.len() as u64);
            }
        }
    }

    #[test]
    fn truncated_detect_integrity() {
        // Build an archive with 3 files
        let (mut dest, _sender_key, _receiver_key, files) =
            build_archive(false, false, false, false);

        // Swap the first 2 bytes of entry1
        let expect = files[0].1.as_slice();
        let pos: Vec<usize> = dest
            .iter()
            .enumerate()
            .filter_map(|e| {
                if e.0 + expect.len() < dest.len() && &dest[e.0..e.0 + expect.len()] == expect {
                    Some(e.0)
                } else {
                    None
                }
            })
            .collect();
        dest.swap(pos[0], pos[0] + 1);

        // Prepare the truncated reader
        let mut mla_fsread = TruncatedArchiveReader::from_config(
            dest.as_slice(),
            TruncatedReaderConfig::without_signature_verification_without_encryption(),
        )
        .unwrap();

        // Prepare the writer
        let dest_w = Vec::new();
        let config = ArchiveWriterConfig::without_encryption_without_signature()
            .unwrap()
            .without_compression();
        let mla_w = ArchiveWriter::from_config(dest_w, config).expect("Writer init failed");

        // Conversion
        match mla_fsread.convert_to_archive(mla_w).unwrap() {
            TruncatedReadError::UnfinishedEntries {
                names,
                stopping_error,
            } => {
                // We expect to ends with a HashDiffers on first file
                assert_eq!(names, vec![files[0].0.clone()]);
                match *stopping_error {
                    TruncatedReadError::HashDiffers { .. } => {}
                    _ => {
                        panic!("Unexpected stopping_error: {stopping_error}");
                    }
                }
            }
            status => {
                panic!("Unexpected status: {status}");
            }
        }
    }

    #[test]
    fn get_hash() {
        // Build an archive with 3 files
        let (dest, _sender_key, receiver_key, files) = build_archive(true, true, false, false);

        // Prepare the reader
        let buf = Cursor::new(dest.as_slice());
        let config = ArchiveReaderConfig::without_signature_verification()
            .with_encryption(&[receiver_key.0.get_decryption_private_key().clone()]);
        let mut mla_read = ArchiveReader::from_config(buf, config).unwrap().0;

        // Get hashes and compare
        for (name, content) in files {
            let hash = mla_read.get_hash(&name).unwrap().unwrap();

            let mut hasher = Sha256::new();
            hasher.update(content);
            let result = hasher.finalize();
            assert_eq!(result.as_slice(), hash);
        }
    }

    fn make_format_regression_files() -> HashMap<EntryName, Vec<u8>> {
        // Build files easily scriptables and checkable
        let mut files: HashMap<EntryName, Vec<u8>> = HashMap::new();

        // One simple file
        let mut simple: Vec<u8> = Vec::new();
        for i in 0..=255 {
            simple.push(i);
        }
        let pattern = simple.clone();
        files.insert(EntryName::from_path("simple").unwrap(), simple);

        // One big file (10 MB)
        let big: Vec<u8> = pattern
            .iter()
            .cycle()
            .take(10 * 1024 * 1024)
            .copied()
            .collect();
        files.insert(EntryName::from_path("big").unwrap(), big);

        // Some constant files
        for i in 0..=255 {
            files.insert(
                EntryName::from_path(format!("file_{i}")).unwrap(),
                std::iter::repeat_n(i, 0x1000).collect::<Vec<u8>>(),
            );
        }

        // sha256 sum of them
        let mut sha256sum: Vec<u8> = Vec::new();
        let mut info: Vec<(&EntryName, &Vec<_>)> = files.iter().collect();
        info.sort_by(|i1, i2| Ord::cmp(&i1.0, &i2.0));
        for (entry, content) in &info {
            let h = Sha256::digest(content);
            sha256sum.extend_from_slice(hex::encode(h).as_bytes());
            sha256sum.push(0x20);
            sha256sum.push(0x20);
            sha256sum.extend(entry.as_arbitrary_bytes());
            sha256sum.push(0x0a);
        }
        files.insert(EntryName::from_path("sha256sum").unwrap(), sha256sum);
        files
    }

    #[test]
    fn create_archive_format_version() {
        // Build an archive to be committed, for format regression
        let file = Vec::new();

        // Use committed keys
        let priv_bytes: &'static [u8] =
            include_bytes!("../../samples/test_mlakey_archive_v2_sender.mlapriv");
        let pub_bytes: &'static [u8] =
            include_bytes!("../../samples/test_mlakey_archive_v2_receiver.mlapub");
        let (_, priv_key) = MLAPrivateKey::deserialize_private_key(priv_bytes)
            .unwrap()
            .get_private_keys();
        let (pub_key, _) = MLAPublicKey::deserialize_public_key(pub_bytes)
            .unwrap()
            .get_public_keys();

        let mut config =
            ArchiveWriterConfig::with_encryption_with_signature(&[pub_key], &[priv_key]).unwrap();
        if let Some(cfg) = config.encryption.as_mut() {
            cfg.rng = crate::crypto::MaybeSeededRNG::Seed([0; 32]);
        }
        if let Some(cfg) = config.signature.as_mut() {
            cfg.rng = crate::crypto::MaybeSeededRNG::Seed([0; 32]);
        }
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let files = make_format_regression_files();
        // First, add a simple file
        let entry_simple = EntryName::from_path("simple").unwrap();
        mla.add_entry(
            entry_simple.clone(),
            files.get(&entry_simple).unwrap().len() as u64,
            files.get(&entry_simple).unwrap().as_slice(),
        )
        .unwrap();

        // Second, add interleaved files
        let entries: Vec<EntryName> = (0..=255)
            .map(|i| format!("file_{i}"))
            .map(|s| EntryName::from_path(&s).unwrap())
            .collect();
        let mut name2id: HashMap<_, _> = HashMap::new();

        // Start files in normal order
        (0..=255)
            .map(|i| {
                let id = mla.start_entry(entries[i].clone()).unwrap();
                name2id.insert(&entries[i], id);
            })
            .for_each(drop);

        // Add some parts in reverse order
        (0..=255)
            .rev()
            .map(|i| {
                let id = name2id.get(&entries[i]).unwrap();
                mla.append_entry_content(*id, 32, &files.get(&entries[i]).unwrap()[..32])
                    .unwrap();
            })
            .for_each(drop);

        // Add the rest of files in normal order
        (0..=255)
            .map(|i| {
                let id = name2id.get(&entries[i]).unwrap();
                let data = &files.get(&entries[i]).unwrap()[32..];
                mla.append_entry_content(*id, data.len() as u64, data)
                    .unwrap();
            })
            .for_each(drop);

        // Finish files in reverse order
        (0..=255)
            .rev()
            .map(|i| {
                let id = name2id.get(&entries[i]).unwrap();
                mla.end_entry(*id).unwrap();
            })
            .for_each(drop);

        // Add a big file
        let entry_big = EntryName::from_path("big").unwrap();
        mla.add_entry(
            entry_big.clone(),
            files.get(&entry_big).unwrap().len() as u64,
            files.get(&entry_big).unwrap().as_slice(),
        )
        .unwrap();

        // Add sha256sum file
        let entry_sha256sum = EntryName::from_path("sha256sum").unwrap();
        mla.add_entry(
            entry_sha256sum.clone(),
            files.get(&entry_sha256sum).unwrap().len() as u64,
            files.get(&entry_sha256sum).unwrap().as_slice(),
        )
        .unwrap();
        let raw_mla = mla.finalize().unwrap();

        std::fs::File::create(std::path::Path::new(&format!(
            "../samples/archive_v{MLA_FORMAT_VERSION}.mla"
        )))
        .unwrap()
        .write_all(&raw_mla)
        .unwrap();

        // check archive_v2 hash
        assert_eq!(
            Sha256::digest(&raw_mla).as_slice(),
            [
                252, 199, 175, 3, 17, 155, 237, 195, 81, 200, 149, 68, 209, 57, 5, 58, 245, 242,
                100, 13, 170, 168, 241, 27, 169, 112, 81, 182, 99, 141, 93, 248
            ]
        );
    }

    #[test]
    fn check_archive_format_v2_content() {
        let privbytes: &'static [u8] =
            include_bytes!("../../samples/test_mlakey_archive_v2_receiver.mlapriv");
        let pubbytes: &'static [u8] =
            include_bytes!("../../samples/test_mlakey_archive_v2_sender.mlapub");

        let mla_data: &'static [u8] = include_bytes!("../../samples/archive_v2.mla");
        let files = make_format_regression_files();

        // Build Reader
        let buf = Cursor::new(mla_data);
        let (privkey, _) = MLAPrivateKey::deserialize_private_key(privbytes)
            .unwrap()
            .get_private_keys();
        let (_, pubkey) = MLAPublicKey::deserialize_public_key(pubbytes)
            .unwrap()
            .get_public_keys();
        let config = ArchiveReaderConfig::with_signature_verification(&[pubkey])
            .with_encryption(std::slice::from_ref(&privkey));
        let mut mla_read = ArchiveReader::from_config(buf, config).unwrap().0;

        // Build TruncatedReader
        let config = TruncatedReaderConfig::without_signature_verification_with_encryption(
            &[privkey],
            TruncatedReaderDecryptionMode::OnlyAuthenticatedData,
        );
        let mut mla_fsread = TruncatedArchiveReader::from_config(mla_data, config).unwrap();

        // Repair the archive (without any damage, but trigger the corresponding code)
        let mut dest_w = Vec::new();
        let config = ArchiveWriterConfig::without_encryption_without_signature()
            .unwrap()
            .without_compression();
        let mla_w = ArchiveWriter::from_config(&mut dest_w, config).expect("Writer init failed");
        if let TruncatedReadError::EndOfOriginalArchiveData =
            mla_fsread.convert_to_archive(mla_w).unwrap()
        {
            // Everything runs as expected
        } else {
            panic!();
        }
        // Get a reader on the `clean-truncated` archive
        let buf2 = Cursor::new(dest_w);
        let repread_config =
            ArchiveReaderConfig::without_signature_verification().without_encryption();
        let mut mla_repread = ArchiveReader::from_config(buf2, repread_config).unwrap().0;

        assert_eq!(files.len(), mla_read.list_entries().unwrap().count());
        assert_eq!(files.len(), mla_repread.list_entries().unwrap().count());

        // Get and check file per file
        for (entry, content) in &files {
            let mut mla_file = mla_read.get_entry(entry.clone()).unwrap().unwrap();
            let mut mla_rep_file = mla_repread.get_entry(entry.clone()).unwrap().unwrap();
            assert_eq!(mla_file.name, entry.clone());
            assert_eq!(mla_rep_file.name, entry.clone());
            let mut buf = Vec::new();
            mla_file.data.read_to_end(&mut buf).unwrap();
            assert_eq!(buf.as_slice(), content.as_slice());
            let mut buf = Vec::new();
            mla_rep_file.data.read_to_end(&mut buf).unwrap();
            assert_eq!(buf.as_slice(), content.as_slice());
        }
    }

    #[test]
    fn not_path_entry_name() {
        let mut file: Vec<u8> = Vec::new();
        let priv_bytes: &'static [u8] =
            include_bytes!("../../samples/test_mlakey_archive_v2_sender.mlapriv");
        let pub_bytes: &'static [u8] =
            include_bytes!("../../samples/test_mlakey_archive_v2_receiver.mlapub");
        let (_, priv_key) = MLAPrivateKey::deserialize_private_key(priv_bytes)
            .unwrap()
            .get_private_keys();
        let (pub_key, _) = MLAPublicKey::deserialize_public_key(pub_bytes)
            .unwrap()
            .get_public_keys();

        let mut config =
            ArchiveWriterConfig::with_encryption_with_signature(&[pub_key], &[priv_key])
                .unwrap()
                .without_compression();
        if let Some(cfg) = config.encryption.as_mut() {
            cfg.rng = crate::crypto::MaybeSeededRNG::Seed([0; 32]);
        }
        if let Some(cfg) = config.signature.as_mut() {
            cfg.rng = crate::crypto::MaybeSeededRNG::Seed([0; 32]);
        }
        let mut mla = ArchiveWriter::from_config(&mut file, config).expect("Writer init failed");

        let name = EntryName::from_arbitrary_bytes(
            b"c:/\0;\xe2\x80\xae\nc\rd\x1b[1;31ma<script>evil\\../\xd8\x01\xc2\x85\xe2\x88\x95",
        )
        .unwrap();

        mla.add_entry(name.clone(), 8, b"' OR 1=1".as_slice())
            .expect("start_file");
        mla.finalize().unwrap();

        std::fs::File::create(std::path::Path::new("../samples/archive_weird.mla"))
            .unwrap()
            .write_all(&file)
            .unwrap();

        assert_eq!(
            Sha256::digest(&file).as_slice(),
            [
                95, 79, 59, 224, 200, 239, 240, 229, 137, 227, 3, 80, 95, 185, 106, 204, 219, 224,
                5, 102, 120, 246, 158, 151, 64, 151, 97, 52, 69, 134, 26, 25
            ]
        );
    }

    #[test]
    fn empty_blocks() {
        // Add a file with containing an empty block - it should work
        let file = Vec::new();
        let config = ArchiveWriterConfig::without_encryption_without_signature()
            .unwrap()
            .without_compression();
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let entry = EntryName::from_path("my_file").unwrap();
        let fake_file = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let id = mla.start_entry(entry.clone()).expect("start_file");
        mla.append_entry_content(id, 4, &fake_file[..4])
            .expect("add content");
        mla.append_entry_content(id, 0, &fake_file[..1])
            .expect("add content empty");
        mla.append_entry_content(id, fake_file.len() as u64 - 4, &fake_file[4..])
            .expect("add rest");
        mla.end_entry(id).unwrap();

        let mla_data = mla.finalize().unwrap();

        let buf = Cursor::new(mla_data);
        let mut mla_read = ArchiveReader::from_config(
            buf,
            ArchiveReaderConfig::without_signature_verification().without_encryption(),
        )
        .expect("archive reader")
        .0;
        let mut out = Vec::new();
        mla_read
            .get_entry(entry)
            .unwrap()
            .unwrap()
            .data
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out.as_slice(), fake_file.as_slice());
    }

    #[test]
    #[ignore = "As it is costly, only enabled by default in the CI."]
    fn more_than_u32_entry() {
        const MORE_THAN_U32: u64 = 0x0001_0001_0000; // U32_max + 0x10000
        const MAX_SIZE: u64 = 5 * 1024 * 1024 * 1024; // 5 GB
        const CHUNK_SIZE: usize = 10 * 1024 * 1024; // 10 MB

        // Use a deterministic RNG in tests, for reproducibility. DO NOT DO THIS IS IN ANY RELEASED BINARY!
        let mut rng = ChaChaRng::seed_from_u64(0);
        let mut rng_data = ChaChaRng::seed_from_u64(0);

        let (private_key, public_key) = generate_keypair_from_seed([0; 32]);
        let config = ArchiveWriterConfig::with_encryption_without_signature(&[public_key]).unwrap();
        let file = Vec::new();
        let mut mla = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        // At least one file will be bigger than 32bits
        let id1 = mla
            .start_entry(EntryName::from_path("file_0").unwrap())
            .unwrap();
        let mut cur_size = 0;
        while cur_size < MORE_THAN_U32 {
            let size = std::cmp::min(u64::from(rng.next_u32()), MORE_THAN_U32 - cur_size);
            let data: Vec<u8> = Standard
                .sample_iter(&mut rng_data)
                .take(usize::try_from(size).expect("Failed to convert size to usize"))
                .collect();
            mla.append_entry_content(id1, size, data.as_slice())
                .unwrap();
            cur_size += size;
        }
        mla.end_entry(id1).unwrap();

        let mut nb_file = 1;

        // Complete up to MAX_SIZE
        while cur_size < MAX_SIZE {
            let id = mla
                .start_entry(EntryName::from_path(format!("file_{nb_file:}")).unwrap())
                .unwrap();
            let size = std::cmp::min(u64::from(rng.next_u32()), MAX_SIZE - cur_size);
            let data: Vec<u8> = Standard
                .sample_iter(&mut rng_data)
                .take(usize::try_from(size).expect("Failed to convert size to usize"))
                .collect();
            mla.append_entry_content(id, size, data.as_slice()).unwrap();
            cur_size += size;
            mla.end_entry(id).unwrap();
            nb_file += 1;
        }
        let mla_data = mla.finalize().unwrap();

        // List files and check the list

        let buf = Cursor::new(mla_data);
        let config =
            ArchiveReaderConfig::without_signature_verification().with_encryption(&[private_key]);
        let mut mla_read = ArchiveReader::from_config(buf, config)
            .expect("archive reader")
            .0;

        let file_names: Vec<EntryName> = (0..nb_file)
            .map(|nb| EntryName::from_path(format!("file_{nb:}")).unwrap())
            .collect();
        let mut file_list = mla_read
            .list_entries()
            .unwrap()
            .cloned()
            .collect::<Vec<_>>();
        file_list.sort();
        assert_eq!(file_list, file_names);

        // Check files content

        // Using the same seed than the one used for data creation, we can compare expected content
        let mut rng_data = ChaChaRng::seed_from_u64(0);

        let mut chunk = vec![0u8; CHUNK_SIZE];
        for file_name in file_names {
            let mut file_stream = mla_read.get_entry(file_name).unwrap().unwrap().data;
            loop {
                let read = file_stream.read(&mut chunk).unwrap();
                let expect: Vec<u8> = Standard.sample_iter(&mut rng_data).take(read).collect();
                assert_eq!(&chunk[..read], expect.as_slice());
                if read == 0 {
                    break;
                }
            }
        }
    }

    #[test]
    fn signature_verification_fails_with_wrong_public_key() {
        let file = Vec::new();

        // Correct keypair for signing
        let (privkey_correct, _pubkey_correct) = generate_mla_keypair_from_seed([1u8; 32]);
        // Wrong public key for verification
        let (_privkey_wrong, pubkey_wrong) = generate_mla_keypair_from_seed([2u8; 32]);

        let config = ArchiveWriterConfig::without_encryption_with_signature(&[privkey_correct
            .get_signing_private_key()
            .clone()])
        .unwrap();

        let mut writer = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let data = vec![10, 20, 30, 40];
        writer
            .add_entry(
                EntryName::from_path("entry1").unwrap(),
                data.len() as u64,
                data.as_slice(),
            )
            .unwrap();

        let archive = writer.finalize().unwrap();
        let buf = Cursor::new(archive.as_slice());

        let config = ArchiveReaderConfig::with_signature_verification(&[pubkey_wrong
            .get_signature_verification_public_key()
            .clone()])
        .without_encryption();

        // Reading with wrong public key should fail on signature verification
        let reader_result = ArchiveReader::from_config(buf, config);

        assert!(
            reader_result.is_err(),
            "Verification should fail with wrong public key"
        );
    }

    #[test]
    fn signature_verification_fails_on_tampered_archive() {
        let file = Vec::new();

        let (privkey, pubkey) = generate_mla_keypair_from_seed([5u8; 32]);

        let config = ArchiveWriterConfig::without_encryption_with_signature(&[privkey
            .get_signing_private_key()
            .clone()])
        .unwrap();

        let mut writer = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let data = vec![50, 60, 70, 80];
        writer
            .add_entry(
                EntryName::from_path("my_file").unwrap(),
                data.len() as u64,
                data.as_slice(),
            )
            .unwrap();

        let mut archive = writer.finalize().unwrap();

        // Tamper with archive bytes (flip one byte)
        archive[10] ^= 0xFF;

        let buf = Cursor::new(archive.as_slice());

        let config = ArchiveReaderConfig::with_signature_verification(&[pubkey
            .get_signature_verification_public_key()
            .clone()])
        .without_encryption();

        // Signature verification should fail on tampered archive
        let result = ArchiveReader::from_config(buf, config);

        assert!(
            result.is_err(),
            "Signature verification should fail on tampered archive"
        );
    }

    #[test]
    fn signature_verification_fails_if_ed25519_signature_corrupted() {
        let file = Vec::new();

        let (privkey, pubkey) = generate_mla_keypair_from_seed([7u8; 32]);

        let config = ArchiveWriterConfig::without_encryption_with_signature(&[privkey
            .get_signing_private_key()
            .clone()])
        .unwrap();

        let mut writer = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let data = vec![10, 20, 30, 40];
        writer
            .add_entry(
                EntryName::from_path("entry1").unwrap(),
                data.len() as u64,
                data.as_slice(),
            )
            .unwrap();

        let mut archive = writer.finalize().unwrap();

        // Flip a byte inside Ed25519 signature payload,
        // should land in the middle of the Ed25519 signature
        let flip_pos = 50;
        archive[flip_pos] ^= 0xFF;

        let buf = std::io::Cursor::new(archive);

        let config = ArchiveReaderConfig::with_signature_verification(&[pubkey
            .get_signature_verification_public_key()
            .clone()])
        .without_encryption();

        let reader_result = ArchiveReader::from_config(buf, config);

        assert!(
            matches!(reader_result, Err(Error::NoValidSignatureFound)),
            "Verification should fail if Ed25519 signature is corrupted"
        );
    }

    #[test]
    fn signature_verification_fails_if_mldsa87_signature_corrupted() {
        let file = Vec::new();

        let (privkey, pubkey) = generate_mla_keypair_from_seed([8u8; 32]);

        let config = ArchiveWriterConfig::without_encryption_with_signature(&[privkey
            .get_signing_private_key()
            .clone()])
        .unwrap();

        let mut writer = ArchiveWriter::from_config(file, config).expect("Writer init failed");

        let data = vec![50, 60, 70, 80];
        writer
            .add_entry(
                EntryName::from_path("my_file").unwrap(),
                data.len() as u64,
                data.as_slice(),
            )
            .unwrap();

        let mut archive = writer.finalize().unwrap();

        // Flip a byte inside MlDsa87 signature payload,
        // should land in the middle of the MlDsa87 signature
        let flip_pos = 4000;
        archive[flip_pos] ^= 0xFF;

        let buf = std::io::Cursor::new(archive);

        let config = ArchiveReaderConfig::with_signature_verification(&[pubkey
            .get_signature_verification_public_key()
            .clone()])
        .without_encryption();

        let reader_result = ArchiveReader::from_config(buf, config);

        assert!(
            matches!(reader_result, Err(Error::NoValidSignatureFound)),
            "Verification should fail if MlDsa87 signature is corrupted"
        );
    }

    #[test]
    fn test_footer_deserialization_none() {
        let data = vec![0u8]; // 0x00 tag = no index
        let res = ArchiveFooter::deserialize_from(Cursor::new(&data)).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn test_footer_deserialization_invalid_index() {
        let data = vec![0x42]; // Not 0x00 or 0x01
        let res = ArchiveFooter::deserialize_from(Cursor::new(&data)).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn test_footer_deserialization_valid_index() {
        let (_dest, _sender_key, _receiver_key, _files, entries_info, ids_info) =
            build_archive2(false, false, false, false);

        // Manually write the index tag before the actual footer content
        let mut buf = Cursor::new(Vec::new());
        buf.write_all(&[1]).unwrap();
        ArchiveFooter::serialize_into(&mut buf, &entries_info, &ids_info).unwrap();
        buf.rewind().unwrap();

        let result = ArchiveFooter::deserialize_from(buf).unwrap();
        assert!(result.is_some());
    }

    #[test]
    #[cfg(feature = "send")]
    fn test_send() {
        static_assertions::assert_cfg!(feature = "send");
        static_assertions::assert_impl_all!(File: Send);
        static_assertions::assert_impl_all!(ArchiveWriter<File>: Send);
        static_assertions::assert_impl_all!(ArchiveReader<File>: Send);
    }
}
