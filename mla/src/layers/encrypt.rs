use crate::crypto::aesgcm::{
    AesGcm256, ConstantTimeEq, Key, Nonce, Tag, KEY_COMMITMENT_SIZE, TAG_LENGTH,
};

use crate::crypto::hpke::{compute_nonce, key_schedule_s};
use crate::crypto::hybrid::{
    HybridKemSharedSecret, HybridMultiRecipientEncapsulatedKey, HybridMultiRecipientsPublicKeys,
    HybridPrivateKey, HybridPublicKey,
};
use crate::layers::traits::{
    InnerWriterTrait, InnerWriterType, LayerFailSafeReader, LayerReader, LayerWriter,
};
use crate::Error;
use std::io;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom, Write};

use crate::config::{ArchiveReaderConfig, ArchiveWriterConfig};
use crate::errors::ConfigError;
use hpke::HpkeError;
use kem::{Decapsulate, Encapsulate};
use rand::SeedableRng;
use rand_chacha::{rand_core::CryptoRngCore, ChaChaRng};

use serde::{Deserialize, Deserializer, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::traits::InnerReaderTrait;

const CIPHER_BUF_SIZE: u64 = 4096;
const CHUNK_SIZE: u64 = 128 * 1024;

const ASSOCIATED_DATA: &[u8; 0] = b"";

// ---------- Key commitment ----------

/// Key commitment chain, to be used to ensure the key is actually the expected one
/// Enforce that all recipients are actually using the same key, so getting the same plaintext
const KEY_COMMITMENT_CHAIN: &[u8; KEY_COMMITMENT_SIZE] =
    b"-KEY COMMITMENT--KEY COMMITMENT--KEY COMMITMENT--KEY COMMITMENT-";

/// Encrypt the hardcoded `KEY_COMMITMENT_CHAIN` with the given key and nonce
fn build_key_commitment_chain(key: &Key, nonce: &Nonce) -> Result<KeyCommitmentAndTag, Error> {
    let mut key_commitment = [0u8; KEY_COMMITMENT_SIZE];
    key_commitment.copy_from_slice(KEY_COMMITMENT_CHAIN);
    let mut cipher = AesGcm256::new(key, &compute_nonce(nonce, 0), ASSOCIATED_DATA)?;
    cipher.encrypt(&mut key_commitment);
    let mut tag = [0u8; TAG_LENGTH];
    tag.copy_from_slice(&cipher.into_tag());
    Ok(KeyCommitmentAndTag {
        key_commitment,
        tag,
    })
}

fn check_key_commitment(
    key: &Key,
    nonce: &Nonce,
    commitment: &KeyCommitmentAndTag,
) -> Result<(), ConfigError> {
    let mut key_commitment = commitment.key_commitment;
    let mut cipher = AesGcm256::new(key, &compute_nonce(nonce, 0), ASSOCIATED_DATA)
        .or(Err(ConfigError::KeyCommitmentCheckingError))?;
    let tag = cipher.decrypt(&mut key_commitment);
    if tag.ct_eq(&commitment.tag).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(ConfigError::KeyCommitmentCheckingError)
    }
}

/// Number of the first chunk used for actual data
///
/// 0: used to encrypt the key commitment chain
/// 1-n: used for the actual data
const FIRST_DATA_CHUNK_NUMBER: u64 = 1;

// ---------- Config ----------
/// Encrypted Key commitment and associated tag
struct KeyCommitmentAndTag {
    key_commitment: [u8; KEY_COMMITMENT_SIZE],
    tag: [u8; TAG_LENGTH],
}

// For now, `serde` does not support generic const array, so [u8; 64] is not supported
// -> Serialize as [u8; 32][u8; 32]
// A Vec<u8> could also be used, but using array avoid having creating arbitrary sized vectors
// that early in the process
// TODO: use serde-big-array
impl Serialize for KeyCommitmentAndTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut part1: [u8; KEY_COMMITMENT_SIZE / 2] = [0; KEY_COMMITMENT_SIZE / 2];
        let mut part2: [u8; KEY_COMMITMENT_SIZE / 2] = [0; KEY_COMMITMENT_SIZE / 2];
        part1.copy_from_slice(&self.key_commitment[..KEY_COMMITMENT_SIZE / 2]);
        part2.copy_from_slice(&self.key_commitment[KEY_COMMITMENT_SIZE / 2..]);
        (part1, part2, self.tag).serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for KeyCommitmentAndTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (part1, part2, tag) = <(
            [u8; KEY_COMMITMENT_SIZE / 2],
            [u8; KEY_COMMITMENT_SIZE / 2],
            [u8; TAG_LENGTH],
        )>::deserialize(deserializer)?;
        let mut key_commitment = [0u8; KEY_COMMITMENT_SIZE];
        key_commitment[..KEY_COMMITMENT_SIZE / 2].copy_from_slice(&part1);
        key_commitment[KEY_COMMITMENT_SIZE / 2..].copy_from_slice(&part2);
        Ok(KeyCommitmentAndTag {
            key_commitment,
            tag,
        })
    }
}

/// Return a Cryptographic random number generator
pub(crate) fn get_crypto_rng() -> impl CryptoRngCore {
    // Use OsRng from crate rand, that uses getrandom() from crate getrandom.
    // getrandom provides implementations for many systems, listed on
    // https://docs.rs/getrandom/0.1.14/getrandom/
    // On Linux it uses `getrandom()` syscall and falls back on `/dev/urandom`.
    // On Windows it uses `RtlGenRandom` API (available since Windows XP/Windows Server 2003).
    //
    // So this seems to be secure, but unfortunately there is no strong
    // warranty that this would stay this way forever.
    // In order to be "better safe than sorry", seed `ChaChaRng` from the
    // bytes generated by `OsRng` in order to build a CSPRNG
    // (Cryptographically Secure PseudoRandom Number Generator).
    // This is actually what `ChaChaRng::from_entropy()` does:
    // https://github.com/rust-random/rand/blob/rand_core-0.5.1/rand_core/src/lib.rs#L378
    // and this function is documented as "secure" in
    // https://docs.rs/rand/0.7.3/rand/trait.SeedableRng.html#method.from_entropy
    //
    // For the same reasons, force at compile time that the Rng implements CryptoRngCore
    ChaChaRng::from_entropy()
}

#[derive(Zeroize, ZeroizeOnDrop)]
/// Cryptographic material used for encryption in the Encrypt layer
/// Part of this data must be kept secret and drop as soon as possible
pub(crate) struct InternalEncryptionConfig {
    pub(crate) key: Key,
    pub(crate) nonce: Nonce,
}

impl InternalEncryptionConfig {
    fn from(shared_secret: HybridKemSharedSecret) -> Result<Self, Error> {
        let (key, nonce) = key_schedule_s(&shared_secret.0)?;

        Ok(Self { key, nonce })
    }
}

/// Configuration stored in the header, to be reloaded
#[derive(Serialize, Deserialize)]
pub struct EncryptionPersistentConfig {
    /// Key-wrapping for each recipients
    pub multi_recipient: HybridMultiRecipientEncapsulatedKey,
    /// Encrypted version of the hardcoded `KEY_COMMITMENT_CHAIN`
    key_commitment: KeyCommitmentAndTag,
}

#[derive(Default)]
/// ArchiveWriterConfig specific configuration for the Encryption, to let API users specify encryption options
pub struct EncryptionConfig {
    /// Public keys of recipients
    public_keys: HybridMultiRecipientsPublicKeys,
}

impl EncryptionConfig {
    /// Consistency check
    pub fn check(&self) -> Result<(), ConfigError> {
        if self.public_keys.keys.is_empty() {
            Err(ConfigError::NoRecipients)
        } else {
            Ok(())
        }
    }

    /// Create a persistent version of the configuration to be reloaded
    ///    and the internal configuration, containing the cryptographic material
    ///
    /// This material is created for the current recipients, and several call to this function
    /// will results in several materials
    pub(crate) fn to_persistent(
        &self,
    ) -> Result<(EncryptionPersistentConfig, InternalEncryptionConfig), ConfigError> {
        // Generate then encapsulate the main key for each recipients
        let (multi_recipient, ss_hybrid) = self.public_keys.encapsulate(&mut get_crypto_rng())?;

        // Generate the main encrypt layer nonce and keep the main key for internal use
        let cryptographic_material = InternalEncryptionConfig::from(ss_hybrid)
            .or(Err(ConfigError::KeyWrappingComputationError))?;

        // Add a key commitment
        let key_commitment =
            build_key_commitment_chain(&cryptographic_material.key, &cryptographic_material.nonce)
                .or(Err(ConfigError::KeyCommitmentComputationError))?;

        // Create the persistent version, to be exported
        Ok((
            EncryptionPersistentConfig {
                multi_recipient,
                key_commitment,
            },
            cryptographic_material,
        ))
    }
}

impl ArchiveWriterConfig {
    /// Set public keys to use
    pub fn add_public_keys(&mut self, keys: &[HybridPublicKey]) -> &mut ArchiveWriterConfig {
        self.encrypt.public_keys.keys.extend_from_slice(keys);
        self
    }
}

#[derive(Default)]
pub struct EncryptionReaderConfig {
    /// Private key(s) to use
    private_keys: Vec<HybridPrivateKey>,
    /// Symmetric encryption key and nonce, if decrypted successfully from header
    // TODO: split in two, like InternalEncryptionConfig
    encrypt_parameters: Option<(Key, Nonce)>,
}

impl EncryptionReaderConfig {
    pub fn load_persistent(
        &mut self,
        config: EncryptionPersistentConfig,
    ) -> Result<(), ConfigError> {
        // Unwrap the private key
        if self.private_keys.is_empty() {
            return Err(ConfigError::PrivateKeyNotSet);
        }
        for private_key in &self.private_keys {
            if let Ok(ss_hybrid) = private_key.decapsulate(&config.multi_recipient) {
                let (key, nonce) = key_schedule_s(&ss_hybrid.0)
                    .or(Err(ConfigError::KeyWrappingComputationError))?;
                self.encrypt_parameters = Some((key, nonce));
                break;
            };
        }

        let (key, nonce) = &self
            .encrypt_parameters
            .ok_or(ConfigError::PrivateKeyNotFound)?;

        // A key has been found, check if it is the one expected
        check_key_commitment(key, nonce, &config.key_commitment)
    }
}

impl ArchiveReaderConfig {
    /// Set private key to use
    pub fn add_private_keys(&mut self, keys: &[HybridPrivateKey]) -> &mut ArchiveReaderConfig {
        self.encrypt.private_keys.extend_from_slice(keys);
        self
    }

    /// Retrieve key and nonce used for encryption
    pub fn get_encrypt_parameters(&self) -> Option<(Key, Nonce)> {
        self.encrypt.encrypt_parameters
    }
}

// ---------- Writer ----------

pub(crate) struct EncryptionLayerWriter<'a, W: 'a + InnerWriterTrait> {
    inner: InnerWriterType<'a, W>,
    cipher: AesGcm256,
    /// Symmetric encryption Key
    key: Key,
    /// Symmetric encryption nonce prefix, see `compute_nonce`
    base_nonce: Nonce,
    current_chunk_offset: u64,
    current_ctr: u64,
}

impl<'a, W: 'a + InnerWriterTrait> EncryptionLayerWriter<'a, W> {
    pub fn new(
        inner: InnerWriterType<'a, W>,
        internal_config: &InternalEncryptionConfig,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner,
            key: internal_config.key,
            base_nonce: internal_config.nonce,
            cipher: AesGcm256::new(
                &internal_config.key,
                &compute_nonce(&internal_config.nonce, FIRST_DATA_CHUNK_NUMBER),
                ASSOCIATED_DATA,
            )?,
            current_chunk_offset: 0,
            current_ctr: FIRST_DATA_CHUNK_NUMBER,
        })
    }

    fn renew_cipher(&mut self) -> Result<Tag, Error> {
        // Prepare a new cipher
        self.current_ctr = self
            .current_ctr
            .checked_add(1)
            .ok_or(HpkeError::MessageLimitReached)?;
        self.current_chunk_offset = 0;
        let cipher = AesGcm256::new(
            &self.key,
            &compute_nonce(&self.base_nonce, self.current_ctr),
            ASSOCIATED_DATA,
        )?;
        let old_cipher = std::mem::replace(&mut self.cipher, cipher);
        Ok(old_cipher.into_tag())
    }
}

impl<'a, W: 'a + InnerWriterTrait> LayerWriter<'a, W> for EncryptionLayerWriter<'a, W> {
    fn into_inner(self) -> Option<InnerWriterType<'a, W>> {
        Some(self.inner)
    }

    fn into_raw(self: Box<Self>) -> W {
        self.inner.into_raw()
    }

    fn finalize(&mut self) -> Result<(), Error> {
        // Write the tag of the current chunk
        let tag = self.renew_cipher()?;
        self.inner.write_all(&tag)?;

        // Recursive call
        self.inner.finalize()
    }
}

impl<'a, W: InnerWriterTrait> Write for EncryptionLayerWriter<'a, W> {
    #[allow(clippy::comparison_chain)]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.current_chunk_offset > CHUNK_SIZE {
            // Should never happen
            return Err(
                Error::WrongWriterState("[EncryptWriter] Chunk too big".to_string()).into(),
            );
        } else if self.current_chunk_offset == CHUNK_SIZE {
            // Prepare a new cipher
            let tag = self.renew_cipher()?;
            // Write the previous chunk tag
            self.inner.write_all(&tag)?;
        }

        // StreamingCipher is working in place, so we use a temporary buffer
        let size = std::cmp::min(
            std::cmp::min(CIPHER_BUF_SIZE, buf.len() as u64),
            CHUNK_SIZE - self.current_chunk_offset,
        );
        let mut buf_tmp = Vec::with_capacity(size as usize);
        let buf_src = BufReader::new(buf);
        io::copy(&mut buf_src.take(size), &mut buf_tmp)?;
        self.cipher.encrypt(&mut buf_tmp);
        self.inner.write_all(&buf_tmp)?;
        self.current_chunk_offset += size;
        Ok(size as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------- Reader ----------

// In the case of stream cipher, encrypting is the same that decrypting. Here, we
// keep the struct separated for any possible future difference
pub struct EncryptionLayerReader<'a, R: Read + Seek> {
    inner: Box<dyn 'a + LayerReader<'a, R>>,
    cipher: AesGcm256,
    key: Key,
    nonce: Nonce,
    chunk_cache: Cursor<Vec<u8>>,
    /// Current chunk number in the data.
    /// Note: the actual chunk number used in the cipher is offseted by FIRST_DATA_CHUNK_NUMBER
    current_chunk_number: u64,
}

impl<'a, R: 'a + Read + Seek> EncryptionLayerReader<'a, R> {
    pub fn new(
        inner: Box<dyn 'a + LayerReader<'a, R>>,
        config: &EncryptionReaderConfig,
    ) -> Result<Self, Error> {
        match config.encrypt_parameters {
            Some((key, nonce)) => Ok(Self {
                inner,
                cipher: AesGcm256::new(
                    &key,
                    &compute_nonce(&nonce, FIRST_DATA_CHUNK_NUMBER),
                    ASSOCIATED_DATA,
                )?,
                key,
                nonce,
                chunk_cache: Cursor::new(Vec::with_capacity(CHUNK_SIZE as usize)),
                current_chunk_number: 0,
            }),
            None => Err(Error::PrivateKeyNeeded),
        }
    }

    /// Load the `self.current_chunk_number` chunk in cache
    /// Assume the inner layer is in the correct position
    fn load_in_cache(&mut self) -> Result<Option<()>, Error> {
        self.cipher = AesGcm256::new(
            &self.key,
            &compute_nonce(
                &self.nonce,
                self.current_chunk_number + FIRST_DATA_CHUNK_NUMBER,
            ),
            ASSOCIATED_DATA,
        )?;

        // Clear current, now useless, allocated memory
        self.chunk_cache.get_mut().clear();

        // Load the current encrypted chunk and the corresponding tag in memory
        let mut data_and_tag = Vec::with_capacity(CHUNK_SIZE as usize + TAG_LENGTH);
        let data_and_tag_read = (&mut self.inner)
            .take(CHUNK_SIZE + TAG_LENGTH as u64)
            .read_to_end(&mut data_and_tag)?;
        // If the inner is at the end of the stream, we cannot read any
        // additional byte -> we must stop
        if data_and_tag_read == 0 {
            return Ok(None);
        }

        // If it is the last block, we may have read less than `CHUNK_SIZE +
        // TAG_LENGTH` bytes. But the `TAG_LENGTH` last bytes are always the tag
        // bytes -> extract it
        let mut tag = [0u8; TAG_LENGTH];
        tag.copy_from_slice(&data_and_tag[data_and_tag_read - TAG_LENGTH..]);
        data_and_tag.resize(data_and_tag_read - TAG_LENGTH, 0);
        let mut data = data_and_tag;

        // Decrypt and verify the current chunk
        let expected_tag = self.cipher.decrypt(data.as_mut_slice());
        if expected_tag.ct_eq(&tag).unwrap_u8() != 1 {
            Err(Error::AuthenticatedDecryptionWrongTag)
        } else {
            self.chunk_cache = Cursor::new(data);
            Ok(Some(()))
        }
    }
}

impl<'a, R: 'a + InnerReaderTrait> LayerReader<'a, R> for EncryptionLayerReader<'a, R> {
    fn into_inner(self) -> Option<Box<dyn 'a + LayerReader<'a, R>>> {
        Some(self.inner)
    }

    fn into_raw(self: Box<Self>) -> R {
        self.inner.into_raw()
    }

    fn initialize(&mut self) -> Result<(), Error> {
        // Recursive call
        self.inner.initialize()?;

        // Load the current buffer in cache
        self.rewind()?;
        Ok(())
    }
}

impl<'a, R: 'a + Read + Seek> Read for EncryptionLayerReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let cache_to_consume = CHUNK_SIZE - self.chunk_cache.position();
        if cache_to_consume == 0 {
            // Cache totally consumed, renew it
            self.current_chunk_number += 1;
            if self.load_in_cache()?.is_none() {
                // No more byte in the inner layer
                return Ok(0);
            }
            return self.read(buf);
        }
        // Consume at most the bytes leaving in the cache, to detect the renewal need
        let size = std::cmp::min(cache_to_consume as usize, buf.len());
        self.chunk_cache.read(&mut buf[..size])
    }
}

// Returns how many chunk are present at position `position`
const CHUNK_TAG_SIZE: u64 = CHUNK_SIZE + TAG_LENGTH as u64;

fn no_tag_position_to_tag_position(position: u64) -> u64 {
    let cur_chunk = position / CHUNK_SIZE;
    let cur_chunk_pos = position % CHUNK_SIZE;
    cur_chunk * CHUNK_TAG_SIZE + cur_chunk_pos
}

fn tag_position_to_no_tag_position(position: u64) -> u64 {
    // Assume the position is not inside a tag. If so, round to the end of the
    // current chunk
    let cur_chunk = position / CHUNK_TAG_SIZE;
    let cur_chunk_pos = position % CHUNK_TAG_SIZE;
    cur_chunk * CHUNK_SIZE + std::cmp::min(cur_chunk_pos, CHUNK_SIZE)
}

impl<'a, R: 'a + Read + Seek> Seek for EncryptionLayerReader<'a, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // `pos` is the position without considering tags
        match pos {
            SeekFrom::Start(pos) => {
                let tag_position = no_tag_position_to_tag_position(pos);
                let chunk_number = tag_position / CHUNK_TAG_SIZE;
                let pos_chunk_start = chunk_number * CHUNK_TAG_SIZE;
                let pos_in_chunk = tag_position % CHUNK_TAG_SIZE;

                // Seek the inner layer at the beginning of the chunk
                self.inner.seek(SeekFrom::Start(pos_chunk_start))?;

                // Load and move into the cache
                self.current_chunk_number = chunk_number;
                self.load_in_cache()?;
                self.chunk_cache.seek(SeekFrom::Start(pos_in_chunk))?;
                Ok(pos)
            }
            SeekFrom::Current(value) => {
                // Inner layer is at the start of the next chunk. The last chunk
                // may not be CHUNK_SIZE long.
                let current_inner = tag_position_to_no_tag_position(self.inner.seek(pos)?);
                let current_inner_chunk = {
                    let chunk_nb = current_inner / CHUNK_SIZE;
                    if chunk_nb == 0 {
                        // Only one chunk, witch is not CHUNK_SIZE long
                        0
                    } else {
                        chunk_nb - 1
                    }
                };
                let current = current_inner_chunk * CHUNK_SIZE + self.chunk_cache.position();
                if value == 0 {
                    // Optimization
                    Ok(current)
                } else {
                    self.seek(SeekFrom::Start((current as i64 + value) as u64))
                }
            }
            SeekFrom::End(pos) => {
                if pos > 0 {
                    // Seeking past the end is unsupported
                    return Err(Error::EndOfStream.into());
                }

                // The last chunk always have a TAG at its end, and might not be
                // CHUNK_SIZE long -> we need to remove the TAG size while
                // converting from tag-aware position to tag-unaware position
                let end_inner_pos = self.inner.seek(SeekFrom::End(0))?;
                let cur_chunk = end_inner_pos / CHUNK_TAG_SIZE;
                let cur_chunk_pos = end_inner_pos % CHUNK_TAG_SIZE;
                let end_pos = cur_chunk * CHUNK_SIZE + cur_chunk_pos - TAG_LENGTH as u64;
                self.seek(SeekFrom::Start((pos + end_pos as i64) as u64))
            }
        }
    }
}

// ---------- Fail-Safe Reader ----------

pub struct EncryptionLayerFailSafeReader<'a, R: Read> {
    inner: Box<dyn 'a + LayerFailSafeReader<'a, R>>,
    cipher: AesGcm256,
    key: Key,
    nonce: Nonce,
    current_chunk_number: u64,
    current_chunk_offset: u64,
}

impl<'a, R: 'a + Read> EncryptionLayerFailSafeReader<'a, R> {
    pub fn new(
        inner: Box<dyn 'a + LayerFailSafeReader<'a, R>>,
        config: &EncryptionReaderConfig,
    ) -> Result<Self, Error> {
        match config.encrypt_parameters {
            Some((key, nonce)) => Ok(Self {
                inner,
                cipher: AesGcm256::new(
                    &key,
                    &compute_nonce(&nonce, FIRST_DATA_CHUNK_NUMBER),
                    ASSOCIATED_DATA,
                )?,
                key,
                nonce,
                current_chunk_number: 0,
                current_chunk_offset: 0,
            }),
            None => Err(Error::PrivateKeyNeeded),
        }
    }
}

impl<'a, R: 'a + Read> LayerFailSafeReader<'a, R> for EncryptionLayerFailSafeReader<'a, R> {
    fn into_inner(self) -> Option<Box<dyn 'a + LayerFailSafeReader<'a, R>>> {
        Some(self.inner)
    }

    fn into_raw(self: Box<Self>) -> R {
        self.inner.into_raw()
    }
}

impl<'a, R: Read> Read for EncryptionLayerFailSafeReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.current_chunk_offset == CHUNK_SIZE {
            // Ignore the tag and renew the cipher
            io::copy(
                &mut (&mut self.inner).take(TAG_LENGTH as u64),
                &mut io::sink(),
            )?;
            self.current_chunk_number = self
                .current_chunk_number
                .checked_add(1)
                .ok_or(Error::HPKEError(HpkeError::MessageLimitReached))?;
            self.current_chunk_offset = 0;
            self.cipher = AesGcm256::new(
                &self.key,
                &compute_nonce(
                    &self.nonce,
                    self.current_chunk_number + FIRST_DATA_CHUNK_NUMBER,
                ),
                ASSOCIATED_DATA,
            )?;
            return self.read(buf);
        }

        // AesGcm256 is working in place, so we use a temporary buffer
        let mut buf_tmp = [0u8; CIPHER_BUF_SIZE as usize];
        let size = std::cmp::min(CIPHER_BUF_SIZE as usize, buf.len());
        // Read at most the chunk size, to detect when renewal is needed
        let size = std::cmp::min((CHUNK_SIZE - self.current_chunk_offset) as usize, size);
        let len = self.inner.read(&mut buf_tmp[..size])?;
        self.current_chunk_offset += len as u64;
        self.cipher.decrypt_unauthenticated(&mut buf_tmp[..len]);
        (&buf_tmp[..len]).read_exact(&mut buf[..len])?;
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::distributions::{Alphanumeric, Distribution};
    use rand::SeedableRng;
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    use crate::crypto::aesgcm::{KEY_SIZE, NONCE_AES_SIZE};
    use crate::layers::raw::{RawLayerFailSafeReader, RawLayerReader, RawLayerWriter};

    static FAKE_FILE: [u8; 26] = *b"abcdefghijklmnopqrstuvwxyz";
    static KEY: Key = [2u8; KEY_SIZE];
    static NONCE: Nonce = [3u8; NONCE_AES_SIZE];

    fn encrypt_write(file: Vec<u8>) -> Vec<u8> {
        // Instantiate a EncryptionLayerWriter and fill it with FAKE_FILE
        let mut encrypt_w = Box::new(
            EncryptionLayerWriter::new(
                Box::new(RawLayerWriter::new(file)),
                &InternalEncryptionConfig {
                    key: KEY,
                    nonce: NONCE,
                },
            )
            .unwrap(),
        );
        encrypt_w.write_all(&FAKE_FILE[..21]).unwrap();
        encrypt_w.write_all(&FAKE_FILE[21..]).unwrap();
        encrypt_w.finalize().unwrap();

        let out = encrypt_w.into_raw();
        assert_eq!(out.len(), FAKE_FILE.len() + TAG_LENGTH);
        assert_ne!(out[..FAKE_FILE.len()], FAKE_FILE);
        out
    }

    #[test]
    fn encrypt_layer() {
        let file = Vec::new();
        let out = encrypt_write(file);

        let buf = Cursor::new(out.as_slice());
        let config = EncryptionReaderConfig {
            private_keys: Vec::new(),
            encrypt_parameters: Some((KEY, NONCE)),
        };
        let mut encrypt_r =
            EncryptionLayerReader::new(Box::new(RawLayerReader::new(buf)), &config).unwrap();
        encrypt_r.initialize().unwrap();
        let mut output = Vec::new();
        encrypt_r.read_to_end(&mut output).unwrap();
        assert_eq!(output, FAKE_FILE);
    }

    #[test]
    fn encrypt_failsafe_layer() {
        let file = Vec::new();
        let out = encrypt_write(file);

        let config = EncryptionReaderConfig {
            private_keys: Vec::new(),
            encrypt_parameters: Some((KEY, NONCE)),
        };
        let mut encrypt_r = EncryptionLayerFailSafeReader::new(
            Box::new(RawLayerFailSafeReader::new(out.as_slice())),
            &config,
        )
        .unwrap();
        let mut output = Vec::new();
        encrypt_r.read_to_end(&mut output).unwrap();
        // Extra output expected, due to the ignored tag in the last chunk
        assert_eq!(output[..FAKE_FILE.len()], FAKE_FILE);
    }

    #[test]
    fn encrypt_failsafe_truncated() {
        let file = Vec::new();
        let out = encrypt_write(file);

        // Truncate at the middle
        let stop = out.len() / 2;

        let config = EncryptionReaderConfig {
            private_keys: Vec::new(),
            encrypt_parameters: Some((KEY, NONCE)),
        };
        let mut encrypt_r = EncryptionLayerFailSafeReader::new(
            Box::new(RawLayerFailSafeReader::new(&out[..stop])),
            &config,
        )
        .unwrap();
        let mut output = Vec::new();
        encrypt_r.read_to_end(&mut output).unwrap();
        // Thanks to the encrypt layer construction, we can recover `stop` bytes
        assert_eq!(output.as_slice(), &FAKE_FILE[..stop]);
    }

    #[test]
    fn seek_encrypt() {
        // First, encrypt a dummy file
        let file = Vec::new();
        let out = encrypt_write(file);

        // Normal decryption
        let buf = Cursor::new(out.as_slice());
        let config = EncryptionReaderConfig {
            private_keys: Vec::new(),
            encrypt_parameters: Some((KEY, NONCE)),
        };
        let mut encrypt_r =
            EncryptionLayerReader::new(Box::new(RawLayerReader::new(buf)), &config).unwrap();
        encrypt_r.initialize().unwrap();
        let mut output = Vec::new();
        encrypt_r.read_to_end(&mut output).unwrap();
        assert_eq!(output, FAKE_FILE);

        // Seek and decrypt twice the same thing
        let pos = encrypt_r.stream_position().unwrap();
        // test the current position retrievial
        assert_eq!(pos, tag_position_to_no_tag_position(FAKE_FILE.len() as u64));
        // decrypt twice the same thing, with an offset
        let pos = encrypt_r.seek(SeekFrom::Start(5)).unwrap();
        assert_eq!(pos, 5);
        let mut output = Vec::new();
        encrypt_r.read_to_end(&mut output).unwrap();
        println!("{:?}", output);
        assert_eq!(output.as_slice(), &FAKE_FILE[5..]);
    }

    #[test]
    fn encrypt_op_chunk_size() {
        // Operate near the chunk size

        // Instantiate a EncryptionLayerWriter and fill it with at least CHUNK_SIZE data
        let file = Vec::new();
        let mut encrypt_w = Box::new(
            EncryptionLayerWriter::new(
                Box::new(RawLayerWriter::new(file)),
                &InternalEncryptionConfig {
                    key: KEY,
                    nonce: NONCE,
                },
            )
            .unwrap(),
        );
        let length = (CHUNK_SIZE * 2) as usize;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0);
        let data: Vec<u8> = Alphanumeric.sample_iter(&mut rng).take(length).collect();
        encrypt_w.write_all(&data).unwrap();
        encrypt_w.finalize().unwrap();

        let out = encrypt_w.into_raw();
        assert_eq!(out.len(), length + 2 * TAG_LENGTH);
        assert_ne!(&out[..length], data.as_slice());

        // Normal decryption
        let buf = Cursor::new(out.as_slice());
        let config = EncryptionReaderConfig {
            private_keys: Vec::new(),
            encrypt_parameters: Some((KEY, NONCE)),
        };
        let mut encrypt_r =
            EncryptionLayerReader::new(Box::new(RawLayerReader::new(buf)), &config).unwrap();
        encrypt_r.initialize().unwrap();
        let mut output = Vec::new();
        encrypt_r.read_to_end(&mut output).unwrap();
        assert_eq!(output, data);

        // Seek and decrypt twice the same thing
        let pos = encrypt_r.seek(SeekFrom::Start(CHUNK_SIZE)).unwrap();
        assert_eq!(pos, CHUNK_SIZE);
        let mut output = Vec::new();
        encrypt_r.read_to_end(&mut output).unwrap();
        assert_eq!(output.as_slice(), &data[CHUNK_SIZE as usize..]);
    }

    #[test]
    fn build_key_commitment_chain_test() {
        // Build the encrypted key commitment chain
        let key: Key = [1u8; KEY_SIZE];
        let nonce: Nonce = [2u8; NONCE_AES_SIZE];
        let result = build_key_commitment_chain(&key, &nonce);
        assert!(result.is_ok());
        let key_commitment_and_tag = result.unwrap();

        // Decrypt it
        let mut cipher = AesGcm256::new(&key, &compute_nonce(&nonce, 0), ASSOCIATED_DATA).unwrap();
        let mut decrypted_key_commitment = [0u8; KEY_COMMITMENT_SIZE];
        decrypted_key_commitment.copy_from_slice(&key_commitment_and_tag.key_commitment);
        let tag = cipher.decrypt(&mut decrypted_key_commitment);
        assert_eq!(tag.ct_eq(&key_commitment_and_tag.tag).unwrap_u8(), 1);
        assert_eq!(decrypted_key_commitment, *KEY_COMMITMENT_CHAIN);
    }

    #[test]
    fn check_key_commitment_test() {
        // Build the encrypted key commitment chain
        let key: Key = [1u8; KEY_SIZE];
        let nonce: Nonce = [2u8; NONCE_AES_SIZE];
        let result = build_key_commitment_chain(&key, &nonce);
        assert!(result.is_ok());
        let key_commitment_and_tag = result.unwrap();

        // Check it
        let result = check_key_commitment(&key, &nonce, &key_commitment_and_tag);
        assert!(result.is_ok());

        // Test with invalid key commitment
        let invalid_key_commitment_and_tag = KeyCommitmentAndTag {
            key_commitment: [0u8; KEY_COMMITMENT_SIZE],
            tag: [0u8; TAG_LENGTH],
        };
        let result = check_key_commitment(&key, &nonce, &invalid_key_commitment_and_tag);
        assert!(result.is_err());
    }
}
