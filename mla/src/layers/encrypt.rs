use crate::config::TruncatedReaderDecryptionMode;
use crate::crypto::aesgcm::{
    AesGcm256, ConstantTimeEq, KEY_COMMITMENT_SIZE, Key, Nonce, TAG_LENGTH, Tag,
};

use crate::crypto::MaybeSeededRNG;
use crate::crypto::hpke::{compute_nonce, key_schedule_base_hybrid_kem};
use crate::crypto::hybrid::{
    HybridKemSharedSecret, HybridMultiRecipientEncapsulatedKey, HybridMultiRecipientsPublicKeys,
    MLADecryptionPrivateKey, MLAEncryptionPublicKey,
};
use crate::helpers::shared_secret::MLADecryptionSharedSecret;
use crate::layers::traits::{
    InnerWriterTrait, InnerWriterType, LayerReader, LayerTruncatedReader, LayerWriter,
};
use crate::{EMPTY_TAIL_OPTS_SERIALIZATION, Error, MLADeserialize, MLASerialize, Opts};
use std::io::{self, ErrorKind};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use crate::errors::ConfigError;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::position::PositionLayerReader;
use super::strip_head_tail::StripHeadTailReader;
use super::traits::InnerReaderTrait;

const CIPHER_BUF_SIZE: u64 = 4096;
// /!\ NORMAL_CHUNK_PT_SIZE value is SECURITY CRITICAL : a chunk size of 64GB or more would be out of AES-GCM security bounds. Please keep this value below. /!\
const NORMAL_CHUNK_PT_SIZE: u64 = 128 * 1024;
const NORMAL_CHUNK_PT_AND_TAG_SIZE: u64 = NORMAL_CHUNK_PT_SIZE + TAG_LENGTH as u64;
// allowed as NORMAL_CHUNK_PT_SIZE and TAG_LENGTH are small enough and known at compile time
#[allow(clippy::cast_possible_truncation)]
const NORMAL_CHUNK_PT_AND_TAG_USIZE: usize = NORMAL_CHUNK_PT_AND_TAG_SIZE as usize;

const ASSOCIATED_DATA: &[u8; 0] = b"";
const FINAL_ASSOCIATED_DATA: &[u8; 8] = b"FINALAAD";
const FINAL_BLOCK_CONTENT: &[u8; 10] = b"FINALBLOCK";

const FINAL_INFO_SIZE: u64 = FINAL_INFO_USIZE as u64;
const FINAL_INFO_USIZE: usize = FINAL_BLOCK_MAGIC.len() + FINAL_BLOCK_CONTENT.len() + TAG_LENGTH;
// WithOut Magic
const FINAL_INFO_SIZE_WOM: usize = FINAL_BLOCK_CONTENT.len() + TAG_LENGTH;

const FINAL_BLOCK_MAGIC: &[u8] = b"M0FNLBLK";

pub const ENCRYPTION_LAYER_MAGIC: &[u8; 8] = b"ENCMLAAA";

const END_OF_ENCRYPTED_INNER_LAYER_MAGIC: &[u8; 8] = b"ENCMLAAB";

const CHUNK_MAGIC: &[u8; 8] = b"M0ENCCNK";
const CHUNK_HEAD_SIZE: u64 = CHUNK_HEAD_USIZE as u64;
const CHUNK_HEAD_USIZE: usize = CHUNK_MAGIC.len() + 8;
const M0_CHUNK_SIZE: u64 = M0_CHUNK_USIZE as u64;
const M0_CHUNK_USIZE: usize = CHUNK_MAGIC.len() + 8 + NORMAL_CHUNK_PT_AND_TAG_USIZE;

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

/// `info` to bound the HPKE usage to the MLA Encrypt Layer
const HPKE_INFO_LAYER: &[u8] = b"MLA Encrypt Layer";

/// Encrypted Key commitment and associated tag
struct KeyCommitmentAndTag {
    key_commitment: [u8; KEY_COMMITMENT_SIZE],
    tag: [u8; TAG_LENGTH],
}

impl<W: Write> MLASerialize<W> for KeyCommitmentAndTag {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        let mut serialization_length: u64 = 0;
        serialization_length = serialization_length
            .checked_add(self.key_commitment.as_slice().serialize(dest)?)
            .ok_or(Error::SerializationError)?;
        serialization_length = serialization_length
            .checked_add(self.tag.as_slice().serialize(dest)?)
            .ok_or(Error::SerializationError)?;
        Ok(serialization_length)
    }
}

impl<R: Read> MLADeserialize<R> for KeyCommitmentAndTag {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let key_commitment = MLADeserialize::deserialize(src)?;
        let tag = MLADeserialize::deserialize(src)?;
        Ok(Self {
            key_commitment,
            tag,
        })
    }
}

/// Return a Cryptographic random number generator
// Returns a Result to allow error propagation when we will
// switch to RNG API that will fail without panicking
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn get_crypto_rng() -> Result<ChaCha20Rng, Error> {
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
    Ok(ChaCha20Rng::from_entropy())
}

#[derive(Zeroize, ZeroizeOnDrop)]
/// Cryptographic material used for encryption in the Encrypt layer
/// Part of this data must be kept secret and drop as soon as possible
pub(crate) struct InternalEncryptionConfig {
    pub(crate) key: Key,
    pub(crate) nonce: Nonce,
}

impl InternalEncryptionConfig {
    // Secret cryptographic material is passed by value to ensure it is not accidentally reused
    #[allow(clippy::needless_pass_by_value)]
    fn from(shared_secret: HybridKemSharedSecret) -> Result<Self, Error> {
        let (key, nonce) = key_schedule_base_hybrid_kem(&shared_secret.0, HPKE_INFO_LAYER)?;

        Ok(Self { key, nonce })
    }
}

/// Configuration stored in the header, to be reloaded
pub struct EncryptionPersistentConfig {
    /// Key-wrapping for each recipients
    pub hybrid_multi_recipient_encapsulate_key: HybridMultiRecipientEncapsulatedKey,
    /// Encrypted version of the hardcoded `KEY_COMMITMENT_CHAIN`
    key_commitment: KeyCommitmentAndTag,
}

impl<W: Write> MLASerialize<W> for EncryptionPersistentConfig {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        let mut serialization_length: u64 = 0;
        serialization_length = serialization_length
            .checked_add(
                self.hybrid_multi_recipient_encapsulate_key
                    .serialize(dest)?,
            )
            .ok_or(Error::SerializationError)?;
        serialization_length = serialization_length
            .checked_add(self.key_commitment.serialize(dest)?)
            .ok_or(Error::SerializationError)?;
        Ok(serialization_length)
    }
}

impl<R: Read> MLADeserialize<R> for EncryptionPersistentConfig {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let hybrid_multi_recipient_encapsulate_key = MLADeserialize::deserialize(src)?;
        let key_commitment = MLADeserialize::deserialize(src)?;
        Ok(Self {
            hybrid_multi_recipient_encapsulate_key,
            key_commitment,
        })
    }
}

/// `ArchiveWriterConfig` specific configuration for the Encryption, to let API users specify encryption options
pub(crate) struct EncryptionConfig {
    /// Public keys of recipients
    public_keys: HybridMultiRecipientsPublicKeys,
    pub(crate) rng: MaybeSeededRNG,
}

impl EncryptionConfig {
    /// Create a persistent version of the configuration to be reloaded
    ///    and the internal configuration, containing the cryptographic material
    ///
    /// This material is created for the current recipients, and several call to this function
    /// will results in several materials
    pub(crate) fn to_persistent(
        &self,
    ) -> Result<(EncryptionPersistentConfig, InternalEncryptionConfig), Error> {
        // Generate then encapsulate the main key for each recipients
        let (hybrid_multi_recipient_encapsulate_key, ss_hybrid) =
            self.public_keys.encapsulate(&mut self.rng.get_rng()?)?;

        // Generate the main encrypt layer nonce and keep the main key for internal use
        let cryptographic_material = InternalEncryptionConfig::from(ss_hybrid).or(Err(
            Error::ConfigError(ConfigError::KeyWrappingComputationError),
        ))?;

        // Add a key commitment
        let key_commitment =
            build_key_commitment_chain(&cryptographic_material.key, &cryptographic_material.nonce)
                .or(Err(Error::ConfigError(
                    ConfigError::KeyCommitmentComputationError,
                )))?;

        // Create the persistent version, to be exported
        Ok((
            EncryptionPersistentConfig {
                hybrid_multi_recipient_encapsulate_key,
                key_commitment,
            },
            cryptographic_material,
        ))
    }

    pub(crate) fn new(
        encryption_public_keys: &[MLAEncryptionPublicKey],
    ) -> Result<Self, ConfigError> {
        if encryption_public_keys.is_empty() {
            return Err(ConfigError::EncryptionKeyIsMissing);
        }
        let public_keys = HybridMultiRecipientsPublicKeys {
            keys: encryption_public_keys.to_vec(),
        };
        Ok(Self {
            public_keys,
            rng: MaybeSeededRNG::default(),
        })
    }
}

#[derive(Default)]
pub struct EncryptionReaderConfig {
    /// Private key(s) to use
    private_keys: Vec<MLADecryptionPrivateKey>,
    /// Symmetric encryption key and nonce, if decrypted successfully from header
    // TODO: split in two, like InternalEncryptionConfig
    encrypt_parameters: Option<(Key, Nonce)>,
    shared_secrets: Vec<MLADecryptionSharedSecret>,
}

impl EncryptionReaderConfig {
    pub(crate) fn set_private_keys(&mut self, private_keys: &[MLADecryptionPrivateKey]) {
        self.private_keys = private_keys.to_vec();
    }

    pub(crate) fn set_shared_secrets(&mut self, shared_secrets: Vec<MLADecryptionSharedSecret>) {
        self.shared_secrets = shared_secrets;
    }

    pub fn load_persistent(
        &mut self,
        config: &EncryptionPersistentConfig,
    ) -> Result<(), ConfigError> {
        if self.private_keys.is_empty() && self.shared_secrets.is_empty() {
            return Err(ConfigError::PrivateKeyNotSet);
        }

        // First try all given shared secrets
        for shared_secret in &self.shared_secrets {
            let (key, nonce) = key_schedule_base_hybrid_kem(&shared_secret.0.0, HPKE_INFO_LAYER)
                .or(Err(ConfigError::KeyWrappingComputationError))?;
            // check if this shared_secret is valid for this archive
            if check_key_commitment(&key, &nonce, &config.key_commitment).is_ok() {
                self.encrypt_parameters = Some((key, nonce));
                break;
            }
        }

        // If no shared secret is valid, try each private key
        if self.encrypt_parameters.is_none() {
            for private_key in &self.private_keys {
                if let Ok(ss_hybrid) =
                    private_key.decapsulate(&config.hybrid_multi_recipient_encapsulate_key)
                {
                    let (key, nonce) = key_schedule_base_hybrid_kem(&ss_hybrid.0, HPKE_INFO_LAYER)
                        .or(Err(ConfigError::KeyWrappingComputationError))?;
                    self.encrypt_parameters = Some((key, nonce));
                    break;
                }
            }
        }

        let (key, nonce) = &self
            .encrypt_parameters
            .ok_or(ConfigError::PrivateKeyNotFound)?;

        // A key has been found, check if it is the expected one
        check_key_commitment(key, nonce, &config.key_commitment)
    }
}

// ---------- Writer ----------
pub(crate) struct EncryptionLayerWriter<'a, W: 'a + InnerWriterTrait>(
    InternalEncryptionLayerWriter<'a, W>,
);

impl<'a, W: 'a + InnerWriterTrait> EncryptionLayerWriter<'a, W> {
    pub fn new(
        mut inner: InnerWriterType<'a, W>,
        encryption_config: &EncryptionConfig,
    ) -> Result<Self, Error> {
        let (persistent_config, internal_config) =
            EncryptionConfig::to_persistent(encryption_config)?;
        inner.write_all(ENCRYPTION_LAYER_MAGIC)?;
        let _ = Opts.dump(&mut inner)?;
        let encryption_method_id = 0u16;
        encryption_method_id.serialize(&mut inner)?;
        persistent_config.serialize(&mut inner)?;
        // first chunk magic
        inner.write_all(CHUNK_MAGIC)?;
        // first chunk number
        1u64.serialize(&mut inner)?;
        Ok(Self(InternalEncryptionLayerWriter::new(
            inner,
            &internal_config,
        )?))
    }
}

impl<'a, W: 'a + InnerWriterTrait> Write for EncryptionLayerWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<'a, W: 'a + InnerWriterTrait> LayerWriter<'a, W> for EncryptionLayerWriter<'a, W> {
    fn finalize(self: Box<Self>) -> Result<W, Error> {
        Box::new(self.0).finalize()
    }
}

struct InternalEncryptionLayerWriter<'a, W: 'a + InnerWriterTrait> {
    inner: InnerWriterType<'a, W>,
    cipher: AesGcm256,
    /// Symmetric encryption Key
    key: Key,
    /// Symmetric encryption nonce prefix, see `compute_nonce`
    base_nonce: Nonce,
    current_chunk_offset: u64,
    current_ctr: u64,
}

impl<'a, W: 'a + InnerWriterTrait> InternalEncryptionLayerWriter<'a, W> {
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

    fn renew_cipher_aad(&mut self, aad: &[u8]) -> Result<Tag, Error> {
        // Prepare a new cipher
        self.current_ctr = self.current_ctr.checked_add(1).ok_or(Error::HPKEError)?;
        self.current_chunk_offset = 0;
        let cipher = AesGcm256::new(
            &self.key,
            &compute_nonce(&self.base_nonce, self.current_ctr),
            aad,
        )?;
        let old_cipher = std::mem::replace(&mut self.cipher, cipher);
        Ok(old_cipher.into_tag())
    }

    fn renew_cipher(&mut self) -> Result<Tag, Error> {
        self.renew_cipher_aad(ASSOCIATED_DATA)
    }

    fn last_renew_cipher(&mut self) -> Result<Tag, Error> {
        self.renew_cipher_aad(FINAL_ASSOCIATED_DATA)
    }
}

impl<'a, W: 'a + InnerWriterTrait> LayerWriter<'a, W> for InternalEncryptionLayerWriter<'a, W> {
    fn finalize(mut self: Box<Self>) -> Result<W, Error> {
        // Write the tag of the current chunk
        // Get previous chunk tag and initialize final block content cipher context with specific AAD
        let last_content_tag = self.last_renew_cipher()?;
        self.inner.write_all(&last_content_tag)?;

        self.inner.write_all(FINAL_BLOCK_MAGIC)?;
        // Write encrypted final block content
        self.write_all(FINAL_BLOCK_CONTENT)?;
        // Write final block tag
        // Only previous chunk tag is used there, further context is not
        let final_tag = self.renew_cipher()?;
        self.inner.write_all(&final_tag)?;
        self.inner.write_all(END_OF_ENCRYPTED_INNER_LAYER_MAGIC)?;

        self.inner.write_all(EMPTY_TAIL_OPTS_SERIALIZATION)?;

        // Recursive call
        self.inner.finalize()
    }
}

impl<W: InnerWriterTrait> Write for InternalEncryptionLayerWriter<'_, W> {
    #[allow(clippy::comparison_chain)]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.current_chunk_offset > NORMAL_CHUNK_PT_SIZE {
            // Should never happen
            return Err(
                Error::WrongWriterState("[EncryptWriter] Chunk too big".to_string()).into(),
            );
        } else if self.current_chunk_offset == NORMAL_CHUNK_PT_SIZE {
            // Prepare a new cipher
            let tag = self.renew_cipher()?;
            // Write the previous chunk tag
            self.inner.write_all(&tag)?;
            self.inner.write_all(CHUNK_MAGIC)?;
            self.current_ctr.serialize(&mut self.inner)?;
        }

        // StreamingCipher is working in place, so we use a temporary buffer
        let buf_len_u64 =
            u64::try_from(buf.len()).map_err(|_| io::Error::other("Invalid buf len"))?;
        let remaining_len_in_chunk = NORMAL_CHUNK_PT_SIZE
            .checked_sub(self.current_chunk_offset)
            .ok_or_else(|| io::Error::other("Invalid current_chunk_offset"))?;
        let size = std::cmp::min(
            std::cmp::min(CIPHER_BUF_SIZE, buf_len_u64),
            remaining_len_in_chunk,
        );
        let mut buf_tmp =
            buf[..usize::try_from(size).expect("Failed to convert size to usize")].to_vec();
        self.cipher.encrypt(&mut buf_tmp);
        self.inner.write_all(&buf_tmp)?;
        self.current_chunk_offset = self
            .current_chunk_offset
            .checked_add(size)
            .ok_or_else(|| io::Error::other("Invalid current_chunk_offset or size"))?;
        usize::try_from(size).map_err(|_| io::Error::other("Invalid size"))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------- Reader ----------

pub(crate) fn read_encryption_header_after_magic<R: Read>(
    src: &mut R,
) -> Result<(EncryptionPersistentConfig, u64), Error> {
    let mut src = PositionLayerReader::new(src);
    let _ = Opts::from_reader(&mut src)?; // No option handled at the moment
    let _encryption_method_id = u16::deserialize(&mut src)?;
    let read_encryption_metadata = EncryptionPersistentConfig::deserialize(&mut src)?;
    let encryption_header_length = src
        .position()
        .checked_add(8)
        .ok_or(Error::DeserializationError)?;

    Ok((read_encryption_metadata, encryption_header_length))
}

pub(crate) struct EncryptionLayerReader<'a, R: InnerReaderTrait>(
    InternalEncryptionLayerReader<Box<dyn 'a + LayerReader<'a, R>>>,
);

impl<'a, R: 'a + InnerReaderTrait> EncryptionLayerReader<'a, R> {
    pub(crate) fn new_skip_magic(
        mut inner: Box<dyn 'a + LayerReader<'a, R>>,
        mut reader_config: EncryptionReaderConfig,
        persistent_config: Option<EncryptionPersistentConfig>,
    ) -> Result<Self, Error> {
        let (read_encryption_metadata, encryption_header_length) =
            read_encryption_header_after_magic(&mut inner)?;
        let persistent_config = persistent_config.unwrap_or(read_encryption_metadata); // this lets us ensure we use previously verified encryption context if given (e.g. by signature layer)

        let raw_encryption_layer_length = inner.seek(SeekFrom::End(0))?;
        inner.seek(SeekFrom::Current(-8))?;
        let encryption_footer_options_length = u64::deserialize(&mut inner)?;
        // skip reading them as there are none for the moment
        let encryption_footer_length = encryption_footer_options_length
            .checked_add(8)
            .ok_or(Error::DeserializationError)?;
        inner.seek(SeekFrom::Start(encryption_header_length))?;
        reader_config.load_persistent(&persistent_config)?;

        // InternalEncryptionLayerReader is feeded with something with encrypted_inner_layer followed by end_of_encrypted_inner_layer_magic
        let inner: Box<dyn 'a + LayerReader<'a, R>> = Box::new(StripHeadTailReader::new(
            inner,
            encryption_header_length,
            encryption_footer_length,
            raw_encryption_layer_length,
            0,
        )?);
        let inner = InternalEncryptionLayerReader::new(inner, &reader_config, None)?;
        Ok(Self(inner))
    }
}

impl<'a, R: 'a + InnerReaderTrait> Read for EncryptionLayerReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<'a, R: 'a + InnerReaderTrait> Seek for EncryptionLayerReader<'a, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

impl<'a, R: 'a + InnerReaderTrait> LayerReader<'a, R> for EncryptionLayerReader<'a, R> {
    fn into_raw(self: Box<Self>) -> R {
        self.0.inner.into_raw()
    }

    fn initialize(&mut self) -> Result<(), Error> {
        self.0.inner.initialize()?;
        self.0.initialize()?;

        Ok(())
    }
}

// In the case of stream cipher, encrypting is the same that decrypting. Here, we
// keep the struct separated for any possible future difference
struct InternalEncryptionLayerReader<R> {
    inner: R,
    cipher: AesGcm256,
    key: Key,
    nonce: Nonce,
    chunk_cache: Cursor<Vec<u8>>,
    next_chunk_cache: Vec<u8>,
    /// Store in state the size of all plaintext computed from inner layer size
    /// to be able to tell if we are in last data chunk or in final block
    all_plaintext_size: u64,
    /// Store in state the current reading position
    current_position_in_this_layer: u64,
    /// Store the final block when found in cache
    _final_block: Option<Vec<u8>>,
    truncated_decryption_mode: Option<TruncatedReaderDecryptionMode>,
}

impl<R: Read> InternalEncryptionLayerReader<R> {
    fn new(
        mut inner: R,
        config: &EncryptionReaderConfig,
        truncated_decryption_mode: Option<TruncatedReaderDecryptionMode>,
    ) -> Result<Self, Error> {
        // load first chunk in next_chunk_cache
        let mut next_chunk_cache = Vec::with_capacity(M0_CHUNK_USIZE);
        (&mut inner)
            .take(M0_CHUNK_SIZE)
            .read_to_end(&mut next_chunk_cache)?;
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
                chunk_cache: Cursor::new(Vec::with_capacity(M0_CHUNK_USIZE)),
                next_chunk_cache,
                all_plaintext_size: 0,
                current_position_in_this_layer: 0,
                _final_block: None,
                truncated_decryption_mode,
            }),
            None => Err(Error::PrivateKeyNeeded),
        }
    }

    fn is_at_least_in_last_data_chunk(&self) -> Result<bool, Error> {
        let last_data_chunk_pos = self
            .last_data_chunk_number()
            .checked_mul(NORMAL_CHUNK_PT_SIZE)
            .ok_or(Error::DeserializationError)?;
        Ok(self.current_position_in_this_layer >= last_data_chunk_pos)
    }

    fn current_data_chunk_number(&self) -> u64 {
        self.current_position_in_this_layer / NORMAL_CHUNK_PT_SIZE
    }

    fn last_data_chunk_number(&self) -> u64 {
        if self.all_plaintext_size.is_multiple_of(NORMAL_CHUNK_PT_SIZE) {
            (self.all_plaintext_size / NORMAL_CHUNK_PT_SIZE).saturating_sub(1)
        } else {
            self.all_plaintext_size / NORMAL_CHUNK_PT_SIZE
        }
    }

    fn _check_final(&mut self) -> Result<(), Error> {
        #[allow(clippy::used_underscore_binding)]
        if let Some(mut final_block) = self._final_block.take() {
            let final_chunk_number = self
                .current_data_chunk_number()
                .checked_add(1)
                .ok_or(Error::DeserializationError)?
                .checked_add(FIRST_DATA_CHUNK_NUMBER)
                .ok_or(Error::DeserializationError)?;
            let mut cipher = AesGcm256::new(
                &self.key,
                &compute_nonce(&self.nonce, final_chunk_number),
                FINAL_ASSOCIATED_DATA,
            )?;
            let data_part = final_block
                .get_mut(..FINAL_BLOCK_CONTENT.len())
                .ok_or_else(|| {
                    Error::WrongReaderState("Invalid final block data part".to_owned())
                })?;
            let computed_tag = cipher.decrypt(data_part);
            if data_part != FINAL_BLOCK_CONTENT {
                return Err(Error::InvalidLastTag);
            }
            let tag_part = &final_block
                .get(FINAL_BLOCK_CONTENT.len()..)
                .ok_or_else(|| {
                    Error::WrongReaderState("Invalid final block data part".to_owned())
                })?;
            if computed_tag.ct_eq(tag_part).unwrap_u8() == 1 {
                Ok(())
            } else {
                Err(Error::InvalidLastTag)
            }
        } else {
            Err(Error::AssertionError(
                "check_final should have Some(final_block)".to_owned(),
            ))
        }
    }

    // Search for final block magic in both chunk caches.
    // This lets us detect end of tag if in TruncatedReaderDecryptionMode::OnlyAuthenticatedData (if the magic has not been truncated away).
    fn final_block_magic_scan(&self) -> Option<usize> {
        // search in chunk_cache
        if let Some(pos) = self
            .chunk_cache
            .get_ref()
            .windows(FINAL_BLOCK_MAGIC.len())
            .position(|candidate| candidate == FINAL_BLOCK_MAGIC)
        {
            Some(pos)
        } else {
            // search in next_chunk_cache
            if let Some(pos) = self
                .next_chunk_cache
                .windows(FINAL_BLOCK_MAGIC.len())
                .position(|candidate| candidate == FINAL_BLOCK_MAGIC)
            {
                Some(self.chunk_cache.get_ref().len().checked_add(pos)?)
            } else {
                // search across the boundary
                (1..FINAL_BLOCK_MAGIC.len())
                    .find(|number_in_chunk_cache| {
                        let chunk_cache = self.chunk_cache.get_ref();
                        let Some(number_in_next_chunk_cache) =
                            FINAL_BLOCK_MAGIC.len().checked_sub(*number_in_chunk_cache)
                        else {
                            return false;
                        };
                        if chunk_cache.len() < *number_in_chunk_cache
                            || self.next_chunk_cache.len() < number_in_next_chunk_cache
                        {
                            false
                        } else {
                            let magic_part1 = &FINAL_BLOCK_MAGIC[..*number_in_chunk_cache];
                            let magic_part2 = &FINAL_BLOCK_MAGIC[*number_in_chunk_cache..];
                            let Some(remaining) =
                                chunk_cache.len().checked_sub(*number_in_chunk_cache)
                            else {
                                return false;
                            };
                            let end_of_chunk_cache = &chunk_cache[remaining..];
                            let start_of_next_chunk_cache =
                                &self.next_chunk_cache[..number_in_next_chunk_cache];
                            end_of_chunk_cache == magic_part1
                                && start_of_next_chunk_cache == magic_part2
                        }
                    })
                    .map(|number_in_chunk_cache| {
                        self.chunk_cache
                            .get_ref()
                            .len()
                            .checked_sub(number_in_chunk_cache)
                    })?
            }
        }
    }

    #[allow(clippy::unused_self)]
    fn try_tag_pos_at_from_0_to(&self, _max_pos: usize) -> Option<usize> {
        // TODO later. For the moment we do not support recovering last bytes
        // in archives where the final tag is truncated
        None
    }

    fn get_end_of_tag_pos(&self) -> Result<usize, Error> {
        let chunk_cache_len = self.chunk_cache.get_ref().len();
        let next_chunk_cache_len = self.next_chunk_cache.len();
        let end_of_tag_pos =
            if chunk_cache_len == M0_CHUNK_USIZE && next_chunk_cache_len > FINAL_INFO_USIZE {
                // chunk_cache is complete
                M0_CHUNK_USIZE
            } else if chunk_cache_len < TAG_LENGTH {
                // tag is truncated and there is no ciphertext, we cannot do anything
                return Err(Error::TruncatedTag);
            } else {
                match self.final_block_magic_scan() {
                    None => {
                        if let Some(pos) = self
                            .try_tag_pos_at_from_0_to(chunk_cache_len.saturating_sub(TAG_LENGTH))
                        {
                            pos
                        } else if matches!(
                            self.truncated_decryption_mode,
                            Some(TruncatedReaderDecryptionMode::DataEvenUnauthenticated)
                        ) {
                            // If data contains <16 bytes of tag, we may interpret it like ciphertext and return garbage
                            chunk_cache_len
                                .checked_add(TAG_LENGTH)
                                .ok_or(Error::DeserializationError)? // +TAG_LENGTH is fake, it will be subtracted for end_of_ciphertext_pos
                        } else {
                            return Err(Error::UnknownTagPosition);
                        }
                    }
                    Some(pos) => pos,
                }
            };

        Ok(end_of_tag_pos)
    }

    /// Load the current chunk number chunk in cache
    /// Assume the inner layer is in the correct position
    ///
    /// At entry of this function, we have the `chunk_cache` we finished
    /// reading and the `next_chunk_cache` which has previously been read from source.
    ///
    /// We need 2 caches because we need to cache more than a chunk to find where the
    /// tag is if we are reading a truncated archive. For example, if the tag ends
    /// one byte before the `chunk_cache` (followed by final block) we wouldn't be able to know.
    fn load_in_cache(&mut self) -> Result<Option<()>, Error> {
        std::mem::swap(self.chunk_cache.get_mut(), &mut self.next_chunk_cache);
        self.chunk_cache.set_position(0);
        self.next_chunk_cache.clear();
        (&mut self.inner)
            .take(M0_CHUNK_SIZE)
            .read_to_end(&mut self.next_chunk_cache)?;
        // At this point, chunk_cache points to the start of a (maybe empty) ciphertext block.
        // Our read implementation never calls load_in_cache again if the plaintext/ciphertext content in chunk_cache is smaller than NORMAL_CHUNK_CT_SIZE
        let end_of_tag_pos =
            if self.truncated_decryption_mode.is_none() && self.is_at_least_in_last_data_chunk()? {
                let content_len = usize::try_from(
                    self.all_plaintext_size
                        .saturating_sub(self.current_position_in_this_layer),
                )
                .expect("Failed to convert content length to usize");
                if content_len == 0 {
                    return Ok(None);
                }

                content_len
                    .checked_add(TAG_LENGTH)
                    .ok_or(Error::DeserializationError)?
                    .checked_add(CHUNK_HEAD_USIZE)
                    .ok_or(Error::DeserializationError)?
            } else {
                self.get_end_of_tag_pos()?
            };

        let end_of_ciphertext_pos = end_of_tag_pos.saturating_sub(TAG_LENGTH);

        if end_of_ciphertext_pos == 0 {
            return Ok(None);
        }

        let sequence_number = self
            .current_data_chunk_number()
            .checked_add(FIRST_DATA_CHUNK_NUMBER)
            .ok_or(Error::DeserializationError)?;
        self.cipher = AesGcm256::new(
            &self.key,
            &compute_nonce(&self.nonce, sequence_number),
            ASSOCIATED_DATA,
        )?;

        // Decrypt the current chunk
        let chunk_cache_slice = self.chunk_cache.get_mut().as_mut_slice();
        let data_part = chunk_cache_slice
            .get_mut(CHUNK_HEAD_USIZE..end_of_ciphertext_pos)
            .ok_or_else(|| Error::WrongReaderState("Invalid chunk cache data part".to_owned()))?;

        // Verify the tag
        if matches!(
            self.truncated_decryption_mode,
            Some(TruncatedReaderDecryptionMode::DataEvenUnauthenticated)
        ) {
            self.cipher.decrypt_unauthenticated(data_part);
        } else {
            let computed_tag = self.cipher.decrypt(data_part);
            let tag_part = chunk_cache_slice
                .get(end_of_ciphertext_pos..end_of_tag_pos)
                .ok_or_else(|| {
                    Error::WrongReaderState("Invalid chunk cache tag part".to_owned())
                })?;
            if computed_tag.ct_eq(tag_part).unwrap_u8() != 1 {
                return Err(Error::AuthenticatedDecryptionWrongTag);
            }
        }

        self.chunk_cache.get_mut().truncate(end_of_ciphertext_pos);
        self.chunk_cache.set_position(CHUNK_HEAD_SIZE);
        Ok(Some(()))
    }

    /// Internal `Read::read` but returning a mla `Error`
    ///
    /// This method checks the tag of each decrypted block
    fn read_internal(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let cache_to_consume = NORMAL_CHUNK_PT_AND_TAG_SIZE
            .checked_sub(self.chunk_cache.position())
            .ok_or(Error::DeserializationError)?;
        if cache_to_consume == 0 {
            // Cache totally consumed, renew it
            if self.load_in_cache()?.is_none() {
                // No more byte in the inner layer
                return Ok(0);
            }
            return self.read_internal(buf);
        }
        // Consume at most the bytes leaving in the cache, to detect the renewal need
        let size = std::cmp::min(
            usize::try_from(cache_to_consume).expect("Failed to convert cache to consume to usize"),
            buf.len(),
        );
        let chunk_cache_read_size = self.chunk_cache.read(&mut buf[..size])?;
        let chunk_cache_read_size_u64 = u64::try_from(chunk_cache_read_size)
            .map_err(|_| Error::Other("Failed to convert read chunk cache size to usize".into()))?;
        self.current_position_in_this_layer = self
            .current_position_in_this_layer
            .checked_add(chunk_cache_read_size_u64)
            .ok_or(Error::DeserializationError)?;
        if chunk_cache_read_size == 0 {
            // TODO: self.check_final()?;
        }
        Ok(chunk_cache_read_size)
    }
}

impl<R: Read + Seek> InternalEncryptionLayerReader<R> {
    fn check_last_block(&mut self) -> Result<(), Error> {
        let offset_usize = FINAL_INFO_SIZE_WOM
            .checked_add(END_OF_ENCRYPTED_INNER_LAYER_MAGIC.len())
            .ok_or(Error::DeserializationError)?;

        let offset_i64 = i64::try_from(offset_usize)
            .map_err(|_| Error::Other("Offset too large for i64 conversion".into()))?;

        self.inner.seek(SeekFrom::End(
            offset_i64
                .checked_neg()
                .ok_or(Error::DeserializationError)?,
        ))?;

        let sequence_number = self
            .last_data_chunk_number()
            .checked_add(1)
            .ok_or(Error::DeserializationError)?
            .checked_add(FIRST_DATA_CHUNK_NUMBER)
            .ok_or(Error::DeserializationError)?;
        self.cipher = AesGcm256::new(
            &self.key,
            &compute_nonce(&self.nonce, sequence_number),
            FINAL_ASSOCIATED_DATA,
        )?;

        let mut data_and_tag = Vec::with_capacity(FINAL_INFO_SIZE_WOM);
        let data_and_tag_read = self.inner.read_to_end(&mut data_and_tag)?;
        if data_and_tag_read < FINAL_INFO_SIZE_WOM {
            return Err(Error::InvalidLastTag);
        }

        let mut tag = [0u8; TAG_LENGTH];
        let tag_part = data_and_tag
            .get(FINAL_BLOCK_CONTENT.len()..FINAL_INFO_SIZE_WOM)
            .ok_or_else(|| {
                Error::WrongReaderState(
                    "Invalid final block data tag part in check last block".to_owned(),
                )
            })?;
        tag.copy_from_slice(tag_part);
        data_and_tag.truncate(FINAL_BLOCK_CONTENT.len());
        let mut data = data_and_tag;

        // Decrypt and verify the current chunk
        let expected_tag = self.cipher.decrypt(data.as_mut_slice());
        if expected_tag.ct_eq(&tag).unwrap_u8() != 1 || data != FINAL_BLOCK_CONTENT {
            Err(Error::InvalidLastTag)
        } else {
            Ok(())
        }
    }

    fn initialize(&mut self) -> Result<(), Error> {
        // Check last block to prevent truncation attacks
        self.set_all_plaintext_size()?;
        self.check_last_block()?;

        // Load the current buffer in cache
        self.rewind()?;
        Ok(())
    }

    fn set_all_plaintext_size(&mut self) -> Result<(), Error> {
        let input_size = self.inner.seek(SeekFrom::End(0))?;
        let end_of_encrypted_inner_layer_magic_len_u64 =
            u64::try_from(END_OF_ENCRYPTED_INNER_LAYER_MAGIC.len())
                .map_err(|_| Error::DeserializationError)?;
        let final_and_header_len = end_of_encrypted_inner_layer_magic_len_u64
            .checked_add(FINAL_INFO_SIZE)
            .ok_or(Error::DeserializationError)?
            .checked_add(CHUNK_HEAD_SIZE)
            .ok_or(Error::DeserializationError)?;
        let input_size_without_final_nor_header = input_size.saturating_sub(final_and_header_len);
        let chunk_number_at_end_of_data = input_size_without_final_nor_header / M0_CHUNK_SIZE;
        let last_chunk_size = input_size_without_final_nor_header % M0_CHUNK_SIZE;
        self.all_plaintext_size = if last_chunk_size == 0 {
            chunk_number_at_end_of_data
                .checked_mul(NORMAL_CHUNK_PT_SIZE)
                .ok_or(Error::DeserializationError)?
        } else {
            chunk_number_at_end_of_data
                .checked_mul(NORMAL_CHUNK_PT_SIZE)
                .ok_or(Error::DeserializationError)?
                .checked_add(last_chunk_size)
                .ok_or(Error::DeserializationError)?
                .checked_sub(TAG_LENGTH as u64)
                .ok_or(Error::DeserializationError)?
        };
        Ok(())
    }
}

impl<R: InnerReaderTrait> Read for InternalEncryptionLayerReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_internal(buf).map_err(mla_error_to_io_error)
    }
}

// Returns how many chunk are present at position `position`
fn this_layer_position_to_inner_position(position: u64) -> io::Result<u64> {
    let cur_chunk = position / NORMAL_CHUNK_PT_SIZE;
    let cur_chunk_pos = position % NORMAL_CHUNK_PT_SIZE;
    let e = || io::Error::from(ErrorKind::InvalidInput);
    cur_chunk
        .checked_mul(M0_CHUNK_SIZE)
        .ok_or_else(e)?
        .checked_add(cur_chunk_pos)
        .ok_or_else(e)?
        .checked_add(CHUNK_HEAD_SIZE)
        .ok_or_else(e)
}

// Given `position` me be inside the "plaintext", not the tag nor the CHUNK_HEAD
fn _inner_position_in_plaintext_to_this_layer_position(position: u64) -> io::Result<u64> {
    let cur_chunk = position / M0_CHUNK_SIZE;
    let e = || io::Error::from(ErrorKind::InvalidInput);
    let cur_chunk_pos = position
        .checked_rem(M0_CHUNK_SIZE)
        .ok_or_else(e)?
        .checked_sub(CHUNK_HEAD_SIZE)
        .ok_or_else(e)?;
    cur_chunk
        .checked_mul(NORMAL_CHUNK_PT_SIZE)
        .ok_or_else(e)?
        .checked_add(cur_chunk_pos)
        .ok_or_else(e)
}

impl<R: Read + Seek> Seek for InternalEncryptionLayerReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let e = || io::Error::from(ErrorKind::InvalidInput);
        // `pos` is the position without considering tags
        match pos {
            SeekFrom::Start(asked_pos) => {
                let inner_position_of_asked_pos = this_layer_position_to_inner_position(asked_pos)?;
                let asked_pos_chunk_number = inner_position_of_asked_pos / M0_CHUNK_SIZE;
                let inner_position_of_m0_chunk_start = asked_pos_chunk_number
                    .checked_mul(M0_CHUNK_SIZE)
                    .ok_or_else(e)?;
                let asked_pos_in_chunk_plaintext = inner_position_of_asked_pos
                    .checked_rem(M0_CHUNK_SIZE)
                    .ok_or_else(e)?
                    .checked_sub(CHUNK_HEAD_SIZE)
                    .ok_or_else(e)?;

                // Seek the inner layer at the beginning of the chunk
                self.inner
                    .seek(SeekFrom::Start(inner_position_of_m0_chunk_start))?;

                // Load and move into the cache
                self.current_position_in_this_layer = asked_pos_chunk_number
                    .checked_mul(NORMAL_CHUNK_PT_SIZE)
                    .ok_or_else(e)?;
                self.next_chunk_cache.clear();
                (&mut self.inner)
                    .take(M0_CHUNK_SIZE)
                    .read_to_end(&mut self.next_chunk_cache)?;
                self.load_in_cache()?;
                self.chunk_cache.set_position(
                    CHUNK_HEAD_SIZE
                        .checked_add(asked_pos_in_chunk_plaintext)
                        .ok_or_else(e)?,
                );
                self.current_position_in_this_layer = self
                    .current_position_in_this_layer
                    .checked_add(asked_pos_in_chunk_plaintext)
                    .ok_or_else(e)?;
                Ok(asked_pos)
            }
            SeekFrom::Current(value) => {
                if value == 0 {
                    // Optimization
                    Ok(self.current_position_in_this_layer)
                } else {
                    let pos_i64 =
                        i64::try_from(self.current_position_in_this_layer).map_err(|_| {
                            Error::Other("Position overflow converting u64 to i64".into())
                        })?;

                    let new_pos_i64 = pos_i64
                        .checked_add(value)
                        .ok_or(Error::Other("Position overflow when adding offset".into()))?;

                    let new_pos = u64::try_from(new_pos_i64)
                        .map_err(|_| Error::Other("Negative position not allowed".into()))?;

                    self.seek(SeekFrom::Start(new_pos))
                }
            }
            SeekFrom::End(pos) => {
                if pos > 0 {
                    // Seeking past the end is unsupported
                    return Err(Error::EndOfStream.into());
                }

                let size_i64 = i64::try_from(self.all_plaintext_size)
                    .map_err(|_| Error::Other("Overflow converting size to i64".into()))?;

                let new_pos_i64 = size_i64
                    .checked_add(pos)
                    .ok_or(Error::Other("Overflow adding offset to size".into()))?;

                let new_pos = u64::try_from(new_pos_i64)
                    .map_err(|_| Error::Other("Overflow converting new position to u64".into()))?;

                self.seek(SeekFrom::Start(new_pos))
            }
        }
    }
}

// ---------- Fail-Safe Reader ----------

pub(crate) struct EncryptionLayerTruncatedReader<'a, R: Read> {
    inner: InternalEncryptionLayerReader<Box<dyn 'a + LayerTruncatedReader<'a, R>>>,
}

impl<'a, R: 'a + Read> EncryptionLayerTruncatedReader<'a, R> {
    fn new_skip_header(
        inner: Box<dyn 'a + LayerTruncatedReader<'a, R>>,
        config: &EncryptionReaderConfig,
        truncated_decryption_mode: TruncatedReaderDecryptionMode,
    ) -> Result<Self, Error> {
        let mut inner =
            InternalEncryptionLayerReader::new(inner, config, Some(truncated_decryption_mode))?;
        inner.load_in_cache()?;

        Ok(Self { inner })
    }

    pub(crate) fn new_skip_magic(
        mut inner: Box<dyn 'a + LayerTruncatedReader<'a, R>>,
        mut reader_config: EncryptionReaderConfig,
        persistent_config: Option<EncryptionPersistentConfig>,
        truncated_decryption_mode: TruncatedReaderDecryptionMode,
    ) -> Result<Self, Error> {
        let (read_encryption_metadata, _) = read_encryption_header_after_magic(&mut inner)?;
        let persistent_config = persistent_config.unwrap_or(read_encryption_metadata); // this lets us ensure we use previously verified encryption context if given (e.g. by signature layer)
        reader_config.load_persistent(&persistent_config)?;
        Self::new_skip_header(inner, &reader_config, truncated_decryption_mode)
    }
}

impl<'a, R: 'a + Read> LayerTruncatedReader<'a, R> for EncryptionLayerTruncatedReader<'a, R> {}

impl<R: Read> Read for EncryptionLayerTruncatedReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read_internal(buf).map_err(mla_error_to_io_error)
    }
}

fn mla_error_to_io_error(err: Error) -> io::Error {
    if let Error::IOError(e) = err {
        e
    } else {
        io::Error::other(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::SeedableRng;
    use rand::distributions::{Alphanumeric, Distribution};
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    use crate::crypto::aesgcm::{KEY_SIZE, NONCE_AES_SIZE};
    use crate::layers::encrypt::{InternalEncryptionLayerReader, InternalEncryptionLayerWriter};
    use crate::layers::raw::{RawLayerReader, RawLayerTruncatedReader, RawLayerWriter};

    static FAKE_FILE: [u8; 26] = *b"abcdefghijklmnopqrstuvwxyz";
    static KEY: Key = [2u8; KEY_SIZE];
    static NONCE: Nonce = [3u8; NONCE_AES_SIZE];

    fn encrypt_write(mut file: Vec<u8>) -> Vec<u8> {
        file.write_all(CHUNK_MAGIC).unwrap();
        file.write_all(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        // Instantiate a EncryptionLayerWriter and fill it with FAKE_FILE
        let mut encrypt_w = Box::new(
            InternalEncryptionLayerWriter::new(
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

        let mut out = encrypt_w.finalize().unwrap();
        out.resize(
            out.len()
                .checked_sub(EMPTY_TAIL_OPTS_SERIALIZATION.len())
                .unwrap(),
            0,
        );
        assert_eq!(
            out.len(),
            FAKE_FILE
                .len()
                .checked_add(CHUNK_MAGIC.len())
                .unwrap()
                .checked_add(8)
                .unwrap()
                .checked_add(TAG_LENGTH)
                .unwrap()
                .checked_add(FINAL_INFO_USIZE)
                .unwrap()
                .checked_add(END_OF_ENCRYPTED_INNER_LAYER_MAGIC.len())
                .unwrap()
        );
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
            shared_secrets: Vec::new(),
        };
        let mut encrypt_r =
            InternalEncryptionLayerReader::new(Box::new(RawLayerReader::new(buf)), &config, None)
                .unwrap();
        encrypt_r.initialize().unwrap();
        let mut output = Vec::new();
        encrypt_r.read_to_end(&mut output).unwrap();
        assert_eq!(output, FAKE_FILE);
    }

    #[test]
    fn encrypt_truncated_layer() {
        let file = Vec::new();
        let out = encrypt_write(file);

        let config = EncryptionReaderConfig {
            private_keys: Vec::new(),
            encrypt_parameters: Some((KEY, NONCE)),
            shared_secrets: Vec::new(),
        };
        let mut encrypt_r = EncryptionLayerTruncatedReader::new_skip_header(
            Box::new(RawLayerTruncatedReader::new(out.as_slice())),
            &config,
            TruncatedReaderDecryptionMode::OnlyAuthenticatedData,
        )
        .unwrap();
        let mut output = Vec::new();
        encrypt_r.read_to_end(&mut output).unwrap();
        // Same length expected as no truncation is done and we applied the `clean-truncated` operation in authenticated mode
        assert!(output.len() == FAKE_FILE.len());
        assert_eq!(output[..FAKE_FILE.len()], FAKE_FILE);
    }

    #[test]
    fn encrypt_truncated_truncated() {
        let file = Vec::new();
        let out = encrypt_write(file);
        // Truncate at the middle of a data chunk + tag
        // Thus, removing final block size which is not expected
        let stop = CHUNK_HEAD_USIZE
            + (out.len()
                - FINAL_INFO_USIZE
                - END_OF_ENCRYPTED_INNER_LAYER_MAGIC.len()
                - CHUNK_HEAD_USIZE)
                / 2;

        let config = EncryptionReaderConfig {
            private_keys: Vec::new(),
            encrypt_parameters: Some((KEY, NONCE)),
            shared_secrets: Vec::new(),
        };
        let mut encrypt_r = EncryptionLayerTruncatedReader::new_skip_header(
            Box::new(RawLayerTruncatedReader::new(&out[..stop])),
            &config,
            TruncatedReaderDecryptionMode::DataEvenUnauthenticated,
        )
        .unwrap();
        let mut output = Vec::new();
        encrypt_r.read_to_end(&mut output).unwrap();
        // Thanks to the encrypt layer construction, we can recover `stop` bytes
        assert_eq!(output.as_slice(), &FAKE_FILE[..(stop - CHUNK_HEAD_USIZE)]);
    }

    #[test]
    fn truncated_auth_vs_unauth() {
        let mut file = Vec::new();
        file.write_all(CHUNK_MAGIC).unwrap();
        file.write_all(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let mut encrypt_w = Box::new(
            InternalEncryptionLayerWriter::new(
                Box::new(RawLayerWriter::new(file)),
                &InternalEncryptionConfig {
                    key: KEY,
                    nonce: NONCE,
                },
            )
            .unwrap(),
        );
        let length = usize::try_from(NORMAL_CHUNK_PT_SIZE * 2)
            .expect("Failed to convert length to usize")
            + 128;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0);
        let data: Vec<u8> = Alphanumeric.sample_iter(&mut rng).take(length).collect();
        encrypt_w.write_all(&data).unwrap();
        let mut out = encrypt_w.finalize().unwrap();
        out.resize(out.len() - EMPTY_TAIL_OPTS_SERIALIZATION.len(), 0);

        assert_eq!(
            out.len(),
            length
                + 3 * CHUNK_HEAD_USIZE
                + 3 * TAG_LENGTH
                + FINAL_INFO_USIZE
                + END_OF_ENCRYPTED_INNER_LAYER_MAGIC.len()
        );

        // data: [CHUNK_HEAD][CHUNK1 (NORMAL_CHUNK_PT_SIZE)][TAG1][CHUNK_HEAD][CHUNK2 (NORMAL_CHUNK_PT_SIZE)][TAG2][CHUNK_HEAD][CHUNK3 (128)][TAG3][FINAL_BLOCK_MAGIC][FINAL_BLOCK_CONTENT][FINAL_BLOCK_TAG][ENCMLAAB]
        // Truncate to remove the last tag
        let trunc = &out[..out.len()
            - TAG_LENGTH
            - FINAL_INFO_USIZE
            - END_OF_ENCRYPTED_INNER_LAYER_MAGIC.len()];

        let config = EncryptionReaderConfig {
            private_keys: Vec::new(),
            encrypt_parameters: Some((KEY, NONCE)),
            shared_secrets: Vec::new(),
        };
        let mut encrypt_r = EncryptionLayerTruncatedReader::new_skip_header(
            Box::new(RawLayerTruncatedReader::new(trunc)),
            &config,
            TruncatedReaderDecryptionMode::OnlyAuthenticatedData,
        )
        .unwrap();
        let mut output = Vec::new();
        assert!(encrypt_r.read_to_end(&mut output).is_err());
        // We should have correctly read 2*CHUNK_SIZE inner data, the last 128 bytes being unauthenticated
        assert_eq!(
            output.len(),
            usize::try_from(2 * NORMAL_CHUNK_PT_SIZE)
                .expect("Failed to convert output length to usize")
        );
        assert_eq!(output, data[..output.len()]);

        let config = EncryptionReaderConfig {
            private_keys: Vec::new(),
            encrypt_parameters: Some((KEY, NONCE)),
            shared_secrets: Vec::new(),
        };
        // read without tag checking
        let mut encrypt_r = EncryptionLayerTruncatedReader::new_skip_header(
            Box::new(RawLayerTruncatedReader::new(trunc)),
            &config,
            TruncatedReaderDecryptionMode::DataEvenUnauthenticated,
        )
        .unwrap();
        let mut output = Vec::new();
        encrypt_r.read_to_end(&mut output).unwrap();

        // We should have correctly read 2*CHUNK_SIZE + 128 bytes, the last 128 bytes being unauthenticated
        assert_eq!(output.len(), length);
        assert_eq!(output, data);
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
            shared_secrets: Vec::new(),
        };
        let mut encrypt_r =
            InternalEncryptionLayerReader::new(Box::new(RawLayerReader::new(buf)), &config, None)
                .unwrap();
        encrypt_r.initialize().unwrap();
        let mut output = Vec::new();
        encrypt_r.read_to_end(&mut output).unwrap();
        assert_eq!(output, FAKE_FILE);

        // Seek and decrypt twice the same thing
        let pos = encrypt_r.stream_position().unwrap();
        // test the current position retrievial
        assert_eq!(pos, FAKE_FILE.len() as u64);
        // decrypt twice the same thing, with an offset
        let pos = encrypt_r.seek(SeekFrom::Start(5)).unwrap();
        assert_eq!(pos, 5);
        let mut output = Vec::new();
        encrypt_r.read_to_end(&mut output).unwrap();
        println!("{output:?}");
        assert_eq!(output.as_slice(), &FAKE_FILE[5..]);
    }

    #[test]
    fn encrypt_op_chunk_size() {
        // Operate near the chunk size

        // Instantiate a EncryptionLayerWriter and fill it with at least CHUNK_SIZE data
        let mut file = Vec::new();
        file.write_all(CHUNK_MAGIC).unwrap();
        file.write_all(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let mut encrypt_w = Box::new(
            InternalEncryptionLayerWriter::new(
                Box::new(RawLayerWriter::new(file)),
                &InternalEncryptionConfig {
                    key: KEY,
                    nonce: NONCE,
                },
            )
            .unwrap(),
        );
        let length =
            usize::try_from(NORMAL_CHUNK_PT_SIZE * 2).expect("Failed to convert length to usize");
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0);
        let data: Vec<u8> = Alphanumeric.sample_iter(&mut rng).take(length).collect();
        encrypt_w.write_all(&data).unwrap();
        let mut out = encrypt_w.finalize().unwrap();
        out.resize(out.len() - EMPTY_TAIL_OPTS_SERIALIZATION.len(), 0);

        assert_eq!(
            out.len(),
            length
                + 2 * CHUNK_HEAD_USIZE
                + 2 * TAG_LENGTH
                + FINAL_INFO_USIZE
                + END_OF_ENCRYPTED_INNER_LAYER_MAGIC.len()
        );
        assert_ne!(&out[..length], data.as_slice());

        // Normal decryption
        let buf = Cursor::new(out.as_slice());
        let config = EncryptionReaderConfig {
            private_keys: Vec::new(),
            encrypt_parameters: Some((KEY, NONCE)),
            shared_secrets: Vec::new(),
        };
        let mut encrypt_r =
            InternalEncryptionLayerReader::new(Box::new(RawLayerReader::new(buf)), &config, None)
                .unwrap();
        encrypt_r.initialize().unwrap();
        let mut output = Vec::new();
        encrypt_r.read_to_end(&mut output).unwrap();
        assert_eq!(output, data);

        // Seek and decrypt twice the same thing
        let pos = encrypt_r
            .seek(SeekFrom::Start(NORMAL_CHUNK_PT_SIZE))
            .unwrap();
        assert_eq!(pos, NORMAL_CHUNK_PT_SIZE);
        let mut output = Vec::new();
        encrypt_r.read_to_end(&mut output).unwrap();
        assert_eq!(
            output.as_slice(),
            &data[usize::try_from(NORMAL_CHUNK_PT_SIZE)
                .expect("Failed to convert position to usize")..]
        );
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
