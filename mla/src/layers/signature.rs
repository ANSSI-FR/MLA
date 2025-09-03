use std::io::{self, Read, Seek, SeekFrom, Write, sink};

use ed25519_dalek::SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH;
use sha2::{Digest, Sha512};

use crate::{
    EMPTY_TAIL_OPTS_SERIALIZATION, MLADeserialize as _, MLASerialize as _, Opts,
    crypto::{
        MaybeSeededRNG,
        hash::{HashWrapperReader, HashWrapperWriter},
        hybrid_signature::{
            HybridMultiRecipientSigningKeys, ML_DSA87_SIGNATURE_SIZE, MLASignature,
            deserialize_signatures,
        },
        mlakey::{MLASignatureVerificationPublicKey, MLASigningPrivateKey},
    },
    errors::{ConfigError, Error},
    helpers::{InnerReaderTrait, InnerWriterTrait},
    layers::{
        encrypt::{
            ENCRYPTION_LAYER_MAGIC, EncryptionPersistentConfig, read_encryption_header_after_magic,
        },
        strip_head_tail::StripHeadTailReader,
        traits::{InnerWriterType, LayerTruncatedReader, LayerReader, LayerWriter},
    },
    read_layer_magic,
};

pub const SIGNATURE_LAYER_MAGIC: &[u8] = b"SIGMLAAA";
pub(crate) struct SignatureLayerWriter<'a, W: 'a + InnerWriterTrait> {
    inner: InnerWriterType<'a, W>,
    signature_config: SignatureConfig,
    hash: Sha512,
}

impl<'a, W: 'a + InnerWriterTrait> SignatureLayerWriter<'a, W> {
    pub fn new(
        inner: InnerWriterType<'a, W>,
        signature_config: SignatureConfig,
        mut hash: Sha512,
    ) -> Result<Self, Error> {
        let mut inner = HashWrapperWriter::new(inner, &mut hash);
        inner.write_all(SIGNATURE_LAYER_MAGIC)?;
        let _ = Opts.dump(&mut inner)?;
        let inner = inner.into_inner();

        Ok(Self {
            inner,
            signature_config,
            hash,
        })
    }
}

impl<'a, W: 'a + InnerWriterTrait> Write for SignatureLayerWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hash.update(buf);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, W: 'a + InnerWriterTrait> LayerWriter<'a, W> for SignatureLayerWriter<'a, W> {
    fn finalize(self: Box<Self>) -> Result<W, Error> {
        let mut out = Box::new(self.inner).finalize()?;

        out.write_all(EMPTY_TAIL_OPTS_SERIALIZATION)?;

        // compute signature_data_content_size (the number of content bytes in the `signature_data` Vec<u8>):
        //  (number of keys) * (ed25519 signature size + mldsa signature size + 2 + 2)
        // There are two +2: one for each signature algo corresponding to the u16 encoding signature_method_id
        // See doc/src/FORMAT.md
        let signature_data_content_size: usize = self.signature_config.signature_keys.keys.len()
            * (2 + ED25519_SIGNATURE_LENGTH + 2 + ML_DSA87_SIGNATURE_SIZE);
        let signature_data_content_size =
            u64::try_from(signature_data_content_size).map_err(|_| Error::DeserializationError)?;
        // Serialize signature_data_content_size:
        signature_data_content_size.serialize(&mut out)?;

        // prepare rng for mldsa
        let mut rng = self.signature_config.rng.get_rng()?;

        for key in self.signature_config.signature_keys.keys {
            let ed25519ph_signature = key.sign_ed25519ph(&self.hash.clone());
            ed25519ph_signature.serialize(&mut out)?;
            let mldsa87_signature = key.sign_mldsa87(self.hash.clone(), &mut rng)?;
            mldsa87_signature.serialize(&mut out)?;
        }
        (signature_data_content_size + 8).serialize(&mut out)?; // +8 for the Vec's length encoding

        Ok(out)
    }
}

pub(crate) struct SignatureConfig {
    signature_keys: HybridMultiRecipientSigningKeys,
    pub(crate) rng: MaybeSeededRNG,
}

impl SignatureConfig {
    pub(crate) fn new(signing_private_keys: &[MLASigningPrivateKey]) -> Result<Self, ConfigError> {
        if signing_private_keys.is_empty() {
            return Err(ConfigError::PrivateKeyNotSet);
        }
        let signature_keys = HybridMultiRecipientSigningKeys {
            keys: signing_private_keys.to_vec(),
        };
        Ok(Self {
            signature_keys,
            rng: MaybeSeededRNG::default(),
        })
    }
}

pub(crate) struct SignatureReaderConfig {
    signature_verification_keys: Vec<MLASignatureVerificationPublicKey>,
    pub(crate) signature_check: bool,
}

impl SignatureReaderConfig {
    pub(crate) fn set_public_keys(&mut self, keys: &[MLASignatureVerificationPublicKey]) {
        self.signature_verification_keys = keys.to_vec();
    }
}

impl Default for SignatureReaderConfig {
    fn default() -> Self {
        Self {
            signature_verification_keys: Vec::default(),
            signature_check: true,
        }
    }
}

pub(crate) struct SignatureLayerReader<'a, R: 'a + InnerReaderTrait>(StripHeadTailReader<'a, R>);

impl<'a, R: 'a + InnerReaderTrait> SignatureLayerReader<'a, R> {
    pub(crate) fn new_skip_magic(
        mut inner: Box<dyn 'a + LayerReader<'a, R>>,
        signature_reader_config: &SignatureReaderConfig,
        archive_header_hash: Sha512,
    ) -> Result<
        (
            Self,
            Vec<MLASignatureVerificationPublicKey>,
            Option<EncryptionPersistentConfig>,
        ),
        Error,
    > {
        let mut signed_hash = archive_header_hash;
        inner.initialize()?;
        let mut src = HashWrapperReader::<_, Sha512>::new(inner, &mut signed_hash);
        let _ = Opts::from_reader(&mut src)?; // No option handled at the moment
        let mut src = src.into_inner();

        let sig_inner_layer_position = src.stream_position()?;
        // Shallow parse signature and footer options now to know up to where to hash
        src.seek(SeekFrom::End(-8))?;
        let signature_data_serialized_vec_length = u64::deserialize(&mut src)?;
        let signature_data_offset_from_end = 8u64 // rewind over signature_data_serialized_vec_length
            .checked_add(signature_data_serialized_vec_length) // rewind over signature_data's Vec
            .ok_or(Error::DeserializationError)?;
        let i64_signature_data_offset_from_end = 0i64
            .checked_sub_unsigned(signature_data_offset_from_end)
            .ok_or(Error::DeserializationError)?;
        src.seek(SeekFrom::End(i64_signature_data_offset_from_end))?;
        let signature_data = Vec::<u8>::deserialize(&mut src)?;
        let signature_options_length_offset_from_end = signature_data_offset_from_end
            .checked_add(8) // rewind over the signature_options_length we want to read
            .ok_or(Error::DeserializationError)?;
        let i64_signature_options_length_offset_from_end = 0i64
            .checked_sub_unsigned(signature_options_length_offset_from_end)
            .ok_or(Error::DeserializationError)?;
        src.seek(SeekFrom::End(i64_signature_options_length_offset_from_end))?;
        let signature_options_length = u64::deserialize(&mut src)?;
        let sig_layer_tail_len = signature_options_length_offset_from_end
            .checked_add(signature_options_length)
            .ok_or(Error::DeserializationError)?;

        let inner_len = src.seek(SeekFrom::End(0))?;
        src.seek(SeekFrom::Start(sig_inner_layer_position))?;
        let mut src = StripHeadTailReader::new(
            src,
            sig_inner_layer_position,
            sig_layer_tail_len,
            inner_len,
            0,
        )?;

        let mut keys_with_valid_signatures = Vec::new();
        let mut read_persistent_encryption_config = None;
        if signature_reader_config.signature_check {
            let mut hashing_src = HashWrapperReader::new(src, &mut signed_hash);
            let next_layer_magic = read_layer_magic(&mut hashing_src)?;
            if &next_layer_magic == ENCRYPTION_LAYER_MAGIC {
                read_persistent_encryption_config =
                    Some(read_encryption_header_after_magic(&mut hashing_src)?.0);
            }
            // hash the rest of sig_inner_layer
            io::copy(&mut hashing_src, &mut sink())?;
            src = hashing_src.into_inner();
            src.rewind()?;

            // check signatures
            let mut keys_ref_with_valid_signatures = Vec::new();
            let signatures = deserialize_signatures(&signature_data)?;
            for key in &signature_reader_config.signature_verification_keys {
                let verified_signatures = signatures
                    .iter()
                    .filter(|sig| key.verify(signed_hash.clone(), sig))
                    .collect::<Vec<_>>();
                let traditional_signature_verified = verified_signatures
                    .iter()
                    .any(|sig| matches!(sig, MLASignature::MLAEd25519Ph(_)));
                let post_quantum_signature_verified = verified_signatures
                    .iter()
                    .any(|sig| matches!(sig, MLASignature::MLAMlDsa87(_)));
                if traditional_signature_verified && post_quantum_signature_verified {
                    keys_ref_with_valid_signatures.push(key);
                }
            }

            if keys_ref_with_valid_signatures.is_empty() {
                return Err(Error::NoValidSignatureFound);
            }
            keys_with_valid_signatures.extend(keys_ref_with_valid_signatures.into_iter().cloned());
        }

        Ok((
            Self(src),
            keys_with_valid_signatures,
            read_persistent_encryption_config,
        ))
    }
}

impl<'a, R: 'a + InnerReaderTrait> Read for SignatureLayerReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<'a, R: 'a + InnerReaderTrait> Seek for SignatureLayerReader<'a, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

impl<'a, R: 'a + InnerReaderTrait> LayerReader<'a, R> for SignatureLayerReader<'a, R> {
    fn into_raw(self: Box<Self>) -> R {
        Box::new(self.0).into_raw()
    }

    fn initialize(&mut self) -> Result<(), Error> {
        // nothing, inner layer was already initialized during new
        Ok(())
    }
}

pub(crate) struct SignatureLayerTruncatedReader<'a, R: Read> {
    inner: Box<dyn 'a + LayerTruncatedReader<'a, R>>,
}

impl<'a, R: 'a + Read> SignatureLayerTruncatedReader<'a, R> {
    pub(crate) fn new_skip_magic(
        mut inner: Box<dyn 'a + LayerTruncatedReader<'a, R>>,
    ) -> Result<Self, Error> {
        let _ = Opts::from_reader(&mut inner)?; // No option handled at the moment
        Ok(Self { inner })
    }
}

impl<'a, R: 'a + Read> LayerTruncatedReader<'a, R> for SignatureLayerTruncatedReader<'a, R> {}

impl<R: Read> Read for SignatureLayerTruncatedReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}
