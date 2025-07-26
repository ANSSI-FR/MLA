use std::io::{self, Write};

use ed25519_dalek::SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH;
use sha2::{Digest, Sha512};

use crate::{
    EMPTY_TAIL_OPTS_SERIALIZATION, MLASerialize as _, Opts,
    crypto::{
        MaybeSeededRNG,
        hybrid_signature::{HybridMultiRecipientSigningKeys, ML_DSA87_SIGNATURE_SIZE},
        mlakey::MLASignaturePrivateKey,
    },
    errors::{ConfigError, Error},
    helpers::InnerWriterTrait,
    layers::traits::{InnerWriterType, LayerWriter},
};

pub const SIGNATURE_LAYER_MAGIC: &[u8] = b"SIGMLAAA";
pub(crate) struct SignatureLayerWriter<'a, W: 'a + InnerWriterTrait> {
    inner: InnerWriterType<'a, W>,
    signature_config: SignatureConfig,
    hash: Sha512,
}

impl<'a, W: 'a + InnerWriterTrait> SignatureLayerWriter<'a, W> {
    pub fn new(
        mut inner: InnerWriterType<'a, W>,
        signature_config: SignatureConfig,
        hash: Sha512,
    ) -> Result<Self, Error> {
        inner.write_all(SIGNATURE_LAYER_MAGIC)?;
        let _ = Opts.dump(&mut inner)?;
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
        let mut rng = self.signature_config.rng.get_rng();

        for key in self.signature_config.signature_keys.keys {
            let ed25519ph_signature = key.sign_ed25519ph(self.hash.clone())?;
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
    pub(crate) fn new(
        signature_private_keys: &[MLASignaturePrivateKey],
    ) -> Result<Self, ConfigError> {
        if signature_private_keys.is_empty() {
            return Err(ConfigError::PrivateKeyNotSet);
        }
        let signature_keys = HybridMultiRecipientSigningKeys {
            keys: signature_private_keys.to_vec(),
        };
        Ok(Self {
            signature_keys,
            rng: MaybeSeededRNG::default(),
        })
    }
}
