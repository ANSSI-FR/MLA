use std::io::Write;

use ed25519_dalek::{SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH, Signature as Ed25519Signature};
use ml_dsa::{MlDsa87, Signature};
use rand_chacha::rand_core::CryptoRngCore;
use sha2::{Digest, Sha512};

use crate::{MLASerialize, crypto::mlakey::MLASignaturePrivateKey, errors::Error};

const ED25519PH_CONTEXT: &[u8] = b"MLAEd25519SigMethod";
const MLDSA87_CONTEXT: &[u8] = b"MLAMLDSA87SigMethod";

pub(crate) struct HybridMultiRecipientSigningKeys {
    pub(crate) keys: Vec<MLASignaturePrivateKey>,
}

impl MLASignaturePrivateKey {
    pub(crate) fn sign_ed25519ph(
        &self,
        hash_to_sign: Sha512,
    ) -> Result<MLAEd25519PhSignature, Error> {
        let ed25519ph_sig = self
            .private_key_ed25519
            .sign_prehashed(hash_to_sign.clone(), Some(ED25519PH_CONTEXT))
            .unwrap(); // Should not fail as it can fail only if context length is greater than 255
        Ok(MLAEd25519PhSignature { ed25519ph_sig })
    }
    pub(crate) fn sign_mldsa87(
        &self,
        hash_to_sign: Sha512,
        mut csprng: impl CryptoRngCore,
    ) -> Result<MLAMLDSA87Signature, Error> {
        let finalized_hash = hash_to_sign.finalize();
        let mldsa87_sig = self
            .private_key_seed_mldsa
            .to_signing_key()
            .sign_randomized(finalized_hash.as_slice(), MLDSA87_CONTEXT, &mut csprng)
            .map_err(|_| Error::RandError)?;
        Ok(MLAMLDSA87Signature { mldsa87_sig })
    }
}

pub(crate) struct MLAEd25519PhSignature {
    ed25519ph_sig: Ed25519Signature,
}

pub(crate) struct MLAMLDSA87Signature {
    mldsa87_sig: Signature<MlDsa87>,
}

pub(crate) const ML_DSA87_SIGNATURE_SIZE: usize = 4627;

const MLAED25519_SIG_METHOD: u16 = 0;
const MLAMLDSA87_SIG_METHOD: u16 = 1;

impl<W: Write> MLASerialize<W> for MLAEd25519PhSignature {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        MLAED25519_SIG_METHOD.serialize(dest)?;
        dest.write_all(&self.ed25519ph_sig.to_bytes())?;
        Ok(2 + ED25519_SIGNATURE_LENGTH as u64)
    }
}

impl<W: Write> MLASerialize<W> for MLAMLDSA87Signature {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        MLAMLDSA87_SIG_METHOD.serialize(dest)?;
        dest.write_all(self.mldsa87_sig.encode().as_slice())?;
        Ok(2 + ML_DSA87_SIGNATURE_SIZE as u64)
    }
}
