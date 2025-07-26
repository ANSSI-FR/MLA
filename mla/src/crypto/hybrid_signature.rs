use std::io::{Read, Write};

use ed25519_dalek::{SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH, Signature as Ed25519Signature};
use ml_dsa::{EncodedSignature, MlDsa87, Signature};
use rand_chacha::rand_core::CryptoRngCore;
use sha2::{Digest, Sha512};

use crate::{
    MLADeserialize, MLASerialize,
    crypto::mlakey::{MLASignaturePrivateKey, MLASignatureVerificationPublicKey},
    errors::Error,
};

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

impl MLASignatureVerificationPublicKey {
    pub(crate) fn verify(&self, hash_to_verify: Sha512, signature: &MLASignature) -> bool {
        match signature {
            MLASignature::MLAEd25519Ph(signature) => self
                .public_key_ed25519
                .verify_prehashed(
                    hash_to_verify,
                    Some(ED25519PH_CONTEXT),
                    &signature.ed25519ph_sig,
                )
                .is_ok(),
            MLASignature::MLAMlDsa87(signature) => {
                let message = hash_to_verify.finalize();
                self.public_key_mldsa87.verify_with_context(
                    message.as_slice(),
                    MLDSA87_CONTEXT,
                    &signature.mldsa87_sig,
                )
            }
        }
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

impl MLAEd25519PhSignature {
    fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self {
            ed25519ph_sig: Ed25519Signature::from_bytes(bytes),
        }
    }
}

impl<W: Write> MLASerialize<W> for MLAEd25519PhSignature {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        MLAED25519_SIG_METHOD.serialize(dest)?;
        dest.write_all(&self.ed25519ph_sig.to_bytes())?;
        Ok(2 + ED25519_SIGNATURE_LENGTH as u64)
    }
}

impl MLAMLDSA87Signature {
    fn from_bytes(bytes: [u8; ML_DSA87_SIGNATURE_SIZE]) -> Result<Self, Error> {
        let encoded_sig = EncodedSignature::<MlDsa87>::from(bytes);
        let mldsa87_sig =
            Signature::<MlDsa87>::decode(&encoded_sig).ok_or(Error::DeserializationError)?;
        Ok(Self { mldsa87_sig })
    }
}

impl<W: Write> MLASerialize<W> for MLAMLDSA87Signature {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        MLAMLDSA87_SIG_METHOD.serialize(dest)?;
        dest.write_all(self.mldsa87_sig.encode().as_slice())?;
        Ok(2 + ML_DSA87_SIGNATURE_SIZE as u64)
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum MLASignature {
    MLAEd25519Ph(MLAEd25519PhSignature),
    MLAMlDsa87(MLAMLDSA87Signature),
}

impl<R: Read> MLADeserialize<R> for MLASignature {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let signature_method_id = u16::deserialize(src)?;
        match signature_method_id {
            0 => {
                let bytes = MLADeserialize::deserialize(src)?;
                let parsed_signature = MLAEd25519PhSignature::from_bytes(&bytes);
                Ok(MLASignature::MLAEd25519Ph(parsed_signature))
            }
            1 => {
                let bytes = MLADeserialize::deserialize(src)?;
                let parsed_signature = MLAMLDSA87Signature::from_bytes(bytes)?;
                Ok(MLASignature::MLAMlDsa87(parsed_signature))
            }
            _ => Err(Error::DeserializationError),
        }
    }
}

pub(crate) fn deserialize_signatures(
    mut signature_data: &[u8],
) -> Result<Vec<MLASignature>, Error> {
    let mut signatures = Vec::new();
    while !signature_data.is_empty() {
        signatures.push(MLASignature::deserialize(&mut signature_data)?);
    }
    Ok(signatures)
}
