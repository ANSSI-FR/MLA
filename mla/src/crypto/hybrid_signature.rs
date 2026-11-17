use std::io::{Read, Write};

use ed25519_dalek::{
    SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH, Signature as Ed25519Signature, Signer, Verifier,
};
use ml_dsa::{EncodedSignature, MlDsa87, Signature};
use rand::CryptoRng;
use sha2::{Digest, Sha512};

use crate::{
    MLADeserialize, MLASerialize,
    crypto::mlakey::{MLASignatureVerificationPublicKey, MLASigningPrivateKey},
    errors::Error,
};

const MLDSA87_CONTEXT: &[u8] = b"MLAMLDSA87SigMethod";

pub(crate) struct HybridMultiRecipientSigningKeys {
    pub(crate) keys: Vec<MLASigningPrivateKey>,
}

impl MLASigningPrivateKey {
    pub(crate) fn sign_ed25519(&self, hash_to_sign: &Sha512) -> MLAEd25519Signature {
        let finalized_hash = hash_to_sign.clone().finalize();
        let ed25519_sig = self.private_key_ed25519.sign(finalized_hash.as_slice());
        MLAEd25519Signature { ed25519_sig }
    }
    pub(crate) fn sign_mldsa87(
        &self,
        hash_to_sign: Sha512,
        mut csprng: impl CryptoRng,
    ) -> Result<MLAMLDSA87Signature, Error> {
        let finalized_hash = hash_to_sign.finalize();
        let mldsa87_sig = self
            .private_key_seed_mldsa
            .to_expanded_signing_key()
            .sign_randomized(finalized_hash.as_slice(), MLDSA87_CONTEXT, &mut csprng)
            .map_err(|_| Error::RandError)?;
        Ok(MLAMLDSA87Signature { mldsa87_sig })
    }
}

impl MLASignatureVerificationPublicKey {
    pub(crate) fn verify(&self, hash_to_verify: Sha512, signature: &MLASignature) -> bool {
        match signature {
            MLASignature::MLAEd25519(signature) => {
                let message = hash_to_verify.finalize();
                self.public_key_ed25519
                    .verify(message.as_slice(), &signature.ed25519_sig)
                    .is_ok()
            }
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

pub(crate) struct MLAEd25519Signature {
    ed25519_sig: Ed25519Signature,
}

pub(crate) struct MLAMLDSA87Signature {
    mldsa87_sig: Signature<MlDsa87>,
}

pub(crate) const ML_DSA87_SIGNATURE_SIZE: usize = 4627;

const MLAED25519_SIG_METHOD: u16 = 0;
const MLAMLDSA87_SIG_METHOD: u16 = 1;

impl MLAEd25519Signature {
    fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self {
            ed25519_sig: Ed25519Signature::from_bytes(bytes),
        }
    }
}

impl<W: Write> MLASerialize<W> for MLAEd25519Signature {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        MLAED25519_SIG_METHOD.serialize(dest)?;
        dest.write_all(&self.ed25519_sig.to_bytes())?;
        Ok(2u64
            .checked_add(u64::try_from(ED25519_SIGNATURE_LENGTH).unwrap())
            .unwrap())
    }
}

impl MLAMLDSA87Signature {
    fn from_bytes(bytes: &[u8; ML_DSA87_SIGNATURE_SIZE]) -> Result<Self, Error> {
        let encoded_sig = EncodedSignature::<MlDsa87>::from(*bytes);
        let mldsa87_sig =
            Signature::<MlDsa87>::decode(&encoded_sig).ok_or(Error::DeserializationError)?;
        Ok(Self { mldsa87_sig })
    }
}

impl<W: Write> MLASerialize<W> for MLAMLDSA87Signature {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        MLAMLDSA87_SIG_METHOD.serialize(dest)?;
        dest.write_all(self.mldsa87_sig.encode().as_slice())?;
        Ok(2u64
            .checked_add(u64::try_from(ML_DSA87_SIGNATURE_SIZE).unwrap())
            .unwrap())
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum MLASignature {
    MLAEd25519(MLAEd25519Signature),
    MLAMlDsa87(MLAMLDSA87Signature),
}

impl<R: Read> MLADeserialize<R> for MLASignature {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let signature_method_id = u16::deserialize(src)?;
        match signature_method_id {
            0 => {
                let bytes = MLADeserialize::deserialize(src)?;
                let parsed_signature = MLAEd25519Signature::from_bytes(&bytes);
                Ok(MLASignature::MLAEd25519(parsed_signature))
            }
            1 => {
                let bytes = MLADeserialize::deserialize(src)?;
                let parsed_signature = MLAMLDSA87Signature::from_bytes(&bytes)?;
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

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::crypto::mlakey::generate_mla_keypair_from_seed;

    const ED25519_SERIALIZED_SIZE: usize = 2 + ED25519_SIGNATURE_LENGTH;
    const MLDSA87_SERIALIZED_SIZE: usize = 2 + ML_DSA87_SIGNATURE_SIZE;

    fn hash_of(data: &[u8]) -> Sha512 {
        let mut hash = Sha512::new();
        hash.update(data);
        hash
    }

    fn keys(seed: u8) -> (MLASigningPrivateKey, MLASignatureVerificationPublicKey) {
        let (privkey, pubkey) = generate_mla_keypair_from_seed([seed; 32]);
        (
            privkey.get_signing_private_key().clone(),
            pubkey.get_signature_verification_public_key().clone(),
        )
    }

    fn signed(key: &MLASigningPrivateKey, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let mut ed25519 = Vec::new();
        let ed25519_len = key.sign_ed25519(&hash_of(data)).serialize(&mut ed25519);
        assert_eq!(ed25519_len.unwrap(), ed25519.len() as u64);
        let mut mldsa87 = Vec::new();
        let mldsa87_len = key
            .sign_mldsa87(hash_of(data), &mut rng)
            .unwrap()
            .serialize(&mut mldsa87);
        assert_eq!(mldsa87_len.unwrap(), mldsa87.len() as u64);
        (ed25519, mldsa87)
    }

    #[test]
    fn signatures_have_fixed_serialized_sizes() {
        let (privkey, _) = keys(1);
        let (ed25519, mldsa87) = signed(&privkey, b"data");
        assert_eq!(ed25519.len(), ED25519_SERIALIZED_SIZE);
        assert_eq!(mldsa87.len(), MLDSA87_SERIALIZED_SIZE);
    }

    #[test]
    fn signatures_roundtrip_and_verify() {
        let (privkey, pubkey) = keys(1);
        let (ed25519, mldsa87) = signed(&privkey, b"data");
        let signatures = deserialize_signatures(&[ed25519, mldsa87].concat()).unwrap();
        assert_eq!(signatures.len(), 2);
        assert!(matches!(signatures[0], MLASignature::MLAEd25519(_)));
        assert!(matches!(signatures[1], MLASignature::MLAMlDsa87(_)));
        for signature in &signatures {
            assert!(pubkey.verify(hash_of(b"data"), signature));
            assert!(!pubkey.verify(hash_of(b"other data"), signature));
        }
    }

    #[test]
    fn signatures_rejected_under_another_key() {
        let (privkey, _) = keys(1);
        let (_, other_pubkey) = keys(2);
        let (ed25519, mldsa87) = signed(&privkey, b"data");
        for signature in deserialize_signatures(&[ed25519, mldsa87].concat()).unwrap() {
            assert!(!other_pubkey.verify(hash_of(b"data"), &signature));
        }
    }

    #[test]
    fn mldsa87_signature_is_bound_to_mla_context() {
        let (privkey, pubkey) = keys(1);
        let message = hash_of(b"data").finalize();
        let signing_key = privkey.private_key_seed_mldsa.to_expanded_signing_key();
        for (context, expected) in [
            (MLDSA87_CONTEXT, true),
            (b"".as_slice(), false),
            (b"MLAMLDSA87SigMethoD".as_slice(), false),
        ] {
            let mldsa87_sig = signing_key
                .sign_deterministic(message.as_slice(), context)
                .unwrap();
            let signature = MLASignature::MLAMlDsa87(MLAMLDSA87Signature { mldsa87_sig });
            assert_eq!(pubkey.verify(hash_of(b"data"), &signature), expected);
        }
    }

    #[test]
    fn unknown_signature_method_rejected() {
        for method in [2u16, 0x100, u16::MAX] {
            let mut data = Vec::new();
            method.serialize(&mut data).unwrap();
            data.extend_from_slice(&[0u8; ML_DSA87_SIGNATURE_SIZE]);
            assert!(matches!(
                deserialize_signatures(&data),
                Err(Error::DeserializationError)
            ));
        }
    }

    #[test]
    fn truncated_or_extended_signatures_rejected() {
        let (privkey, _) = keys(1);
        let (ed25519, mldsa87) = signed(&privkey, b"data");
        for serialized in [&ed25519, &mldsa87] {
            for len in [1, 2, 3, serialized.len() - 1] {
                assert!(deserialize_signatures(&serialized[..len]).is_err());
            }
            let mut extended = serialized.clone();
            extended.push(0);
            assert!(deserialize_signatures(&extended).is_err());
        }
    }

    #[test]
    fn malformed_mldsa87_hint_rejected() {
        let (privkey, _) = keys(1);
        let (_, mut mldsa87) = signed(&privkey, b"data");
        let len = mldsa87.len();
        mldsa87[len - 8..].fill(0xff);
        assert!(matches!(
            deserialize_signatures(&mldsa87),
            Err(Error::DeserializationError)
        ));
    }
}
