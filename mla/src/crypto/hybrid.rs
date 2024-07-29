use crate::crypto::aesgcm::{ConstantTimeEq, Key, KEY_SIZE, NONCE_AES_SIZE, TAG_LENGTH};
use crate::crypto::ecc::{derive_key as ecc_derive_key, DHKEMCipherText};
use crate::errors::ConfigError;
use crate::layers::encrypt::get_crypto_rng;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem1024};
use rand::Rng;
use rand_chacha::rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

/// Common structures for ML-KEM 1024
type MLKEMCiphertext = [u8; 1568];
/// ML-KEM 1024 "private key"
pub type MLKEMDecapsulationKey = <MlKem1024 as KemCore>::DecapsulationKey;
/// ML-KEM 1024 "public key"
pub type MLKEMEncapsulationKey = <MlKem1024 as KemCore>::EncapsulationKey;

const HYBRIDKEM_ASSOCIATED_DATA: &[u8; 0] = b"";

/// Concatenation scheme to keep IND-CCA, proved in [1] and explained in [4]
/// It is very similar to the one used by TLS [2] and IKE [3], and this kind of scheme
/// follows ANSSI recommandations [5]
///
/// key = KDF(ss1 . ss2 . ct1 . ct2), with ss1 and ss2 the shared secrets and ct1 and ct2 the ciphertexts
///
/// [1] "F. Giacon, F. Heuer, and B. Poettering. Kem combiners, Cham, 2018"
/// [2] https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/
/// [3] https://datatracker.ietf.org/doc/html/rfc9370
/// [4] https://eprint.iacr.org/2024/039
/// [5] https://cyber.gouv.fr/en/publications/follow-position-paper-post-quantum-cryptography
fn combine(
    shared_secret1: &[u8],
    shared_secret2: &[u8],
    ciphertext1: &[u8],
    ciphertext2: &[u8],
) -> Key {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret1);
    hasher.update(shared_secret2);
    hasher.update(ciphertext1);
    hasher.update(ciphertext2);
    hasher.finalize().into()
    // TODO: Consider adding a HKDF, like some of the referenced sources
}

// ------- KEM implementation for a multi-recipient, hybrid, scheme -------
//
// Scheme 1: ECC, with X25519
// Scheme 2: ML (post-quantum), with FIPS-203 ML-KEM (CRYSTALS Kyber 1024)
//
// Use `_ecc` and `_ml` naming rather than a generic approach (`_1``, `_2`)
// to avoid confusion / prone-to-error code

/// Per-recipient hybrid encapsulated key
#[derive(Serialize, Deserialize)]
struct HybridRecipientEncapsulatedKey {
    /// Ciphertext for ML-KEM
    #[serde(with = "BigArray")]
    ct_ml: MLKEMCiphertext,
    /// Wrapped (encrypted) version of the main key
    /// - Algorithm: AES-GCM 256
    /// - Key: hybrid shared secret
    /// - Nonce: per-recipient
    wrapped_key: [u8; KEY_SIZE],
    /// Associated tag
    tag: [u8; TAG_LENGTH],
    /// Associated nonce
    nonce: [u8; NONCE_AES_SIZE],
}

/// Key encapsulated for multiple recipient with hybrid cryptography
/// Will be store in and load from the header
#[derive(Serialize, Deserialize)]
pub struct HybridMultiRecipientEncapsulatedKey {
    /// Common ciphertext for DH-KEM (actually an ECC ephemeral public key)
    ct_ecc: DHKEMCipherText,
    /// Key wrapping for each recipient
    recipients: Vec<HybridRecipientEncapsulatedKey>,
}

impl HybridMultiRecipientEncapsulatedKey {
    /// Return the number of recipients' key
    pub fn count_keys(&self) -> usize {
        self.recipients.len()
    }
}

/// Private key for hybrid cryptography, made of
/// - a X25519 key, for ECC (pre-quantum) cryptography
/// - a ML-KEM 1024 key, for post-quantum cryptography
///
/// Support KEM decapsulation
#[derive(Clone)]
pub struct HybridPrivateKey {
    pub private_key_ecc: X25519StaticSecret,
    pub private_key_ml: MLKEMDecapsulationKey,
}

impl Decapsulate<HybridMultiRecipientEncapsulatedKey, Key> for HybridPrivateKey {
    type Error = ConfigError;

    fn decapsulate(
        &self,
        encapsulated_key: &HybridMultiRecipientEncapsulatedKey,
    ) -> Result<Key, Self::Error> {
        // For each possible recipient, compute the candidate hybrid shared secret
        let ss_ecc = ecc_derive_key(
            &self.private_key_ecc,
            &X25519PublicKey::from(encapsulated_key.ct_ecc),
        )
        .or(Err(ConfigError::ECIESComputationError))?;
        for recipient in &encapsulated_key.recipients {
            let ss_ml = self
                .private_key_ml
                .decapsulate(&recipient.ct_ml.into())
                .or(Err(ConfigError::MLKEMComputationError))?;

            let shared_secret =
                combine(&ss_ecc, &ss_ml, &encapsulated_key.ct_ecc, &recipient.ct_ml);

            // Unwrap the candidate key and check it using AES-GCM tag validation
            let mut cipher = crate::crypto::aesgcm::AesGcm256::new(
                &shared_secret,
                &recipient.nonce,
                HYBRIDKEM_ASSOCIATED_DATA,
            )
            .or(Err(ConfigError::KeyWrappingComputationError))?;
            let mut decrypted_key = Key::default();
            decrypted_key.copy_from_slice(&recipient.wrapped_key);
            let tag = cipher.decrypt(&mut decrypted_key);
            if tag.ct_eq(&recipient.tag).unwrap_u8() == 1 {
                return Ok(decrypted_key);
            }
        }

        // No candidate key found
        Err(ConfigError::PrivateKeyNotFound)
    }
}

/// Public key for hybrid cryptography, made of
/// - a X25519 key, for ECC (pre-quantum) cryptography
/// - a ML-KEM 1024 key, for post-quantum cryptography
#[derive(Clone)]
pub struct HybridPublicKey {
    pub public_key_ecc: X25519PublicKey,
    pub public_key_ml: MLKEMEncapsulationKey,
}

/// Public keys for multiple recipients, used for hybrid cryptography
///
/// Support KEM encapsulation
#[derive(Default)]
pub(crate) struct HybridMultiRecipientsPublicKeys {
    pub(crate) keys: Vec<HybridPublicKey>,
}

impl Encapsulate<HybridMultiRecipientEncapsulatedKey, Key> for HybridMultiRecipientsPublicKeys {
    type Error = ConfigError;

    fn encapsulate(
        &self,
        csprng: &mut impl CryptoRngCore,
    ) -> Result<(HybridMultiRecipientEncapsulatedKey, Key), Self::Error> {
        // Generate the final Key -- the one each recipient will finally retrieve
        let key = csprng.gen::<Key>();

        // A `StaticSecret` is used instead of an `EphemeralSecret` to allow for
        // multiple diffie-hellman computation
        let ephemeral = X25519StaticSecret::from(csprng.gen::<[u8; 32]>());
        let ct_ecc = X25519PublicKey::from(&ephemeral);

        let mut recipients = Vec::new();
        for recipient in &self.keys {
            // Compute the ECC shared secret
            let ss_ecc = ecc_derive_key(&ephemeral, &recipient.public_key_ecc)
                .or(Err(ConfigError::ECIESComputationError))?;

            // Compute the ML-KEM shared secret
            let (ct_ml, ss_ml) = &recipient
                .public_key_ml
                .encapsulate(csprng)
                .or(Err(ConfigError::MLKEMComputationError))?;

            // Combine them to obtain the hybrid shared secret
            let ss_hybrid = combine(&ss_ecc, ss_ml, ct_ecc.as_bytes(), ct_ml);

            // Wrap the final key
            let nonce = csprng.gen::<[u8; NONCE_AES_SIZE]>();
            let mut cipher = crate::crypto::aesgcm::AesGcm256::new(
                &ss_hybrid,
                &nonce,
                HYBRIDKEM_ASSOCIATED_DATA,
            )
            .or(Err(ConfigError::KeyWrappingComputationError))?;
            let mut wrapped_key = Key::default();
            wrapped_key.copy_from_slice(&key);
            cipher.encrypt(&mut wrapped_key);
            let mut tag = [0u8; TAG_LENGTH];
            tag.copy_from_slice(&cipher.into_tag());

            recipients.push(HybridRecipientEncapsulatedKey {
                ct_ml: (*ct_ml).into(),
                wrapped_key,
                tag,
                nonce,
            });
        }

        Ok((
            HybridMultiRecipientEncapsulatedKey {
                ct_ecc: ct_ecc.to_bytes(),
                recipients,
            },
            key,
        ))
    }
}

/// Generate an Hybrid key pair using the provided csprng
pub fn generate_keypair_from_rng(
    mut csprng: impl CryptoRngCore,
) -> (HybridPrivateKey, HybridPublicKey) {
    let private_key_ecc = X25519StaticSecret::random_from_rng(&mut csprng);
    let public_key_ecc = X25519PublicKey::from(&private_key_ecc);
    let (private_key_ml, public_key_ml) = MlKem1024::generate(&mut csprng);
    (
        HybridPrivateKey {
            private_key_ecc,
            private_key_ml,
        },
        HybridPublicKey {
            public_key_ecc,
            public_key_ml,
        },
    )
}

/// Generate an Hybrid key pair using a CSPRNG
pub fn generate_keypair() -> (HybridPrivateKey, HybridPublicKey) {
    generate_keypair_from_rng(get_crypto_rng())
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use brotli;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use std::collections::HashSet;

    use super::*;

    /// Test that combine indeed depends on each input
    #[test]
    fn test_combine() {
        let shared_secret1 = vec![1, 2, 3];
        let shared_secret1_mod = vec![0xff, 2, 3];
        let shared_secret2 = vec![4, 5, 6];
        let shared_secret2_mod = vec![0xff, 5, 6];
        let ciphertext1 = vec![7, 8, 9];
        let ciphertext1_mod = vec![0xff, 8, 9];
        let ciphertext2 = vec![10, 11, 12];
        let ciphertext2_mod = vec![0xff, 11, 12];

        // Cartesian product of all possibilities
        let res1 = combine(&shared_secret1, &shared_secret2, &ciphertext1, &ciphertext2);
        let res2 = combine(
            &shared_secret1_mod,
            &shared_secret2,
            &ciphertext1,
            &ciphertext2,
        );
        let res3 = combine(
            &shared_secret1,
            &shared_secret2_mod,
            &ciphertext1,
            &ciphertext2,
        );
        let res4 = combine(
            &shared_secret1,
            &shared_secret2,
            &ciphertext1_mod,
            &ciphertext2,
        );
        let res5 = combine(
            &shared_secret1,
            &shared_secret2,
            &ciphertext1,
            &ciphertext2_mod,
        );

        // Ensure they are all unique
        let unique_results: HashSet<_> = vec![res1, res2, res3, res4, res5].into_iter().collect();
        assert_eq!(unique_results.len(), 5);
    }

    /// Test the encapsulation and decapsulation of an hybrid key
    #[test]
    fn test_encapsulate_decapsulate() {
        let mut csprng = ChaChaRng::from_entropy();

        // Create public and private keys
        let private_key_ecc = X25519StaticSecret::from(csprng.gen::<[u8; 32]>());
        let public_key_ecc = X25519PublicKey::from(&private_key_ecc);
        let (private_key_ml, public_key_ml) = MlKem1024::generate(&mut csprng);

        // Create hybrid public and private keys
        let hybrid_private_key = HybridPrivateKey {
            private_key_ecc,
            private_key_ml,
        };
        let hybrid_public_key = HybridPublicKey {
            public_key_ecc,
            public_key_ml,
        };

        // Create hybrid multi-recipient encapsulated keys
        let hybrid_multi_recipient_keys = HybridMultiRecipientsPublicKeys {
            keys: vec![hybrid_public_key],
        };

        // Encapsulate a key
        let (encapsulated_keys, key_encap) = hybrid_multi_recipient_keys
            .encapsulate(&mut csprng)
            .unwrap();

        // Decapsulate the key
        let key_decap = hybrid_private_key.decapsulate(&encapsulated_keys).unwrap();

        // Ensure both key match
        assert_eq!(key_encap, key_decap);
    }

    const NB_RECIPIENT: u32 = 10;
    /// Test the encapsulation and decapsulation of an hybrid key for several recipients
    #[test]
    fn test_encapsulate_decapsulate_multi() {
        let mut csprng = ChaChaRng::from_entropy();

        let mut hybrid_multi_recipient_public_keys =
            HybridMultiRecipientsPublicKeys { keys: Vec::new() };
        let mut hybrid_multi_recipient_private_keys = Vec::new();
        for _ in 0..NB_RECIPIENT {
            // Create public and private keys
            let private_key_ecc = X25519StaticSecret::from(csprng.gen::<[u8; 32]>());
            let public_key_ecc = X25519PublicKey::from(&private_key_ecc);
            let (private_key_ml, public_key_ml) = MlKem1024::generate(&mut csprng);

            // Create hybrid public and private keys
            let hybrid_private_key = HybridPrivateKey {
                private_key_ecc,
                private_key_ml,
            };
            let hybrid_public_key = HybridPublicKey {
                public_key_ecc,
                public_key_ml,
            };

            hybrid_multi_recipient_public_keys
                .keys
                .push(hybrid_public_key);
            hybrid_multi_recipient_private_keys.push(hybrid_private_key);
        }

        // Encapsulate a key
        let (encapsulated_keys, key_encap) = hybrid_multi_recipient_public_keys
            .encapsulate(&mut csprng)
            .unwrap();

        // Decapsulate the key for each recipient
        for private_key in &hybrid_multi_recipient_private_keys {
            let key_decap = private_key.decapsulate(&encapsulated_keys).unwrap();

            // Check the key is the expected one
            assert_eq!(key_encap, key_decap);
        }
    }

    /// Test cryprographic materials (including the encapsulated key) for entropy
    #[test]
    fn test_encapsulated_key_entropy() {
        let mut csprng = ChaChaRng::from_entropy();

        // Create initial materials
        let private_key_ecc = X25519StaticSecret::from(csprng.gen::<[u8; 32]>());
        let public_key_ecc = X25519PublicKey::from(&private_key_ecc);
        let (_private_key_ml, public_key_ml) = MlKem1024::generate(&mut csprng);
        let hybrid_public_key = HybridPublicKey {
            public_key_ecc,
            public_key_ml,
        };
        let hybrid_multi_recipient_keys = HybridMultiRecipientsPublicKeys {
            keys: vec![hybrid_public_key],
        };

        // Encapsulate a key
        let (encapsulated_keys, key_encap) = hybrid_multi_recipient_keys
            .encapsulate(&mut csprng)
            .unwrap();
        let recipient = &encapsulated_keys.recipients[0];

        // Ensure materials have enough entropy
        // This is a naive check, using compression, to avoid naive bugs
        let materials: Vec<&[u8]> = vec![
            &key_encap,
            &recipient.nonce,
            &recipient.tag,
            &recipient.wrapped_key,
        ];
        for material in materials {
            let mut compressed = brotli::CompressorReader::new(material, 0, 0, 0);
            let mut compressed_data = Vec::new();
            compressed.read_to_end(&mut compressed_data).unwrap();

            assert!(compressed_data.len() >= material.len());
        }
    }

    /// Test the generation of a key pair
    #[test]
    fn test_generate_keypair() {
        let (private_key, public_key) = generate_keypair();

        // Ensure the ECC private key correspond to the ECC public key
        let public_key_ecc = X25519PublicKey::from(&private_key.private_key_ecc);
        assert_eq!(public_key_ecc, public_key.public_key_ecc);

        // Ensure the ML private key correspond to the ML public key
        let mut rng = ChaChaRng::from_entropy();
        let (encap, key) = public_key.public_key_ml.encapsulate(&mut rng).unwrap();
        let key_decap = private_key.private_key_ml.decapsulate(&encap).unwrap();
        assert_eq!(key, key_decap);
    }

    #[test]
    fn test_generate_keypair_from_rng() {
        // Ensure reproductability
        let mut rng = ChaChaRng::seed_from_u64(0);
        let (private_key, public_key) = generate_keypair_from_rng(&mut rng);
        let mut rng = ChaChaRng::seed_from_u64(0);
        let (private_key2, public_key2) = generate_keypair_from_rng(&mut rng);

        assert_eq!(
            private_key.private_key_ecc.to_bytes(),
            private_key2.private_key_ecc.to_bytes()
        );
        assert_eq!(private_key.private_key_ml, private_key2.private_key_ml);
        assert_eq!(
            public_key.public_key_ecc.as_bytes(),
            public_key2.public_key_ecc.as_bytes()
        );
        assert_eq!(public_key.public_key_ml, public_key2.public_key_ml);

        // Ensure keypair are different
        let mut rng = ChaChaRng::seed_from_u64(1);
        let (private_key3, public_key3) = generate_keypair_from_rng(&mut rng);

        assert_ne!(
            private_key.private_key_ecc.to_bytes(),
            private_key3.private_key_ecc.to_bytes()
        );
        assert_ne!(private_key.private_key_ml, private_key3.private_key_ml);
        assert_ne!(
            public_key.public_key_ecc.as_bytes(),
            public_key3.public_key_ecc.as_bytes()
        );
        assert_ne!(public_key.public_key_ml, public_key3.public_key_ml);
    }
}
