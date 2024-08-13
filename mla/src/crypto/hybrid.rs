use crate::crypto::aesgcm::{ConstantTimeEq, Key, KEY_SIZE, TAG_LENGTH};
use crate::crypto::hpke::{dhkem_decap, dhkem_encap, key_schedule_s, DHKEMCiphertext};
use crate::errors::ConfigError;
use crate::layers::encrypt::get_crypto_rng;
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem1024};
use rand::Rng;
use rand_chacha::rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// `info` to bound the HPKE usage to the MLA Recipient derivation
const HPKE_INFO_RECIPIENT: &[u8] = b"MLA Recipient";

/// Common structures for ML-KEM 1024
type MLKEMCiphertext = [u8; 1568];
/// ML-KEM 1024 "private key"
pub type MLKEMDecapsulationKey = <MlKem1024 as KemCore>::DecapsulationKey;
/// ML-KEM 1024 "public key"
pub type MLKEMEncapsulationKey = <MlKem1024 as KemCore>::EncapsulationKey;

type HybridKemSharedSecretArray = [u8; 32];
type EncryptedSharedSecret = HybridKemSharedSecretArray;

/// A shared secret, as produced by the Hybrid KEM decapsulation/encapsulation
///
/// The type is wrapped to ease future changes & traits implementation
#[derive(Zeroize, ZeroizeOnDrop, Debug)]
pub(crate) struct HybridKemSharedSecret(pub(crate) HybridKemSharedSecretArray);

impl HybridKemSharedSecret {
    /// Generate a new HybridKemSharedSecret from a CSPRNG
    pub fn from_rng<R: CryptoRngCore>(csprng: &mut R) -> Self {
        Self(csprng.gen::<HybridKemSharedSecretArray>())
    }
}

impl PartialEq for HybridKemSharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

const HYBRIDKEM_ASSOCIATED_DATA: &[u8; 0] = b"";

/// Produce a secret key by combining two KEM-Encaps outputs, using a "Nested Dual-PRF Combiner", proved in [6] (3.3)
///
/// Arguments:
/// - The use of concatenation scheme **including the ciphertext** keeps IND-CCA2 if one of the two
///   underlying scheme is IND-CCA2, as proved in [1] and explained in [4]
/// - TLS [2] uses a similar scheme, and IKE [3] also uses a concatenation scheme
/// - This kind of scheme follows ANSSI recommandations [5]
/// - HKDF can be considered as a Dual-PRF if both inputs are uniformly random [7]. In MLA, the `combine` method
///   is called with a shared secret from ML-KEM, and the resulting ECC key derivation -- both are uniformly random
/// - To avoid potential mistake in the future, or a mis-reuse of this method, the "Nested Dual-PRF Combiner" is
///   used instead of the "Dual-PRF Combiner" (also from [6]). Indeed, this combiner force the "salt" part of HKDF
///   to be uniformly random using an additionnal PRF use, ensuring the following HKDF is indeed a Dual-PRF
///
/// uniformly_random_ss1 = HKDF-SHA256-Extract(
///     salt=0,
///     ikm=ss1
/// )
/// key = HKDF(
///     salt=uniformly_random_ss1,
///     ikm=ss2,
///     info=ct1 . ct2
/// )
///
/// with ss1 and ss2 the shared secrets and ct1 and ct2 the ciphertexts
///
/// [1] "F. Giacon, F. Heuer, and B. Poettering. Kem combiners, Cham, 2018"
/// [2] https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/
/// [3] https://datatracker.ietf.org/doc/html/rfc9370
/// [4] https://eprint.iacr.org/2024/039
/// [5] https://cyber.gouv.fr/en/publications/follow-position-paper-post-quantum-cryptography
/// [6] https://eprint.iacr.org/2018/903.pdf
/// [7] https://eprint.iacr.org/2023/861
fn combine(
    shared_secret1: &[u8],
    shared_secret2: &[u8],
    ciphertext1: &[u8],
    ciphertext2: &[u8],
) -> Key {
    // Make the first shared-secret uniformly random
    let (uniformly_random_ss1, _hkdf) = Hkdf::<Sha256>::extract(None, shared_secret1);

    // As uniformly_random_ss1 is uniformly random, HKDF-Extract act as a Dual-PRF
    let hkdf = Hkdf::<Sha256>::new(
        Some(&uniformly_random_ss1),
        // Combine with the second shared secret
        shared_secret2,
    );

    // Include ciphertexts to keep IND-CCA2 even if one of the KEM is not
    let mut key = [0u8; KEY_SIZE];
    hkdf.expand_multi_info(&[ciphertext1, ciphertext2], &mut key)
        .expect("Safe to unwrap, 32 is a valid length for SHA256");

    key
}

// ------- KEM implementation for a multi-recipient, hybrid, scheme -------
//
// Scheme 1: ECC, with X25519
// Scheme 2: ML (post-quantum), with FIPS-203 ML-KEM (CRYSTALS Kyber 1024)
//
// Use `_ecc` and `_ml` naming rather than a generic approach (`_1``, `_2`)
// to avoid confusion / prone-to-error code

/// Per-recipient hybrid encapsulated shared secret
#[derive(Serialize, Deserialize)]
struct HybridRecipientEncapsulatedKey {
    /// Ciphertext for ML-KEM
    #[serde(with = "BigArray")]
    ct_ml: MLKEMCiphertext,
    /// Ciphertext for DH-KEM (actually an ECC ephemeral public key)
    ct_ecc: DHKEMCiphertext,
    /// Wrapped (encrypted) version of the main shared secret
    /// - Algorithm: AES-256-GCM
    /// - Key: per-recipient hybrid shared secret
    /// - Nonce: per-recipient
    wrapped_ss: EncryptedSharedSecret,
    /// Associated tag
    tag: [u8; TAG_LENGTH],
}

/// Key encapsulated for multiple recipient with hybrid cryptography
/// Will be store in and load from the header
#[derive(Serialize, Deserialize)]
pub struct HybridMultiRecipientEncapsulatedKey {
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

impl Zeroize for HybridPrivateKey {
    fn zeroize(&mut self) {
        self.private_key_ecc.zeroize();
        //TODO: once ml_kem introduce zeroize for DecapsulationKey, use it instead
        // The current solution has no guarantee
        let (private, _pub) = MlKem1024::generate(&mut get_crypto_rng());
        self.private_key_ml = private;
    }
}

impl Decapsulate<HybridMultiRecipientEncapsulatedKey, HybridKemSharedSecret> for HybridPrivateKey {
    type Error = ConfigError;

    fn decapsulate(
        &self,
        encapsulated_key: &HybridMultiRecipientEncapsulatedKey,
    ) -> Result<HybridKemSharedSecret, Self::Error> {
        // For each possible recipient, compute the candidate hybrid shared secret
        for recipient in &encapsulated_key.recipients {
            let ss_ecc = dhkem_decap(&recipient.ct_ecc, &self.private_key_ecc)
                .or(Err(ConfigError::DHKEMComputationError))?;
            let ss_ml = self
                .private_key_ml
                .decapsulate(&recipient.ct_ml.into())
                .or(Err(ConfigError::MLKEMComputationError))?;

            let ss_recipient = combine(
                &ss_ecc.0,
                &ss_ml,
                &recipient.ct_ecc.to_bytes(),
                &recipient.ct_ml,
            );

            let (unwrap_key, unwrap_nonce) = key_schedule_s(&ss_recipient, HPKE_INFO_RECIPIENT)
                .or(Err(ConfigError::KeyWrappingComputationError))?;

            // Unwrap the candidate shared secret and check it using AES-GCM tag validation
            let mut cipher = crate::crypto::aesgcm::AesGcm256::new(
                &unwrap_key,
                &unwrap_nonce,
                HYBRIDKEM_ASSOCIATED_DATA,
            )
            .or(Err(ConfigError::KeyWrappingComputationError))?;
            let mut decrypted_ss = HybridKemSharedSecretArray::default();
            decrypted_ss.copy_from_slice(&recipient.wrapped_ss);
            let tag = cipher.decrypt(&mut decrypted_ss);
            if tag.ct_eq(&recipient.tag).unwrap_u8() == 1 {
                return Ok(HybridKemSharedSecret(decrypted_ss));
            }
        }

        // No candidate found
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

impl Encapsulate<HybridMultiRecipientEncapsulatedKey, HybridKemSharedSecret>
    for HybridMultiRecipientsPublicKeys
{
    type Error = ConfigError;

    fn encapsulate(
        &self,
        csprng: &mut impl CryptoRngCore,
    ) -> Result<(HybridMultiRecipientEncapsulatedKey, HybridKemSharedSecret), Self::Error> {
        // Generate the final shared secret -- the one each recipient will finally retrieve
        let final_ss_hybrid = HybridKemSharedSecret::from_rng(csprng);

        let mut recipients = Vec::new();
        for recipient in &self.keys {
            // Compute the ECC shared secret
            let (ss_ecc, ct_ecc) = dhkem_encap(&recipient.public_key_ecc)
                .or(Err(ConfigError::DHKEMComputationError))?;

            // Compute the ML-KEM shared secret
            let (ct_ml, ss_ml) = &recipient
                .public_key_ml
                .encapsulate(csprng)
                .or(Err(ConfigError::MLKEMComputationError))?;

            // Combine them to obtain the recipient's hybrid key
            let ss_recipient = combine(&ss_ecc.0, ss_ml, &ct_ecc.to_bytes(), ct_ml);

            // Wrap the final shared secret
            let (wrap_key, wrap_nonce) = key_schedule_s(&ss_recipient, HPKE_INFO_RECIPIENT)
                .or(Err(ConfigError::KeyWrappingComputationError))?;
            let mut cipher = crate::crypto::aesgcm::AesGcm256::new(
                &wrap_key,
                &wrap_nonce,
                HYBRIDKEM_ASSOCIATED_DATA,
            )
            .or(Err(ConfigError::KeyWrappingComputationError))?;
            let mut wrapped_ss = EncryptedSharedSecret::default();
            wrapped_ss.copy_from_slice(&final_ss_hybrid.0);
            cipher.encrypt(&mut wrapped_ss);
            let mut tag = [0u8; TAG_LENGTH];
            tag.copy_from_slice(&cipher.into_tag());

            recipients.push(HybridRecipientEncapsulatedKey {
                ct_ml: (*ct_ml).into(),
                ct_ecc,
                wrapped_ss,
                tag,
            });
        }

        Ok((
            HybridMultiRecipientEncapsulatedKey { recipients },
            final_ss_hybrid,
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

    /// Vector test for combine
    ///
    /// Generated using the following script:
    /// ```python
    /// from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
    /// from cryptography.hazmat.primitives import hashes
    ///
    /// shared_secret1 = b"shared_secret1"
    /// shared_secret2 = b"shared_secret2"
    /// ciphertext1 = b"ciphertext1"
    /// ciphertext2 = b"ciphertext2"
    ///
    /// c = ciphertext1 + ciphertext2
    /// ke = HKDF(
    ///     hashes.SHA256(),
    ///     length=32,
    ///     salt=None,
    ///     info=None
    /// )._extract(shared_secret1)
    /// k = HKDF(
    ///     hashes.SHA256(),
    ///     length=32,
    ///     salt=ke,
    ///     info=c
    /// ).derive(shared_secret2)
    /// print(list(k))
    /// ```
    #[test]
    fn test_combine_vector() {
        let computed_result = combine(
            b"shared_secret1",
            b"shared_secret2",
            b"ciphertext1",
            b"ciphertext2",
        );
        let expected_result = [
            48, 101, 217, 203, 204, 40, 30, 190, 224, 0, 235, 53, 164, 222, 55, 98, 101, 174, 142,
            98, 125, 204, 252, 210, 251, 111, 59, 45, 110, 150, 250, 11,
        ];
        assert_eq!(&computed_result, &expected_result);
    }

    /// Test the encapsulation and decapsulation of an hybrid shared secret
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

        // Encapsulate a shared secret
        let (encapsulated_keys, ss_hybrid_encap) = hybrid_multi_recipient_keys
            .encapsulate(&mut csprng)
            .unwrap();

        // Decapsulate the shared secret
        let ss_hybrid_decap = hybrid_private_key.decapsulate(&encapsulated_keys).unwrap();

        // Ensure both secret match
        assert_eq!(ss_hybrid_encap, ss_hybrid_decap);
    }

    const NB_RECIPIENT: u32 = 10;
    /// Test the encapsulation and decapsulation of an hybrid shared secret for several recipients
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

        // Encapsulate a shared secret
        let (encapsulated_keys, ss_hybrid_encap) = hybrid_multi_recipient_public_keys
            .encapsulate(&mut csprng)
            .unwrap();

        // Decapsulate the shared secret for each recipient
        for private_key in &hybrid_multi_recipient_private_keys {
            let ss_hybrid_decap = private_key.decapsulate(&encapsulated_keys).unwrap();

            // Check the shared secret is the expected one
            assert_eq!(ss_hybrid_encap, ss_hybrid_decap);
        }
    }

    /// Test cryptographic materials (including the encapsulated shared secret) for entropy
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
        let (encapsulated_keys, ss_hybrid) = hybrid_multi_recipient_keys
            .encapsulate(&mut csprng)
            .unwrap();
        let recipient = &encapsulated_keys.recipients[0];

        // Ensure materials have enough entropy
        // This is a naive check, using compression, to avoid naive bugs
        let materials: Vec<&[u8]> = vec![&ss_hybrid.0, &recipient.tag, &recipient.wrapped_ss];
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
