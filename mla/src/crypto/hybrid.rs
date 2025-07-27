use std::io::{Read, Write};

use crate::crypto::aesgcm::{ConstantTimeEq, KEY_SIZE, Key, TAG_LENGTH};
use crate::crypto::hpke::{DHKEMCiphertext, dhkem_decap, key_schedule_base_hybrid_kem_recipient};
use crate::errors::{ConfigError, Error};
use crate::{MLADeserialize, MLASerialize};
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{B32, KemCore, MlKem1024};
use rand::Rng;
use rand_chacha::rand_core::CryptoRngCore;
use sha2::Sha512;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::hpke::dhkem_encap_from_rng;

pub(crate) const MLKEM_DZ_SIZE: usize = 64;

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
        Self(csprng.r#gen::<HybridKemSharedSecretArray>())
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
/// - The use of concatenation scheme **including ciphertexts** keeps IND-CCA2 if one of the two
///   underlying scheme is IND-CCA2, as proved in [1] and explained in [4]
/// - TLS [2] uses a similar scheme, and IKE [3] also uses a concatenation scheme
/// - This kind of scheme follows ANSSI recommendations [5]
/// - HKDF can be considered as a Dual-PRF if both inputs are uniformly random [7]. In MLA, the `combine` method
///   is called with a shared secret from ML-KEM, and the resulting ECC key derivation -- both are uniformly random
/// - To avoid potential mistake in the future, or a mis-reuse of this method, the "Nested Dual-PRF Combiner" is
///   used instead of the "Dual-PRF Combiner" (also from [6]). Indeed, this combiner force the "salt" part of HKDF
///   to be uniformly random using an additional PRF use, ensuring the following HKDF is indeed a Dual-PRF
///
/// uniformly_random_ss1 = HKDF-SHA512-Extract(
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
/// [2] <https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/>
/// [3] <https://datatracker.ietf.org/doc/html/rfc9370>
/// [4] <https://eprint.iacr.org/2024/039>
/// [5] <https://cyber.gouv.fr/en/publications/follow-position-paper-post-quantum-cryptography>
/// [6] <https://eprint.iacr.org/2018/903.pdf>
/// [7] <https://eprint.iacr.org/2023/861>
fn combine(
    shared_secret1: &[u8],
    shared_secret2: &[u8],
    ciphertext1: &[u8],
    ciphertext2: &[u8],
) -> Key {
    // Make the first shared-secret uniformly random
    let (uniformly_random_ss1, _hkdf) = Hkdf::<Sha512>::extract(None, shared_secret1);

    // As uniformly_random_ss1 is uniformly random, HKDF-Extract act as a Dual-PRF
    let hkdf = Hkdf::<Sha512>::new(
        Some(&uniformly_random_ss1),
        // Combine with the second shared secret
        shared_secret2,
    );

    // Include ciphertexts to keep IND-CCA2 even if one of the KEM is not
    let mut key = [0u8; KEY_SIZE];
    hkdf.expand_multi_info(&[ciphertext1, ciphertext2], &mut key)
        .expect("Safe to unwrap, 32 is a valid length for SHA512");

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
pub struct HybridRecipientEncapsulatedKey {
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

impl<W: Write> MLASerialize<W> for HybridRecipientEncapsulatedKey {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        let mut serialization_length = 0;
        serialization_length += self.ct_ml.as_slice().serialize(dest)?;
        let mut ct_ecc_bytes = self.ct_ecc.to_bytes();
        serialization_length += ct_ecc_bytes.as_slice().serialize(dest)?;
        ct_ecc_bytes.zeroize();
        serialization_length += self.wrapped_ss.as_slice().serialize(dest)?;
        serialization_length += self.tag.as_slice().serialize(dest)?;
        Ok(serialization_length)
    }
}

impl<R: Read> MLADeserialize<R> for HybridRecipientEncapsulatedKey {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let ct_ml = MLADeserialize::deserialize(src)?;
        let mut ct_ecc_bytes = <[u8; 32]>::deserialize(src)?;
        let ct_ecc =
            DHKEMCiphertext::from_bytes(&ct_ecc_bytes).or(Err(Error::DeserializationError))?;
        ct_ecc_bytes.zeroize();
        let wrapped_ss = MLADeserialize::deserialize(src)?;
        let tag = MLADeserialize::deserialize(src)?;
        Ok(Self {
            ct_ml,
            ct_ecc,
            wrapped_ss,
            tag,
        })
    }
}

/// Key encapsulated for multiple recipient with hybrid cryptography
/// Will be store in and load from the header
pub struct HybridMultiRecipientEncapsulatedKey {
    /// Key wrapping for each recipient
    pub recipients: Vec<HybridRecipientEncapsulatedKey>,
}

impl<W: Write> MLASerialize<W> for HybridMultiRecipientEncapsulatedKey {
    fn serialize(&self, dest: &mut W) -> Result<u64, Error> {
        self.recipients.serialize(dest)
    }
}

impl<R: Read> MLADeserialize<R> for HybridMultiRecipientEncapsulatedKey {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let recipients = MLADeserialize::deserialize(src)?;
        Ok(Self { recipients })
    }
}

impl HybridMultiRecipientEncapsulatedKey {
    /// Return the number of recipients' key
    pub fn count_keys(&self) -> usize {
        self.recipients.len()
    }
}

/// Represents a 64-byte seed split into two 32-byte parts (`d` and `z`).
///
/// This seed is used internally in the ML-KEM encryption scheme for
/// deterministic key derivation.
#[derive(Clone)]
pub(crate) struct MLKEMSeed {
    d: B32,
    z: B32,
}

impl MLKEMSeed {
    fn generate_from_csprng(mut csprng: impl CryptoRngCore) -> Self {
        let mut d_array = [0u8; 32];
        csprng.fill_bytes(&mut d_array);
        let mut z_array = [0u8; 32];
        csprng.fill_bytes(&mut z_array);
        Self::from_d_z_32(d_array, z_array)
    }

    fn from_d_z_32(d: [u8; 32], z: [u8; 32]) -> Self {
        let d = B32::from(d);
        let z = B32::from(z);
        Self { d, z }
    }

    /// Creates an MLKEMSeed from a 64-byte array `[d || z]`.
    pub(crate) fn from_d_z_64(mut dz: [u8; 64]) -> Self {
        let d = B32::try_from(&dz[0..32]).unwrap(); // should not fail as length is 64
        let z = B32::try_from(&dz[32..64]).unwrap(); // should not fail as length is 64
        dz.zeroize();
        Self { d, z }
    }

    pub(crate) fn to_d_z_64(&self) -> Zeroizing<[u8; 64]> {
        let mut dz64 = [0u8; 64];
        let dpart = &mut dz64[0..32];
        dpart.copy_from_slice(self.d.as_slice());
        let zpart = &mut dz64[32..];
        zpart.copy_from_slice(self.z.as_slice());
        Zeroizing::new(dz64)
    }

    pub(crate) fn to_privkey(&self) -> MLKEMDecapsulationKey {
        MlKem1024::generate_deterministic(&self.d, &self.z).0
    }

    pub(crate) fn to_pubkey(&self) -> MLKEMEncapsulationKey {
        MlKem1024::generate_deterministic(&self.d, &self.z).1
    }
}

impl PartialEq for MLKEMSeed {
    fn eq(&self, other: &Self) -> bool {
        self.d.ct_eq(&other.d).into() && self.z.ct_eq(&other.z).into()
    }
}

impl Zeroize for MLKEMSeed {
    fn zeroize(&mut self) {
        self.d.zeroize();
        self.z.zeroize();
    }
}

impl Drop for MLKEMSeed {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for MLKEMSeed {}

#[derive(Clone)]
pub struct MLADecryptionPrivateKey {
    pub(crate) private_key_ecc: X25519StaticSecret,
    pub(crate) private_key_seed_ml: MLKEMSeed,
}

impl Drop for MLADecryptionPrivateKey {
    fn drop(&mut self) {
        self.private_key_ecc.zeroize();
        // ml-kem zeroization is done natively on drop cf. https://github.com/RustCrypto/KEMs/commit/a75d842b697aa54477d017c0c7c5da661e689be3
    }
}

impl Decapsulate<HybridMultiRecipientEncapsulatedKey, HybridKemSharedSecret>
    for MLADecryptionPrivateKey
{
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
                .private_key_seed_ml
                .to_privkey()
                .decapsulate(&recipient.ct_ml.into())
                .or(Err(ConfigError::MLKEMComputationError))?;

            let ss_recipient = combine(
                &ss_ecc.0,
                &ss_ml,
                &recipient.ct_ecc.to_bytes(),
                &recipient.ct_ml,
            );

            let (unwrap_key, unwrap_nonce) =
                key_schedule_base_hybrid_kem_recipient(&ss_recipient, HPKE_INFO_RECIPIENT)
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

#[derive(Clone)]
pub struct MLAEncryptionPublicKey {
    pub(crate) public_key_ecc: X25519PublicKey,
    pub(crate) public_key_ml: MLKEMEncapsulationKey,
}

/// Public keys for multiple recipients, used for hybrid cryptography
///
/// Support KEM encapsulation
#[derive(Default)]
pub(crate) struct HybridMultiRecipientsPublicKeys {
    pub(crate) keys: Vec<MLAEncryptionPublicKey>,
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
            let (ss_ecc, ct_ecc) = dhkem_encap_from_rng(&recipient.public_key_ecc, csprng)
                .or(Err(ConfigError::DHKEMComputationError))?;

            // Compute the ML-KEM shared secret
            let (ct_ml, ss_ml) = &recipient
                .public_key_ml
                .encapsulate(csprng)
                .or(Err(ConfigError::MLKEMComputationError))?;

            // Combine them to obtain the recipient's hybrid key
            let ss_recipient = combine(&ss_ecc.0, ss_ml, &ct_ecc.to_bytes(), ct_ml);

            // Wrap the final shared secret
            let (wrap_key, wrap_nonce) =
                key_schedule_base_hybrid_kem_recipient(&ss_recipient, HPKE_INFO_RECIPIENT)
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

/// WARNING: the seed is thus as secret as the private key.
/// If provided, it should be a cryptographically secure random.
/// You should probably rather use the `generate_keypair` function.
///
/// Generate an Hybrid key pair using the provided seed
#[cfg(test)]
pub fn generate_keypair_from_seed(
    seed: [u8; 32],
) -> (MLADecryptionPrivateKey, MLAEncryptionPublicKey) {
    use rand::SeedableRng;
    let mut csprng = rand_chacha::ChaCha20Rng::from_seed(seed);
    generate_keypair_from_rng(&mut csprng)
}

/// Generate an Hybrid key pair using the provided csprng
pub(crate) fn generate_keypair_from_rng(
    mut csprng: impl CryptoRngCore,
) -> (MLADecryptionPrivateKey, MLAEncryptionPublicKey) {
    let private_key_ecc = X25519StaticSecret::random_from_rng(&mut csprng);
    let public_key_ecc = X25519PublicKey::from(&private_key_ecc);
    let private_key_seed_ml = MLKEMSeed::generate_from_csprng(&mut csprng);
    let public_key_ml = private_key_seed_ml.to_pubkey();
    (
        MLADecryptionPrivateKey {
            private_key_ecc,
            private_key_seed_ml,
        },
        MLAEncryptionPublicKey {
            public_key_ecc,
            public_key_ml,
        },
    )
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use brotli;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use std::collections::HashSet;

    use crate::crypto::mlakey::generate_mla_keypair;

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
            147, 69, 15, 150, 130, 155, 67, 230, 172, 36, 219, 184, 233, 104, 18, 142, 225, 251,
            62, 222, 149, 181, 39, 58, 182, 235, 181, 250, 45, 173, 134, 129,
        ];
        assert_eq!(&computed_result, &expected_result);
    }

    /// Test the encapsulation and decapsulation of an hybrid shared secret
    #[test]
    fn test_encapsulate_decapsulate() {
        let mut csprng = ChaChaRng::from_entropy();

        // Create public and private keys
        let private_key_ecc = X25519StaticSecret::from(csprng.r#gen::<[u8; 32]>());
        let public_key_ecc = X25519PublicKey::from(&private_key_ecc);
        let private_key_seed_ml = MLKEMSeed::generate_from_csprng(&mut csprng);
        let public_key_ml = private_key_seed_ml.to_pubkey();

        // Create hybrid public and private keys
        let hybrid_private_key = MLADecryptionPrivateKey {
            private_key_ecc,
            private_key_seed_ml,
        };
        let hybrid_public_key = MLAEncryptionPublicKey {
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
            let private_key_ecc = X25519StaticSecret::from(csprng.r#gen::<[u8; 32]>());
            let public_key_ecc = X25519PublicKey::from(&private_key_ecc);
            let private_key_seed_ml = MLKEMSeed::generate_from_csprng(&mut csprng);
            let public_key_ml = private_key_seed_ml.to_pubkey();

            // Create hybrid public and private keys
            let hybrid_private_key = MLADecryptionPrivateKey {
                private_key_ecc,
                private_key_seed_ml,
            };
            let hybrid_public_key = MLAEncryptionPublicKey {
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
        let private_key_ecc = X25519StaticSecret::from(csprng.r#gen::<[u8; 32]>());
        let public_key_ecc = X25519PublicKey::from(&private_key_ecc);
        let private_key_seed_ml = MLKEMSeed::generate_from_csprng(&mut csprng);
        let public_key_ml = private_key_seed_ml.to_pubkey();
        let hybrid_public_key = MLAEncryptionPublicKey {
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
        let (private_key, public_key) = generate_mla_keypair();

        // Ensure the ECC private key correspond to the ECC public key
        let public_key_ecc =
            X25519PublicKey::from(&private_key.get_decryption_private_key().private_key_ecc);
        assert_eq!(
            public_key_ecc,
            public_key.get_encryption_public_key().public_key_ecc
        );

        // Ensure the ML private key correspond to the ML public key
        let mut rng = ChaChaRng::from_entropy();
        let (encap, key) = public_key
            .get_encryption_public_key()
            .public_key_ml
            .encapsulate(&mut rng)
            .unwrap();
        let key_decap = private_key
            .get_decryption_private_key()
            .private_key_seed_ml
            .to_privkey()
            .decapsulate(&encap)
            .unwrap();
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
        assert_eq!(
            private_key.private_key_seed_ml.to_d_z_64(),
            private_key2.private_key_seed_ml.to_d_z_64()
        );
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
        assert_ne!(
            private_key.private_key_seed_ml.to_d_z_64(),
            private_key3.private_key_seed_ml.to_d_z_64()
        );
        assert_ne!(
            public_key.public_key_ecc.as_bytes(),
            public_key3.public_key_ecc.as_bytes()
        );
        assert_ne!(public_key.public_key_ml, public_key3.public_key_ml);
    }

    #[test]
    fn test_seed_to_and_from_dz64() {
        let original_seed = MLKEMSeed::generate_from_csprng(&mut rand::rngs::OsRng);
        let dz64 = original_seed.to_d_z_64();
        let recovered = MLKEMSeed::from_d_z_64(*dz64);
        assert!(original_seed == recovered);
    }

    #[test]
    fn test_seed_determinism() {
        let d = [42u8; 32];
        let z = [7u8; 32];
        let seed1 = MLKEMSeed::from_d_z_32(d, z);
        let seed2 = MLKEMSeed::from_d_z_32(d, z);
        assert!(seed1 == seed2);
    }

    #[test]
    fn test_seed_inequality() {
        let seed1 = MLKEMSeed::from_d_z_32([1u8; 32], [2u8; 32]);
        let seed2 = MLKEMSeed::from_d_z_32([3u8; 32], [4u8; 32]);
        assert!(seed1 != seed2);
    }

    #[test]
    fn test_seed_to_keypair_roundtrip() {
        let seed = MLKEMSeed::generate_from_csprng(&mut rand::rngs::OsRng);
        let privkey = seed.to_privkey();
        let pubkey = seed.to_pubkey();

        let (expected_privkey, expected_pubkey) =
            MlKem1024::generate_deterministic(&seed.d, &seed.z);

        assert_eq!(privkey, expected_privkey);
        assert_eq!(pubkey, expected_pubkey);
    }
}
