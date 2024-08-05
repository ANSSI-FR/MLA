/// Implements RFC 9180 for MLA needs
use hpke::{kem::X25519HkdfSha256, Kem as KemTrait};
use hpke::{Deserializable, Serializable};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::errors::Error;
use crate::layers::encrypt::get_crypto_rng;

type Kem = X25519HkdfSha256;
type WrappedPublicKey = <Kem as KemTrait>::PublicKey;
type WrappedPrivateKey = <Kem as KemTrait>::PrivateKey;
type DHKEMSharedSecret = hpke::kem::SharedSecret<Kem>;

// ----- DHKEM(X25519) -----
// This implementation wraps https://github.com/rozbb/rust-hpke, which has been partially reviewed

/// Wrap an `rust-hpke` `EncappedKey` to provide custom traits and prevent futur changes
pub(crate) struct DHKEMCiphertext(<Kem as KemTrait>::EncappedKey);

impl DHKEMCiphertext {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(DHKEMCiphertext(<Kem as KemTrait>::EncappedKey::from_bytes(
            bytes,
        )?))
    }
    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes().into()
    }
}

impl Serialize for DHKEMCiphertext {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DHKEMCiphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        DHKEMCiphertext::from_bytes(&bytes)
            .or(Err(serde::de::Error::custom("Invalid DHKEMCiphertext")))
    }
}

/// Provides DHKEM encapsulation over X25519 curve (RFC 9180 §4.1) from a given CryptoRng
///
/// Return a shared secret and the corresponding ciphertext
pub(crate) fn dhkem_encap_from_rng(
    pubkey: &X25519PublicKey,
    csprng: &mut (impl CryptoRng + RngCore),
) -> Result<(DHKEMSharedSecret, DHKEMCiphertext), Error> {
    let wrapped = WrappedPublicKey::from_bytes(&pubkey.to_bytes())?;
    let (shared_secret, ciphertext) = X25519HkdfSha256::encap(&wrapped, None, csprng)?;
    Ok((shared_secret, DHKEMCiphertext(ciphertext)))
}

/// Provides DHKEM encapsulation over X25519 curve (RFC 9180 §4.1)
///
/// Return a shared secret and the corresponding ciphertext
pub(crate) fn dhkem_encap(
    pubkey: &X25519PublicKey,
) -> Result<(DHKEMSharedSecret, DHKEMCiphertext), Error> {
    dhkem_encap_from_rng(pubkey, &mut get_crypto_rng())
}

/// Provides DHKEM decapsulation over X25519 curve (RFC 9180 §4.1)
///
/// Returns the shared secret
pub(crate) fn dhkem_decap(
    encapped_key: &DHKEMCiphertext,
    private_key: &x25519_dalek::StaticSecret,
) -> Result<DHKEMSharedSecret, Error> {
    let wrapped = WrappedPrivateKey::from_bytes(&private_key.to_bytes())?;
    Ok(X25519HkdfSha256::decap(&wrapped, None, &encapped_key.0)?)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::{BufReader, Cursor};

    use super::*;
    use hex_literal::hex;
    use hpke::Serializable;
    use rand::{CryptoRng, RngCore};
    use x25519_dalek::StaticSecret;

    /// Rng used for tests, mocking the RngCore and CryptoRng trait
    /// This RNG always returns the bytes provided during instanciation
    ///
    /// DO NOT USE OUTSIDE TESTS
    struct MockRng {
        buf: BufReader<Cursor<Vec<u8>>>,
    }

    impl MockRng {
        fn new(data: &[u8]) -> Self {
            MockRng {
                buf: BufReader::new(Cursor::new(data.to_vec())),
            }
        }
    }

    impl RngCore for MockRng {
        fn fill_bytes(&mut self, mut dest: &mut [u8]) {
            io::copy(&mut self.buf, &mut dest).unwrap();
        }

        fn next_u32(&mut self) -> u32 {
            let mut buf = [0u8; 4];
            self.fill_bytes(&mut buf);
            u32::from_le_bytes(buf)
        }

        fn next_u64(&mut self) -> u64 {
            let mut buf = [0u8; 8];
            self.fill_bytes(&mut buf);
            u64::from_le_bytes(buf)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for MockRng {}

    /// RFC 9180 §A.1.1
    const RFC_IKME: [u8; 32] =
        hex!("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
    const RFC_PKEM: [u8; 32] =
        hex!("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    const RFC_SKEM: [u8; 32] =
        hex!("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");

    const RFC_IKMR: [u8; 32] =
        hex!("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037");
    const RFC_PKRM: [u8; 32] =
        hex!("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    const RFC_SKRM: [u8; 32] =
        hex!("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");

    const RFC_ENC: [u8; 32] =
        hex!("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    const RFC_SHARED_SECRET: [u8; 32] =
        hex!("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");

    /// Test Serialization and Deserialization of DHKEMCiphertext
    #[test]
    fn dhkem_ciphertext_serde() {
        // from_bytes / to_bytes
        let ciphertext = DHKEMCiphertext::from_bytes(&RFC_PKRM).unwrap();
        assert_eq!(ciphertext.to_bytes(), RFC_PKRM);

        // serialize / deserialize
        let serialized = bincode::serialize(&ciphertext).unwrap();
        let deserialized: DHKEMCiphertext = bincode::deserialize(&serialized).unwrap();
        assert_eq!(ciphertext.to_bytes(), deserialized.to_bytes());
    }

    /// RFC 9180 §A.1.1
    ///
    /// These test vectors are already tested by `hpke` crates, but we ensure
    /// there is no regression change, even if we later change our base crate
    #[test]
    fn rfc9180_dhkem_vector_tests() {
        // Key derivation
        let (privkey_em, pubkey_em) = X25519HkdfSha256::derive_keypair(&RFC_IKME);
        assert_eq!(&pubkey_em.to_bytes().as_ref(), &RFC_PKEM);
        assert_eq!(&privkey_em.to_bytes().as_ref(), &RFC_SKEM);

        let (privkey_rm, pubkey_rm) = X25519HkdfSha256::derive_keypair(&RFC_IKMR);
        assert_eq!(&pubkey_rm.to_bytes().as_ref(), &RFC_PKRM);
        assert_eq!(&privkey_rm.to_bytes().as_ref(), &RFC_SKRM);

        // DHKEM Encapsulation
        let mut rng = MockRng::new(&RFC_IKME);
        let (shared_secret, cipher_text) =
            dhkem_encap_from_rng(&X25519PublicKey::from(RFC_PKRM), &mut rng).unwrap();
        assert_eq!(&cipher_text.to_bytes().as_ref(), &RFC_ENC);
        assert_eq!(&shared_secret.0.to_vec(), &RFC_SHARED_SECRET);

        // DHKEM Decapsulation
        let shared_secret = dhkem_decap(
            &DHKEMCiphertext::from_bytes(&RFC_ENC).unwrap(),
            &StaticSecret::from(RFC_SKRM),
        )
        .unwrap();
        assert_eq!(&shared_secret.0.to_vec(), &RFC_SHARED_SECRET);
    }
}
