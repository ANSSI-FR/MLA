use crate::crypto::aesgcm::Key;
use crate::errors::Error;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub const PUBLIC_KEY_SIZE: usize = 32;
/// The ciphertext in DH-KEM / ECIES is a public key
pub(crate) type DHKEMCipherText = [u8; PUBLIC_KEY_SIZE];
const DERIVE_KEY_INFO: &[u8; 14] = b"KEY DERIVATION";

// TODO: consider DH-KEM
// Implementation inspired from XSTREAM/x25519hkdf.rs
// /!\ in XSTREAM/x25519hkdf.rs, the arguments of Hkdf::new seem inverted
pub(crate) fn derive_key(private_key: &StaticSecret, public_key: &PublicKey) -> Result<Key, Error> {
    let mut shared_secret = private_key.diffie_hellman(public_key);
    let hkdf: Hkdf<Sha256> = Hkdf::new(None, shared_secret.as_bytes());
    let mut output = Key::default();
    hkdf.expand(DERIVE_KEY_INFO, &mut output)?;
    shared_secret.zeroize();
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn ecies() {
        let mut csprng = ChaChaRng::from_entropy();
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        let ephemeral_scalar = StaticSecret::from(bytes);
        let ephemeral_public = PublicKey::from(&ephemeral_scalar);

        csprng.fill_bytes(&mut bytes);
        let receiver_private = StaticSecret::from(bytes);
        let receiver_public = PublicKey::from(&receiver_private);

        let symmetric_key = derive_key(&ephemeral_scalar, &receiver_public).unwrap();

        let receiver_key = derive_key(&receiver_private, &ephemeral_public).unwrap();

        assert_eq!(symmetric_key, receiver_key);
    }
}
