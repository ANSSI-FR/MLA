use crate::crypto::aesgcm;
use crate::crypto::aesgcm::{ConstantTimeEq, KEY_SIZE, TAG_LENGTH};
use crate::errors::Error;
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const DERIVE_KEY_INFO: &[u8; 14] = b"KEY DERIVATION";
const ECIES_NONCE: &[u8; 12] = b"ECIES NONCE0";

// Implementation inspired from XSTREAM/x25519hkdf.rs
// /!\ in XSTREAM/x25519hkdf.rs, the arguments of Hkdf::new seem inverted
fn derive_key(private_key: &StaticSecret, public_key: &PublicKey) -> Result<[u8; KEY_SIZE], Error> {
    let mut shared_secret = private_key.diffie_hellman(public_key);
    let hkdf: Hkdf<Sha256> = Hkdf::new(None, shared_secret.as_bytes());
    let mut output = [0u8; KEY_SIZE];
    hkdf.expand(DERIVE_KEY_INFO, &mut output)?;
    shared_secret.zeroize();
    Ok(output)
}

#[derive(Serialize, Deserialize)]
struct KeyAndTag {
    key: [u8; KEY_SIZE],
    tag: [u8; TAG_LENGTH],
}

#[derive(Serialize, Deserialize)]
pub struct MultiRecipientPersistent {
    /// Ephemeral public key
    public: [u8; 32],
    encrypted_keys: Vec<KeyAndTag>,
}

impl MultiRecipientPersistent {
    pub const fn count_keys(&self) -> usize {
        self.encrypted_keys.len()
    }
}

/// Perform ECIES with several recipients, to share a common `key`, and return a
/// serializable structure (Key-wrapping made thanks to `AesGcm256`)
pub(crate) fn store_key_for_multi_recipients<T>(
    recipients: &[PublicKey],
    key: &[u8; KEY_SIZE],
    csprng: &mut T,
) -> Result<MultiRecipientPersistent, Error>
where
    T: RngCore + CryptoRng,
{
    // A `StaticSecret` is used instead of an `EphemeralSecret` to allow for
    // multiple diffie-hellman computation
    let mut bytes = [0u8; 32];
    csprng.fill_bytes(&mut bytes);
    let ephemeral = StaticSecret::from(bytes);

    let public = PublicKey::from(&ephemeral);
    let mut encrypted_keys = Vec::new();
    for recipient in recipients {
        // Perform an ECIES to obtain the common key
        let dh_key = derive_key(&ephemeral, recipient)?;

        // Encrypt the final shared key with it
        // As the key is completely random and use only once, no need for a
        // random NONCE
        let mut cipher = aesgcm::AesGcm256::new(&dh_key, ECIES_NONCE, b"")?;
        let mut encrypted_key = [0u8; KEY_SIZE];
        encrypted_key.copy_from_slice(key);
        cipher.encrypt(&mut encrypted_key);
        let mut tag = [0u8; TAG_LENGTH];
        tag.copy_from_slice(&cipher.into_tag());
        // Save it for later serialization
        encrypted_keys.push(KeyAndTag {
            key: encrypted_key,
            tag,
        });
    }

    Ok(MultiRecipientPersistent {
        public: *public.as_bytes(),
        encrypted_keys,
    })
}

/// Try to recover the shared key from the `MultiRecipientPersistent`, using the private key `private_key`
pub(crate) fn retrieve_key(
    persist: &MultiRecipientPersistent,
    private_key: &StaticSecret,
) -> Result<Option<[u8; KEY_SIZE]>, Error> {
    // Perform an ECIES to obtain the common key
    let key = derive_key(private_key, &PublicKey::from(persist.public))?;

    // Try to find the correct key using the tag validation
    for keytag in &persist.encrypted_keys {
        let mut cipher = aesgcm::AesGcm256::new(&key, ECIES_NONCE, b"")?;
        let mut data = [0u8; KEY_SIZE];
        data.copy_from_slice(&keytag.key);
        let tag = cipher.decrypt(&mut data);
        if tag.ct_eq(&keytag.tag).unwrap_u8() == 1 {
            return Ok(Some(data));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn ecies() {
        let mut csprng = ChaChaRng::from_os_rng();
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

    #[test]
    fn multi_recipients() {
        // Create fake recipients
        let mut csprng = ChaChaRng::from_os_rng();
        let mut bytes = [0u8; 32];
        let mut recipients_priv = Vec::new();
        let mut recipients_pub = Vec::new();
        for _ in 0..5 {
            csprng.fill_bytes(&mut bytes);
            let skey = StaticSecret::from(bytes);
            recipients_pub.push(PublicKey::from(&skey));
            recipients_priv.push(skey);
        }

        // Perform multi-recipients ECIES
        let key = csprng.random::<[u8; KEY_SIZE]>();
        let persist = store_key_for_multi_recipients(&recipients_pub, &key, &mut csprng).unwrap();

        // Count keys
        assert_eq!(persist.count_keys(), 5);

        // Ensure each recipient can retrieve the shared key
        for private_key in &recipients_priv {
            let ret_key = retrieve_key(&persist, private_key).unwrap().unwrap();
            assert_eq!(ret_key, key);
        }

        // Ensure another recipient does not obtain the shared key
        csprng.fill_bytes(&mut bytes);
        let fake_recipient = StaticSecret::from(bytes);
        assert!(retrieve_key(&persist, &fake_recipient).unwrap().is_none());
    }
}
