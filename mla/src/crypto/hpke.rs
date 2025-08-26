/// Implements RFC 9180 for MLA needs
use hpke::aead::{Aead as HPKEAeadTrait, AesGcm256 as HPKEAesGcm256};
use hpke::kdf::{HkdfSha512, Kdf as HpkeKdfTrait, LabeledExpand, labeled_extract};
use hpke::{Deserializable, Serializable};
use hpke::{Kem as KemTrait, kem::X25519HkdfSha256};
use rand::{CryptoRng, RngCore};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::crypto::aesgcm::{Key, Nonce};
use crate::errors::Error;

type Kem = X25519HkdfSha256;
type WrappedPublicKey = <Kem as KemTrait>::PublicKey;
type WrappedPrivateKey = <Kem as KemTrait>::PrivateKey;
type DHKEMSharedSecret = hpke::kem::SharedSecret<Kem>;

// ----- DHKEM(X25519) -----
// This implementation wraps https://github.com/rozbb/rust-hpke, which has been partially reviewed

/// Wrap an `rust-hpke` `EncappedKey` to provide custom traits and prevent futur changes
pub(crate) struct DHKEMCiphertext(<Kem as KemTrait>::EncappedKey);

impl DHKEMCiphertext {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(DHKEMCiphertext(
            <Kem as KemTrait>::EncappedKey::from_bytes(bytes).map_err(|_| Error::HPKEError)?,
        ))
    }
    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes().into()
    }
}

/// Provides DHKEM encapsulation over X25519 curve (RFC 9180 §4.1) from a given `CryptoRng`
///
/// Return a shared secret and the corresponding ciphertext
pub(crate) fn dhkem_encap_from_rng(
    pubkey: &X25519PublicKey,
    csprng: &mut (impl CryptoRng + RngCore),
) -> Result<(DHKEMSharedSecret, DHKEMCiphertext), Error> {
    let wrapped = WrappedPublicKey::from_bytes(&pubkey.to_bytes()).map_err(|_| Error::HPKEError)?;
    let (shared_secret, ciphertext) =
        X25519HkdfSha256::encap(&wrapped, None, csprng).map_err(|_| Error::HPKEError)?;
    Ok((shared_secret, DHKEMCiphertext(ciphertext)))
}

/// Provides DHKEM decapsulation over X25519 curve (RFC 9180 §4.1)
///
/// Returns the shared secret
pub(crate) fn dhkem_decap(
    encapped_key: &DHKEMCiphertext,
    private_key: &x25519_dalek::StaticSecret,
) -> Result<DHKEMSharedSecret, Error> {
    let wrapped =
        WrappedPrivateKey::from_bytes(&private_key.to_bytes()).map_err(|_| Error::HPKEError)?;
    X25519HkdfSha256::decap(&wrapped, None, &encapped_key.0).map_err(|_| Error::HPKEError)
}

// ----- Key scheduling / Encryption context -----
// Based on RFC 9180, extract a key and a base nonce for future AEAD encryption
//
// rust-hpke provides `setup_sender` and `setup_receiver`
// Unfortunately, re-using their code means:
// - implementing the rust-hpke `Kem` trait for our Hybrid encryption KEM, while we are not yet able to convert a private key to a public one
// - re-implement the AEAD trait for our AesGcm, to be able to repair
// - implementing struct to use suite ID which are not in the RFC (because we are using our own Hybrid KEM)
//
// Regarding the code quantity involved, the choice has been made to rather have it implemented here

type HpkeKdf = HkdfSha512;
type HpkeAead = HPKEAesGcm256;
///  5. Hybrid Public Key Encryption - HPKE Modes (§5.1 - Table 1)
const HPKE_MODE_BASE: u8 = 0;

/// Custom KEM ID, not in the RFC 9180
/// Hybrid : DHKEM(X25519, HKDF-SHA256) + MLKEM, wrapping a shared secret to support multi-recipient
const HYBRID_KEM_ID: u16 = 0x1020;
/// Custom KEM ID, not in the RFC 9180
/// Hybrid Recipient : DHKEM(X25519, HKDF-SHA256) + MLKEM, used internally in the Hybrid KEM to wrap the per-recipient shared secret
const HYBRID_KEM_RECIPIENT_ID: u16 = 0x1120;

/// Return the `suite_id` for the Hybrid KEM (RFC 9180 §5.1)
/// `suite_id = concat(
///   "HPKE",
///   I2OSP(kem_id, 2),
///   I2OSP(kdf_id, 2),
///   I2OSP(aead_id, 2)
/// )`
///
/// `kem_id` is kept as an argument to allow testing against RFC 9180 test vectors
fn build_suite_id(kem_id: u16) -> [u8; 10] {
    // TODO : convert to a const fn
    let mut out = [0u8; 10];
    out[0..4].copy_from_slice(b"HPKE");
    out[4..6].copy_from_slice(&kem_id.to_be_bytes());
    out[6..8].copy_from_slice(&HpkeKdf::KDF_ID.to_be_bytes());
    out[8..10].copy_from_slice(&HpkeAead::AEAD_ID.to_be_bytes());
    out
}

/// Key schedule (RFC 9180 §5.1), mode Base
///
/// Parameters are:
/// - `shared_secret`: the shared secret from the Hybrid KEM
/// - mode: set to Base (no PSK nor sender key)
/// - `info`: the info to use in HPKE
/// - psk: no PSK, because the mode used is "Base"
/// - algorithms:
///     - Kem: `kem_id`
///     - Kdf: HKDF-SHA512
///     - Aead: AES-GCM-256
fn key_schedule_base(
    shared_secret: &[u8],
    info: &[u8],
    kem_id: u16,
) -> Result<(Key, Nonce), Error> {
    let suite_id = build_suite_id(kem_id);
    let mut key = Key::default();
    let mut base_nonce = Nonce::default();

    // No PSK, no Info
    let (psk_id_hash, _psk_kdf) = labeled_extract::<HpkeKdf>(&[], &suite_id, b"psk_id_hash", b"");
    let (info_hash, _info_kdf) = labeled_extract::<HpkeKdf>(&[], &suite_id, b"info_hash", info);
    // Concat HPKE_MODE_BASE and info
    let mut key_schedule_context: Vec<u8> = vec![];
    key_schedule_context.push(HPKE_MODE_BASE);
    key_schedule_context.extend_from_slice(&psk_id_hash);
    key_schedule_context.extend_from_slice(&info_hash);

    let (_prk, secret_kdf) = labeled_extract::<HpkeKdf>(shared_secret, &suite_id, b"secret", b"");
    secret_kdf
        .labeled_expand(&suite_id, b"key", &key_schedule_context, &mut key)
        .map_err(|_| Error::HPKEError)?;
    secret_kdf
        .labeled_expand(
            &suite_id,
            b"base_nonce",
            &key_schedule_context,
            &mut base_nonce,
        )
        .map_err(|_| Error::HPKEError)?;

    Ok((key, base_nonce))
}

/// Key schedule (RFC 9180 §5.1), mode Base, for the custom multi-recipient Hybrid KEM
pub(crate) fn key_schedule_base_hybrid_kem(
    shared_secret: &[u8],
    info: &[u8],
) -> Result<(Key, Nonce), Error> {
    key_schedule_base(shared_secret, info, HYBRID_KEM_ID)
}

/// Key schedule (RFC 9180 §5.1), mode Base, for the custom per-recipient Hybrid KEM
pub(crate) fn key_schedule_base_hybrid_kem_recipient(
    shared_secret: &[u8],
    info: &[u8],
) -> Result<(Key, Nonce), Error> {
    key_schedule_base(shared_secret, info, HYBRID_KEM_RECIPIENT_ID)
}

/// Compute the nonce for a given sequence number (RFC 9180 §5.2)
pub(crate) fn compute_nonce(base_nonce: &Nonce, seq: u64) -> Nonce {
    // RFC 9180 §5.2: seq must not be superior to 1 << (8*Nn)
    // As we use AES-256-GCM, Nn = 12 (RFC 9180 §7.3), so u64 is always enough

    // Nonce = nonce ^ 0...seq
    let mut nonce = *base_nonce;
    let seq_be = seq.to_be_bytes();
    for i in 0..seq_be.len() {
        let nonce_idx = i + nonce.len() - seq_be.len();
        nonce[nonce_idx] ^= seq_be[i];
    }
    nonce
}

#[cfg(test)]
mod tests {
    use crate::{MLADeserialize, MLASerialize};
    use std::io;
    use std::io::{BufReader, Cursor};

    use crate::crypto::aesgcm::AesGcm256;

    use super::*;
    use hex_literal::hex;
    use hpke::Serializable;
    use rand::{CryptoRng, RngCore};
    use x25519_dalek::StaticSecret;

    /// Rng used for tests, mocking the `RngCore` and `CryptoRng` trait
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

    /// Test Serialization and Deserialization of `DHKEMCiphertext`
    #[test]
    fn dhkem_ciphertext_serialization() {
        // from_bytes / to_bytes
        let ciphertext = DHKEMCiphertext::from_bytes(&RFC_PKRM).unwrap();
        assert_eq!(ciphertext.to_bytes(), RFC_PKRM);
        // encode / decode
        let mut encoded = Vec::<u8>::new();
        RFC_PKRM.as_slice().serialize(&mut encoded).unwrap();
        let data: [u8; 32] = MLADeserialize::deserialize(&mut Cursor::new(encoded)).unwrap();
        assert_eq!(RFC_PKRM, data);
    }

    /// RFC 9180 §A.1.1
    ///
    /// These test vectors are already tested by `hpke` crates, but we ensure
    /// there is no regression change, even if we later change our base crate
    #[test]
    fn rfc9180_dhkem_vector_tests() {
        // Key derivation for sender (ephemeral keypair)
        let (sender_privkey, sender_pubkey) = X25519HkdfSha256::derive_keypair(&RFC_IKME);
        assert_eq!(&sender_pubkey.to_bytes().as_ref(), &RFC_PKEM);
        assert_eq!(&sender_privkey.to_bytes().as_ref(), &RFC_SKEM);

        // Key derivation for receiver (static keypair)
        let (receiver_privkey, receiver_pubkey) = X25519HkdfSha256::derive_keypair(&RFC_IKMR);
        assert_eq!(&receiver_pubkey.to_bytes().as_ref(), &RFC_PKRM);
        assert_eq!(&receiver_privkey.to_bytes().as_ref(), &RFC_SKRM);

        // DHKEM Encapsulation (sender side)
        let mut rng = MockRng::new(&RFC_IKME);
        let (shared_secret_encap, encapped_key) =
            dhkem_encap_from_rng(&X25519PublicKey::from(RFC_PKRM), &mut rng).unwrap();
        assert_eq!(&encapped_key.to_bytes().as_ref(), &RFC_ENC);
        assert_eq!(&shared_secret_encap.0.to_vec(), &RFC_SHARED_SECRET);

        // DHKEM Decapsulation (receiver side)
        let shared_secret_decap = dhkem_decap(
            &DHKEMCiphertext::from_bytes(&RFC_ENC).unwrap(),
            &StaticSecret::from(RFC_SKRM),
        )
        .unwrap();
        assert_eq!(&shared_secret_decap.0.to_vec(), &RFC_SHARED_SECRET);
    }

    /// RFC 9180 §A.6.1 - DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM
    const RFC_A6_INFO: [u8; 20] = hex!("4f6465206f6e2061204772656369616e2055726e");
    const RFC_A6_SHARED_SECRET: [u8; 64] = hex!(
        "776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1d5e43653336fef33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46d30e818"
    );
    const RFC_A6_KEM_ID: u16 = 18;
    const RFC_A6_KEY: [u8; 32] =
        hex!("751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70");
    const RFC_A6_BASE_NONCE: [u8; 12] = hex!("55ff7a7d739c69f44b25447b");

    /// RFC 9180 §A.6.1
    ///
    /// Use A.6 for HKDF-SHA512 and AES-256-GCM
    /// In MLA, we rather use a custom Kem ID (Hybrid KEM), but this method does the main job
    #[test]
    fn test_key_schedule_base() {
        let (key, nonce) =
            key_schedule_base(&RFC_A6_SHARED_SECRET, &RFC_A6_INFO, RFC_A6_KEM_ID).unwrap();
        assert_eq!(key, RFC_A6_KEY);
        assert_eq!(nonce, RFC_A6_BASE_NONCE);
    }

    const RFC_A6_SEQS: [u64; 6] = [0, 1, 2, 4, 255, 256];
    const RFC_A6_NONCE: [[u8; 12]; 6] = [
        hex!("55ff7a7d739c69f44b25447b"), // sequence_number: 0
        hex!("55ff7a7d739c69f44b25447a"), // sequence_number: 1
        hex!("55ff7a7d739c69f44b254479"), // sequence_number: 2
        hex!("55ff7a7d739c69f44b25447f"), // sequence_number: 4
        hex!("55ff7a7d739c69f44b254484"), // sequence_number: 255
        hex!("55ff7a7d739c69f44b25457b"), // sequence_number: 256
    ];

    const RFC_A6_AAD: [&[u8]; 6] = [
        &hex!("436f756e742d30"),     // sequence number: 0
        &hex!("436f756e742d31"),     // sequence number: 1
        &hex!("436f756e742d32"),     // sequence number: 2
        &hex!("436f756e742d34"),     // sequence number: 4
        &hex!("436f756e742d323535"), // sequence number: 255
        &hex!("436f756e742d323536"), // sequence number: 256
    ];
    const RFC_A6_PT: &[u8] = &hex!("4265617574792069732074727574682c20747275746820626561757479");
    const RFC_A6_CT: [&[u8]; 6] = [
        &hex!(
            "170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a"
        ), // sequence number: 0
        &hex!(
            "d9ee248e220ca24ac00bbbe7e221a832e4f7fa64c4fbab3945b6f3af0c5ecd5e16815b328be4954a05fd352256"
        ), // sequence number: 1
        &hex!(
            "142cf1e02d1f58d9285f2af7dcfa44f7c3f2d15c73d460c48c6e0e506a3144bae35284e7e221105b61d24e1c7a"
        ), // sequence number: 2
        &hex!(
            "3bb3a5a07100e5a12805327bf3b152df728b1c1be75a9fd2cb2bf5eac0cca1fb80addb37eb2a32938c7268e3e5"
        ), // sequence number: 4
        &hex!(
            "4f268d0930f8d50b8fd9d0f26657ba25b5cb08b308c92e33382f369c768b558e113ac95a4c70dd60909ad1adc7"
        ), // sequence number: 255
        &hex!(
            "dbbfc44ae037864e75f136e8b4b4123351d480e6619ae0e0ae437f036f2f8f1ef677686323977a1ccbb4b4f16a"
        ), // sequence number: 256
    ];

    /// RFC 9180 §A.6.1.1
    #[test]
    fn test_compute_nonce() {
        for i in 0..RFC_A6_SEQS.len() {
            let computed_nonce = compute_nonce(&RFC_A6_BASE_NONCE, RFC_A6_SEQS[i]);
            assert_eq!(computed_nonce, RFC_A6_NONCE[i]);
        }
    }

    /// RFC 9180 §A.6.1.1
    ///
    /// As AES and previous values from RFC are already tested, this test is optional
    /// But it helps to ensure we correctly implements HPKE
    #[test]
    fn test_rfc_a6_encryption() {
        for i in 0..RFC_A6_SEQS.len() {
            let mut aes = AesGcm256::new(
                &RFC_A6_KEY,
                &compute_nonce(&RFC_A6_BASE_NONCE, RFC_A6_SEQS[i]),
                RFC_A6_AAD[i],
            )
            .unwrap();
            let mut buf = Vec::from(RFC_A6_PT);
            aes.encrypt(buf.as_mut_slice());
            buf.extend_from_slice(&aes.into_tag());
            assert_eq!(buf, RFC_A6_CT[i]);
        }
    }
}
