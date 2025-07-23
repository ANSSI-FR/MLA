use hkdf::Hkdf;
use rand::SeedableRng as _;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::CryptoRngCore;
use zeroize::Zeroize;

use std::io::{Cursor, ErrorKind, Read, Write};

use curve25519_dalek::montgomery::MontgomeryPoint;
use ml_kem::EncodedSizeUser;
use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::base64::{base64_decode, base64_encode};
pub use crate::crypto::hybrid::{MLADecryptionPrivateKey, MLAEncryptionPublicKey};
pub use crate::crypto::hybrid::{generate_keypair, generate_keypair_from_seed};

use crate::MLADeserialize;
use crate::crypto::hybrid::{MLKEM_DZ_SIZE, MLKEMEncapsulationKey, MLKEMSeed};
use crate::errors::Error;
use crate::layers::encrypt::get_crypto_rng;

use super::hybrid::generate_keypair_from_rng;

const MLA_PRIV_DEC_KEY_HEADER: &[u8] = b"MLA PRIVATE DECRYPTION KEY ";
//const MLA_PRIV_SIG_KEY_HEADER: &[u8] = b"MLA PRIVATE SIGNATURE KEY ";
const DEC_METHOD_ID_0_PRIV: &[u8] = b"mla-kem-private-x25519-mlkem1024";
//const SIG_METHOD_ID_0_PRIV: &[u8] = b"mla-signature-private-ed25519-mldsa87";

const MLA_PUB_ENC_KEY_HEADER: &[u8] = b"MLA PUBLIC ENCRYPTION KEY ";
//const MLA_PUB_SIGVERIF_KEY_HEADER: &[u8] = b"MLA PUBLIC SIGNATURE VERIFICATION KEY ";
const ENC_METHOD_ID_0_PUB: &[u8] = b"mla-kem-public-x25519-mlkem1024";
//const SIGVERIF_METHOD_ID_0_PUB: &[u8] = b"mla-signature-verification-public-ed25519-mldsa87";

const PRIV_KEY_FILE_HEADER: &[u8] = b"DO NOT SEND THIS TO ANYONE - MLA PRIVATE KEY FILE V1";
const PRIV_KEY_FILE_FOOTER: &[u8] = b"END OF MLA PRIVATE KEY FILE";
const PUB_KEY_FILE_HEADER: &[u8] = b"MLA PUBLIC KEY FILE V1";
const PUB_KEY_FILE_FOOTER: &[u8] = b"END OF MLA PUBLIC KEY FILE";

#[allow(clippy::slow_vector_initialization, clippy::manual_memcpy)]
fn zeroizeable_read_to_end(mut src: impl Read) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut min_capacity = 4096; // buf has always at least this capacity
    buf.resize(min_capacity, 0);
    let mut read_offset = 0; // up to where in buf we have read data
    loop {
        if read_offset == min_capacity {
            // grow with zeroizing
            min_capacity *= 2;
            let mut new_buf = Vec::new();
            new_buf.resize(min_capacity, 0);
            for i in 0..buf.len() {
                new_buf[i] = buf[i];
            }
            buf.zeroize();
            buf = new_buf;
        }
        match src.read(&mut buf[read_offset..min_capacity]) {
            Ok(n) => {
                if n == 0 {
                    buf.resize(read_offset, 0);
                    return Ok(buf);
                } else {
                    read_offset += n;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => {
                buf.zeroize();
                return Err(Error::DeserializationError);
            }
        }
    }
}

/// No buffering to avoid having to zeroize eventual secret data parsed by this function
#[allow(clippy::needless_range_loop)]
fn split_five_lines_without_buffering(content: &[u8]) -> Result<[&[u8]; 5], Error> {
    fn split_line(content: &[u8]) -> Result<(&[u8], &[u8]), Error> {
        let mut carriage_return_index = 0;
        for i in 0..content.len() {
            if content[i] == b'\r' {
                carriage_return_index = i;
                break;
            }
        }
        if carriage_return_index == 0 {
            return Err(Error::DeserializationError);
        }
        let (line, rest) = content.split_at(carriage_return_index);
        if rest.len() < 2 || rest[0] != b'\r' && rest[1] != b'\n' {
            return Err(Error::DeserializationError);
        }
        let rest = &rest[2..];
        Ok((line, rest))
    }
    let (first_line, rest) = split_line(content)?;
    let (second_line, rest) = split_line(rest)?;
    let (third_line, rest) = split_line(rest)?;
    let (fourth_line, rest) = split_line(rest)?;
    let (fifth_line, rest) = split_line(rest)?;
    if !rest.is_empty() {
        return Err(Error::DeserializationError);
    }
    Ok([first_line, second_line, third_line, fourth_line, fifth_line])
}

#[derive(Clone)]
struct KeyOpts;

impl KeyOpts {
    fn serialize_key_opts<W: Write>(&self, mut dst: W) -> Result<(), Error> {
        // nothing for the moment
        dst.write_all(b"AAAAAA==\r\n")?;
        Ok(())
    }
}

impl<R: Read> MLADeserialize<R> for KeyOpts {
    fn deserialize(src: &mut R) -> Result<Self, Error> {
        let opts_len = u32::deserialize(src)?;
        let mut opts = vec![0; opts_len as usize];
        src.read_exact(opts.as_mut_slice())
            .map_err(|_| Error::DeserializationError)?;
        Ok(KeyOpts)
    }
}

impl MLADecryptionPrivateKey {
    fn deserialize_decryption_private_key(line: &[u8]) -> Result<Self, Error> {
        let b64data = line
            .strip_prefix(MLA_PRIV_DEC_KEY_HEADER)
            .ok_or(Error::DeserializationError)?;
        let data = base64_decode(b64data).map_err(|_| Error::DeserializationError)?;
        let mut cursor = Cursor::new(data);
        let mut method_id = [0; DEC_METHOD_ID_0_PRIV.len()];
        cursor
            .read_exact(&mut method_id)
            .map_err(|_| Error::DeserializationError)?;
        if method_id.as_slice() != DEC_METHOD_ID_0_PRIV {
            return Err(Error::DeserializationError);
        }
        let _opts = KeyOpts::deserialize(&mut cursor)?;
        let mut serialized_ecc_key = [0; ECC_PRIVKEY_SIZE];
        cursor
            .read_exact(&mut serialized_ecc_key)
            .map_err(|_| Error::DeserializationError)?;
        let private_key_ecc = StaticSecret::from(serialized_ecc_key);
        serialized_ecc_key.zeroize();
        let mut serialized_mlkem_seed = [0; MLKEM_DZ_SIZE];
        cursor
            .read_exact(&mut serialized_mlkem_seed)
            .map_err(|_| Error::DeserializationError)?;
        let private_key_seed_ml = MLKEMSeed::from_d_z_64(serialized_mlkem_seed);
        cursor.into_inner().zeroize();
        Ok(Self {
            private_key_ecc,
            private_key_seed_ml,
        })
    }

    fn serialize_decryption_private_key<W: Write>(&self, mut dst: W) -> Result<(), Error> {
        const KEY_OPTS_LEN: usize = 4;

        dst.write_all(MLA_PRIV_DEC_KEY_HEADER)?;
        let mut b64data = vec![];
        b64data.extend_from_slice(DEC_METHOD_ID_0_PRIV);
        b64data.extend_from_slice(&[0u8; KEY_OPTS_LEN]); // key opts, empty length for the moment
        b64data.extend_from_slice(&self.private_key_ecc.to_bytes());
        b64data.extend_from_slice(self.private_key_seed_ml.to_d_z_64().as_ref());
        let mut encoded = base64_encode(&b64data);
        dst.write_all(&encoded)?;
        encoded.zeroize();
        dst.write_all(b"\r\n")?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct MLASignaturePrivateKey {}

impl MLASignaturePrivateKey {
    fn serialize_signature_private_key<W: Write>(&self, mut dst: W) -> Result<(), Error> {
        dst.write_all(b"TODO\r\n").unwrap();
        Ok(())
    }
}

impl Drop for MLASignaturePrivateKey {
    fn drop(&mut self) {
        // TODO
    }
}

#[derive(Clone)]
pub struct MLAPrivateKey {
    // zeroized on drop for both ecc and mlkem keys
    decryption_private_key: MLADecryptionPrivateKey,
    // TODO: zeroize on drop
    signature_private_key: MLASignaturePrivateKey,
    opts: KeyOpts,
}

impl MLAPrivateKey {
    /// Deserialize an MLA private key from a source implementing `Read`.
    ///
    /// If zeroizing key memory matters to you, ensure that the `Read`
    /// implementation of your argument does not use temporary buffers
    /// and do not forget to zeroize the eventual backing data after this call.
    ///
    /// The serialization format is described in `doc/src/KEY_FORMAT.md`.
    pub fn deserialize_private_key(src: impl Read) -> Result<Self, Error> {
        let mut content = zeroizeable_read_to_end(src)?;
        let lines = split_five_lines_without_buffering(&content)?;
        if lines[0] != PRIV_KEY_FILE_HEADER {
            return Err(Error::DeserializationError);
        }
        if lines[4] != PRIV_KEY_FILE_FOOTER {
            return Err(Error::DeserializationError);
        }
        let decryption_private_key =
            MLADecryptionPrivateKey::deserialize_decryption_private_key(lines[1])?;
        // TODO: deserialize signature private key when implemented
        let signature_private_key = MLASignaturePrivateKey {};
        content.zeroize();
        Ok(Self {
            decryption_private_key,
            signature_private_key,
            opts: KeyOpts,
        })
    }

    pub fn from_decryption_and_signature_keys(
        decryption_private_key: MLADecryptionPrivateKey,
        signature_private_key: MLASignaturePrivateKey,
    ) -> Self {
        MLAPrivateKey {
            decryption_private_key,
            signature_private_key,
            opts: KeyOpts,
        }
    }

    pub fn get_decryption_private_key(&self) -> &MLADecryptionPrivateKey {
        &self.decryption_private_key
    }

    pub fn get_private_keys(self) -> (MLADecryptionPrivateKey, MLASignaturePrivateKey) {
        (self.decryption_private_key, self.signature_private_key)
    }

    pub fn get_signature_private_key(&self) -> &MLASignaturePrivateKey {
        &self.signature_private_key
    }

    /// Serialize the MLA private key into `dst`.
    ///
    /// The serialization format is described in `doc/src/KEY_FORMAT.md`.
    pub fn serialize_private_key<W: Write>(&self, mut dst: W) -> Result<(), Error> {
        dst.write_all(PRIV_KEY_FILE_HEADER)?;
        dst.write_all(b"\r\n")?;
        self.decryption_private_key
            .serialize_decryption_private_key(&mut dst)?;
        self.signature_private_key
            .serialize_signature_private_key(&mut dst)?;
        self.opts.serialize_key_opts(&mut dst)?;
        dst.write_all(PRIV_KEY_FILE_FOOTER)?;
        dst.write_all(b"\r\n")?;
        Ok(())
    }
}

impl MLAEncryptionPublicKey {
    fn deserialize_encryption_public_key(line: &[u8]) -> Result<Self, Error> {
        let b64data = line
            .strip_prefix(MLA_PUB_ENC_KEY_HEADER)
            .ok_or(Error::DeserializationError)?;
        let data = base64_decode(b64data).map_err(|_| Error::DeserializationError)?;
        let mut cursor = Cursor::new(data);
        let mut method_id = [0; ENC_METHOD_ID_0_PUB.len()];
        cursor
            .read_exact(&mut method_id)
            .map_err(|_| Error::DeserializationError)?;
        if method_id.as_slice() != ENC_METHOD_ID_0_PUB {
            return Err(Error::DeserializationError);
        }
        let _opts = KeyOpts::deserialize(&mut cursor)?;
        let mut serialized_ecc_key = [0; ECC_PUBKEY_SIZE];
        cursor
            .read_exact(&mut serialized_ecc_key)
            .map_err(|_| Error::DeserializationError)?;
        let public_key_ecc = PublicKey::from(MontgomeryPoint(serialized_ecc_key).to_bytes());
        let mut serialized_mlkem_key = Vec::new();
        cursor
            .read_to_end(&mut serialized_mlkem_key)
            .map_err(|_| Error::DeserializationError)?;
        let public_key_ml = MLKEMEncapsulationKey::from_bytes(
            serialized_mlkem_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::DeserializationError)?,
        );

        Ok(Self {
            public_key_ecc,
            public_key_ml,
        })
    }

    fn serialize_encryption_public_key<W: Write>(&self, mut dst: W) -> Result<(), Error> {
        const KEY_OPTS_LEN: usize = 4;

        dst.write_all(MLA_PUB_ENC_KEY_HEADER)?;
        let mut b64data = vec![];
        b64data.extend_from_slice(ENC_METHOD_ID_0_PUB);
        b64data.extend_from_slice(&[0u8; KEY_OPTS_LEN]); // key opts, empty length for the moment
        b64data.extend_from_slice(&self.public_key_ecc.to_bytes());
        b64data.extend_from_slice(&self.public_key_ml.as_bytes());
        dst.write_all(&base64_encode(&b64data))?;
        dst.write_all(b"\r\n")?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct MLASignatureVerificationPublicKey {}

impl MLASignatureVerificationPublicKey {
    fn serialize_signature_verification_public_key<W: Write>(
        &self,
        mut dst: W,
    ) -> Result<(), Error> {
        dst.write_all(b"TODO\r\n").unwrap();
        Ok(())
    }
}

#[derive(Clone)]
pub struct MLAPublicKey {
    encryption_public_key: MLAEncryptionPublicKey,
    signature_verification_public_key: MLASignatureVerificationPublicKey,
    opts: KeyOpts,
}

impl MLAPublicKey {
    pub fn deserialize_public_key(src: impl Read) -> Result<Self, Error> {
        let mut content = zeroizeable_read_to_end(src)?;
        let lines = split_five_lines_without_buffering(&content)?;
        if lines[0] != PUB_KEY_FILE_HEADER {
            return Err(Error::DeserializationError);
        }
        if lines[4] != PUB_KEY_FILE_FOOTER {
            return Err(Error::DeserializationError);
        }
        let encryption_public_key =
            MLAEncryptionPublicKey::deserialize_encryption_public_key(lines[1])?;
        let signature_verification_public_key = MLASignatureVerificationPublicKey {};
        content.zeroize();
        Ok(Self {
            encryption_public_key,
            signature_verification_public_key,
            opts: KeyOpts,
        })
    }

    pub fn from_encryption_and_signature_verification_keys(
        encryption_public_key: MLAEncryptionPublicKey,
        signature_verification_public_key: MLASignatureVerificationPublicKey,
    ) -> Self {
        MLAPublicKey {
            encryption_public_key,
            signature_verification_public_key,
            opts: KeyOpts,
        }
    }

    pub fn get_encryption_public_key(&self) -> &MLAEncryptionPublicKey {
        &self.encryption_public_key
    }

    pub fn get_public_keys(self) -> (MLAEncryptionPublicKey, MLASignatureVerificationPublicKey) {
        (
            self.encryption_public_key,
            self.signature_verification_public_key,
        )
    }

    pub fn get_signature_verification_public_key(&self) -> &MLASignatureVerificationPublicKey {
        &self.signature_verification_public_key
    }

    pub fn serialize_public_key<W: Write>(&self, mut dst: W) -> Result<(), Error> {
        dst.write_all(PUB_KEY_FILE_HEADER)?;
        dst.write_all(b"\r\n")?;
        self.encryption_public_key
            .serialize_encryption_public_key(&mut dst)?;
        self.signature_verification_public_key
            .serialize_signature_verification_public_key(&mut dst)?;
        self.opts.serialize_key_opts(&mut dst)?;
        dst.write_all(PUB_KEY_FILE_FOOTER)?;
        dst.write_all(b"\r\n")?;
        Ok(())
    }
}

pub fn generate_mla_keypair() -> (MLAPrivateKey, MLAPublicKey) {
    generate_mla_keypair_from_rng(get_crypto_rng())
}

pub fn generate_mla_keypair_from_seed(seed: [u8; 32]) -> (MLAPrivateKey, MLAPublicKey) {
    let csprng = ChaCha20Rng::from_seed(seed);
    generate_mla_keypair_from_rng(csprng)
}

fn generate_mla_keypair_from_rng(mut csprng: impl CryptoRngCore) -> (MLAPrivateKey, MLAPublicKey) {
    let (decryption_private_key, encryption_public_key) = generate_keypair_from_rng(&mut csprng);
    // TODO: generate a real signature keypair
    let (signature_private_key, signature_verification_public_key) = (
        MLASignaturePrivateKey {},
        MLASignatureVerificationPublicKey {},
    );
    let priv_key = MLAPrivateKey {
        decryption_private_key,
        signature_private_key,
        opts: KeyOpts,
    };
    let pub_key = MLAPublicKey {
        encryption_public_key,
        signature_verification_public_key,
        opts: KeyOpts,
    };
    (priv_key, pub_key)
}

const ECC_PRIVKEY_SIZE: usize = 32;
const ECC_PUBKEY_SIZE: usize = 32;

const DERIVE_PATH_SALT: &[u8; 15] = b"PATH DERIVATION";

/// Return a seed based on a path and an hybrid private key
///
/// The derivation scheme is based on the same ideas than `mla::crypto::hybrid::combine`, ie.
/// 1. a dual-PRF (HKDF-Extract with a uniform random salt \[1\]) to extract entropy from the private key
/// 2. HKDF-Expand to derive along the given path
///
/// seed = HKDF-SHA512(
///     salt=HKDF-SHA512-Extract(salt=0, ikm=ECC-key),
///     ikm=MLKEM-key,
///     info="PATH DERIVATION" . Derivation path
/// )
///
/// Note: the secret is consumed on call
///
/// \[1\] <https://eprint.iacr.org/2023/861>
fn apply_derive(path: &[u8], src: MLADecryptionPrivateKey) -> [u8; 32] {
    const SEED_LEN: usize = 32;

    // Force uniform-randomness on ECC-key, used as the future HKDF "salt" argument
    let (dprf_salt, _hkdf) = Hkdf::<Sha512>::extract(None, src.private_key_ecc.as_bytes());

    // `salt` being uniformly random, HKDF can be viewed as a dual-PRF
    let hkdf: Hkdf<Sha512> = Hkdf::new(
        Some(&dprf_salt),
        src.private_key_seed_ml.to_d_z_64().as_ref(),
    );
    let mut seed = [0u8; SEED_LEN];
    hkdf.expand_multi_info(&[DERIVE_PATH_SALT, path], &mut seed)
        .expect("Unexpected error while derivating along the path");

    seed
}

fn derive_one_path_component(
    path: &[u8],
    privkey: MLADecryptionPrivateKey,
) -> (MLADecryptionPrivateKey, MLAEncryptionPublicKey) {
    let seed = apply_derive(path, privkey);
    generate_keypair_from_seed(seed)
}

/// Return a KeyPair based on a succession of path components and an hybrid private key.
/// Return None if `path_components` is empty.
///
/// See `doc/KEY_DERIVATION.md`.
pub fn derive_keypair_from_path<'a>(
    path_components: impl Iterator<Item = &'a [u8]>,
    src: MLADecryptionPrivateKey,
) -> Option<(MLADecryptionPrivateKey, MLAEncryptionPublicKey)> {
    // None for public key: we do not have one at the beginning
    let initial_keypair = (src, None);
    // Use a fold to feed each newly generated keypair into next derive_one_path_component
    let (privkey, opt_pubkey) = path_components.fold(initial_keypair, |keypair, path| {
        let (privkey, pubkey) = derive_one_path_component(path, keypair.0);
        (privkey, Some(pubkey))
    });
    // opt_pubkey will be None iff path_components is empty
    opt_pubkey.map(|pubkey| (privkey, pubkey))
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom};

    use super::*;
    use kem::{Decapsulate, Encapsulate};
    use x25519_dalek::PublicKey;

    /// Check key coherence
    fn check_key_pair(pub_key: &MLAEncryptionPublicKey, priv_key: &MLADecryptionPrivateKey) {
        // Check the public ECC key rebuilt from the private ECC key is the expected one
        let computed_ecc_pubkey = PublicKey::from(&priv_key.private_key_ecc);
        assert_eq!(pub_key.public_key_ecc.as_bytes().len(), ECC_PUBKEY_SIZE);
        assert_eq!(priv_key.private_key_ecc.as_bytes().len(), ECC_PRIVKEY_SIZE);
        assert_eq!(
            pub_key.public_key_ecc.as_bytes(),
            computed_ecc_pubkey.as_bytes()
        );

        // Check the public ML-KEM key correspond to the private one
        const MLKEM_1024_PUBKEY_SIZE: usize = 1568;
        assert_eq!(
            pub_key.public_key_ml.as_bytes().len(),
            MLKEM_1024_PUBKEY_SIZE
        );
        let mut rng = rand::rngs::OsRng {};
        let (encap, key) = pub_key.public_key_ml.encapsulate(&mut rng).unwrap();
        let key_decap = priv_key
            .private_key_seed_ml
            .to_privkey()
            .decapsulate(&encap)
            .unwrap();
        assert_eq!(key, key_decap);
    }

    /// Ensure the generated keypair is coherent and re-readable
    #[test]
    fn keypair_serialize_deserialize_and_check() {
        let (priv_key, pub_key) = generate_mla_keypair();

        let mut cursor = Cursor::new(Vec::new());
        priv_key.serialize_private_key(&mut cursor).unwrap();
        cursor.seek(SeekFrom::Start(0)).unwrap();
        let priv_key = MLAPrivateKey::deserialize_private_key(&mut cursor).unwrap();
        cursor.seek(SeekFrom::Start(0)).unwrap();
        pub_key.serialize_public_key(&mut cursor).unwrap();
        cursor.seek(SeekFrom::Start(0)).unwrap();
        let pub_key = MLAPublicKey::deserialize_public_key(&mut cursor).unwrap();

        check_key_pair(
            pub_key.get_encryption_public_key(),
            priv_key.get_decryption_private_key(),
        );
    }

    /// Ensure the keypair generation is deterministic
    #[test]
    fn keypair_deterministic() {
        // Use a deterministic RNG in tests, for reproductability. DO NOT DO THIS IS IN ANY RELEASED BINARY!

        // Check the created key is deterministic
        let (priv1, pub1) = generate_mla_keypair_from_seed([0; 32]);
        let (priv2, pub2) = generate_mla_keypair_from_seed([0; 32]);
        let mut priv1s = Vec::new();
        let mut pub1s = Vec::new();
        let mut priv2s = Vec::new();
        let mut pub2s = Vec::new();
        priv1.serialize_private_key(&mut priv1s).unwrap();
        pub1.serialize_public_key(&mut pub1s).unwrap();
        priv2.serialize_private_key(&mut priv2s).unwrap();
        pub2.serialize_public_key(&mut pub2s).unwrap();
        assert_eq!(priv1s, priv2s);
        assert_eq!(pub1s, pub2s);

        // Ensure it is not always the same
        let (priv3, pub3) = generate_mla_keypair_from_seed([1; 32]);
        let mut priv3s = Vec::new();
        let mut pub3s = Vec::new();
        priv3.serialize_private_key(&mut priv3s).unwrap();
        pub3.serialize_public_key(&mut pub3s).unwrap();
        assert_ne!(priv1s, priv3s);
        assert_ne!(pub1s, pub3s);
    }

    #[test]
    /// Naive checks for "apply_derive", to avoid naive erros
    fn check_apply_derive() {
        use std::collections::HashSet;
        use x25519_dalek::StaticSecret;

        const SEED_LEN: usize = 32;

        // Ensure determinism
        let (privkey, _pubkey) = generate_keypair_from_seed([0; 32]);

        // Derive along "test"
        let path = b"test";
        let seed = apply_derive(path, privkey);
        assert_ne!(seed, [0u8; SEED_LEN]);

        // Derive along "test2"
        let (privkey, _pubkey) = generate_keypair_from_seed([0; 32]);
        let path = b"test2";
        let seed2 = apply_derive(path, privkey);
        assert_ne!(seed, seed2);

        // Ensure the secret depends on both keys
        let mut priv_keys = vec![];
        for i in 0..1 {
            for j in 0..1 {
                priv_keys.push(MLADecryptionPrivateKey {
                    private_key_ecc: StaticSecret::from([i as u8; 32]),
                    private_key_seed_ml: MLKEMSeed::from_d_z_64([j as u8; 64]),
                });
            }
        }

        // Generated seeds for (0, 0), (0, 1), (1, 0) and (1, 1) must be different
        let seeds: Vec<_> = priv_keys
            .into_iter()
            .map(|pkey| apply_derive(b"test", pkey))
            .collect();
        assert_eq!(HashSet::<_>::from_iter(seeds.iter()).len(), seeds.len());
    }

    #[test]
    fn check_derive_paths() {
        let ser_priv: &'static [u8] = include_bytes!("../../../samples/test_mlakey.mlapriv");
        let ser_derived_priv: &'static [u8] =
            include_bytes!("../../../samples/test_mlakey_derived.mlapriv");
        let secret =
            crate::crypto::mlakey::MLAPrivateKey::deserialize_private_key(ser_priv).unwrap();
        // Safe to unwrap, there is at least one derivation path
        let path = [b"pathcomponent1".as_slice(), b"pathcomponent2".as_slice()];
        let (decryption_private_key, _) = derive_keypair_from_path(
            path.into_iter(),
            secret.get_decryption_private_key().clone(),
        )
        .unwrap();
        let privkey = MLAPrivateKey::from_decryption_and_signature_keys(
            decryption_private_key,
            // TODO: fix MLASignaturePrivateKey after implementing it
            MLASignaturePrivateKey {},
        );
        let mut computed_ser_derived_priv = Vec::new();
        privkey
            .serialize_private_key(&mut computed_ser_derived_priv)
            .unwrap();

        assert_eq!(computed_ser_derived_priv.as_slice(), ser_derived_priv);
    }

    #[test]
    fn test_deserialization_errors() {
        use std::io::Cursor;

        // 1. Invalid header string (missing or wrong header)
        let missing_header = b"WRONG HEADER bWxhLWtlbS1wdWJsaWMtMTIzNDU2\n";
        let mut cursor = Cursor::new(&missing_header[..]);
        let result = MLAPrivateKey::deserialize_private_key(&mut cursor);
        assert!(matches!(result, Err(Error::DeserializationError)));

        // 2. Corrupted base64 (invalid characters)
        let corrupted_base64 = b"MLA PRIVATE DECRYPTION KEY !!@@##\n";
        let mut cursor = Cursor::new(&corrupted_base64[..]);
        let result = MLAPrivateKey::deserialize_private_key(&mut cursor);
        assert!(matches!(result, Err(Error::DeserializationError)));

        // 3. Wrong method ID length (simulate bad base64 with short method id bytes)
        // Here we craft a base64 string too short to contain a valid method ID.
        let bad_method_id = b"MLA PRIVATE DECRYPTION KEY QUFB\n";
        let mut cursor = Cursor::new(&bad_method_id[..]);
        let result = MLAPrivateKey::deserialize_private_key(&mut cursor);
        assert!(matches!(result, Err(Error::DeserializationError)));

        // 4. Truncated base64 data
        let truncated_data = b"MLA PRIVATE DECRYPTION KEY bWxh\n";
        let mut cursor = Cursor::new(&truncated_data[..]);
        let result = MLAPrivateKey::deserialize_private_key(&mut cursor);
        assert!(matches!(result, Err(Error::DeserializationError)));
    }
}
