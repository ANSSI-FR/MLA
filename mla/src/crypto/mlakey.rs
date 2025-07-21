use der_parser::der::*;
use der_parser::error::BerError;
use rand::SeedableRng as _;
use rand_chacha::rand_core::CryptoRngCore;

use der_parser::oid::Oid;
use der_parser::*;
use hkdf::Hkdf;
use nom::IResult;
use nom::combinator::{complete, eof};
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroize;

use core::convert::{From, TryInto};
use std::io::{BufRead, BufReader, Cursor, Read, Write};

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use ml_kem::EncodedSizeUser;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use core::fmt;

use crate::base64::{base64_decode, base64_encode};
pub use crate::crypto::hybrid::{MLADecryptionPrivateKey, MLAEncryptionPublicKey};
pub use crate::crypto::hybrid::{generate_keypair, generate_keypair_from_seed};

use crate::MLADeserialize;
use crate::crypto::hybrid::{MLKEMDecapsulationKey, MLKEMEncapsulationKey};
use crate::errors::Error;
use crate::layers::encrypt::get_crypto_rng;

use super::hybrid::generate_keypair_from_rng;

const MLA_PRIV_DEC_KEY_HEADER: &[u8] = b"DO NOT SEND THIS TO ANYONE - MLA PRIVATE DECRYPTION KEY ";
//const MLA_PRIV_SIG_KEY_HEADER: &[u8] = b"DO NOT SEND THIS TO ANYONE - MLA PRIVATE SIGNATURE KEY ";
const DEC_METHOD_ID_0_PRIV: &[u8] = b"mla-kem-private-x25519-mlkem1024";
//const SIG_METHOD_ID_0_PRIV: &[u8] = b"mla-signature-private-ed25519-mldsa87";

const MLA_PUB_ENC_KEY_HEADER: &[u8] = b"MLA PUBLIC ENCRYPTION KEY ";
//const MLA_PUB_SIGVERIF_KEY_HEADER: &[u8] = b"MLA PUBLIC SIGNATURE VERIFICATION KEY ";
const ENC_METHOD_ID_0_PUB: &[u8] = b"mla-kem-public-x25519-mlkem1024";
//const SIGVERIF_METHOD_ID_0_PUB: &[u8] = b"mla-signature-verification-public-ed25519-mldsa87";

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
    fn deserialize_decryption_private_key(src: impl Read) -> Result<Self, Error> {
        let mut line = String::new();
        BufReader::new(src).read_line(&mut line)?;
        let b64data = line
            .as_bytes()
            .strip_prefix(MLA_PRIV_DEC_KEY_HEADER)
            .ok_or(Error::DeserializationError)?
            .strip_suffix(b"\r\n")
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
        let mut serialized_mlkem_key = Vec::new();
        cursor
            .read_to_end(&mut serialized_mlkem_key)
            .map_err(|_| Error::DeserializationError)?;
        let private_key_ml = MLKEMDecapsulationKey::from_bytes(
            serialized_mlkem_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::DeserializationError)?,
        );
        serialized_mlkem_key.zeroize();
        Ok(Self {
            private_key_ecc,
            private_key_ml,
        })
    }

    fn serialize_decryption_private_key<W: Write>(&self, mut dst: W) -> Result<(), Error> {
        dst.write_all(MLA_PRIV_DEC_KEY_HEADER)?;
        let mut b64data = vec![];
        b64data.extend_from_slice(DEC_METHOD_ID_0_PRIV);
        b64data.extend_from_slice(&[0u8; 4]); // key opts, empty length for the moment
        b64data.extend_from_slice(&self.private_key_ecc.to_bytes());
        b64data.extend_from_slice(&self.private_key_ml.as_bytes());
        dst.write_all(&base64_encode(&b64data))?;
        dst.write_all(b"\r\n")?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct MLASignaturePrivateKey {}

impl MLASignaturePrivateKey {
    fn serialize_signature_private_key<W: Write>(&self, _dst: W) -> Result<(), Error> {
        // TODO
        Ok(())
    }
}

#[derive(Clone)]
pub struct MLAPrivateKey {
    decryption_private_key: MLADecryptionPrivateKey,
    signature_private_key: MLASignaturePrivateKey,
    opts: KeyOpts,
}

impl MLAPrivateKey {
    pub fn deserialize_private_key(mut src: impl Read) -> Result<Self, Error> {
        let decryption_private_key =
            MLADecryptionPrivateKey::deserialize_decryption_private_key(&mut src)?;
        let signature_private_key = MLASignaturePrivateKey {};
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

    pub fn serialize_private_key<W: Write>(&self, mut dst: W) -> Result<(), Error> {
        self.decryption_private_key
            .serialize_decryption_private_key(&mut dst)?;
        self.signature_private_key
            .serialize_signature_private_key(&mut dst)?;
        self.opts.serialize_key_opts(&mut dst)?;
        Ok(())
    }
}

impl MLAEncryptionPublicKey {
    fn deserialize_encryption_public_key(src: impl Read) -> Result<Self, Error> {
        let mut line = String::new();
        BufReader::new(src).read_line(&mut line)?;
        let b64data = line
            .as_bytes()
            .strip_prefix(MLA_PUB_ENC_KEY_HEADER)
            .ok_or(Error::DeserializationError)?
            .strip_suffix(b"\r\n")
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
        dst.write_all(MLA_PUB_ENC_KEY_HEADER)?;
        let mut b64data = vec![];
        b64data.extend_from_slice(ENC_METHOD_ID_0_PUB);
        b64data.extend_from_slice(&[0u8; 4]); // key opts, empty length for the moment
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
    fn serialize_signature_verification_public_key<W: Write>(&self, _dst: W) -> Result<(), Error> {
        // TODO
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
    pub fn deserialize_public_key(mut src: impl Read) -> Result<Self, Error> {
        let encryption_public_key =
            MLAEncryptionPublicKey::deserialize_encryption_public_key(&mut src)?;
        let signature_verification_public_key = MLASignatureVerificationPublicKey {};
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
        self.encryption_public_key
            .serialize_encryption_public_key(&mut dst)?;
        self.signature_verification_public_key
            .serialize_signature_verification_public_key(&mut dst)?;
        self.opts.serialize_key_opts(&mut dst)?;
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

const ED_25519_OID: Oid<'static> = oid!(1.3.101.112);
const X_25519_OID: Oid<'static> = oid!(1.3.101.110);
const ECC_PRIVKEY_SIZE: usize = 32;
const ECC_PUBKEY_SIZE: usize = 32;

// TODO: update with actual OID once attribued by NIST/IANA
// For now, use a ANSSI factice OID
// https://datatracker.ietf.org/doc/html/draft-ietf-lamps-kyber-certificates
const MLKEM_1024_OID: Oid<'static> = oid!(1.2.250.1.223.201);

const MLKEM_1024_PUBKEY_SIZE: usize = 1568;
const MLKEM_1024_PRIVKEY_SIZE: usize = 3168;

pub const MLAKEY_PRIVKEY_DER_SIZE: usize = 3243;
pub const MLAKEY_PUBKEY_DER_SIZE: usize = 1636;

// ---- Error handling ----

#[derive(Debug)]
pub enum MLAKeyParserError {
    /// BER Parsing error (wrong tag, not enough DER elements, etc.)
    BerError,
    /// PEM Parsing error
    PemError,
    /// Nom parsing error (wrong format, unexpected elements, etc.)
    NomError,
    UnknownOid,
    InvalidData,
    InvalidPEMTag,
}
impl From<der_parser::error::BerError> for MLAKeyParserError {
    fn from(_error: der_parser::error::BerError) -> Self {
        MLAKeyParserError::BerError
    }
}

impl From<pem::PemError> for MLAKeyParserError {
    fn from(_error: pem::PemError) -> Self {
        MLAKeyParserError::PemError
    }
}

impl From<nom::Err<der_parser::error::BerError>> for MLAKeyParserError {
    fn from(_error: nom::Err<der_parser::error::BerError>) -> Self {
        MLAKeyParserError::NomError
    }
}

impl fmt::Display for MLAKeyParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // For now, use the debug derived version
        write!(f, "{self:?}")
    }
}

// ---- Commons ----

#[derive(Debug, PartialEq)]
struct DerTag<'a> {
    tag: DerObject<'a>,
}

#[derive(Debug, PartialEq)]
struct DerStruct<'a> {
    header: DerTag<'a>,
    data: DerObject<'a>,
}

/// Parse the following structure:
/// ```ascii
/// Seq(
///     OID(tag)    
/// )
/// ```
/// Return the corresponding tag
fn parse_seq_oid(i: &[u8]) -> IResult<&[u8], DerTag, BerError> {
    parse_der_container(|i: &[u8], hdr| {
        if hdr.tag() != Tag::Sequence {
            return Err(nom::Err::Error(BerError::InvalidTag));
        }
        let (i, tag) = parse_der_oid(i)?;
        eof(i)?;
        Ok((i, DerTag { tag }))
    })(i)
}

// ---- Private key ----

/// Parse the following structure:
/// ```ascii
/// Seq(
///     Int, (ignored)
///     Seq(
///         OID(tag)
///     ),
///     OctetString(data)
/// )
/// ```
fn parse_seq_int_tag_octetstring(i: &[u8]) -> IResult<&[u8], DerStruct, BerError> {
    parse_der_container(|i: &[u8], hdr| {
        if hdr.tag() != Tag::Sequence {
            return Err(nom::Err::Error(BerError::InvalidTag));
        }
        let (i, _unk) = parse_der_integer(i)?;
        let (i, header) = complete(parse_seq_oid)(i)?;
        let (i, data) = parse_der_octetstring(i)?;
        eof(i)?;
        Ok((i, DerStruct { header, data }))
    })(i)
}

const TAG_OCTETSTRING: u8 = 4;

/// Take a parsed DER Sequence of a ED25519 or X25519 private key, and return the corresponding
/// `x25519_dalek::StaticSecret`
///
/// Expected structure (OpenSSL X25519):
///
/// ASN1:
///    0:d=0  hl=2 l=  46 cons: SEQUENCE
///    2:d=1  hl=2 l=   1 prim: INTEGER           :00
///    5:d=1  hl=2 l=   5 cons: SEQUENCE
///    7:d=2  hl=2 l=   3 prim: OBJECT            :ED25519 OR :X25519
///   12:d=1  hl=2 l=  34 prim: OCTET STRING
///
/// Tree view:
/// Seq(
///     Int,
///     Seq(
///         OID(1.3.101.112), // ED25519 OR OID(1.3.101.110), // X25519
///     ),
///     OctetString(TAG_OCTETSTRING + LENGTH + DATA),
/// )
///
/// From RFC8032, to obtain the corresponding `x25519_dalek::StaticSecret` from an ed25519 key:
///   `clamping(Sha512(DATA)[0..32])`
/// with `clamping` operation already done on `StaticSecret` creation
fn parse_openssl_25519_privkey_internal(
    private: DerStruct,
) -> Result<StaticSecret, MLAKeyParserError> {
    let data = private.data.content.as_slice()?;
    // data[0] == TAG_OCTETSTRING(4)
    // data[1] == LENGTH
    if data.len() != 2 + ECC_PRIVKEY_SIZE
        || data[0] != TAG_OCTETSTRING
        || data[1] != ECC_PRIVKEY_SIZE as u8
    {
        return Err(MLAKeyParserError::InvalidData);
    }
    let mut key_data = [0u8; ECC_PRIVKEY_SIZE];

    let read_oid = private.header.tag.as_oid()?;
    if read_oid == &ED_25519_OID {
        key_data
            .copy_from_slice(&Sha512::digest(&data[2..2 + ECC_PRIVKEY_SIZE])[0..ECC_PRIVKEY_SIZE]);
    } else if read_oid == &X_25519_OID {
        key_data.copy_from_slice(&data[2..2 + ECC_PRIVKEY_SIZE]);
    } else {
        return Err(MLAKeyParserError::UnknownOid);
    }
    Ok(StaticSecret::from(key_data))
}

/// Take a parsed DER Sequence of a MLA private key, and return the corresponding
/// `mla::crypto::hybrid::MLKEMDecapsulationKey`
///
/// Expected structure:
/// Seq(
///     Int,
///     Seq(
///         OID(1.2.250.1.223.201)
///     ),
///     OctetString(private key)
/// )
fn parse_mlkem_decapkey_internal(
    private: DerStruct,
) -> Result<MLKEMDecapsulationKey, MLAKeyParserError> {
    let data = private.data.content.as_slice()?;
    let read_oid = private.header.tag.as_oid()?;
    if read_oid != &MLKEM_1024_OID {
        return Err(MLAKeyParserError::UnknownOid);
    }
    if data.len() != MLKEM_1024_PRIVKEY_SIZE {
        return Err(MLAKeyParserError::InvalidData);
    }
    Ok(MLKEMDecapsulationKey::from_bytes(
        data.try_into()
            .map_err(|_| MLAKeyParserError::InvalidData)?,
    ))
}

/// Parse given DER data as an MLA private key
///
/// Expected structure:
///
/// - ASN1:
/// ```ascii
///     0:d=0  hl=4 l=3239 cons: SEQUENCE          
///     4:d=1  hl=2 l=  46 cons:  SEQUENCE          
///     6:d=2  hl=2 l=   1 prim:   INTEGER           :00
///     9:d=2  hl=2 l=   5 cons:   SEQUENCE          
///     11:d=3  hl=2 l=   3 prim:    OBJECT            :X25519
///     16:d=2  hl=2 l=  34 prim:   OCTET STRING      [HEX DUMP]:...
///     52:d=1  hl=4 l=3187 cons:  SEQUENCE          
///     56:d=2  hl=2 l=   1 prim:   INTEGER           :01
///     59:d=2  hl=2 l=  10 cons:   SEQUENCE          
///     61:d=3  hl=2 l=   8 prim:    OBJECT            :1.2.250.1.223.201
///     71:d=2  hl=4 l=3168 prim:   OCTET STRING      [HEX DUMP]:...
/// ```
///
/// Tree view:
/// Seq(
///     Seq(
///         Int,
///         Seq(
///             OID(1.3.101.112), // ED25519 OR OID(1.3.101.110), // X25519
///         ),
///         OctetString(TAG_OCTETSTRING + LENGTH + DATA),
///     ),
///     Seq(
///         Int,
///         Seq(
///             OID(1.2.250.1.223.201)
///         ),
///         OctetString(private key)
///     )
/// )
///
/// Note: OID order can change (Ed/X 25519 then MLKEM, MLKEM then Ed/X 25519)
pub fn parse_mlakey_privkey_der(data: &[u8]) -> Result<MLADecryptionPrivateKey, MLAKeyParserError> {
    let (_remain, (seq_25519, seq_mlkem)) = parse_der_container(|i: &[u8], hdr| {
        if hdr.tag() != Tag::Sequence {
            return Err(nom::Err::Error(BerError::InvalidTag));
        }
        // Expect a Seq(Seq, Seq)
        let (i, seq1) = parse_seq_int_tag_octetstring(i)?;
        let (i, seq2) = parse_seq_int_tag_octetstring(i)?;
        eof(i)?;

        // OID order can change
        // This is not the real OID check, only for variable order
        let (seq_25519, seq_mlkem) = {
            if seq1.header.tag.as_oid()? == &MLKEM_1024_OID {
                // MLKEM, then Ed/X 25519
                (seq2, seq1)
            } else {
                // Ed/X 25519 then MLKEM
                (seq1, seq2)
            }
        };

        Ok((i, (seq_25519, seq_mlkem)))
    })(data)?;

    // Parse ML-KEM part
    let private_key_ml = parse_mlkem_decapkey_internal(seq_mlkem)?;

    // Parse X/Ed 25519 part
    let private_key_ecc = parse_openssl_25519_privkey_internal(seq_25519)?;

    Ok(MLADecryptionPrivateKey {
        private_key_ecc,
        private_key_ml,
    })
}

// ---- Public key ----

/// Parse the following structure:
/// ```ascii
/// Seq(
///    Seq(
///       OID(tag)
///    ),
///    BitString(data)
/// )
/// ```
/// Return the corresponding tag and data
fn parse_seq_tag_bitstring(i: &[u8]) -> IResult<&[u8], DerStruct, BerError> {
    parse_der_container(|i: &[u8], hdr| {
        if hdr.tag() != Tag::Sequence {
            return Err(nom::Err::Error(BerError::InvalidTag));
        }
        let (i, header) = complete(parse_seq_oid)(i)?;
        let (i, data) = parse_der_bitstring(i)?;
        eof(i)?;
        Ok((i, DerStruct { header, data }))
    })(i)
}

/// Parse the following structure:
/// ```ascii
/// Seq(
///    Seq(
///       OID(tag)
///    ),
///    OctetString(data)
/// )
/// ```
/// Return the corresponding tag and data
fn parse_seq_tag_octetstring(i: &[u8]) -> IResult<&[u8], DerStruct, BerError> {
    parse_der_container(|i: &[u8], hdr| {
        if hdr.tag() != Tag::Sequence {
            return Err(nom::Err::Error(BerError::InvalidTag));
        }
        let (i, header) = complete(parse_seq_oid)(i)?;
        let (i, data) = parse_der_octetstring(i)?;
        eof(i)?;
        Ok((i, DerStruct { header, data }))
    })(i)
}

/// Take a parsed DER Sequence of a Ed25519 or X25519 public key, and return the corresponding
/// `x25519_dalek::PublicKey`
///
/// Expected structure:
///
/// ASN1:
///  0:d=0  hl=2 l=  42 cons: SEQUENCE
///  2:d=1  hl=2 l=   5 cons: SEQUENCE
///  4:d=2  hl=2 l=   3 prim: OBJECT            :ED25519
///  9:d=1  hl=2 l=  33 prim: BIT STRING
///
/// Tree view:
/// Seq(
///     Seq(
///         OID(1.3.101.112), // ED25519  OR  OID(1.3.101.110), // X25519
///     ),
///     BitString(DATA),
/// )
///
/// From RFC8032 and OpenSSL format, to obtain the corresponding
/// `x25519_dalek::PublicKey`, which internally use the Montgomery form
/// from an Ed25519 key:
///   to_montgomery(decompress_edwardspoint(DATA))
fn parse_openssl_25519_pubkey_internal(
    ed25519_public: DerStruct,
) -> Result<PublicKey, MLAKeyParserError> {
    let data = ed25519_public.data.content.as_slice()?;
    let data: [u8; ECC_PUBKEY_SIZE] = data
        .try_into()
        .map_err(|_| MLAKeyParserError::InvalidData)?;
    let read_oid = ed25519_public.header.tag.as_oid()?;
    if read_oid == &ED_25519_OID {
        CompressedEdwardsY::from_slice(&data)
            .ok()
            .and_then(|c| c.decompress())
            .map(|v| PublicKey::from(v.to_montgomery().to_bytes()))
            .ok_or(MLAKeyParserError::InvalidData)
    } else if read_oid == &X_25519_OID {
        Ok(PublicKey::from(MontgomeryPoint(data).to_bytes()))
    } else {
        Err(MLAKeyParserError::UnknownOid)
    }
}

/// Parse a DER MLA public key, and return the corresponding
/// `mla::crypto::hybrid::MLKEMEncapsulationKey`
///
/// Expected structure:
/// Seq(
///    Seq(
///      OID(1.2.250.1.223.201)
///    ),
///    OctetString(data)
/// )
fn parse_mlkem_encapkey_internal(
    public: DerStruct,
) -> Result<MLKEMEncapsulationKey, MLAKeyParserError> {
    let data = public.data.content.as_slice()?;
    let read_oid = public.header.tag.as_oid()?;
    if read_oid != &MLKEM_1024_OID {
        return Err(MLAKeyParserError::UnknownOid);
    }
    if data.len() != MLKEM_1024_PUBKEY_SIZE {
        return Err(MLAKeyParserError::InvalidData);
    }
    Ok(MLKEMEncapsulationKey::from_bytes(
        data.try_into()
            .map_err(|_| MLAKeyParserError::InvalidData)?,
    ))
}

/// Parse given DER data as an MLA private key
///
/// Expected structure:
///
/// - ASN1:
/// ```ascii
///     0:d=0  hl=4 l=1632 cons: SEQUENCE          
///     4:d=1  hl=2 l=  42 cons:  SEQUENCE          
///     6:d=2  hl=2 l=   5 cons:   SEQUENCE          
///     8:d=3  hl=2 l=   3 prim:    OBJECT            :X25519
///     13:d=2  hl=2 l=  33 prim:   BIT STRING        
///     48:d=1  hl=4 l=1584 cons:  SEQUENCE          
///     52:d=2  hl=2 l=  10 cons:   SEQUENCE          
///     54:d=3  hl=2 l=   8 prim:    OBJECT            :1.2.250.1.223.201
///     64:d=2  hl=4 l=1568 prim:   OCTET STRING      [HEX DUMP]:...
/// ```
///
/// Tree view:
/// Seq(
///     Seq(
///         Seq(
///             OID(1.3.101.112), // ED25519 OR OID(1.3.101.110), // X25519
///         ),
///         BiString(DATA),
///     ),
///     Seq(
///         Seq(
///             OID(1.2.250.1.223.201)
///         ),
///         OctetString(public key)
///     )
/// )
///
/// Note: OID order can change (Ed/X 25519 then MLKEM, MLKEM then Ed/X 25519)
pub fn parse_mlakey_pubkey_der(data: &[u8]) -> Result<MLAEncryptionPublicKey, MLAKeyParserError> {
    let (_remain, (seq_25519, seq_mlkem)) = parse_der_container(|i: &[u8], hdr| {
        if hdr.tag() != Tag::Sequence {
            return Err(nom::Err::Error(BerError::InvalidTag));
        }

        // Expect a Seq(Seq, Seq)
        // OID are not checked here, only for variable order
        if let Ok((i, seq_25519)) = parse_seq_tag_bitstring(i) {
            // Ed/X 25519 then MLKEM
            let (i, seq_mlkem) = parse_seq_tag_octetstring(i)?;
            eof(i)?;
            Ok((i, (seq_25519, seq_mlkem)))
        } else if let Ok((i, seq_mlkem)) = parse_seq_tag_octetstring(i) {
            // MLKEM then Ed/X 25519
            let (i, seq_25519) = parse_seq_tag_bitstring(i)?;
            eof(i)?;
            Ok((i, (seq_25519, seq_mlkem)))
        } else {
            return Err(nom::Err::Error(BerError::InvalidTag));
        }
    })(data)?;

    // Parse ML-KEM part
    let public_key_ml = parse_mlkem_encapkey_internal(seq_mlkem)?;

    // Parse X/Ed 25519 part
    let public_key_ecc = parse_openssl_25519_pubkey_internal(seq_25519)?;

    Ok(MLAEncryptionPublicKey {
        public_key_ecc,
        public_key_ml,
    })
}

// ---- PEM ----

const PUBLIC_TAG: &[u8] = b"PUBLIC KEY";
const PRIVATE_TAG: &[u8] = b"PRIVATE KEY";

/// Parse an MLA private key in PEM format
pub fn parse_mlakey_privkey_pem(data: &[u8]) -> Result<MLADecryptionPrivateKey, MLAKeyParserError> {
    if let Ok(pem_data) = pem::parse(data) {
        // First, try as a PEM
        if pem_data.tag().as_bytes() != PRIVATE_TAG {
            return Err(MLAKeyParserError::InvalidPEMTag);
        }
        parse_mlakey_privkey_der(pem_data.contents())
    } else {
        Err(MLAKeyParserError::InvalidData)
    }
}

/// Parse several contiguous MLA public keys in PEM format
pub fn parse_mlakey_privkeys_pem_many(
    data: &[u8],
) -> Result<Vec<MLADecryptionPrivateKey>, MLAKeyParserError> {
    let mut output = Vec::new();
    for pem_data in pem::parse_many(data)? {
        if pem_data.tag().as_bytes() != PRIVATE_TAG {
            return Err(MLAKeyParserError::InvalidPEMTag);
        }
        output.push(parse_mlakey_privkey_der(pem_data.contents())?);
    }
    Ok(output)
}

/// Parse an MLA public key in PEM format
pub fn parse_mlakey_pubkey_pem(data: &[u8]) -> Result<MLAEncryptionPublicKey, MLAKeyParserError> {
    if let Ok(pem_data) = pem::parse(data) {
        // First, try as a PEM
        if pem_data.tag().as_bytes() != PUBLIC_TAG {
            return Err(MLAKeyParserError::InvalidPEMTag);
        }
        parse_mlakey_pubkey_der(pem_data.contents())
    } else {
        Err(MLAKeyParserError::InvalidData)
    }
}

/// Parse several contiguous MLA public keys in PEM format
pub fn parse_mlakey_pubkeys_pem_many(
    data: &[u8],
) -> Result<Vec<MLAEncryptionPublicKey>, MLAKeyParserError> {
    let mut output = Vec::new();
    for pem_data in pem::parse_many(data)? {
        if pem_data.tag().as_bytes() != PUBLIC_TAG {
            return Err(MLAKeyParserError::InvalidPEMTag);
        }
        output.push(parse_mlakey_pubkey_der(pem_data.contents())?);
    }
    Ok(output)
}

// ---- Strict Export ----

// This is done with constant data instead of real DER building, as the format
// is strict and key size are constant

// Private key: PRIV_KEY_PREFIX1 + ECC private key, X25519 form + PRIV_KEY_PREFIX2 + MLKEM private key
const PRIV_KEY_PREFIX1: &[u8] =
    b"\x30\x82\x0c\xa7\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20";
const PRIV_KEY_PREFIX2: &[u8] =
    b"\x30\x82\x0c\x73\x02\x01\x01\x30\x0a\x06\x08\x2a\x81\x7a\x01\x81\x5f\x81\x49\x04\x82\x0c\x60";
const PRIV_DER_LEN: usize =
    PRIV_KEY_PREFIX1.len() + ECC_PUBKEY_SIZE + PRIV_KEY_PREFIX2.len() + MLKEM_1024_PRIVKEY_SIZE;

// Public key: PUB_KEY_PREFIX1 + ECC public key, X25519 form + PUB_KEY_PREFIX2 + MLKEM public key
const PUB_KEY_PREFIX1: &[u8] = b"\x30\x82\x06\x60\x30\x2a\x30\x05\x06\x03\x2b\x65\x6e\x03\x21\x00";
const PUB_KEY_PREFIX2: &[u8] =
    b"\x30\x82\x06\x30\x30\x0a\x06\x08\x2a\x81\x7a\x01\x81\x5f\x81\x49\x04\x82\x06\x20";
const PUB_DER_LEN: usize =
    PUB_KEY_PREFIX1.len() + ECC_PUBKEY_SIZE + PUB_KEY_PREFIX2.len() + MLKEM_1024_PUBKEY_SIZE;

const PRIV_KEY_TAG: &str = "PRIVATE KEY";
const PUB_KEY_TAG: &str = "PUBLIC KEY";

impl MLAEncryptionPublicKey {
    pub fn to_der(&self) -> [u8; PUB_DER_LEN] {
        let mut public_der = [0u8; PUB_DER_LEN];
        public_der[..PUB_KEY_PREFIX1.len()].copy_from_slice(PUB_KEY_PREFIX1);
        public_der[PUB_KEY_PREFIX1.len()..PUB_KEY_PREFIX1.len() + ECC_PUBKEY_SIZE]
            .copy_from_slice(&self.public_key_ecc.to_bytes());
        public_der[PUB_KEY_PREFIX1.len() + ECC_PUBKEY_SIZE
            ..PUB_KEY_PREFIX1.len() + ECC_PUBKEY_SIZE + PUB_KEY_PREFIX2.len()]
            .copy_from_slice(PUB_KEY_PREFIX2);
        public_der[PUB_KEY_PREFIX1.len() + ECC_PUBKEY_SIZE + PUB_KEY_PREFIX2.len()..]
            .copy_from_slice(&self.public_key_ml.as_bytes());

        public_der
    }

    pub fn to_pem(&self) -> String {
        pem::encode(&pem::Pem::new(PUB_KEY_TAG, self.to_der()))
    }
}

impl MLADecryptionPrivateKey {
    pub fn to_der(&self) -> [u8; PRIV_DER_LEN] {
        let mut private_der = [0u8; PRIV_DER_LEN];
        private_der[..PRIV_KEY_PREFIX1.len()].copy_from_slice(PRIV_KEY_PREFIX1);
        private_der[PRIV_KEY_PREFIX1.len()..PRIV_KEY_PREFIX1.len() + ECC_PRIVKEY_SIZE]
            .copy_from_slice(&self.private_key_ecc.to_bytes());
        private_der[PRIV_KEY_PREFIX1.len() + ECC_PRIVKEY_SIZE
            ..PRIV_KEY_PREFIX1.len() + ECC_PRIVKEY_SIZE + PRIV_KEY_PREFIX2.len()]
            .copy_from_slice(PRIV_KEY_PREFIX2);
        private_der[PRIV_KEY_PREFIX1.len() + ECC_PRIVKEY_SIZE + PRIV_KEY_PREFIX2.len()..]
            .copy_from_slice(&self.private_key_ml.as_bytes());

        private_der
    }

    pub fn to_pem(&self) -> String {
        pem::encode(&pem::Pem::new(PRIV_KEY_TAG, self.to_der()))
    }
}

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
    // Force uniform-randomness on ECC-key, used as the future HKDF "salt" argument
    let (dprf_salt, _hkdf) = Hkdf::<Sha512>::extract(None, src.private_key_ecc.as_bytes());

    // `salt` being uniformly random, HKDF can be viewed as a dual-PRF
    let hkdf: Hkdf<Sha512> = Hkdf::new(Some(&dprf_salt), &src.private_key_ml.as_bytes());
    let mut seed = [0u8; 32];
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
        assert_eq!(
            pub_key.public_key_ml.as_bytes().len(),
            MLKEM_1024_PUBKEY_SIZE
        );
        let mut rng = rand::rngs::OsRng {};
        let (encap, key) = pub_key.public_key_ml.encapsulate(&mut rng).unwrap();
        let key_decap = priv_key.private_key_ml.decapsulate(&encap).unwrap();
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
        use crate::crypto::hybrid::MLKEMDecapsulationKey;
        use std::collections::HashSet;
        use x25519_dalek::StaticSecret;

        // Ensure determinism
        let (privkey, _pubkey) = generate_keypair_from_seed([0; 32]);

        // Derive along "test"
        let path = b"test";
        let seed = apply_derive(path, privkey);
        assert_ne!(seed, [0u8; 32]);

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
                    private_key_ml: MLKEMDecapsulationKey::from_bytes(&[j as u8; 3168].into()),
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
        let der_priv: &'static [u8] = include_bytes!("../../../samples/test_mlakey.mlapriv");
        let der_derived_priv: &'static [u8] =
            include_bytes!("../../../samples/test_mlakey_derived.mlapriv");
        let secret = crate::crypto::mlakey::parse_mlakey_privkey_der(der_priv).unwrap();
        // Safe to unwrap, there is at least one derivation path
        let path = [b"pathcomponent1".as_slice(), b"pathcomponent2".as_slice()];
        let (privkey, _) = derive_keypair_from_path(path.into_iter(), secret).unwrap();
        assert_eq!(privkey.to_der().as_slice(), der_derived_priv);
    }
}
