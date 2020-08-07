use der_parser::ber::BerObjectHeader;
use der_parser::der::*;
use der_parser::error::BerError;

use der_parser::oid::Oid;
use der_parser::*;
use nom::IResult;

use std::convert::{From, TryInto};

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use sha2::{Digest, Sha512};
// Re-export x25519_dalek structures for convenience
pub use x25519_dalek::{PublicKey, StaticSecret};

use rand_core::{CryptoRng, RngCore};

use std::fmt;

const ED_25519_OID: [u64; 4] = [1, 3, 101, 112];
const X_25519_OID: [u64; 4] = [1, 3, 101, 110];

// ---- Error handling ----

#[derive(Debug)]
pub enum Curve25519ParserError {
    /// BER Parsing error (wrong tag, not enough DER elements, etc.)
    BerError(der_parser::error::BerError),
    /// Nom parsing error (wrong format, unexpected elements, etc.)
    NomError(nom::Err<der_parser::error::BerError>),
    UnknownOid,
    InvalidData,
    InvalidPEMTag,
}
impl From<der_parser::error::BerError> for Curve25519ParserError {
    fn from(error: der_parser::error::BerError) -> Self {
        Curve25519ParserError::BerError(error)
    }
}

impl From<nom::Err<der_parser::error::BerError>> for Curve25519ParserError {
    fn from(error: nom::Err<der_parser::error::BerError>) -> Self {
        Curve25519ParserError::NomError(error)
    }
}

impl fmt::Display for Curve25519ParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // For now, use the debug derived version
        write!(f, "{:?}", self)
    }
}

// ---- Private key ----

/// Expected structure:
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

#[derive(Debug, PartialEq)]
struct Der25519PrivateHeader<'a> {
    tag: DerObject<'a>,
}

#[derive(Debug, PartialEq)]
struct Der25519PrivateStruct<'a> {
    header: Der25519PrivateHeader<'a>,
    data: DerObject<'a>,
}

fn parse_25519_private_header(
    i: &[u8],
) -> IResult<&[u8], (BerObjectHeader, Der25519PrivateHeader), BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        tag: parse_der_oid >> eof!() >> (Der25519PrivateHeader { tag })
    )
}

fn parse_25519_private(
    i: &[u8],
) -> IResult<&[u8], (BerObjectHeader, Der25519PrivateStruct), BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        _unk: parse_der_integer >>
        header: complete!(parse_25519_private_header) >>
        data: parse_der_octetstring >>
           eof!() >>
        ( Der25519PrivateStruct{ header: header.1, data } )
    )
}

const TAG_OCTETSTRING: u8 = 4;

/// Parse a DER ED25519 or X25519 private key, and return the corresponding
/// `x25519_dalek::StaticSecret`
pub fn parse_openssl_25519_privkey_der(data: &[u8]) -> Result<StaticSecret, Curve25519ParserError> {
    let ed25519_oid = Oid::from(&ED_25519_OID);
    let x25519_oid = Oid::from(&X_25519_OID);
    let (_remain, (_header, private)) = parse_25519_private(data)?;
    let data = private.data.content.as_slice()?;
    // data[0] == TAG_OCTETSTRING(4)
    // data[1] == LENGTH
    if data.len() != 34 || data[0] != TAG_OCTETSTRING || data[1] != 32 {
        return Err(Curve25519ParserError::InvalidData);
    }
    let mut key_data = [0u8; 32];

    let read_oid = private.header.tag.as_oid()?;
    if read_oid == &ed25519_oid {
        key_data.copy_from_slice(&Sha512::digest(&data[2..34])[0..32]);
    } else if read_oid == &x25519_oid {
        key_data.copy_from_slice(&data[2..34]);
    } else {
        return Err(Curve25519ParserError::UnknownOid);
    }
    Ok(StaticSecret::from(key_data))
}

// ---- Public key ----

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

#[derive(Debug, PartialEq)]
struct DerEd25519PublicHeader<'a> {
    tag: DerObject<'a>,
}

#[derive(Debug, PartialEq)]
struct DerEd25519PublicStruct<'a> {
    header: DerEd25519PublicHeader<'a>,
    data: DerObject<'a>,
}

fn parse_25519_public_header(
    i: &[u8],
) -> IResult<&[u8], (BerObjectHeader, DerEd25519PublicHeader), BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        tag: parse_der_oid >> eof!() >> (DerEd25519PublicHeader { tag })
    )
}

fn parse_25519_public(
    i: &[u8],
) -> IResult<&[u8], (BerObjectHeader, DerEd25519PublicStruct), BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        header: complete!(parse_25519_public_header) >>
        data: parse_der_bitstring >>
           eof!() >>
        ( DerEd25519PublicStruct{ header: header.1, data } )
    )
}

/// Parse a DER Ed25519 or X25519 public key, and return the corresponding
/// `x25519_dalek::PublicKey`
pub fn parse_openssl_25519_pubkey_der(data: &[u8]) -> Result<PublicKey, Curve25519ParserError> {
    let ed25519_oid = Oid::from(&ED_25519_OID);
    let x25519_oid = Oid::from(&X_25519_OID);
    let (_remain, (_header, ed25519_public)) = parse_25519_public(data)?;
    let data = ed25519_public.data.content.as_slice()?;
    let data: [u8; 32] = data
        .try_into()
        .map_err(|_| Curve25519ParserError::InvalidData)?;
    let read_oid = ed25519_public.header.tag.as_oid()?;
    if read_oid == &ed25519_oid {
        if let Some(edwards_val) = CompressedEdwardsY::from_slice(&data).decompress() {
            Ok(PublicKey::from(edwards_val.to_montgomery().to_bytes()))
        } else {
            Err(Curve25519ParserError::InvalidData)
        }
    } else if read_oid == &x25519_oid {
        Ok(PublicKey::from(MontgomeryPoint(data).to_bytes()))
    } else {
        Err(Curve25519ParserError::UnknownOid)
    }
}

// ---- PEM ----

const PUBLIC_TAG: &[u8] = b"PUBLIC KEY";
const PRIVATE_TAG: &[u8] = b"PRIVATE KEY";

/// Parse an OpenSSL Ed25519 or X25519 public key, either in PEM or DER format
pub fn parse_openssl_25519_pubkey(data: &[u8]) -> Result<PublicKey, Curve25519ParserError> {
    if let Ok(pem_data) = pem::parse(data) {
        // First, try as a PEM
        if pem_data.tag.as_bytes() != PUBLIC_TAG {
            return Err(Curve25519ParserError::InvalidPEMTag);
        }
        parse_openssl_25519_pubkey_der(&pem_data.contents)
    } else {
        // Fallback to DER format
        parse_openssl_25519_pubkey_der(data)
    }
}

/// Parse an OpenSSL Ed25519 or X25519 private key, either in PEM or DER format
pub fn parse_openssl_25519_privkey(data: &[u8]) -> Result<StaticSecret, Curve25519ParserError> {
    if let Ok(pem_data) = pem::parse(data) {
        // First, try as a PEM
        if pem_data.tag.as_bytes() != PRIVATE_TAG {
            return Err(Curve25519ParserError::InvalidPEMTag);
        }
        parse_openssl_25519_privkey_der(&pem_data.contents)
    } else {
        // Fallback to DER format
        parse_openssl_25519_privkey_der(data)
    }
}

/// Parse several contiguous OpenSSL Ed25519 org X25519 public keys in PEM format
pub fn parse_openssl_25519_pubkeys_pem_many(
    data: &[u8],
) -> Result<Vec<PublicKey>, Curve25519ParserError> {
    let mut output = Vec::new();
    for pem_data in pem::parse_many(data) {
        if pem_data.tag.as_bytes() != PUBLIC_TAG {
            return Err(Curve25519ParserError::InvalidPEMTag);
        }
        output.push(parse_openssl_25519_pubkey_der(&pem_data.contents)?);
    }
    Ok(output)
}

// ---- Strict Export ----

// This is done with constant data instead of real DER building, as the format
// is strict and key size are constant

const PRIV_KEY_PREFIX: &[u8] = b"\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20";
const PUB_KEY_PREFIX: &[u8] = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x6e\x03\x21\x00";
const PRIV_KEY_TAG: &str = "PRIVATE KEY";
const PUB_KEY_TAG: &str = "PUBLIC KEY";

pub struct KeyPair {
    pub public_der: [u8; PUB_KEY_PREFIX.len() + 32],
    pub private_der: [u8; PRIV_KEY_PREFIX.len() + 32],
}

impl KeyPair {
    pub fn public_as_pem(&self) -> String {
        let out = pem::Pem {
            tag: PUB_KEY_TAG.to_string(),
            contents: self.public_der.to_vec(),
        };
        pem::encode(&out)
    }

    pub fn private_as_pem(&self) -> String {
        let out = pem::Pem {
            tag: PRIV_KEY_TAG.to_string(),
            contents: self.private_der.to_vec(),
        };
        pem::encode(&out)
    }
}

/// Generate a keypair, in DER format
pub fn generate_keypair<T>(csprng: &mut T) -> Option<KeyPair>
where
    T: RngCore + CryptoRng,
{
    // Get the seed
    let mut private = [0u8; 32];
    csprng.fill_bytes(&mut private);

    // Get the corresponding public key
    let priv_key = StaticSecret::from(private);
    let pubkey = PublicKey::from(&priv_key);

    // Get the public data bytes

    let public = pubkey.as_bytes();

    let mut private_der = [0u8; PRIV_KEY_PREFIX.len() + 32];
    private_der[..PRIV_KEY_PREFIX.len()].copy_from_slice(PRIV_KEY_PREFIX);
    private_der[PRIV_KEY_PREFIX.len()..].copy_from_slice(&private);

    let mut public_der = [0u8; PUB_KEY_PREFIX.len() + 32];
    public_der[..PUB_KEY_PREFIX.len()].copy_from_slice(PUB_KEY_PREFIX);
    public_der[PUB_KEY_PREFIX.len()..].copy_from_slice(&public[..]);

    Some(KeyPair {
        public_der,
        private_der,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use x25519_dalek::PublicKey;

    // Samples, generated by:
    // openssl genpkey -algorithm x25519 -outform DER -out test_x25519.der
    static X_DER_PRIV: &[u8] = include_bytes!("../../samples/test_x25519.der");
    // openssl pkey -outform DER -pubout -in test_x25519.der -inform DER -out test_x25519_pub.der
    static X_DER_PUB: &[u8] = include_bytes!("../../samples/test_x25519_pub.der");

    // openssl genpkey -algorithm ed25519 -outform DER -out test_ed25519.der
    static ED_DER_PRIV: &[u8] = include_bytes!("../../samples/test_ed25519.der");
    // openssl pkey -outform DER -pubout -in test_ed25519.der -inform DER -out test_ed25519_pub.der
    static ED_DER_PUB: &[u8] = include_bytes!("../../samples/test_ed25519_pub.der");

    // openssl pkey -in test_ed25519_pub.der -inform DER -pubin -out test_ed25519_pub.pem -outform PEM -pubout
    static PEM_PUB: &[u8] = include_bytes!("../../samples/test_ed25519_pub.pem");
    // openssl pkey -in test_ed25519.der -inform DER -out test_ed25519.pem -outform PEM
    static PEM_PRIV: &[u8] = include_bytes!("../../samples/test_ed25519.pem");

    // Many[0] is PEM_PUB
    static PEM_PUB_MANY: &[u8] = include_bytes!("../../samples/test_25519_pub_many.pem");

    #[test]
    fn parse_and_check_ed_pubkeys_der() {
        let priv_key = parse_openssl_25519_privkey_der(ED_DER_PRIV).unwrap();
        let pub_key = parse_openssl_25519_pubkey_der(ED_DER_PUB).unwrap();
        let computed_pub_key = PublicKey::from(&priv_key);
        assert_eq!(pub_key.as_bytes().len(), 32);
        assert_eq!(priv_key.to_bytes().len(), 32);
        assert_eq!(computed_pub_key.as_bytes(), pub_key.as_bytes());
    }

    #[test]
    fn parse_and_check_x_pubkeys_der() {
        let priv_key = parse_openssl_25519_privkey_der(X_DER_PRIV).unwrap();
        let pub_key = parse_openssl_25519_pubkey_der(X_DER_PUB).unwrap();
        let computed_pub_key = PublicKey::from(&priv_key);
        assert_eq!(pub_key.as_bytes().len(), 32);
        assert_eq!(priv_key.to_bytes().len(), 32);
        assert_eq!(computed_pub_key.as_bytes(), pub_key.as_bytes());
    }

    #[test]
    fn parse_and_check_pubkeys_multi_format() {
        let pub_key_pem = parse_openssl_25519_pubkey(PEM_PUB).unwrap();
        let pub_key_der = parse_openssl_25519_pubkey(ED_DER_PUB).unwrap();
        assert_eq!(pub_key_der.as_bytes().len(), 32);
        assert_eq!(pub_key_der.as_bytes(), pub_key_pem.as_bytes());
        let priv_key_pem = parse_openssl_25519_privkey(PEM_PRIV).unwrap();
        let priv_key_der = parse_openssl_25519_privkey(ED_DER_PRIV).unwrap();
        assert_eq!(priv_key_der.to_bytes().len(), 32);
        assert_eq!(priv_key_der.to_bytes(), priv_key_pem.to_bytes());
    }

    #[test]
    fn parse_many_pubkeys() {
        let pub_keys_pem = parse_openssl_25519_pubkeys_pem_many(PEM_PUB).unwrap();
        assert_eq!(pub_keys_pem.len(), 1);
        let pub_key_der = parse_openssl_25519_pubkey(ED_DER_PUB).unwrap();
        assert_eq!(pub_key_der.as_bytes().len(), 32);
        assert_eq!(pub_key_der.as_bytes(), pub_keys_pem[0].as_bytes());

        let pub_keys_pem = parse_openssl_25519_pubkeys_pem_many(PEM_PUB_MANY).unwrap();
        assert_eq!(pub_keys_pem.len(), 3);
        assert_eq!(pub_key_der.as_bytes(), pub_keys_pem[0].as_bytes());
        assert_ne!(pub_key_der.as_bytes(), pub_keys_pem[1].as_bytes());

        let pub_x_key_der = parse_openssl_25519_pubkey(X_DER_PUB).unwrap();
        assert_eq!(pub_x_key_der.as_bytes(), pub_keys_pem[2].as_bytes());
    }

    #[test]
    fn exports() {
        let mut csprng = OsRng {};
        let keypair = generate_keypair(&mut csprng).unwrap();

        let priv_key = parse_openssl_25519_privkey_der(&keypair.private_der).unwrap();
        let pub_key = parse_openssl_25519_pubkey_der(&keypair.public_der).unwrap();
        let computed_pub_key = PublicKey::from(&priv_key);
        assert_eq!(pub_key.as_bytes().len(), 32);
        assert_eq!(priv_key.to_bytes().len(), 32);
        assert_eq!(computed_pub_key.as_bytes(), pub_key.as_bytes());

        let pub_pem_key = keypair.public_as_pem();
        assert_eq!(
            parse_openssl_25519_pubkey(&pub_pem_key.as_bytes())
                .unwrap()
                .as_bytes(),
            pub_key.as_bytes()
        );
        let priv_pem_key = keypair.private_as_pem();
        assert_eq!(
            &parse_openssl_25519_privkey(&priv_pem_key.as_bytes())
                .unwrap()
                .to_bytes(),
            &priv_key.to_bytes()
        );
    }
}
