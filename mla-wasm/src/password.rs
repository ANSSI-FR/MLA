use std::io::Cursor;

use argon2::{Algorithm, Argon2, Params, Version};
use mla::config::{ArchiveReaderConfig, ArchiveWriterConfig};
use mla::crypto::mlakey::generate_mla_keypair_from_seed;
use mla::entry::EntryName;
use mla::{ArchiveReader, ArchiveWriter};
use wasm_bindgen::prelude::*;

use crate::error::WasmMlaError;

/// Longueur du salt aléatoire préfixé au ciphertext (en octets).
const SALT_LEN: usize = 16;

/// Dérive une paire de clés MLA depuis un mot de passe et un salt via Argon2id.
///
/// Le salt est généré aléatoirement à chaque chiffrement et stocké en clair
/// en préfixe du ciphertext. Il n'est pas secret : la sécurité repose sur
/// la robustesse du mot de passe et le coût d'Argon2id.
fn derive_keypair_from_password(
    password: &str,
    salt: &[u8],
) -> Result<
    (
        mla::crypto::mlakey::MLAPrivateKey,
        mla::crypto::mlakey::MLAPublicKey,
    ),
    WasmMlaError,
> {
    // time_cost=3, memory_cost=64 MiB (65536 KB), parallelism=4 — ANSSI/OWASP recommendation
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| WasmMlaError::from(std::io::Error::other(format!("Argon2 params: {e}"))))?;
    let mut seed = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut seed)
        .map_err(|e| WasmMlaError::from(std::io::Error::other(format!("Argon2 error: {e}"))))?;
    Ok(generate_mla_keypair_from_seed(seed))
}

/// Core encryption logic operating on native Rust types.
fn encrypt_with_password_impl(
    file_names: &[String],
    file_contents: &[Vec<u8>],
    password: &str,
) -> Result<Vec<u8>, JsValue> {
    if file_names.len() != file_contents.len() {
        return Err(JsValue::from_str(
            "file_names and file_contents must have the same length",
        ));
    }

    // Générer un salt aléatoire unique pour ce transfert
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| JsValue::from_str(&format!("RNG error: {e}")))?;

    let (priv_key, pub_key) =
        derive_keypair_from_password(password, &salt).map_err(JsValue::from)?;
    let (enc_key, _verif_key) = pub_key.get_public_keys();
    let (_dec_key, sig_key) = priv_key.get_private_keys();

    let mut mla_bytes = Vec::new();
    let config = ArchiveWriterConfig::with_encryption_with_signature(&[enc_key], &[sig_key])
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?;

    let mut archive = ArchiveWriter::from_config(&mut mla_bytes, config)
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?;

    for (name, data) in file_names.iter().zip(file_contents.iter()) {
        let entry_name =
            EntryName::from_path(name).map_err(|_| JsValue::from_str("Decryption failed"))?;
        archive
            .add_entry(entry_name, data.len() as u64, &data[..])
            .map_err(WasmMlaError::from)
            .map_err(JsValue::from)?;
    }

    archive
        .finalize()
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?;

    // Format de sortie : [salt (16 octets)] || [ciphertext MLA]
    let mut output = Vec::with_capacity(SALT_LEN.saturating_add(mla_bytes.len()));
    output.extend_from_slice(&salt);
    output.extend(mla_bytes);
    Ok(output)
}

/// Encrypt files into an MLA archive using a password.
///
/// A fresh random 16-byte salt is generated for each call and prepended to
/// the returned bytes. The API is unchanged: callers receive an opaque
/// `Uint8Array` that `decrypt_with_password` knows how to parse.
#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)] // wasm_bindgen requires owned types
pub fn encrypt_with_password(
    file_names: Vec<String>,
    file_contents: js_sys::Array,
    password: &str,
) -> Result<Vec<u8>, JsValue> {
    let contents: Vec<Vec<u8>> = file_contents
        .iter()
        .map(|val| js_sys::Uint8Array::new(&val).to_vec())
        .collect();
    encrypt_with_password_impl(&file_names, &contents, password)
}

/// Core decryption logic operating on native Rust types.
fn decrypt_with_password_impl(
    mla_data: &[u8],
    password: &str,
) -> Result<Vec<(String, Vec<u8>)>, JsValue> {
    // Lire le salt depuis les 16 premiers octets
    if mla_data.len() < SALT_LEN {
        return Err(JsValue::from_str("Decryption failed"));
    }
    let (salt, ciphertext) = mla_data.split_at(SALT_LEN);

    let (priv_key, pub_key) =
        derive_keypair_from_password(password, salt).map_err(JsValue::from)?;
    let (dec_key, _sig_key) = priv_key.get_private_keys();
    let (_enc_key, verif_key) = pub_key.get_public_keys();

    let config =
        ArchiveReaderConfig::with_signature_verification(&[verif_key]).with_encryption(&[dec_key]);

    let cursor = Cursor::new(ciphertext);
    let (mut archive, _signers) = ArchiveReader::from_config(cursor, config)
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?;

    let file_list: Vec<EntryName> = archive
        .list_entries()
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?
        .cloned()
        .collect();

    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();

    for entry_name in file_list {
        let display_name = entry_name.raw_content_to_escaped_string();
        let mut entry = archive
            .get_entry(entry_name)
            .map_err(WasmMlaError::from)
            .map_err(JsValue::from)?
            .ok_or_else(|| JsValue::from_str("Decryption failed"))?;
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut entry.data, &mut data)
            .map_err(WasmMlaError::from)
            .map_err(JsValue::from)?;
        entries.push((display_name, data));
    }

    Ok(entries)
}

/// Decrypt an MLA archive using a password.
///
/// Expects the first 16 bytes to be the Argon2id salt generated during
/// encryption. Returns a `JsValue` containing a `Vec<(String, Vec<u8>)>`.
#[wasm_bindgen]
pub fn decrypt_with_password(mla_data: &[u8], password: &str) -> Result<JsValue, JsValue> {
    let entries = decrypt_with_password_impl(mla_data, password)?;
    serde_wasm_bindgen::to_value(&entries)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}
