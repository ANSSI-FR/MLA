use std::io::Cursor;

use mla::config::{ArchiveReaderConfig, ArchiveWriterConfig};
use mla::crypto::mlakey::{MLAPrivateKey, MLAPublicKey};
use mla::entry::EntryName;
use mla::{ArchiveReader, ArchiveWriter};
use wasm_bindgen::prelude::*;

use crate::error::WasmMlaError;

/// Core encryption logic operating on native Rust types.
fn encrypt_with_keys_impl(
    file_names: &[String],
    file_contents: &[Vec<u8>],
    sender_private_key: &[u8],
    receiver_public_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if file_names.len() != file_contents.len() {
        return Err(JsValue::from_str(
            "file_names and file_contents must have the same length",
        ));
    }

    let sender_priv = MLAPrivateKey::deserialize_private_key(Cursor::new(sender_private_key))
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?;
    let receiver_pub = MLAPublicKey::deserialize_public_key(Cursor::new(receiver_public_key))
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?;

    let (enc_key, _verif_key) = receiver_pub.get_public_keys();
    let (_dec_key, sig_key) = sender_priv.get_private_keys();

    let mut output = Vec::new();
    let config = ArchiveWriterConfig::with_encryption_with_signature(&[enc_key], &[sig_key])
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?;

    let mut archive = ArchiveWriter::from_config(&mut output, config)
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
    Ok(output)
}

/// Encrypt files into an MLA archive using sender's private key and receiver's public key.
///
/// `file_names` is a JS array of strings, `file_contents` is a JS array of `Uint8Array`.
/// `sender_private_key` and `receiver_public_key` are serialized MLA key bytes.
#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)] // wasm_bindgen requires owned types
pub fn encrypt_with_keys(
    file_names: Vec<String>,
    file_contents: js_sys::Array,
    sender_private_key: &[u8],
    receiver_public_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let contents: Vec<Vec<u8>> = file_contents
        .iter()
        .map(|val| js_sys::Uint8Array::new(&val).to_vec())
        .collect();
    encrypt_with_keys_impl(
        &file_names,
        &contents,
        sender_private_key,
        receiver_public_key,
    )
}

/// Core decryption logic operating on native Rust types.
fn decrypt_with_keys_impl(
    mla_data: &[u8],
    receiver_private_key: &[u8],
    sender_public_key: &[u8],
) -> Result<Vec<(String, Vec<u8>)>, JsValue> {
    let receiver_priv = MLAPrivateKey::deserialize_private_key(Cursor::new(receiver_private_key))
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?;
    let sender_pub = MLAPublicKey::deserialize_public_key(Cursor::new(sender_public_key))
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?;

    let (dec_key, _sig_key) = receiver_priv.get_private_keys();
    let (_enc_key, verif_key) = sender_pub.get_public_keys();

    let config =
        ArchiveReaderConfig::with_signature_verification(&[verif_key]).with_encryption(&[dec_key]);

    let cursor = Cursor::new(mla_data);
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

/// Decrypt an MLA archive using receiver's private key and sender's public key.
///
/// Returns a `JsValue` containing a `Vec<(String, Vec<u8>)>` of file entries.
#[wasm_bindgen]
pub fn decrypt_with_keys(
    mla_data: &[u8],
    receiver_private_key: &[u8],
    sender_public_key: &[u8],
) -> Result<JsValue, JsValue> {
    let entries = decrypt_with_keys_impl(mla_data, receiver_private_key, sender_public_key)?;
    serde_wasm_bindgen::to_value(&entries)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}
