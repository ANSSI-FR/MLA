use mla::crypto::mlakey::generate_mla_keypair;
use wasm_bindgen::prelude::*;

use crate::error::WasmMlaError;

#[wasm_bindgen]
pub struct MlaKeypair {
    private_key_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
}

#[wasm_bindgen]
impl MlaKeypair {
    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key_bytes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes.clone()
    }
}

#[wasm_bindgen]
pub fn generate_keypair() -> Result<MlaKeypair, JsValue> {
    let (priv_key, pub_key) = generate_mla_keypair().map_err(WasmMlaError::from)?;

    let mut priv_bytes = Vec::new();
    priv_key
        .serialize_private_key(&mut priv_bytes)
        .map_err(WasmMlaError::from)?;

    let mut pub_bytes = Vec::new();
    pub_key
        .serialize_public_key(&mut pub_bytes)
        .map_err(WasmMlaError::from)?;

    Ok(MlaKeypair {
        private_key_bytes: priv_bytes,
        public_key_bytes: pub_bytes,
    })
}
