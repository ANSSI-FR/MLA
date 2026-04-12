use wasm_bindgen::JsValue;

#[derive(Debug)]
pub struct WasmMlaError(String);

// All conversion impls use generic messages at the WASM boundary.
// Leaking internal error variants (wrong password vs. corrupted data vs. key
// mismatch) would create a distinguishing oracle that attackers could exploit.

impl From<mla::errors::Error> for WasmMlaError {
    fn from(_: mla::errors::Error) -> Self {
        Self("Decryption failed".to_string())
    }
}

impl From<mla::errors::ConfigError> for WasmMlaError {
    fn from(_: mla::errors::ConfigError) -> Self {
        Self("Decryption failed".to_string())
    }
}

impl From<std::io::Error> for WasmMlaError {
    fn from(_: std::io::Error) -> Self {
        Self("Decryption failed".to_string())
    }
}

impl From<WasmMlaError> for JsValue {
    fn from(e: WasmMlaError) -> Self {
        JsValue::from_str(&e.0)
    }
}
