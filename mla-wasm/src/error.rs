use wasm_bindgen::JsValue;

#[derive(Debug)]
pub struct WasmMlaError(String);

impl From<mla::errors::Error> for WasmMlaError {
    fn from(e: mla::errors::Error) -> Self {
        Self(format!("MLA error: {e:?}"))
    }
}

impl From<mla::errors::ConfigError> for WasmMlaError {
    fn from(e: mla::errors::ConfigError) -> Self {
        Self(format!("MLA config error: {e:?}"))
    }
}

impl From<std::io::Error> for WasmMlaError {
    fn from(e: std::io::Error) -> Self {
        Self(format!("IO error: {e}"))
    }
}

impl From<WasmMlaError> for JsValue {
    fn from(e: WasmMlaError) -> Self {
        JsValue::from_str(&e.0)
    }
}
