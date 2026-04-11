# MLA-WASM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the MLA crypto library as a WebAssembly module callable depuis JavaScript/TypeScript pour keygen, chiffrement/dechiffrement par mot de passe et par cles MLA.

**Architecture:** Un crate Rust `mla-wasm` dans le workspace existant, compilable via `wasm-pack` en WASM. Il wrappe la lib `mla` et expose une API simple via `wasm-bindgen`. Argon2id derive un seed 32 octets depuis un mot de passe pour le mode simple. Toutes les operations crypto restent cote client (zero-knowledge).

**Tech Stack:** Rust, wasm-bindgen, wasm-pack, argon2 (crate), getrandom avec feature `js` pour le CSPRNG navigateur.

**Note repo:** Ce projet est sur GitHub (origin: `Kodetis/MLA-Transfert`), donc on utilise `gh` (pas `glab`).

---

## File Structure

```
mla-wasm/
├── Cargo.toml           # Crate config, crate-type = cdylib, dependencies
├── src/
│   ├── lib.rs           # Point d'entree wasm-bindgen, re-exports
│   ├── keygen.rs        # generate_keypair() -> JsKeypair
│   ├── password.rs      # derive_keypair_from_password(), encrypt/decrypt_with_password()
│   ├── keys.rs          # encrypt/decrypt_with_keys()
│   └── error.rs         # WasmMlaError, conversion MLA errors -> JsValue
├── tests/
│   └── wasm.rs          # wasm-bindgen-test integration tests
```

**Modifications au workspace existant:**
- Modify: `Cargo.toml` (root) -- ajouter `mla-wasm` au workspace members

---

### Task 1: Creer le crate mla-wasm et configurer le workspace

**Files:**
- Modify: `Cargo.toml:2` (workspace root, ajouter member)
- Create: `mla-wasm/Cargo.toml`
- Create: `mla-wasm/src/lib.rs`
- Create: `mla-wasm/src/error.rs`

- [ ] **Step 1: Ajouter mla-wasm au workspace**

Dans `Cargo.toml` (racine), ajouter `"mla-wasm"` aux members :

```toml
[workspace]
members = [
    "mla",
    "mla-fuzz-afl",
    "mlar",
    "mlar/mlar-upgrader",
    "bindings/C",
    "mla-wasm",
]
```

- [ ] **Step 2: Creer mla-wasm/Cargo.toml**

```toml
[package]
name = "mla-wasm"
version = "0.1.0"
edition = "2024"
license = "LGPL-3.0-only"
description = "WebAssembly bindings for the MLA archive library"
publish = false

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
mla = { path = "../mla" }
wasm-bindgen = "0.2"
js-sys = "0.3"
argon2 = { version = "0.5", default-features = false, features = ["alloc"] }
getrandom = { version = "0.2", features = ["js"] }
serde = { version = "1", features = ["derive"] }
serde-wasm-bindgen = "0.6"

[dev-dependencies]
wasm-bindgen-test = "0.3"

[lints]
workspace = true
```

- [ ] **Step 3: Creer mla-wasm/src/error.rs**

```rust
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
```

- [ ] **Step 4: Creer mla-wasm/src/lib.rs (squelette)**

```rust
mod error;
mod keygen;
mod keys;
mod password;
```

- [ ] **Step 5: Verifier que le workspace compile**

Run: `cargo check -p mla-wasm`
Expected: compilation OK (warnings acceptables, pas d'erreurs)

- [ ] **Step 6: Commit**

```bash
git add mla-wasm/ Cargo.toml
git commit -m "feat(mla-wasm): scaffold WASM crate with error handling"
```

---

### Task 2: Keygen -- generer une paire de cles MLA

**Files:**
- Create: `mla-wasm/src/keygen.rs`
- Modify: `mla-wasm/src/lib.rs` (ajouter re-export)

- [ ] **Step 1: Ecrire le test WASM pour keygen**

Creer `mla-wasm/tests/wasm.rs` :

```rust
#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

use mla_wasm::generate_keypair;

#[wasm_bindgen_test]
fn test_generate_keypair_returns_keys() {
    let result = generate_keypair();
    assert!(result.is_ok(), "keygen should succeed");
    let keypair = result.unwrap();

    // Les cles doivent etre non-vides
    let priv_key: Vec<u8> = keypair.private_key();
    let pub_key: Vec<u8> = keypair.public_key();
    assert!(!priv_key.is_empty(), "private key should not be empty");
    assert!(!pub_key.is_empty(), "public key should not be empty");
}

#[wasm_bindgen_test]
fn test_generate_keypair_unique() {
    let kp1 = generate_keypair().unwrap();
    let kp2 = generate_keypair().unwrap();
    assert_ne!(
        kp1.private_key(),
        kp2.private_key(),
        "two keypairs should be different"
    );
}
```

- [ ] **Step 2: Implementer keygen.rs**

Creer `mla-wasm/src/keygen.rs` :

```rust
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
    let (priv_key, pub_key) =
        generate_mla_keypair().map_err(WasmMlaError::from)?;

    let mut priv_bytes = Vec::new();
    priv_key
        .serialize_private_key(&mut priv_bytes)
        .map_err(|e| WasmMlaError::from(std::io::Error::other(format!("{e:?}"))))?;

    let mut pub_bytes = Vec::new();
    pub_key
        .serialize_public_key(&mut pub_bytes)
        .map_err(|e| WasmMlaError::from(std::io::Error::other(format!("{e:?}"))))?;

    Ok(MlaKeypair {
        private_key_bytes: priv_bytes,
        public_key_bytes: pub_bytes,
    })
}
```

- [ ] **Step 3: Mettre a jour lib.rs**

```rust
mod error;

pub mod keygen;
mod keys;
mod password;

pub use keygen::{MlaKeypair, generate_keypair};
```

- [ ] **Step 4: Verifier la compilation native**

Run: `cargo check -p mla-wasm`
Expected: OK

- [ ] **Step 5: Lancer les tests WASM**

Run: `wasm-pack test --node mla-wasm`
Expected: 2 tests passent (test_generate_keypair_returns_keys, test_generate_keypair_unique)

Note: si `wasm-pack` n'est pas installe, lancer d'abord : `cargo install wasm-pack`

- [ ] **Step 6: Commit**

```bash
git add mla-wasm/src/keygen.rs mla-wasm/src/lib.rs mla-wasm/tests/
git commit -m "feat(mla-wasm): expose generate_keypair via wasm-bindgen"
```

---

### Task 3: Mode mot de passe -- derivation Argon2 et chiffrement

**Files:**
- Create: `mla-wasm/src/password.rs`
- Modify: `mla-wasm/src/lib.rs` (ajouter re-export)
- Modify: `mla-wasm/tests/wasm.rs` (ajouter tests)

- [ ] **Step 1: Ecrire les tests pour le mode mot de passe**

Ajouter dans `mla-wasm/tests/wasm.rs` :

```rust
use mla_wasm::{decrypt_with_password, encrypt_with_password};

#[wasm_bindgen_test]
fn test_encrypt_decrypt_password_roundtrip() {
    let file_name = "test.txt";
    let file_data: Vec<u8> = b"Hello, MLA!".to_vec();
    let password = "my-secret-password";

    let encrypted = encrypt_with_password(
        vec![file_name.to_string()],
        vec![file_data.clone()],
        password,
    )
    .expect("encryption should succeed");

    assert!(!encrypted.is_empty(), "encrypted data should not be empty");
    assert_ne!(encrypted, file_data, "encrypted should differ from plaintext");

    let decrypted = decrypt_with_password(&encrypted, password)
        .expect("decryption should succeed");

    // decrypted is a JsValue containing a Map of filename -> Uint8Array
    // We verify via serde-wasm-bindgen
    let entries: Vec<(String, Vec<u8>)> = serde_wasm_bindgen::from_value(decrypted)
        .expect("should deserialize to Vec<(String, Vec<u8>)>");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, file_name);
    assert_eq!(entries[0].1, file_data);
}

#[wasm_bindgen_test]
fn test_wrong_password_fails() {
    let encrypted = encrypt_with_password(
        vec!["test.txt".to_string()],
        vec![b"data".to_vec()],
        "correct-password",
    )
    .unwrap();

    let result = decrypt_with_password(&encrypted, "wrong-password");
    assert!(result.is_err(), "wrong password should fail decryption");
}
```

- [ ] **Step 2: Implementer password.rs**

Creer `mla-wasm/src/password.rs` :

```rust
use std::io::Cursor;

use argon2::Argon2;
use mla::config::{ArchiveReaderConfig, ArchiveWriterConfig};
use mla::crypto::mlakey::{generate_mla_keypair_from_seed, MLAPrivateKey, MLAPublicKey};
use mla::entry::EntryName;
use mla::{ArchiveReader, ArchiveWriter};
use wasm_bindgen::prelude::*;

use crate::error::WasmMlaError;

/// Salt fixe pour la derivation Argon2 en mode mot de passe.
/// En mode mot de passe, l'expediteur et le destinataire doivent deriver
/// la meme cle a partir du meme mot de passe. Le salt est donc fixe
/// et public -- la securite repose entierement sur le mot de passe.
const PASSWORD_SALT: &[u8; 16] = b"MLA-Transfert!!\0";

/// Derive une paire de cles MLA a partir d'un mot de passe via Argon2id
fn derive_keypair_from_password(
    password: &str,
) -> Result<(MLAPrivateKey, MLAPublicKey), WasmMlaError> {
    let mut seed = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), PASSWORD_SALT, &mut seed)
        .map_err(|e| WasmMlaError::from(std::io::Error::other(format!("Argon2 error: {e}"))))?;

    Ok(generate_mla_keypair_from_seed(seed))
}

#[wasm_bindgen]
pub fn encrypt_with_password(
    file_names: Vec<String>,
    file_contents: Vec<Vec<u8>>,
    password: &str,
) -> Result<Vec<u8>, JsValue> {
    if file_names.len() != file_contents.len() {
        return Err(JsValue::from_str("file_names and file_contents must have the same length"));
    }

    let (priv_key, pub_key) = derive_keypair_from_password(password)
        .map_err(JsValue::from)?;

    let (_dec_key, enc_key) = pub_key.get_public_keys();
    let (_dec_priv, sig_key) = priv_key.get_private_keys();

    let mut output = Vec::new();
    let config = ArchiveWriterConfig::with_encryption_with_signature(&[enc_key], &[sig_key])
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?;

    let mut archive = ArchiveWriter::from_config(&mut output, config)
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?;

    for (name, data) in file_names.iter().zip(file_contents.iter()) {
        let entry_name = EntryName::from_path(name)
            .map_err(|e| JsValue::from_str(&format!("Invalid entry name: {e:?}")))?;
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

#[wasm_bindgen]
pub fn decrypt_with_password(
    mla_data: &[u8],
    password: &str,
) -> Result<JsValue, JsValue> {
    let (priv_key, pub_key) = derive_keypair_from_password(password)
        .map_err(JsValue::from)?;

    let (dec_key, _sig_key) = priv_key.get_private_keys();
    let (_enc_key, verif_key) = pub_key.get_public_keys();

    let config = ArchiveReaderConfig::with_signature_verification(&[verif_key])
        .with_encryption(&[dec_key]);

    let mut cursor = Cursor::new(mla_data);
    let mut archive = ArchiveReader::from_config(&mut cursor, config)
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?;

    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();

    let file_list: Vec<String> = archive
        .list_files()
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?
        .cloned()
        .map(|name| name.raw_content_to_escaped_string())
        .collect();

    for file_name in &file_list {
        let entry_name = EntryName::from_path(file_name)
            .map_err(|e| JsValue::from_str(&format!("Invalid entry name: {e:?}")))?;
        let mut entry = archive
            .get_entry(&entry_name)
            .map_err(WasmMlaError::from)
            .map_err(JsValue::from)?
            .ok_or_else(|| JsValue::from_str(&format!("Entry not found: {file_name}")))?;
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut entry.data, &mut data)
            .map_err(WasmMlaError::from)
            .map_err(JsValue::from)?;
        entries.push((file_name.clone(), data));
    }

    serde_wasm_bindgen::to_value(&entries)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}
```

- [ ] **Step 3: Mettre a jour lib.rs**

```rust
mod error;

pub mod keygen;
mod keys;
pub mod password;

pub use keygen::{MlaKeypair, generate_keypair};
pub use password::{decrypt_with_password, encrypt_with_password};
```

- [ ] **Step 4: Verifier la compilation**

Run: `cargo check -p mla-wasm`
Expected: OK

- [ ] **Step 5: Lancer les tests WASM**

Run: `wasm-pack test --node mla-wasm`
Expected: 4 tests passent (2 keygen + 2 password)

- [ ] **Step 6: Commit**

```bash
git add mla-wasm/src/password.rs mla-wasm/src/lib.rs mla-wasm/tests/wasm.rs
git commit -m "feat(mla-wasm): add password-based encrypt/decrypt with Argon2id derivation"
```

---

### Task 4: Mode avance -- chiffrement/dechiffrement avec cles MLA

**Files:**
- Create: `mla-wasm/src/keys.rs`
- Modify: `mla-wasm/src/lib.rs` (ajouter re-export)
- Modify: `mla-wasm/tests/wasm.rs` (ajouter tests)

- [ ] **Step 1: Ecrire les tests pour le mode cles**

Ajouter dans `mla-wasm/tests/wasm.rs` :

```rust
use mla_wasm::{decrypt_with_keys, encrypt_with_keys, generate_keypair};

#[wasm_bindgen_test]
fn test_encrypt_decrypt_keys_roundtrip() {
    let sender = generate_keypair().unwrap();
    let receiver = generate_keypair().unwrap();

    let file_name = "secret.pdf";
    let file_data: Vec<u8> = b"PDF content here".to_vec();

    let encrypted = encrypt_with_keys(
        vec![file_name.to_string()],
        vec![file_data.clone()],
        &sender.private_key(),   // sender signe
        &receiver.public_key(),  // receiver dechiffre
    )
    .expect("encryption should succeed");

    let decrypted = decrypt_with_keys(
        &encrypted,
        &receiver.private_key(), // receiver dechiffre
        &sender.public_key(),    // verifie signature sender
    )
    .expect("decryption should succeed");

    let entries: Vec<(String, Vec<u8>)> = serde_wasm_bindgen::from_value(decrypted).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, file_name);
    assert_eq!(entries[0].1, file_data);
}

#[wasm_bindgen_test]
fn test_wrong_key_fails_decryption() {
    let sender = generate_keypair().unwrap();
    let receiver = generate_keypair().unwrap();
    let wrong_receiver = generate_keypair().unwrap();

    let encrypted = encrypt_with_keys(
        vec!["test.txt".to_string()],
        vec![b"data".to_vec()],
        &sender.private_key(),
        &receiver.public_key(),
    )
    .unwrap();

    // Tenter de dechiffrer avec la mauvaise cle privee
    let result = decrypt_with_keys(
        &encrypted,
        &wrong_receiver.private_key(),
        &sender.public_key(),
    );
    assert!(result.is_err(), "wrong key should fail");
}

#[wasm_bindgen_test]
fn test_multiple_files() {
    let sender = generate_keypair().unwrap();
    let receiver = generate_keypair().unwrap();

    let names = vec!["a.txt".to_string(), "b.txt".to_string()];
    let contents = vec![b"content a".to_vec(), b"content b".to_vec()];

    let encrypted = encrypt_with_keys(
        names.clone(),
        contents.clone(),
        &sender.private_key(),
        &receiver.public_key(),
    )
    .unwrap();

    let decrypted = decrypt_with_keys(
        &encrypted,
        &receiver.private_key(),
        &sender.public_key(),
    )
    .unwrap();

    let entries: Vec<(String, Vec<u8>)> = serde_wasm_bindgen::from_value(decrypted).unwrap();
    assert_eq!(entries.len(), 2);
}
```

- [ ] **Step 2: Implementer keys.rs**

Creer `mla-wasm/src/keys.rs` :

```rust
use std::io::Cursor;

use mla::config::{ArchiveReaderConfig, ArchiveWriterConfig};
use mla::crypto::mlakey::{MLAPrivateKey, MLAPublicKey};
use mla::entry::EntryName;
use mla::{ArchiveReader, ArchiveWriter};
use wasm_bindgen::prelude::*;

use crate::error::WasmMlaError;

#[wasm_bindgen]
pub fn encrypt_with_keys(
    file_names: Vec<String>,
    file_contents: Vec<Vec<u8>>,
    sender_private_key: &[u8],
    receiver_public_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if file_names.len() != file_contents.len() {
        return Err(JsValue::from_str(
            "file_names and file_contents must have the same length",
        ));
    }

    let sender_priv = MLAPrivateKey::deserialize_private_key(sender_private_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid sender private key: {e:?}")))?;
    let receiver_pub = MLAPublicKey::deserialize_public_key(receiver_public_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid receiver public key: {e:?}")))?;

    let (_dec_key, enc_key) = receiver_pub.get_public_keys();
    let (_dec_priv, sig_key) = sender_priv.get_private_keys();

    let mut output = Vec::new();
    let config = ArchiveWriterConfig::with_encryption_with_signature(&[enc_key], &[sig_key])
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?;

    let mut archive = ArchiveWriter::from_config(&mut output, config)
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?;

    for (name, data) in file_names.iter().zip(file_contents.iter()) {
        let entry_name = EntryName::from_path(name)
            .map_err(|e| JsValue::from_str(&format!("Invalid entry name: {e:?}")))?;
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

#[wasm_bindgen]
pub fn decrypt_with_keys(
    mla_data: &[u8],
    receiver_private_key: &[u8],
    sender_public_key: &[u8],
) -> Result<JsValue, JsValue> {
    let receiver_priv = MLAPrivateKey::deserialize_private_key(receiver_private_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid receiver private key: {e:?}")))?;
    let sender_pub = MLAPublicKey::deserialize_public_key(sender_public_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid sender public key: {e:?}")))?;

    let (dec_key, _sig_key) = receiver_priv.get_private_keys();
    let (_enc_key, verif_key) = sender_pub.get_public_keys();

    let config = ArchiveReaderConfig::with_signature_verification(&[verif_key])
        .with_encryption(&[dec_key]);

    let mut cursor = Cursor::new(mla_data);
    let mut archive = ArchiveReader::from_config(&mut cursor, config)
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?;

    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();

    let file_list: Vec<String> = archive
        .list_files()
        .map_err(WasmMlaError::from)
        .map_err(JsValue::from)?
        .cloned()
        .map(|name| name.raw_content_to_escaped_string())
        .collect();

    for file_name in &file_list {
        let entry_name = EntryName::from_path(file_name)
            .map_err(|e| JsValue::from_str(&format!("Invalid entry name: {e:?}")))?;
        let mut entry = archive
            .get_entry(&entry_name)
            .map_err(WasmMlaError::from)
            .map_err(JsValue::from)?
            .ok_or_else(|| JsValue::from_str(&format!("Entry not found: {file_name}")))?;
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut entry.data, &mut data)
            .map_err(WasmMlaError::from)
            .map_err(JsValue::from)?;
        entries.push((file_name.clone(), data));
    }

    serde_wasm_bindgen::to_value(&entries)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}
```

- [ ] **Step 3: Mettre a jour lib.rs**

```rust
mod error;

pub mod keygen;
pub mod keys;
pub mod password;

pub use keygen::{MlaKeypair, generate_keypair};
pub use keys::{decrypt_with_keys, encrypt_with_keys};
pub use password::{decrypt_with_password, encrypt_with_password};
```

- [ ] **Step 4: Verifier la compilation**

Run: `cargo check -p mla-wasm`
Expected: OK

- [ ] **Step 5: Lancer les tests WASM**

Run: `wasm-pack test --node mla-wasm`
Expected: 7 tests passent (2 keygen + 2 password + 3 keys)

- [ ] **Step 6: Commit**

```bash
git add mla-wasm/src/keys.rs mla-wasm/src/lib.rs mla-wasm/tests/wasm.rs
git commit -m "feat(mla-wasm): add key-based encrypt/decrypt with signature verification"
```

---

### Task 5: Build WASM et verification integration

**Files:**
- Aucun nouveau fichier

- [ ] **Step 1: Build le package WASM**

Run: `wasm-pack build mla-wasm --target web --out-dir pkg`
Expected: build OK, fichiers generes dans `mla-wasm/pkg/` :
- `mla_wasm_bg.wasm`
- `mla_wasm.js`
- `mla_wasm.d.ts` (types TypeScript auto-generes)
- `package.json`

- [ ] **Step 2: Verifier les types TypeScript generes**

Run: `cat mla-wasm/pkg/mla_wasm.d.ts`
Expected: declarations pour `generate_keypair`, `encrypt_with_password`, `decrypt_with_password`, `encrypt_with_keys`, `decrypt_with_keys`, `MlaKeypair`

- [ ] **Step 3: Lancer tous les tests une derniere fois**

Run: `wasm-pack test --node mla-wasm`
Expected: 7 tests passent

- [ ] **Step 4: Commit**

```bash
git commit -m "build(mla-wasm): verify WASM build and TypeScript bindings generation"
```

---

## API TypeScript resultante

Apres build, le frontend pourra importer :

```typescript
import init, {
  generate_keypair,
  encrypt_with_password,
  decrypt_with_password,
  encrypt_with_keys,
  decrypt_with_keys,
  MlaKeypair,
} from 'mla-wasm';

// Initialiser le module WASM
await init();

// Mode simple
const encrypted = encrypt_with_password(["doc.pdf"], [fileBytes], "password123");
const entries = decrypt_with_password(encrypted, "password123");

// Mode avance
const keypair = generate_keypair();
const encrypted = encrypt_with_keys(["doc.pdf"], [fileBytes], senderPrivKey, receiverPubKey);
const entries = decrypt_with_keys(encrypted, receiverPrivKey, senderPubKey);
```

---

## Prochains plans (a ecrire apres completion de celui-ci)

1. **mla-transfert-server** -- backend Axum (upload/download relay, signaling WebRTC, expiration)
2. **mla-transfert-web** -- frontend Astro+React+Tailwind (UI, integration WASM, P2P)
3. **V2 : client lourd Tauri** -- meme UI, crypto native Rust
