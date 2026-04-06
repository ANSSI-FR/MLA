#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

use mla_wasm::{decrypt_with_password, encrypt_with_password, generate_keypair};

#[wasm_bindgen_test]
fn test_generate_keypair_returns_keys() {
    let result = generate_keypair();
    assert!(result.is_ok(), "keygen should succeed");
    let keypair = result.unwrap();

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

/// Helper to build a JS array of `Uint8Array` from Rust byte slices.
fn make_js_file_contents(contents: &[&[u8]]) -> js_sys::Array {
    let arr = js_sys::Array::new();
    for data in contents {
        let uint8 = js_sys::Uint8Array::new_with_length(data.len() as u32);
        uint8.copy_from(data);
        arr.push(&uint8.into());
    }
    arr
}

#[wasm_bindgen_test]
fn test_encrypt_decrypt_password_roundtrip() {
    let file_name = "test.txt";
    let file_data: &[u8] = b"Hello, MLA!";
    let password = "my-secret-password";

    let file_contents = make_js_file_contents(&[file_data]);

    let encrypted = encrypt_with_password(
        vec![file_name.to_string()],
        file_contents,
        password,
    )
    .expect("encryption should succeed");

    assert!(!encrypted.is_empty(), "encrypted data should not be empty");
    assert_ne!(
        encrypted,
        file_data.to_vec(),
        "encrypted should differ from plaintext"
    );

    let decrypted =
        decrypt_with_password(&encrypted, password).expect("decryption should succeed");

    let entries: Vec<(String, Vec<u8>)> = serde_wasm_bindgen::from_value(decrypted)
        .expect("should deserialize to Vec<(String, Vec<u8>)>");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, file_name);
    assert_eq!(entries[0].1, file_data);
}

#[wasm_bindgen_test]
fn test_wrong_password_fails() {
    let file_contents = make_js_file_contents(&[b"data"]);

    let encrypted = encrypt_with_password(
        vec!["test.txt".to_string()],
        file_contents,
        "correct-password",
    )
    .unwrap();

    let result = decrypt_with_password(&encrypted, "wrong-password");
    assert!(result.is_err(), "wrong password should fail decryption");
}
