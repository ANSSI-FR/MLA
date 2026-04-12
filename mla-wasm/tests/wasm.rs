#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

use mla_wasm::{
    decrypt_with_keys, decrypt_with_password, encrypt_with_keys, encrypt_with_password,
    generate_keypair,
};

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

    let encrypted = encrypt_with_password(vec![file_name.to_string()], file_contents, password)
        .expect("encryption should succeed");

    assert!(!encrypted.is_empty(), "encrypted data should not be empty");
    assert_ne!(
        encrypted,
        file_data.to_vec(),
        "encrypted should differ from plaintext"
    );

    let decrypted = decrypt_with_password(&encrypted, password).expect("decryption should succeed");

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

#[wasm_bindgen_test]
fn test_encrypt_decrypt_keys_roundtrip() {
    let sender = generate_keypair().unwrap();
    let receiver = generate_keypair().unwrap();

    let file_name = "secret.txt";
    let file_data: &[u8] = b"Hello from key-based encryption!";
    let file_contents = make_js_file_contents(&[file_data]);

    let encrypted = encrypt_with_keys(
        vec![file_name.to_string()],
        file_contents,
        &sender.private_key(),
        &receiver.public_key(),
    )
    .expect("encryption should succeed");

    assert!(!encrypted.is_empty(), "encrypted data should not be empty");

    let decrypted = decrypt_with_keys(&encrypted, &receiver.private_key(), &sender.public_key())
        .expect("decryption should succeed");

    let entries: Vec<(String, Vec<u8>)> = serde_wasm_bindgen::from_value(decrypted)
        .expect("should deserialize to Vec<(String, Vec<u8>)>");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, file_name);
    assert_eq!(entries[0].1, file_data);
}

#[wasm_bindgen_test]
fn test_wrong_key_fails_decryption() {
    let sender = generate_keypair().unwrap();
    let receiver_a = generate_keypair().unwrap();
    let receiver_b = generate_keypair().unwrap();

    let file_contents = make_js_file_contents(&[b"confidential"]);

    let encrypted = encrypt_with_keys(
        vec!["test.txt".to_string()],
        file_contents,
        &sender.private_key(),
        &receiver_a.public_key(),
    )
    .unwrap();

    // Try to decrypt with receiver B's private key -- should fail
    let result = decrypt_with_keys(&encrypted, &receiver_b.private_key(), &sender.public_key());
    assert!(result.is_err(), "wrong receiver key should fail decryption");
}

#[wasm_bindgen_test]
fn test_multiple_files() {
    let sender = generate_keypair().unwrap();
    let receiver = generate_keypair().unwrap();

    let names = vec!["file1.txt".to_string(), "file2.bin".to_string()];
    let data1: &[u8] = b"First file content";
    let data2: &[u8] = b"Second file content";
    let file_contents = make_js_file_contents(&[data1, data2]);

    let encrypted = encrypt_with_keys(
        names.clone(),
        file_contents,
        &sender.private_key(),
        &receiver.public_key(),
    )
    .expect("encryption should succeed");

    let decrypted = decrypt_with_keys(&encrypted, &receiver.private_key(), &sender.public_key())
        .expect("decryption should succeed");

    let entries: Vec<(String, Vec<u8>)> = serde_wasm_bindgen::from_value(decrypted)
        .expect("should deserialize to Vec<(String, Vec<u8>)>");
    assert_eq!(entries.len(), 2);

    // Entries may not be in insertion order, so check by name
    for (name, data) in &entries {
        match name.as_str() {
            "file1.txt" => assert_eq!(data, data1),
            "file2.bin" => assert_eq!(data, data2),
            other => panic!("unexpected entry: {other}"),
        }
    }
}
