#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

use mla_wasm::generate_keypair;

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
