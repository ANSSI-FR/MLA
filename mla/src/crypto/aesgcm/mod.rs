use core::slice;

use crate::Error;

use aes::Aes256;

use generic_array::{GenericArray, typenum::U16};
use ghash::{GHash, universal_hash::UniversalHash};
pub use subtle::ConstantTimeEq;

use ctr::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

pub const BLOCK_SIZE: usize = 128 / 8;
pub const TAG_LENGTH: usize = BLOCK_SIZE;
pub const KEY_SIZE: usize = 32;
pub const NONCE_AES_SIZE: usize = 96 / 8;
// Based on "How to abuse and fix authenticated encryption without key commitment", 2020
// Key commitment chain must be as long as twice the expected security strength
pub const KEY_COMMITMENT_SIZE: usize = KEY_SIZE * 2;

pub type Nonce = [u8; NONCE_AES_SIZE];
pub type Key = [u8; KEY_SIZE];

// Inspired from RustCrypto's AesGcm implementation
pub struct AesGcm256 {
    cipher: Aes256Ctr,
    /// Gallois Hash, for data authentication
    ghash: GHash,
    /// Size of the authenticated data, in bits
    associated_data_bits_len: u64,
    /// Encrypted data not yet hashed.
    /// Corresponds to the bytes unaligned with the BLOCK_SIZE, ie:
    /// ```ascii-art
    /// [BLOCK_SIZE][BLOCK_SIZE]
    /// [ data encrypted ]
    ///             [    ] -> data remaining, going to `current_block`
    /// ```
    /// Once `current_block` is full (with a length of BLOCK_SIZE), it is used
    /// to update the `ghash`, and is cleared.
    current_block: Vec<u8>,
    /// Number of bytes encrypted - workaround for
    /// <https://github.com/RustCrypto/block-ciphers/issues/71>
    bytes_encrypted: u64,
}

/// AES-GCM tags
pub type Tag = GenericArray<u8, U16>;

impl AesGcm256 {
    pub fn new(key: &Key, nonce: &Nonce, associated_data: &[u8]) -> Result<AesGcm256, Error> {
        // Convert the nonce (96 bits) to the AES-GCM form
        let mut counter_block = [0u8; BLOCK_SIZE];
        counter_block[..12].copy_from_slice(nonce);
        counter_block[15] = 1;

        // Initialize the GHash with a empty ciphered block
        let mut ghash_key = GenericArray::default();
        let cipher = Aes256::new(GenericArray::from_slice(key));
        cipher.encrypt_block(&mut ghash_key);

        // Add the associated data to authenticate
        let mut ghash = GHash::new(&ghash_key);
        ghash.update_padded(associated_data);

        // Prepare the cipher for further operations
        let mut cipher = Aes256Ctr::new(key.into(), &counter_block.into());
        // First block is ignored, as it has been used for the GHash
        cipher.seek(BLOCK_SIZE as u64);

        Ok(AesGcm256 {
            cipher,
            ghash,
            associated_data_bits_len: (associated_data.len() as u64) * 8,
            current_block: Vec::with_capacity(BLOCK_SIZE),
            bytes_encrypted: 0,
        })
    }

    pub fn encrypt(&mut self, mut buffer: &mut [u8]) {
        // Update the number of byte encrypted
        self.bytes_encrypted += buffer.len() as u64;

        // Finish the current block, if any
        if !self.current_block.is_empty() {
            if (self.current_block.len() + buffer.len()) < BLOCK_SIZE {
                self.cipher.apply_keystream(buffer);
                self.current_block.extend_from_slice(buffer);
                return;
            } else {
                let (in_block, out_block) =
                    buffer.split_at_mut(BLOCK_SIZE - self.current_block.len());
                self.cipher.apply_keystream(in_block);
                self.current_block.extend_from_slice(in_block);
                // `current_block` length is now BLOCK_SIZE -> update GHash and
                // clear it
                self.ghash
                    .update(slice::from_ref(self.current_block.as_slice().into()));
                self.current_block.clear();

                // Deals with the rest of the data, now aligned on BLOCK_SIZE
                buffer = out_block;
            }
        }

        let mut chunks = buffer.chunks_exact_mut(BLOCK_SIZE);

        // Interleaved ghash update
        for chunk in &mut chunks {
            self.cipher.apply_keystream(chunk);
            self.ghash
                .update(slice::from_ref(GenericArray::from_slice(chunk)));
        }

        // Encrypt and save extra encrypted bytes for further GHash computation
        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            self.cipher.apply_keystream(rem);
            self.current_block.extend_from_slice(rem);
        }
    }

    /// Finalize encryption and returns the associated tag
    // Force a move, to avoid further calls to `encrypt`
    pub fn into_tag(mut self) -> Tag {
        // Finish the current block, if any
        self.ghash.update_padded(&self.current_block);

        // Compute "len(associated data) || len(bytes encrypted)"
        let buffer_bits = self.bytes_encrypted * 8;
        let mut block = GenericArray::default();
        block[..8].copy_from_slice(&self.associated_data_bits_len.to_be_bytes());
        block[8..].copy_from_slice(&buffer_bits.to_be_bytes());

        self.ghash.update(&[block]);

        // Final update
        let mut tag = self.ghash.finalize();
        self.cipher.seek(0);
        self.cipher.apply_keystream(tag.as_mut_slice());
        tag
    }

    /// Decrypt without considering the associated data
    /// /!\ this mode of decryption is unauthenticated, use it carefully
    pub fn decrypt_unauthenticated(&mut self, buffer: &mut [u8]) {
        self.cipher.apply_keystream(buffer);
    }

    /// Decrypt and compute the associated tag
    pub fn decrypt(&mut self, buffer: &mut [u8]) -> Tag {
        let mut chunks = buffer.chunks_exact_mut(BLOCK_SIZE);

        // Interleaved ghash update
        for chunk in &mut chunks {
            self.ghash
                .update(slice::from_ref(GenericArray::from_slice(chunk)));
            self.cipher.apply_keystream(chunk);
        }

        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            self.ghash.update_padded(rem);
            self.cipher.apply_keystream(rem);
        }

        // Compute "len(associated data) || len(bytes encrypted)"
        let buffer_bits = (buffer.len() as u64) * 8;
        let mut block = GenericArray::default();
        block[..8].copy_from_slice(&self.associated_data_bits_len.to_be_bytes());
        block[8..].copy_from_slice(&buffer_bits.to_be_bytes());

        self.ghash.update(&[block]);

        // Final update
        let mut tag = self.ghash.clone().finalize();
        self.cipher.seek(0);
        self.cipher.apply_keystream(tag.as_mut_slice());
        tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aead::Payload;
    use aes_gcm::{Aes256Gcm, aead::Aead};

    fn test_against_aesgcm(key: &Key, nonce: &Nonce, associated_data: &[u8], msg: &[u8]) {
        // Full (all at once)
        let extern_cipher = Aes256Gcm::new(key.into());
        let extern_ciphertext = extern_cipher
            .encrypt(
                &GenericArray::clone_from_slice(nonce),
                Payload {
                    msg,
                    aad: associated_data,
                },
            )
            .expect("encryption failure!");

        let mut crate_cipher = AesGcm256::new(key, nonce, associated_data).unwrap();
        let mut buf = msg.to_vec();
        crate_cipher.encrypt(&mut buf);
        let tag = crate_cipher.into_tag();
        assert_eq!(tag.len(), TAG_LENGTH);

        assert_eq!(
            &extern_ciphertext[..extern_ciphertext.len() - TAG_LENGTH],
            buf.as_slice()
        );
        assert_eq!(
            extern_ciphertext[extern_ciphertext.len() - TAG_LENGTH..],
            tag[..]
        );

        for size in &[
            1,              // Byte per byte, forcing unaligned
            BLOCK_SIZE + 1, // BLOCK_SIZE + 1, forcing unaligned with extra data
        ] {
            let mut crate_cipher = AesGcm256::new(key, nonce, associated_data).unwrap();
            let mut buffer = msg.to_vec();
            let mut chunks = buffer.as_mut_slice().chunks_mut(*size);

            for chunk in &mut chunks {
                crate_cipher.encrypt(chunk);
            }
            let tag = crate_cipher.into_tag();
            assert_eq!(tag.len(), TAG_LENGTH);

            assert_eq!(
                &extern_ciphertext[..extern_ciphertext.len() - TAG_LENGTH],
                buffer.as_slice()
            );
            assert_eq!(
                extern_ciphertext[extern_ciphertext.len() - TAG_LENGTH..],
                tag[..]
            );
        }
    }

    #[test]
    fn test_against_aes_gcm() {
        // Test vector "60-byte Packet Encryption Using GCM-AES-256" from
        // "MACsec GCM-AES Test Vectors", IEEE P802.1 Security Task Group
        test_against_aesgcm(
            b"\xe3\xc0\x8a\x8f\x06\xc6\xe3\xad\x95\xa7\x05\x57\xb2\x3f\x75\x48\x3c\xe3\x30\x21\xa9\xc7\x2b\x70\x25\x66\x62\x04\xc6\x9c\x0b\x72",
            b"\x12\x15\x35\x24\xc0\x89\x5e\x81\xb2\xc2\x84\x65", // 96-bits; unique per message
            b"\xd6\x09\xb1\xf0\x56\x63\x7a\x0d\x46\xdf\x99\x8d\x88\xe5\x2e\x00\xb2\xc2\x84\x65\x12\x15\x35\x24\xc0\x89\x5e\x81",
            b"\x08\x00\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x00\x02",
        );

        // 47 bytes plaintext (not aligned on block size)
        test_against_aesgcm(
            b"\xe3\xc0\x8a\x8f\x06\xc6\xe3\xad\x95\xa7\x05\x57\xb2\x3f\x75\x48\x3c\xe3\x30\x21\xa9\xc7\x2b\x70\x25\x66\x62\x04\xc6\x9c\x0b\x72",
            b"\x12\x15\x35\x24\xc0\x89\x5e\x81\xb2\xc2\x84\x65", // 96-bits; unique per message
            b"\xd6\x09\xb1\xf0\x56\x63\x7a\x0d\x46\xdf\x99\x8d\x88\xe5\x2e\x00\xb2\xc2\x84\x65\x12\x15\x35\x24\xc0\x89\x5e\x81",
            b"\x08\x00\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x00",
        );
    }

    #[test]
    fn test_decryption() {
        let key = b"\xe3\xc0\x8a\x8f\x06\xc6\xe3\xad\x95\xa7\x05\x57\xb2\x3f\x75\x48\x3c\xe3\x30\x21\xa9\xc7\x2b\x70\x25\x66\x62\x04\xc6\x9c\x0b\x72";
        let nonce = b"\x12\x15\x35\x24\xc0\x89\x5e\x81\xb2\xc2\x84\x65";
        let associated_data = b"\xd6\x09\xb1\xf0\x56\x63\x7a\x0d\x46\xdf\x99\x8d\x88\xe5\x2e\x00\xb2\xc2\x84\x65\x12\x15\x35\x24\xc0\x89\x5e\x81";
        let msg = b"\x08\x00\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x00\x02";

        let extern_cipher = Aes256Gcm::new(key.into());
        let extern_ciphertext = extern_cipher
            .encrypt(
                &GenericArray::clone_from_slice(nonce),
                Payload {
                    msg,
                    aad: associated_data,
                },
            )
            .expect("encryption failure!");

        let mut crate_cipher = AesGcm256::new(key, nonce, associated_data).unwrap();
        let mut buf = msg.to_vec();
        crate_cipher.encrypt(&mut buf);
        let tag = crate_cipher.into_tag();
        assert_eq!(tag.len(), TAG_LENGTH);

        // Unauthenticated decryption
        let mut crate_cipher = AesGcm256::new(key, nonce, b"").unwrap();
        let mut buf = extern_ciphertext[..extern_ciphertext.len() - TAG_LENGTH].to_vec();
        crate_cipher.decrypt_unauthenticated(&mut buf);
        assert_eq!(buf.as_slice(), &msg[..]);

        // Authenticated decryption
        let mut crate_cipher = AesGcm256::new(key, nonce, associated_data).unwrap();
        let mut buf = extern_ciphertext[..extern_ciphertext.len() - TAG_LENGTH].to_vec();
        let expected_tag = extern_ciphertext[extern_ciphertext.len() - TAG_LENGTH..].to_vec();
        let tag = crate_cipher.decrypt(&mut buf);
        assert_eq!(buf.as_slice(), &msg[..]);
        assert_eq!(&tag[..], expected_tag.as_slice());
    }
}
