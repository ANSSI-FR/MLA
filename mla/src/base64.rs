use zeroize::Zeroize;

use crate::errors::Error;

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Uses compilation cast `as` for safe conversion from u8 to u32 because
// it is time constant and won't vary like std on different platforms
#[allow(clippy::cast_lossless)]
pub(crate) fn base64_encode(data: &[u8]) -> Vec<u8> {
    // We know output size given input size, so we allocate exactly needed capacity now to avoid Vec reallocations which would let buffers unzeroized
    let mut encoded = Vec::with_capacity(4 * ((data.len() + 2) / 3));
    let mut i = 0;
    while i < data.len() {
        let mut val: u32 = 0;
        let mut n = 0;
        while n < 3 && i < data.len() {
            val = (val << 8) | (data[i] as u32);
            n += 1;
            i += 1;
        }
        if n == 1 {
            val <<= 16;
        } else if n == 2 {
            val <<= 8;
        }
        for j in 0..4 {
            if j < (n + 1) {
                let mut idx = ((val >> ((3 - j) * 6)) & 0x3F) as usize;
                encoded.push(BASE64_CHARS[idx]);
                idx.zeroize();
            } else {
                encoded.push(b'=');
            }
        }
        val.zeroize();
    }

    encoded
}

// Uses compilation cast `as` for safe conversion from u8 to u32 because
// it is time constant and won't vary like std on different platforms
#[allow(clippy::cast_lossless)]
pub(crate) fn base64_decode(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    if !encoded.len().is_multiple_of(4) {
        return Err(Error::DeserializationError);
    }
    let decoded_len = (encoded.len() / 4) * 3;
    let encoded = match encoded {
        [rest @ .., b'=', b'='] | [rest @ .., b'='] => rest,
        _ => encoded,
    };
    // We know output size given input size, so we allocate needed capacity now to avoid Vec reallocations which would let buffers unzeroized
    let mut decoded = Vec::with_capacity(decoded_len);
    let mut i = 0;
    while i < encoded.len() {
        let mut val: u32 = 0;
        let mut n = 0;
        while n < 4 && i < encoded.len() {
            let c = encoded[i];
            let idx = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => return Err(Error::DeserializationError),
            };
            val = (val << 6) | (idx as u32);
            n += 1;
            i += 1;
        }
        if n == 3 {
            val <<= 6;
        } else if n == 2 {
            val <<= 12;
        }
        for j in 0..3 {
            if j < n - 1 {
                decoded.push(((val >> ((2 - j) * 8)) & 0xFF) as u8);
            }
        }
        val.zeroize();
    }
    Ok(decoded)
}
