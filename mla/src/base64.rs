use zeroize::Zeroize;

use crate::errors::Error;

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Uses compilation cast `as` for safe conversion from u8 to u32 because
// it is time constant and won't vary like std on different platforms
#[allow(clippy::cast_lossless)]
pub(crate) fn base64_encode(data: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    let mut i: usize = 0;
    while i < data.len() {
        let mut val: u32 = 0;
        let mut n: u8 = 0;
        while n < 3 && i < data.len() {
            val = (val << 8) | (data[i] as u32);
            n = n.checked_add(1).unwrap();
            i = i.checked_add(1).unwrap();
        }
        if n == 1 {
            val <<= 16;
        } else if n == 2 {
            val <<= 8;
        }
        for j in 0..4 {
            if j < n.checked_add(1).unwrap() {
                let mut idx =
                    ((val >> 3u8.checked_sub(j).unwrap().checked_mul(6).unwrap()) & 0x3F) as usize;
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
    let encoded = match encoded {
        [rest @ .., b'=', b'='] | [rest @ .., b'='] => rest,
        _ => encoded,
    };
    let mut decoded = Vec::new();
    let mut i: usize = 0;
    while i < encoded.len() {
        let mut val: u32 = 0;
        let mut n: u8 = 0;
        while n < 4 && i < encoded.len() {
            let c = encoded[i];
            let idx = match c {
                b'A'..=b'Z' => c.checked_sub(b'A').unwrap(),
                b'a'..=b'z' => c.checked_sub(b'a').unwrap().checked_add(26).unwrap(),
                b'0'..=b'9' => c.checked_sub(b'0').unwrap().checked_add(52).unwrap(),
                b'+' => 62,
                b'/' => 63,
                _ => return Err(Error::DeserializationError),
            };
            val = (val << 6) | (idx as u32);
            n = n.checked_add(1).unwrap();
            i = i.checked_add(1).unwrap();
        }
        if n == 3 {
            val <<= 6;
        } else if n == 2 {
            val <<= 12;
        }
        for j in 0..3 {
            if j < n.checked_sub(1).unwrap() {
                decoded.push(
                    (val >> 2u8.checked_sub(j).unwrap().checked_mul(8).unwrap() & 0xFF) as u8,
                );
            }
        }
        val.zeroize();
    }
    Ok(decoded)
}
