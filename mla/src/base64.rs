use zeroize::Zeroize;

use crate::errors::Error;

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Uses compilation cast `as` for safe conversion from u8 to u32 because
// it is time constant and won't vary like std on different platforms
#[allow(clippy::cast_lossless)]
pub(crate) fn base64_encode(data: &[u8]) -> Result<Vec<u8>, Error> {
    // We know output size given input size, so we allocate exactly needed capacity now to avoid Vec reallocations which would let buffers unzeroized
    // Vec capacity is defined as a manual implementation of div_ceil(3) function with overflow checks: 4 * ((data.len() + 2) / 3)
    let capacity = data
        .len()
        .checked_add(2)
        .and_then(|x| x.checked_div(3))
        .and_then(|x| x.checked_mul(4))
        .ok_or(Error::SerializationError)?;
    let mut encoded = Vec::with_capacity(capacity);
    let mut i: usize = 0;
    while i < data.len() {
        let mut val: u32 = 0;
        let mut n: u8 = 0;
        while n < 3 && i < data.len() {
            val = (val << 8) | (data[i] as u32);
            n = n.checked_add(1).ok_or(Error::SerializationError)?;
            i = i.checked_add(1).ok_or(Error::SerializationError)?;
        }
        if n == 1 {
            val <<= 16;
        } else if n == 2 {
            val <<= 8;
        }
        for j in 0..4 {
            if j < n.checked_add(1).ok_or(Error::SerializationError)? {
                let mut idx = ((val
                    >> 3u8
                        .checked_sub(j)
                        .and_then(|x| x.checked_mul(6))
                        .ok_or(Error::SerializationError)?)
                    & 0x3F) as usize;
                encoded.push(BASE64_CHARS[idx]);
                idx.zeroize();
            } else {
                encoded.push(b'=');
            }
        }
        val.zeroize();
    }

    Ok(encoded)
}

// Uses compilation cast `as` for safe conversion from u8 to u32 because
// it is time constant and won't vary like std on different platforms
#[allow(clippy::cast_lossless)]
pub(crate) fn base64_decode(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    if !encoded.len().is_multiple_of(4) {
        return Err(Error::DeserializationError);
    }
    let decoded_len = encoded
        .len()
        .checked_div(4)
        .and_then(|x| x.checked_mul(3))
        .ok_or(Error::DeserializationError)?;
    let encoded = match encoded {
        [rest @ .., b'=', b'='] | [rest @ .., b'='] => rest,
        _ => encoded,
    };
    // We know output size given input size, so we allocate needed capacity now to avoid Vec reallocations which would let buffers unzeroized
    let mut decoded = Vec::with_capacity(decoded_len);
    let mut i: usize = 0;
    while i < encoded.len() {
        let mut val: u32 = 0;
        let mut n: u8 = 0;
        while n < 4 && i < encoded.len() {
            let c = encoded[i];
            let idx = match c {
                b'A'..=b'Z' => c.checked_sub(b'A').ok_or(Error::SerializationError)?,
                b'a'..=b'z' => c
                    .checked_sub(b'a')
                    .and_then(|x| x.checked_add(26))
                    .ok_or(Error::SerializationError)?,
                b'0'..=b'9' => c
                    .checked_sub(b'0')
                    .and_then(|x| x.checked_add(52))
                    .ok_or(Error::SerializationError)?,
                b'+' => 62,
                b'/' => 63,
                _ => return Err(Error::DeserializationError),
            };
            val = (val << 6) | (idx as u32);
            n = n.checked_add(1).ok_or(Error::SerializationError)?;
            i = i.checked_add(1).ok_or(Error::SerializationError)?;
        }
        if n == 3 {
            val <<= 6;
        } else if n == 2 {
            val <<= 12;
        }
        for j in 0..3 {
            if j < n.checked_sub(1).ok_or(Error::SerializationError)? {
                decoded.push(
                    (val >> 2u8
                        .checked_sub(j)
                        .and_then(|x| x.checked_mul(8))
                        .ok_or(Error::SerializationError)?
                        & 0xFF) as u8,
                );
            }
        }
        val.zeroize();
    }
    Ok(decoded)
}
