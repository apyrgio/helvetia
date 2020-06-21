//! # HMAC helpers
//!
//! This module contains helpers around the HMAC API of the [`ring`]
//! crate.
//!
//! [`ring`]: https://github.com/briansmith/ring

use ring::digest;
use ring::hmac;

/// Sign a data buffer with a key.
///
/// Use a key to cryptographically sign a data buffer and produce a tag. This
/// tag will be unique for the (key, data) pair, and can be used to verify its
/// integrity.
///
/// ```
/// use helvetia::hmac::sign;
///
/// let key = [9u8; 32];
/// let mut data = [0u8; 9];
///
/// let tag1 = sign(&key, &data);
/// data[0] = 1;
/// let tag2 = sign(&key, &data);
/// assert_ne!(tag1, tag2);
/// ```
// XXX: We don't enforce a key of a specific size here, but internally we
// should work with 256-bit keys.
pub fn sign(key: &[u8], data: &[u8]) -> [u8; digest::SHA256_OUTPUT_LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, data);
    let mut _tag = [0u8; digest::SHA256_OUTPUT_LEN];
    _tag.copy_from_slice(tag.as_ref());
    _tag
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign() {
        // Test 1 - Ensure that the sign function works with keys of any size,
        // and that it produces different results for each key, when we operate
        // on the same data buffer.
        let key1 = vec![1u8; digest::SHA256.block_len];
        let key2 = [2u8; 1];
        let key3 = [3u8; 1000];
        let data = [0u8; 9];

        let tag1 = sign(&key1, &data);
        let tag2 = sign(&key2, &data);
        let tag3 = sign(&key3, &data);

        assert_ne!(tag1, tag2);
        assert_ne!(tag1, tag3);
        assert_ne!(tag2, tag3);
    }
}
