//! # HKDF helpers
//!
//! This module contains helpers around the HKDF-related API of the [`ring`]
//! crate. For more info on how HKDF works, you can refer to the very well
//! written [RFC-5869]. Note that it is necessary to understand this RFC, if
//! you want to derive a key using [`ring`], since the ring's API follows the
//! RFC faithfully.
//!
//! [`ring`]: https://github.com/briansmith/ring
//! [RFC-5869]: https://tools.ietf.org/html/rfc5869

use ring::hkdf;
use ring::hkdf::KeyType;

use crate::res;

/// The `ring` API requires to create a struct that simply returns the desired
/// size of the new key. Since this struct is not used anywhere else, we keep
/// it private.
#[derive(Debug, PartialEq)]
struct _KeyType(usize);

impl KeyType for _KeyType {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derive a new key from an input key using HKDF and HMAC-SHA-256.
///
/// This function accepts the following parameters:
///
/// * An input key.
/// * A random, but not secret, salt value. Optionally, this value can be an
///   empty array. To decide whether to pass a salt value, read [RFC-5869,
///   Section 3.1].
/// * An info value, which can be used to bind a key to a specific context.
///   Different info values produce different keys.
/// * A buffer that will be filled with the derived key.
///
/// ## Example
///
/// In the following example, we create two keys from the same input key, but
/// we use different salts and info parameters.
///
/// ```
/// use helvetia::hkdf::derive_key;
///
/// let key = vec![9u8; 9];
/// let salt = vec![1u8; 19];
///
/// let mut new_key1 = vec![0u8; 32];
/// let res = derive_key(&key, &salt, "ctx1".as_bytes(), &mut new_key1);
/// assert!(res.is_ok());
///
/// let mut new_key2 = vec![0u8; 32];
/// let res = derive_key(&key, &[], "ctx2".as_bytes(), &mut new_key2);
/// assert!(res.is_ok());
///
/// assert_ne!(new_key1, new_key2)
/// ```
///
/// [RFC-5869, Section 3.1]: https://tools.ietf.org/html/rfc5869#section-3.1
pub fn derive_key(
    in_key: &[u8],
    salt: &[u8],
    info: &[u8],
    out_key: &mut [u8],
) -> res::Res<()> {
    // Extract

    // It seems that SHA-512 still does not have much of a benefit over
    // SHA-256. In our case, we will probably derive a key only at startup, so
    // we don't care about the performance impact either. Thus, we use
    // HMAC-SHA-256.
    let algo = hkdf::HKDF_SHA256;
    let salt = hkdf::Salt::new(algo, salt);
    let prk = salt.extract(in_key);

    // Expand

    let _info = &[info];
    let okm = match prk.expand(_info, _KeyType(out_key.len())) {
        Ok(okm) => okm,
        Err(e) => {
            // The HKDF RFC bounds the length of the OKM to 255x the length of
            // the hashing algorithm. This means that a larger buffer for the
            // derived key is prohibited and `ring` returns an error. In our
            // case, since this is not a generic function, we consider this as
            // a bug.
            let err_msg = format!("Bug during prk.expand(): {:?}", e);
            return Err(res::Error::Bug(anyhow!(err_msg)));
        }
    };

    match okm.fill(out_key) {
        Ok(_) => Ok(()),
        Err(e) => {
            let err_msg = format!("Bug during okm.fill(): {:?}", e);
            Err(res::Error::Bug(anyhow!(err_msg)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex;

    #[test]
    fn test_derive_key() {
        // Test 1 - To ensure that the `derive_key()` wrapper works as
        // expected, we test it over some of the test vectors in the RFC [1].
        //
        // [1]: https://tools.ietf.org/html/rfc5869#appendix-A

        // A.1.  Test Case 1 (Basic)
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
            .unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf3\
             4007208d5b887185865"
        ).unwrap();

        let mut out_key = vec![0u8; 42];
        let res = derive_key(&key, &salt, &info, &mut out_key);
        assert_eq!(res, Ok(()));
        assert_eq!(out_key, expected);

        // A.3.  Test Case 3 (Empty salt/info)
        let expected = hex::decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9\
             d201395faa4b61a96c8"
        ).unwrap();

        let res = derive_key(&key, &[], &[], &mut out_key);
        assert_eq!(res, Ok(()));
        assert_eq!(out_key, expected);

        // Test 2 - We check that in case of a buggy behavior, where we ask for
        // a very large key, we get a Bug error.
        let mut out_key = vec![0u8; 10000];
        let bug_err = Err(res::Error::Bug(anyhow!("")));
        let res = derive_key(&[], &[], &[], &mut out_key);
        assert_eq!(res, bug_err);
    }

    #[test]
    fn test2() {
        // A.1.  Test Case 1 (Basic)
        let mut out_key = vec![0u8; 42];
        let res = derive_key(&[], &[], &[], &mut out_key);
        assert_eq!(res, Ok(()));

        let in_key = vec![0u8; 10000];
        let res = derive_key(&in_key, &[], &[], &mut out_key);
        assert_eq!(res, Ok(()));
    }
}
