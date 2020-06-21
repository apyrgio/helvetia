//! # Constant-time operations
//!
//! This module provides helpers for constant-time operations. For more info
//! regarding constant-time oprations and why they are useful, read the
//! relevant [BearSSL section] on this subject. Note that for the underlying
//! constant-time equality checks, we use the [`subtle`] crate.
//!
//! [BearSSL section]: https://www.bearssl.org/constanttime.html
//! [`subtle`]: https://github.com/dalek-cryptography/subtle

use subtle::ConstantTimeEq;

/// Compare two strings in constant time.
pub fn str_eq(s1: &str, s2: &str) -> bool {
    let s1 = s1.as_bytes();
    let s2 = s2.as_bytes();

    s1.ct_eq(s2).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_str_eq() {
        assert!(!str_eq(&"", &"that"));
        assert!(!str_eq(&"this", &""));
        assert!(!str_eq(&"this", &"that"));
        assert!(str_eq(&"this", &"this"));
    }
}
