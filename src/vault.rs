//! # Vault
//!
//! This module contains [`Vault`], which is a construct that controls access
//! to secrets and stores them securely.
//!
//! [`Vault`]: struct.Vault.html

use base64;
use tindercrypt::{cryptors, metadata};

use crate::{ct, hkdf, hmac, res, secret};

// The HKDF parameters for the encryption keys that Vault will create.
const NAME_INFO: &str = "NAME";
const DATA_INFO: &str = "DATA";
const TOKEN_INFO: &str = "TOKEN";
const ENCRYPTION_KEY_SIZE: usize = 32;

/// The type of the token.
///
/// This is for internal use, in order to pass a token, along with its intended
/// usage, to lower Vault layers.
enum TokenType<'a> {
    /// The provided token should match the secret's owner token.
    Owner(&'a str),
    /// The provided token should match any of the secret's tokens.
    Any(&'a str),
}

/// The encryption algorithm that Vault will use.
///
/// The encryption algorithms provided here map 1:1 to the encryption
/// algorithms of [Tindercrypt].
///
/// [Tindercrypt]: https://docs.rs/tindercrypt
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum EncryptionAlgorithm {
    /// The AES-256-GCM encryption algorithm.
    AES256GCM,
    /// The ChaCha20-Poly1305 encryption algorithm.
    ChaCha20Poly1305,
}

/// The keys that Vault will use for encryption purposes.
#[derive(Copy, Clone, Debug, PartialEq)]
struct EncryptionKeys {
    /// The key used for hashing the name of a secret.
    name: [u8; ENCRYPTION_KEY_SIZE],
    /// The key used for encrypting the secret as a whole.
    data: [u8; ENCRYPTION_KEY_SIZE],
    /// The key used for hashing the tokens of a secret.
    token: [u8; ENCRYPTION_KEY_SIZE],
}

impl EncryptionKeys {
    /// Create various encryption keys from a provided one.
    pub fn new(in_key: &[u8]) -> Self {
        let mut name_key = [0u8; ENCRYPTION_KEY_SIZE];
        let mut data_key = [0u8; ENCRYPTION_KEY_SIZE];
        let mut token_key = [0u8; ENCRYPTION_KEY_SIZE];

        // The HKDF RFC specifies that we don't need to use a salt, if the key
        // has been produced by a random source. In our case, we don't want to
        // hardcode a salt, or make the user remember it, so we omit it.
        //
        // XXX: We can safely unwrap the result here, since the size of the
        // encryption key is within the limits of the HKDF algorithm.
        hkdf::derive_key(in_key, &[], NAME_INFO.as_bytes(), &mut name_key)
            .unwrap();
        hkdf::derive_key(in_key, &[], DATA_INFO.as_bytes(), &mut data_key)
            .unwrap();
        hkdf::derive_key(in_key, &[], TOKEN_INFO.as_bytes(), &mut token_key)
            .unwrap();

        Self {
            name: name_key,
            data: data_key,
            token: token_key,
        }
    }

    /// Derive an encryption key for a secret's data from the secret's name.
    pub fn derive_data_key(&self, name: &str) -> [u8; ENCRYPTION_KEY_SIZE] {
        let mut data_key = [0u8; ENCRYPTION_KEY_SIZE];
        hkdf::derive_key(&self.data, &[], name.as_bytes(), &mut data_key)
            .unwrap();
        data_key
    }
}

/// Secure operations on secrets.
///
/// In order to keep a [`Secret`], well, _secret_, we need a way to control
/// access to it and ensure that it can't get stolen. This role is fulfilled by
/// [`Vault`], which offers the following functionality:
///
/// 1. Provide an API for making actions on secrets, using tokens for
///    authentication. The logic is simple; in order to make an action on a
///    secret, you need to provide the same token that is stored in said
///    secret. You can read more on the [Authentication] section.
/// 2. Encrypt/decrypt the name and the data of the secret, to protect the
///    secret's data, as well as its metadata. You can read more on the [Secure
///    storage of secrets] section.
/// 3. Store, retrieve and delete secrets using a key-value store backed by
///    [Caves].
///
/// ## Examples
///
/// Here's a simple way to create a [`Vault`] and perform operations on a
/// secret.
///
/// ```
/// use rand::{thread_rng, Rng};
///
/// use caves::MemoryCave;
/// use helvetia::secret::Secret;
/// use helvetia::vault::{EncryptionAlgorithm, Vault};
///
/// // Define a dummy secret for testing purposes.
/// let token = "token".to_string();
/// let secret = Secret::new(token.clone(), None, "data".to_string(), None)?;
///
/// // Create a random encryption key for Vault.
/// let mut key = [0u8; 32];
/// thread_rng().fill(&mut key);
///
/// // Create a key-value store for testing purposes.
/// let kv = Box::new(MemoryCave::new());
///
/// // Create a new Vault instance.
/// let vault = Vault::new(&key, EncryptionAlgorithm::AES256GCM, kv);
///
/// // Store the secret as "shhh!".
/// let res = vault.create_secret("shhh!", &token, &secret);
/// assert!(res.is_ok());
///
/// // Retrieve the secret's data.
/// let data = vault.get_secret_data("shhh!", &token);
/// assert_eq!(Ok("data".as_bytes().to_vec()), data);
///
/// // Retrieve the secret's metadata.
/// let meta = vault.get_secret_meta("shhh!", &token);
/// assert_eq!(Ok(vec![]), meta);
///
/// // Delete the secret.
/// let res = vault.delete_secret("shhh!", &token);
/// assert!(res.is_ok());
///
/// # use helvetia::res;
/// # Ok::<(), res::Error>(())
/// ```
///
/// ## Authentication
///
/// Each secret has two fields that are used for authentication; the owner
/// token and the meta token (optional). The first allows all actions on the
/// secret, while the second grants access only to the secret's metadata.
///
/// So, when [`Vault`] is asked to perform an operation on a secret, it first
/// retrieves the secret and checks:
///
/// * if the user-provided token matches the one stored in the secret, and
/// * the type of the operation.
///
/// If it doesn't match, it returns a [`Forbidden`] error.
///
/// ## Secure storage of secrets
///
/// In order to safely store and retrieve a secret from the key-value store,
/// [`Vault`] performs various operations on it.
///
/// The steps to store a secret are the following:
///
/// 1. Create a cryptographic hash from the secret's name: [`Vault`] has a key
///    dedicated for this operation. Using this key and the secret's name, it
///    applies the HMAC-SHA256 algorithm on it and produces a unique hash.
/// 2. Create a cryptographic hash for the secret's tokens, using the same
///    method as above but with a different dedicated key.
/// 3. Encode the hash with Base64: Because the underlying key value store
///    may have restrictions on the names of the keys, encode the hash as an
///    ASCII string with Base64, and use the URL-safe character set for better
///    interoperability.
/// 4. Serialize the secret into a data buffer. For more info, read the
///    [`Serialization`] section on the [`Secret`] doc.
/// 5. Prepare the encryption operation by creating the necessary metadata
///    (nonces, encryption algorithm, etc.) and using the original name of the
///    secret as AD (associated data).
/// 6. Use the original name of the secret and Helvetia's encryption key to
///    temporarily derive a new encryption key, using the HKDF algorithm.
/// 7. Encrypt the serialized secret using the derived encryption key.
/// 8. Store the (name hash, encrypted secret) pair in the underlying key-value
///    store.
///
/// The steps to retrieve a secret by its name are the following:
///
/// 1. Create a cryptographic hash from the secret's name and encode it in
///    Base64 (see above).
/// 2. Retrieve the encrypted secret using its hashed name from the key-value
///    store.
/// 3. Derive a new encryption key from the original secret's name and Vault's
///    encryption key (see above).
/// 4. Decrypt the secret using the derived encryption key.
/// 5. Deserialize the secret from the decrypted data buffer.
///
/// ### How does Vault produce encryption keys?
///
/// In order to create a [`Vault`], the user must provide a key. From this key,
/// [`Vault`] produces two new keys using [HKDF]; one for the secret's name and
/// one for the secret's data.
///
/// For the data key, there is a second key derivation step; on every request,
/// we derive with [HKDF] a new encryption key using the [`Vault`]'s encryption
/// key and the original name of the secret. We use this new key to
/// encrypt/decrypt the serialized secret, and then it's erased from
/// [`Vault`]'s memory. This way, a stored secret can only be decrypted by
/// those who know the [`Vault`]'s encryption key and the original name of the
/// secret. For secret names with high entropy, this means that even if a
/// Helvetia server is subsequently compromised, their secret should remain
/// safe (see [Weak perfect forward secrecy] for a description of this security
/// property).
///
/// In order to always create the same encryption keys from the same input key,
/// [`Vault`] does not use a salt for the [HKDF] operation. This does not
/// affect the security properties of [`Vault`], as long as the provided key
/// contains enough bits of entropy.
///
/// ### Why do we hash the secret's name?
///
/// The name of the secret may leak information about its owner or its
/// contents, so it makes sense to hide it. Another reason we want the name of
/// the secret to be irretrievable is because it reduces the impact of a
/// compromised Helvetia server (for more info read the previous section).
///
/// ### Why do we hash the secret's tokens?
///
/// We don't want to store the tokens in plaintext, in case the user has reused
/// them as passwords in other places. Password reusal is of course frowned
/// upon, but we still have to protect users against such attacks.
///
/// ### Why do we use the secret's name as AD?
///
/// Since [`Vault`] uses [AEAD] ciphers, it has the option to provide
/// additional data (AD) to the encrypt/decrypt operations. This is a useful
/// property that [`Vault`] can take advantage of to ensure that malicious
/// key-value stores can't simply return an encrypted secret for a
/// different secret name.
///
/// One more detail is that [`Vault`] uses as AD the hash of the secret's
/// name, and not the actual name of the secret, since the AD should always be
/// non-secret values.
///
/// ### How does Vault encrypt the secret?
///
/// [`Vault`] uses [Tindercrypt] for the encryption. In a nutshell
/// [`Vault`] passes to [Tindercrypt] the metadata for the encryption
/// operation and [Tindercrypt] uses the [`ring`] crate to encrypt the
/// secret, and [Protocol Buffers] to bundle the encryption metadata with the
/// ciphertext. You can read more about the encryption logic on the
/// [Tindercrypt] docs.
///
/// [`Secret`]: ../secret/struct.Secret.html
/// [`Vault`]: struct.Vault.html
/// [Caves]: https://github.com/apyrgio/caves
/// [`Serialization`]: ../secret/struct.Secret.html#serialization
/// [HKDF]: https://en.wikipedia.org/wiki/HKDF
/// [AEAD]: https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD)
/// [Tindercrypt]: https://docs.rs/tindercrypt
/// [Protocol Buffers]: https://developers.google.com/protocol-buffers/
/// [Authentication]: struct.Vault.html#authentication
/// [Secure storage of secrets]: struct.Vault.html#secure-storage-of-secrets
/// [`Forbidden`]: ../res/enum.Error.html#variant.Forbidden
/// [`ring`]: https://github.com/briansmith/ring
/// [Weak perfect forward secrecy]: https://en.wikipedia.org/wiki/Forward_secrecy#Weak_perfect_forward_secrecy
// XXX: We allow missing debug implementations because, while all the key-value
// stores derive from `Debug`, the Cave trait does not require it.
#[allow(missing_debug_implementations)]
pub struct Vault {
    /// The encryption keys for the name/data of the secrets.
    keys: EncryptionKeys,
    /// The encryption algorithm that Vault will use.
    algo: EncryptionAlgorithm,
    /// The key value store were the secret will be stored.
    kv: Box<dyn caves::Cave>,
}

impl Vault {
    /// Initialize `Vault`.
    ///
    /// Intialize `Vault` using a key, from which the encryption keys will be
    /// generated, an encryption algorithm, and the key-value store where
    /// `Vault` will store the secrets.
    pub fn new(
        key: &[u8],
        algo: EncryptionAlgorithm,
        kv: Box<dyn caves::Cave>,
    ) -> Self {
        Self {
            keys: EncryptionKeys::new(key),
            algo,
            kv,
        }
    }

    /// Generate the metadata for the encryption.
    ///
    /// Note that the encryption metadata cannot be generated beforehand, else
    /// this would lead to nonce-reusal.
    fn _generate_tc_meta(&self, len: usize) -> metadata::Metadata {
        let key_meta = metadata::EncryptionMetadata::generate();
        let tc_key_algo = metadata::KeyDerivationAlgorithm::None;
        let tc_enc_algo = match self.algo {
            EncryptionAlgorithm::AES256GCM => {
                metadata::EncryptionAlgorithm::AES256GCM(key_meta)
            }
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                metadata::EncryptionAlgorithm::ChaCha20Poly1305(key_meta)
            }
        };
        metadata::Metadata::new(tc_key_algo, tc_enc_algo, len)
    }

    /// Check that a token provided by the user and a stored one match.
    ///
    /// Since we hash the tokens before storing them, this function should
    /// perform the same type of hashing before checking the tokens for
    /// equality.
    fn _token_eq(&self, original_token: &str, stored_token: &str) -> bool {
        let hashed_original_token = self._hmac_token(original_token);
        // FIXME: This is probably not necessary.
        ct::str_eq(&hashed_original_token, stored_token)
    }

    /// Hash a string buffer using a key.
    ///
    /// Apply the HMAC-SHA256 algorithm on a string buffer, and encode the
    /// result in Base64.
    fn _hmac(&self, data: &str, key: &[u8]) -> String {
        // Calculate the HMAC-SHA256 hash of the data using the provided key.
        let hash = hmac::sign(key, data.as_bytes());

        // Encode it in Base64 with the URL-safe character set and no padding,
        // so that the value can be used in URLs as well.
        base64::encode_config(&hash, base64::URL_SAFE_NO_PAD)
    }

    /// Hash a name using the Helvetia's respective key.
    fn _hmac_name(&self, name: &str) -> String {
        self._hmac(name, &self.keys.name)
    }

    /// Hash a token using the Helvetia's respective key.
    fn _hmac_token(&self, token: &str) -> String {
        self._hmac(token, &self.keys.token)
    }

    /// Get a Tindercrypt cryptor for the secret.
    ///
    /// Create a `RingCryptor` struct and make it use as AAD the actual name
    /// of the secret.
    fn _get_cryptor_for_secret<'a>(
        &self,
        name: &'a str,
    ) -> cryptors::RingCryptor<'a> {
        cryptors::RingCryptor::new().with_aad(name.as_bytes())
    }

    /// Get the secret from the key-value store.
    ///
    /// Hash the name of the secret, retrieve it from the key-value store, and
    /// then decrypt it.
    fn _get_secret(&self, name: &str) -> res::Res<secret::Secret> {
        let ciphername = self._hmac_name(name);
        let ciphertext = match self.kv.get(&ciphername) {
            Ok(b) => b.to_vec(),
            Err(e) => match e {
                res::CavesError::NotFound(_) => {
                    return Err(res::Error::SecretNotFound(name.to_string()))
                }
                e => return Err(res::Error::from(e)),
            },
        };
        let cryptor = self._get_cryptor_for_secret(&ciphername);
        let data_key = self.keys.derive_data_key(name);
        let plaintext = cryptor.open(&data_key, &ciphertext)?;
        secret::Secret::from_buf(&plaintext)
    }

    /// Store a secret to the key-value store.
    ///
    /// Hash the name of the secret, encrypt it, and then store it to the
    /// key-value store.
    fn _create_secret(
        &self,
        name: &str,
        secret: &secret::Secret,
    ) -> res::Res<()> {
        // XXX: Hash the tokens of the secret before storing them.
        let mut secret = secret.clone();
        secret.owner_token = self._hmac_token(&secret.owner_token);
        secret.meta_token = match secret.meta_token {
            None => None,
            Some(t) => Some(self._hmac_token(&t)),
        };
        let secret = secret;

        let ciphername = self._hmac_name(name);
        let plaintext = secret.to_buf();
        let meta = self._generate_tc_meta(plaintext.len());
        let cryptor = self._get_cryptor_for_secret(&ciphername);
        let data_key = self.keys.derive_data_key(name);
        let ciphertext =
            cryptor.seal_with_meta(&meta, &data_key, &plaintext)?;
        let _ = self.kv.set(&ciphername, &ciphertext)?;
        Ok(())
    }

    /// Get secret, only if provided token matches.
    ///
    /// Get a secret from the key-value store, but return it to the upper
    /// layers only if the provided token matches the one stored in the secret.
    fn _get_secret_if_token_matches(
        &self,
        name: &str,
        token: &TokenType,
    ) -> res::Res<secret::Secret> {
        let secret = self._get_secret(name)?;
        let token_matches = match token {
            TokenType::Owner(token) => {
                self._token_eq(token, &secret.owner_token)
            }
            TokenType::Any(token) => {
                if self._token_eq(token, &secret.owner_token) {
                    true
                } else {
                    match &secret.meta_token {
                        None => false,
                        Some(meta_token) => self._token_eq(token, &meta_token),
                    }
                }
            }
        };

        match token_matches {
            true => Ok(secret),
            false => Err(res::Error::Forbidden(name.to_string())),
        }
    }

    /// Get a secret, if the owner token matches.
    fn get_secret(&self, name: &str, token: &str) -> res::Res<secret::Secret> {
        let t = TokenType::Owner(token);
        self._get_secret_if_token_matches(name, &t)
    }

    /// Get the data of a secret.
    pub fn get_secret_data(&self, name: &str, token: &str) -> res::Data {
        let secret = self.get_secret(name, token)?;
        Ok(secret.data.as_bytes().to_vec())
    }

    /// Get the metadata of a secret.
    ///
    /// If the metadata do not exist, simply return an empty buffer.
    pub fn get_secret_meta(&self, name: &str, token: &str) -> res::Data {
        let t = TokenType::Any(token);
        let secret = self._get_secret_if_token_matches(name, &t)?;
        match secret.meta {
            Some(meta) => Ok(meta.as_bytes().to_vec()),
            None => Ok(Vec::new()),
        }
    }

    /// Create or replace a secret.
    ///
    /// Create a new secret, if it doesn't exist, or replace it, if the tokens
    /// match.
    pub fn create_secret(
        &self,
        name: &str,
        token: &str,
        secret: &secret::Secret,
    ) -> res::Res<()> {
        match self.get_secret(name, token) {
            Ok(_) | Err(res::Error::SecretNotFound(_)) => {
                self._create_secret(name, secret)
            }
            Err(e) => Err(e),
        }
    }

    /// Delete a secret.
    pub fn delete_secret(&self, name: &str, token: &str) -> res::Res<()> {
        let _ = self.get_secret(name, token)?;
        let ciphername = self._hmac_name(name);
        let _ = self.kv.delete(&ciphername)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{thread_rng, Rng};

    #[test]
    fn test_encryption() {
        // Create a Secret for the test.
        let name = "secret";
        let s = secret::tests::create_secret(&[]).unwrap();

        // Create a Vault for the test.
        let kv = caves::MemoryCave::new();
        let mut key = [0u8; 32];
        thread_rng().fill(&mut key);
        let mut vault = Vault::new(
            &key,
            EncryptionAlgorithm::ChaCha20Poly1305,
            Box::new(kv),
        );

        // Define some common errors.
        let not_found_err = Err(res::Error::SecretNotFound(name.to_string()));
        let key_inv_err = Err(res::Error::KeyInvalid(anyhow!("")));

        // Test 1 - Check that we can create a secret and retrieve its data.
        let res = vault.create_secret(name, &s.owner_token, &s);
        assert!(res.is_ok());
        let res = vault.get_secret_data(name, &s.owner_token);
        assert!(res.is_ok());

        // Test 2 - Create different encryption keys for the existing Vault,
        // and check that the previously stored secret is lost.
        let mut key = [0u8; 32];
        thread_rng().fill(&mut key);
        let orig_keys = vault.keys.clone();
        let keys = EncryptionKeys::new(&key);
        vault.keys = keys;

        let res = vault.get_secret_data(name, &s.owner_token);
        assert_eq!(res, not_found_err);

        // Test 3 - Restore the original encryption keys, but use a different
        // encryption algorithm for the existing Vault. The previously stored
        // secret should now be accessible again.
        vault.keys = orig_keys;
        vault.algo = EncryptionAlgorithm::AES256GCM;
        let res = vault.get_secret_data(name, &s.owner_token);
        assert!(res.is_ok());

        // Test 4 - Duplicate the existing secret with a different name. Make
        // sure that vault cannot decrypt it, due to the use of AD.
        let ciphername = vault._hmac_name(name);
        let ciphertext = vault.kv.get(&ciphername).unwrap();
        let bad_name = "bad_name";
        let bad_ciphername = vault._hmac_name(bad_name);
        let res = vault.kv.set(&bad_ciphername, &ciphertext);
        assert!(res.is_ok());

        let res = vault.get_secret_data(bad_name, &s.owner_token);
        assert_eq!(res, key_inv_err);

        // Test 5 - Ensure that the vault key alone cannot decrypt the secret.
        // Instead, we need to derive a data key from the secret's name to do
        // so.
        let cryptor = vault._get_cryptor_for_secret(&ciphername);
        let res = cryptor.open(&vault.keys.data, &ciphertext);
        assert!(res.is_err());
        let data_key = vault.keys.derive_data_key(name);
        let res = cryptor.open(&data_key, &ciphertext);
        assert!(res.is_ok());
    }

    #[test]
    fn test_operations() {
        // Create a Secret for the test, and get its fields.
        let name = "secret";
        let (owner_token, meta_token, data, meta) =
            secret::tests::default_secret_fields();
        let meta_token = meta_token.unwrap();
        let ok_data = Ok(data.clone().into_bytes());
        let ok_meta = Ok(meta.unwrap().into_bytes());

        // Create a Vault for the test.
        let kv = caves::MemoryCave::new();
        let mut key = [0u8; 32];
        thread_rng().fill(&mut key);
        let vault =
            Vault::new(&key, EncryptionAlgorithm::AES256GCM, Box::new(kv));

        // Define some common errors.
        //
        // NOTE: Since the create/delete operations return a different kind of
        // result, we prepend their errors with an `_`, to distinguish them
        // from the errors of get operations.
        let not_found_err = Err(res::Error::SecretNotFound(name.to_string()));
        let token_inv_err = Err(res::Error::Forbidden(name.to_string()));
        let _not_found_err = Err(res::Error::SecretNotFound(name.to_string()));
        let _token_inv_err = Err(res::Error::Forbidden(name.to_string()));

        // Test 1 - Ensure we get a SecretNotFound error, if the secret does
        // not exist.
        assert_eq!(vault.get_secret_data(name, &owner_token), not_found_err);
        assert_eq!(vault.get_secret_meta(name, &owner_token), not_found_err);
        assert_eq!(vault.delete_secret(name, &owner_token), _not_found_err);

        // Test 2 - If a secret does not exist, we can freely create it. If we
        // pass the stored token, we can then replace it.
        let mut s = secret::tests::create_secret(&[]).unwrap();
        s.data = "initial".to_string();
        let res = vault.create_secret(name, &owner_token, &s);
        assert_eq!(res, Ok(()));
        assert_eq!(
            vault.get_secret_data(name, &owner_token),
            Ok("initial".as_bytes().to_vec())
        );

        s.data = data.clone();
        let res = vault.create_secret(name, &owner_token, &s);
        assert_eq!(res, Ok(()));
        assert_eq!(vault.get_secret_data(name, &owner_token), ok_data);

        // Test 3 - Check that we cannot perform admin actions with the
        // metadata token, except for getting the secret's metadata.
        assert_eq!(vault.get_secret_data(name, &meta_token), token_inv_err);
        assert_eq!(vault.create_secret(name, &meta_token, &s), _token_inv_err);
        assert_eq!(vault.delete_secret(name, &meta_token), _token_inv_err);
        assert_eq!(vault.get_secret_meta(name, &meta_token), ok_meta);

        // Test 4 - Check that we can do everything with the admin token.
        assert_eq!(vault.get_secret_data(name, &owner_token), ok_data);
        assert_eq!(vault.get_secret_meta(name, &owner_token), ok_meta);
        assert_eq!(vault.create_secret(name, &owner_token, &s), Ok(()));
        assert_eq!(vault.delete_secret(name, &owner_token), Ok(()));

        // Test 5 - Check that delete secrets do not resurface.
        assert_eq!(vault.get_secret_data(name, &owner_token), not_found_err);
        assert_eq!(vault.get_secret_meta(name, &owner_token), not_found_err);
        assert_eq!(vault.delete_secret(name, &owner_token), _not_found_err);

        // Test 6 - Check that we can change a secret's stored token, by
        // creating a secret with the new token, but providing the old owner
        // token.
        let res = vault.create_secret(name, &owner_token, &s);
        assert_eq!(res, Ok(()));
        assert_eq!(vault.get_secret_data(name, &owner_token), ok_data);
        assert_eq!(vault.get_secret_meta(name, &meta_token), ok_meta);

        let new_owner_token = "new_owner_token".to_string();
        let new_meta_token = "new_meta_token".to_string();
        s.owner_token = new_owner_token.clone();
        s.meta_token = Some(new_meta_token.clone());
        let res = vault.create_secret(name, &owner_token, &s);
        assert_eq!(res, Ok(()));

        // Subsequent actions with the old owner's token should fail
        assert_eq!(vault.get_secret_data(name, &owner_token), token_inv_err);
        assert_eq!(vault.get_secret_meta(name, &owner_token), token_inv_err);
        // Actions with the new token should succeed though.
        assert_eq!(vault.get_secret_data(name, &new_owner_token), ok_data);
        assert_eq!(vault.get_secret_meta(name, &new_meta_token), ok_meta);
        assert_eq!(vault.delete_secret(name, &new_owner_token), Ok(()));

        // Test 7 - Check that the secret's metadata can be retrieved, even if
        // they, and the metadata token, are empty.
        let mut s = secret::tests::create_secret(&[]).unwrap();
        s.meta_token = Some(String::new());
        s.meta = None;
        let res = vault.create_secret(name, &owner_token, &s);
        assert_eq!(res, Ok(()));

        assert_eq!(vault.get_secret_meta(name, &owner_token), Ok(Vec::new()));
        assert_eq!(vault.get_secret_meta(name, &meta_token), token_inv_err);
    }
}
