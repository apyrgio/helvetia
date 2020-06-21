//! # Secrets
//!
//! This module contains the Rust definition of a Helvetia [`Secret`], and the
//! logic to (de)serialize it.
//!
//! [`Secret`]: struct.Secret.html

use protobuf::Message;

use crate::proto::secret as psecret;
use crate::res;

/// A Helvetia secret.
///
/// A [`Secret`] is a bundle that contains data, metadata, and authentication
/// tokens. The concept is that when one creates a secret, they also define the
/// tokens with which they will subsequently access it.
///
/// A secret can be serialized into a data buffer, and vice versa, via
/// [Protocol Buffers]. For more info, see the [Serialization] section.
/// Note that we use the [`Secret`] struct throughout this crate, instead of
/// the low-level [`proto::secret::Secret`] struct, because it abstracts the
/// protobuf complexity and offers a cleaner and extensible API.
///
/// ## Serialization
///
/// Helvetia uses [Protocol Buffers] to handle the (de)serialization of the
/// [`Secret`] struct. The protobuf definition is under the `proto/` directory,
/// and the generated Rust code is available in the [`proto::secret`] module.
///
/// In a nutshell, the serialization process is the following:
///
/// * Convert a [`Secret`] struct to a [`proto::secret::Secret`] message.
/// * Serialize the [`proto::secret::Secret`] message to a `Vec<u8>`
///   buffer.
///
/// The deserialization process is a bit more involved, as we must also check
/// the integrity of the secret:
///
/// * Deserialize the buffer into a [`proto::secret::Secret`] message. Failure
///   to do so means that the buffer is corrupted.
/// * Convert the [`proto::secret::Secret`] message into a [`Secret`]
///   struct. Failure to do so means that the buffer contains a structurally
///   valid secret, but its fields contain invalid values.
///
/// ### Unset vs. empty strings
///
/// A design choice of Protocol Buffers v3 is to make every field optional and
/// with a default value. For strings, the default value is `""`, meaning that
/// the code cannot distinguish between unset and empty strings. While we can
/// use some [tricks] to detect unset/null fields, in practice we don't need
/// to add extra complexity, as we can just follow these simple rules:
///
/// 1. For fields that *may* be set:
///    * Must be represented as `Option<String>` in [`Secret`].
///    * Empty proto values are converted to `None` and vice versa.
///    * `Some("")` is ambiguous and prohibited.
/// 2. For fields that *must* be set:
///    * Must be represented as `String` in [`Secret`].
///    * `""` is prohibited.
///
/// # Examples
///
/// Here's a way to create a secret, serialize and deserialize it.
///
/// ```
/// use helvetia::secret::Secret;
///
/// let owner_token = "owner_token".to_string();
/// let meta_token = Some("meta_token".to_string());
/// let data = "The cake is a lie".to_string();
/// let meta = Some("Portal".to_string());
///
/// let secret = Secret::new(owner_token, meta_token, data, meta)?;
/// let buf = secret.to_buf();
/// assert_eq!(secret, Secret::from_buf(&buf)?);
///
/// # use helvetia::res;
/// # Ok::<(), res::Error>(())
/// ```
///
/// [`Secret`]: struct.Secret.html
/// [Protocol Buffers]: https://developers.google.com/protocol-buffers/
/// [Serialization]: #serialization
/// [`proto::secret`]: ../proto/secret/index.html
/// [`proto::secret::Secret`]: ../proto/secret/struct.Secret.html
/// [tricks]: https://itnext.io/protobuf-and-null-support-1908a15311b6?gi=cfafc76cad5f
#[derive(Clone, Debug, PartialEq)]
pub struct Secret {
    /// The main token for the secret.
    ///
    /// This token grants full read/write access to the secret. `""` is
    /// prohibited.
    pub owner_token: String,

    /// The metadata-only token for the secret.
    ///
    /// This token is optional and grants read-only access to the secret's
    /// metadata. `Some("")` is prohibited.
    pub meta_token: Option<String>,

    /// The secret's data.
    ///
    /// This field contains the data of the secret. `""` is prohibited.
    pub data: String,

    /// The secret's metadata.
    ///
    /// This field is optional and contains the metadata of the secret.
    /// `Some("")` is prohibited.
    pub meta: Option<String>,
}

impl<'a> Secret {
    /// Create a new secret from user-provided values.
    ///
    /// This function returns an error for fields that are set but empty. For
    /// `Option` fields, this means `Some("")`. For the rationale behind this
    /// restriction, read the [Unset vs. empty strings] paragraph.
    ///
    /// [Unset vs. empty strings]: #unset-vs-empty-strings
    pub fn new(
        owner_token: String,
        meta_token: Option<String>,
        data: String,
        meta: Option<String>,
    ) -> res::Res<Self> {
        // XXX: Once the struct is initialized, a user can alter its fields
        // to have empty values. We could add getters/setters for that, but
        // I don't think it's worth it for now.
        Self::_check_empty_str_field(&owner_token, "owner_token")?;
        Self::_check_empty_str_field(&data, "data")?;
        Self::_check_empty_opt_field(&meta_token, "meta_token")?;
        Self::_check_empty_opt_field(&meta, "meta")?;

        Ok(Self {
            owner_token,
            meta_token,
            data,
            meta,
        })
    }

    /// Return an error if a `String` field is empty (`""`).
    fn _check_empty_str_field(val: &str, field: &str) -> res::Res<()> {
        match val.is_empty() {
            true => Err(res::Error::SecretFieldEmpty(field.to_string())),
            false => Ok(()),
        }
    }

    /// Return an error if an `Option<String>` field is empty (`Some("")`).
    fn _check_empty_opt_field(
        val: &Option<String>,
        field: &str,
    ) -> res::Res<()> {
        match val {
            Some(s) => Self::_check_empty_str_field(s, field),
            _ => Ok(()),
        }
    }

    fn _str_to_opt(val: &str) -> Option<String> {
        match val.is_empty() {
            true => None,
            false => Some(val.to_string()),
        }
    }

    fn _opt_to_str(val: &Option<String>) -> String {
        match val {
            Some(s) => s.to_string(),
            None => String::new(),
        }
    }

    /// Create a secret from the respective protobuf-generated secret.
    ///
    /// This method may return an error, if the protobuf-generated secret
    /// has any empty fields.
    pub fn from_proto(proto_secret: &psecret::Secret) -> res::Res<Self> {
        let tokens = proto_secret.get_auth().get_tokens();
        let data = proto_secret.get_data();

        Self::new(
            tokens.get_owner().to_string(),
            Self::_str_to_opt(tokens.get_meta()),
            data.get_data().to_string(),
            Self::_str_to_opt(data.get_meta()),
        )
    }

    /// Convert a Secret to the respective protobuf-generated secret.
    pub fn to_proto(&self) -> psecret::Secret {
        let mut proto_auth_tokens = psecret::AuthTokens::new();
        proto_auth_tokens.set_owner(self.owner_token.clone());
        proto_auth_tokens.set_meta(Self::_opt_to_str(&self.meta_token));

        let mut proto_auth = psecret::Auth::new();
        proto_auth.set_tokens(proto_auth_tokens);

        let mut proto_data = psecret::Data::new();
        proto_data.set_data(self.data.clone());
        proto_data.set_meta(Self::_opt_to_str(&self.meta));

        let mut proto_secret = psecret::Secret::new();
        proto_secret.set_auth(proto_auth);
        proto_secret.set_data(proto_data);
        proto_secret
    }

    /// Create a Secret from a serialized buffer.
    ///
    /// This method may return an error, if the buffer cannot be deserialized
    /// or if the protobuf-generated secret has any empty fields.
    pub fn from_buf(buf: &'a [u8]) -> res::Res<Self> {
        match protobuf::parse_from_bytes(&buf) {
            Ok(s) => Self::from_proto(&s),
            // FIXME: We may need to log a reason why
            Err(_) => Err(res::Error::SecretInvalid),
        }
    }

    /// Serialize a Secret into a buffer.
    pub fn to_buf(&self) -> Vec<u8> {
        let proto_secret = self.to_proto();

        // NOTE: It's probably safe to unwrap the result here, since the errors
        // it can return are by underlying functions that deal with smaller
        // buffers. In our case, we let the protobuf library create the buffer
        // itself, so any errors should be treated as bugs.
        proto_secret.write_to_bytes().unwrap()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    fn _empty_field_err(field: &str) -> res::Error {
        res::Error::SecretFieldEmpty(field.to_string())
    }

    pub fn default_secret_fields(
    ) -> (String, Option<String>, String, Option<String>) {
        let owner_token = "owner_token".to_string();
        let meta_token = Some("meta_token".to_string());
        let data = "data".to_string();
        let meta = Some("meta".to_string());

        (owner_token, meta_token, data, meta)
    }

    #[derive(Clone, Debug, PartialEq)]
    pub enum SecretField {
        OwnerToken(String),
        MetaToken(Option<String>),
        Data(String),
        Meta(Option<String>),
    }

    /// Create a secret with default arguments, and override them if requested.
    ///
    /// This would be much simpler if Rust had keyword arguments in function
    /// signatures, but I digress...
    pub fn create_secret(args: &[&SecretField]) -> res::Res<Secret> {
        let (mut owner_token, mut meta_token, mut data, mut meta) =
            default_secret_fields();
        for field in args {
            match field {
                SecretField::OwnerToken(s) => owner_token = s.clone(),
                SecretField::MetaToken(o) => meta_token = o.clone(),
                SecretField::Data(s) => data = s.clone(),
                SecretField::Meta(o) => meta = o.clone(),
            }
        }

        Secret::new(owner_token, meta_token, data, meta)
    }

    #[test]
    fn test_secret_creation() {
        // Test 1 - Check that empty fields are detected and return an
        // appropriate error.
        let (owner_token, meta_token, data, meta) = default_secret_fields();
        let empty_str = String::new();
        let empty_opt = Some(String::new());

        for (field, name) in &[
            (SecretField::OwnerToken(empty_str.clone()), "owner_token"),
            (SecretField::MetaToken(empty_opt.clone()), "meta_token"),
            (SecretField::Data(empty_str.clone()), "data"),
            (SecretField::Meta(empty_opt.clone()), "meta"),
        ] {
            let err = create_secret(&[field]);
            assert_eq!(err, Err(_empty_field_err(name)));
        }

        // Test 2 - Check that `None` options pass the validation.
        let secret = create_secret(&[
            &SecretField::MetaToken(None),
            &SecretField::Meta(None),
        ])
        .unwrap();
        assert_eq!(secret.meta_token, None);
        assert_eq!(secret.meta, None);

        // Test 3 - Check that fields are stored as provided.
        let secret = create_secret(&[]).unwrap();
        assert_eq!(secret.owner_token, owner_token);
        assert_eq!(secret.meta_token, meta_token);
        assert_eq!(secret.data, data);
        assert_eq!(secret.meta, meta);
    }

    #[test]
    fn test_secret_proto() {
        // Test 1 - Check that to/from protobuf-generated code works as
        // expected.
        let (owner_token, _, data, _) = default_secret_fields();
        let secret = create_secret(&[]).unwrap();
        let proto_secret = secret.to_proto();
        assert_eq!(Secret::from_proto(&proto_secret), Ok(secret));

        // Ensure that `None` values are preserved.
        let secret = Secret::new(owner_token, None, data, None).unwrap();
        let proto_secret = secret.to_proto();
        assert_eq!(Secret::from_proto(&proto_secret), Ok(secret));

        // Test 2 - Check that invalid proto structs with empty strings are
        // detected and return an error.
        let inv_proto_secret = psecret::Secret::new();
        assert_eq!(
            Secret::from_proto(&inv_proto_secret),
            Err(_empty_field_err(&"owner_token"))
        );
    }

    #[test]
    fn test_secret_buf() {
        // Test 1 - Check that secret serialization/deserialization works
        // properly.
        let secret = create_secret(&[]).unwrap();
        let buf = secret.to_buf();
        assert_eq!(Secret::from_buf(&buf), Ok(secret.clone()));

        // Test 2 - Check that corrupted buffers are detected.
        let invalid_err = Err(res::Error::SecretInvalid);
        assert_eq!(Secret::from_buf("bad".as_bytes()), invalid_err);

        let mut proto_secret = secret.to_proto();
        proto_secret.clear_data();
        let buf = proto_secret.write_to_bytes().unwrap();
        assert_eq!(Secret::from_buf(&buf), Err(_empty_field_err(&"data")));
    }
}
