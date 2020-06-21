//! # Results and errors
//!
//! In this module, we define the error and result types that Helvetia can
//! return.

use anyhow;
use caves;
use thiserror;
use warp;

/// Alias for a Helvetia result.
pub type Res<T> = Result<T, Error>;
/// Alias for a Helvetia result that contains a data buffer.
pub type Data = Res<Vec<u8>>;
/// Alias for HTTP responses that are accepted by the [warp] create.
///
/// Our API handlers must return an HTTP response that [warp] can use, which
/// practically means that it must implement the [warp::Reply] trait. We choose
/// to return an `http::Response<impl Into<hyper::Body>>` struct, since it
/// is the most expressive of the (currently) supported types.
///
/// [warp]: https://github.com/seanmonstar/warp
/// [warp::Reply]: https://docs.rs/warp/latest/warp/reply/trait.Reply.html
pub type WarpResponse = warp::http::Response<warp::hyper::Body>;

/// Alias for errors from the Caves crate.
pub type CavesError = caves::errors::Error;
/// Alias for errors from the Tindercrypt crate.
pub type TCError = tindercrypt::errors::Error;

/// Errors for every problem that Helvetia may encounter.
///
/// Each enum variant should apply to a different error that Helvetia may
/// encounter. Every variant has its own error message, which gives the
/// context for the error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The secret was not found.
    #[error("Secret with name `{0}` was not found")]
    SecretNotFound(String),

    /// The stored secret is invalid and cannot be deserialized.
    #[error("Unable to deserialize stored secret")]
    SecretInvalid,

    /// The secret cannot be created due to an empty field.
    #[error("Cannot create secret due to an empty field: {0}")]
    SecretFieldEmpty(String),

    /// The user has not provided a token for the operation.
    #[error(
        "You need to pass a token as `Helvetia-Token`, in order to use the \
         API"
    )]
    Unauthorized,

    /// The provided token cannot be used to access a secret.
    #[error("Secret with name `{0}` cannot be accessed")]
    Forbidden(String),

    // FIXME: Can I chain the Tindercrypt and Helvetia errors?
    /// The encryption key cannot be used to decrypt a secret.
    #[error("Cannot decrypt secret with the provided key: {0}")]
    KeyInvalid(anyhow::Error),

    /// An internal error occurred.
    ///
    /// This usually means that a transient error occurred, or that there's a
    /// configuration error.
    #[error("An internal error occurred: {0}")]
    Internal(anyhow::Error),

    /// An unexpected error occurred. This must be a bug on our side.
    #[error("An unexpected error occurred: {0}")]
    Bug(anyhow::Error),
}

// FIXME: It's ugly to define all of our errors here.
impl PartialEq for Error {
    fn eq(&self, other: &Error) -> bool {
        match (self, other) {
            (Error::Bug(_), Error::Bug(_)) => true,
            (Error::Internal(_), Error::Internal(_)) => true,
            (Error::SecretNotFound(s1), Error::SecretNotFound(s2)) => s1 == s2,
            (Error::SecretFieldEmpty(s1), Error::SecretFieldEmpty(s2)) => {
                s1 == s2
            }
            (Error::KeyInvalid(_), Error::KeyInvalid(_)) => true,
            (Error::SecretInvalid, Error::SecretInvalid) => true,
            (Error::Forbidden(s1), Error::Forbidden(s2)) => s1 == s2,
            _ => false,
        }
    }
}

impl From<CavesError> for Error {
    fn from(err: CavesError) -> Self {
        match err {
            CavesError::NotFound(s) => Error::SecretNotFound(s),
            CavesError::Internal(e) => Error::Internal(e),
            CavesError::Bug(e) => Error::Bug(e),
        }
    }
}

impl From<TCError> for Error {
    fn from(err: TCError) -> Self {
        match err {
            TCError::DecryptionError => Error::KeyInvalid(anyhow!(err)),
            _ => Error::Bug(anyhow!(err)),
        }
    }
}

impl From<Error> for WarpResponse {
    fn from(err: Error) -> WarpResponse {
        let body = format!("{}", err);
        let body = warp::hyper::Body::from(body);
        let status = match err {
            Error::SecretFieldEmpty(_) => 400,
            Error::Unauthorized => 401,
            Error::Forbidden(_) => 403,
            Error::SecretNotFound(_) => 404,
            Error::SecretInvalid
            | Error::KeyInvalid(_)
            | Error::Internal(_)
            | Error::Bug(_) => 500,
        };

        warp::http::Response::builder()
            .status(status)
            .body(body)
            .unwrap()
    }
}
