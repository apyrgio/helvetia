use reqwest;
use thiserror;
use url;

/// Alias for a Helvetia client result.
pub type Res<T> = Result<T, Error>;

/// Errors for every problem that the Helvetia client may encounter.
///
/// Each enum variant should apply to a different error that the Helvetia
/// client may encounter. Every variant has its own error message, which gives
/// the explanation for the error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Cannot use the provided URL as the root of the Helvetia API.
    #[error(
        "Cannot use the provided URL as the root URL of the Helvetia API."
    )]
    InvalidUrl,

    /// Cannot use the provided token as an authentication header.
    #[error("Cannot use the provided token as an authentication header")]
    InvalidToken,

    /// Cannot use the provided name as part of the request URL.
    #[error("Cannot use the provided name as part of the request URL")]
    InvalidName(#[from] url::ParseError),

    /// The stored token does not match the provided one.
    #[error("The stored token does not match the provided one")]
    TokenMismatch {
        /// The source of this error.
        source: reqwest::Error,
    },

    /// Could not find the provided secret.
    #[error("Could not find the provided secret")]
    SecretNotFound {
        /// The source of this error.
        source: reqwest::Error,
    },

    /// The size of the secret surpassed a server threshold.
    #[error("The size of the secret surpassed a server threshold")]
    SecretTooLarge {
        /// The source of this error.
        source: reqwest::Error,
    },

    /// An error occurred before the request could complete.
    #[error("An error occurred before the request could complete: {msg:?}")]
    RequestError {
        /// The original error message.
        msg: String,
        /// The source of this error.
        source: reqwest::Error,
    },

    ///An unexpected client error (HTTP 4xx) occurred.
    #[error("An unexpected client error occurred: {msg:?}")]
    ClientError {
        /// The original error message.
        msg: String,
        /// The source of this error.
        source: reqwest::Error,
    },

    ///An unexpected server error (HTTP 5xx) occurred.
    #[error("An unexpected server error occurred: {msg:?}")]
    ServerError {
        /// The original error message.
        msg: String,
        /// The source of this error.
        source: reqwest::Error,
    },

    // This is a catch-all error for any reqwest error that does not fall in
    // one of the above categories. In theory, we should never encounter this
    // error anywhere.
    /// Gasp! A bug in our client logic.
    #[error("The client received an unexpected error response: {msg:?}")]
    Bug {
        /// The original error message.
        msg: String,
        /// The source of this error.
        source: reqwest::Error,
    },
}

impl From<reqwest::header::InvalidHeaderValue> for Error {
    fn from(_err: reqwest::header::InvalidHeaderValue) -> Self {
        Error::InvalidToken
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        let msg = format!("{}", err);
        match err.status() {
            None => Error::RequestError {
                msg: msg,
                source: err,
            },
            Some(s) => {
                let code = s.as_u16();
                if code == 403 {
                    Error::TokenMismatch { source: err }
                } else if code == 404 {
                    Error::SecretNotFound { source: err }
                } else if code == 413 {
                    Error::SecretTooLarge { source: err }
                } else if (code >= 400) && (code < 500) {
                    Error::ClientError {
                        msg: msg,
                        source: err,
                    }
                } else if code >= 500 {
                    Error::ServerError {
                        msg: msg,
                        source: err,
                    }
                } else {
                    Error::Bug {
                        msg: msg,
                        source: err,
                    }
                }
            }
        }
    }
}
