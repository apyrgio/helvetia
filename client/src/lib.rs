//! # Helvetia Client
//!
//! This library contains an HTTP client for the [Helvetia] API. It follows the
//! [v0 API spec].
//!
//! ## Example
//!
//! There are three main operations that this client supports: create a secret,
//! get its data/metadata, delete a secret. Here's an example of all three:
//!
//! ```no_run
//! # use helvetia_client::Res;
//! # use tokio;
//! # #[tokio::main]
//! # async fn main() -> Res<()> {
//! use url;
//! use helvetia_client::{Data,Meta,HelvetiaClient};
//!
//! let owner_token = "owner_token";
//! let meta_token = "meta_token";
//! let secret_name = "secret";
//! let data = "The cake is a lie";
//! let meta = "Aperture";
//!
//! // Create a client.
//! let server_url = url::Url::parse("https://helvetia.example.com")?;
//! let client = HelvetiaClient::from_url(server_url)?;
//!
//! // Create a secret.
//! let data_req = Data::new(owner_token, data);
//! let meta_req = Meta::new(meta_token, meta);
//! let res = client.create_secret(secret_name, data_req, Some(meta_req)).await?;
//! assert_eq!(res, ());
//!
//! // Get the data of a secret.
//! let res = client.get_secret_data(secret_name, owner_token).await?;
//! assert_eq!(&res, data);
//!
//! // Get the metadata of a secret.
//! let res = client.get_secret_meta(secret_name, meta_token).await?;
//! assert_eq!(&res, meta);
//!
//! // Delete a secret.
//! let res = client.delete_secret(secret_name, owner_token).await?;
//! assert_eq!(res, ());
//!
//! # Ok(())
//! # }
//! ```
//!
//! [Helvetia]: https://docs.rs/helvetia
//! [v0 API spec]: https://docs.rs/helvetia/latest/helvetia/api/index.html

#![deny(
    warnings,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications,
    unused_extern_crates,
    unused_must_use,
    unused_results,
    variant_size_differences
)]

mod client;
mod errors;

pub use crate::client::{Data, HelvetiaClient, Meta};
pub use crate::errors::{Error, Res};
