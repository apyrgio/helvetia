//! # Helvetia
//!
//! Helvetia is a service that allows anonymous storage of secrets, with a
//! simple rule; any user can create a secret using a token, and they can only
//! access it using the same token. Helvetia will then go to great lengths to
//! ensure that the secret remains safe, even from itself.
//!
//! ## Architecture
//!
//! Helvetia can be roughly separated in the following layers, from top to
//! bottom:
//!
//! ### API
//!
//! Helvetia exposes a REST API for basic CRUD operations:
//!
//! * Create or replace a secret.
//! * Read a secret's (meta)data.
//! * Delete a secret.
//!
//! You can find more details about the supported API calls in the [`api`]
//! module.
//!
//! ### Authorization
//!
//! Operations on a secret follow a simple logic; if the secret does not exist,
//! anyone can create it. If it does, only those with a token can view/edit it.
//! Optionally, during secret creation, users can specify a separate token that
//! can be used only for accessing the metadata of the secret.
//!
//! The implementation of this logic can be found in the [`vault`] module.
//!
//! ### Persistence
//!
//! The secrets are stored in a key-value stored provided by the [caves]
//! crate. This gives us the option to store them in-memory, in a filesystem or
//! in a RocksDB database, using the same interface.
//!
//! [`api`]: api/index.html
//! [`vault`]: vault/index.html
//! [caves]: https://docs.rs/caves

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

#[macro_use]
extern crate warp;

#[macro_use]
extern crate anyhow;

pub mod api;
pub mod ct;
pub mod hkdf;
pub mod hmac;
#[path = "../proto/mod.rs"]
pub mod proto;
pub mod res;
pub mod secret;
pub mod vault;
