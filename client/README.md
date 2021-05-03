# 🇨🇭 Helvetia Client

An HTTP client for the [Helvetia] API.

[![CI](https://github.com/apyrgio/helvetia/actions/workflows/CI_client.yaml/badge.svg)](https://github.com/apyrgio/helvetia/actions/workflows/CI_client.yaml)
[![Crates.io](https://img.shields.io/crates/v/helvetia-cliennt.svg)](https://crates.io/crates/helvetia_client)
[![Docs.rs](https://docs.rs/helvetia_client/badge.svg)](https://docs.rs/helvetia_client)

## Overview

The [Helvetia API] is a fully documented REST API, which you can interact with
via an HTTP client. For those that need a Rust interface on top of this API,
they can use this client instead.

## Usage

Here's an example on how you can instantiate the Helvetia client and use it to
create/get/delete a secret:

```rust
use url;
use helvetia_client::client::{Data,Meta,HelvetiaClient};

let owner_token = "owner_token";
let meta_token = "meta_token";
let secret_name = "secret";
let data = "The cake is a lie";
let meta = "Aperture";

// Create a client.
let server_url = url::Url::parse("https://helvetia.example.com")?;
let client = HelvetiaClient::from_url(server_url)?;

// Create a secret.
let data_req = Data::new(owner_token, data);
let meta_req = Meta::new(meta_token, meta);
let res = client.create_secret(secret_name, data_req, Some(meta_req)).await?;
assert_eq!(res, ());

// Get the data of a secret.
let res = client.get_secret_data(secret_name, owner_token).await?;
assert_eq!(&res, data);

// Get the metadata of a secret.
let res = client.get_secret_meta(secret_name, meta_token).await?;
assert_eq!(&res, meta);

// Delete a secret.
let res = client.delete_secret(secret_name, owner_token).await?;
assert_eq!(res, ());
```

## Installation

You can add this crate to your `Cargo.toml` with the following snippet:

```toml
helvetia_client = "0.1"
```

## Contributing

You can read the [`CONTRIBUTING.md`] guide for more info on how to contribute to
this project.

## Legal

Licensed under MPL-2.0. Please read the [`NOTICE.md`] and [`LICENSE`] files for
the full copyright and license information.


[Helvetia]: https://github.com/apyrgio/helvetia
[Helvetia API]: https://docs.rs/helvetia/latest/helvetia/api/index.html
[`CONTRIBUTING.md`]: ../CONTRIBUTING.md
[`NOTICE.md`]: ../NOTICE.md
[`LICENSE`]: ../LICENSE
