# 🇨🇭 Helvetia

A library and API server that allows for anonymous storage of secrets, with a
simple rule; any user can create a secret using a token, and they can only
access it using the same token. Helvetia will then go to great lengths to ensure
that the secret remains safe, even from itself.

[![Crates.io](https://img.shields.io/crates/v/helvetia.svg)](https://crates.io/crates/helvetia)
[![Docs.rs](https://docs.rs/helvetia/badge.svg)](https://docs.rs/helvetia)

## Overview

Helvetia can be used either as a standalone API server or as a library. In the
first case, you can interact with it using its REST API, while in the second
case you can interact with it through its [`vault`] module.

The way Helvetia works is pretty simple. Users first need to create a secret,
which consists of the following parts:

* Name
* Data, which contain the secret that a user wants to store
* _[optional]_ Metadata, which can be any type of data that relate to the secret,
  but may be less sensitive.
* Token, which can be used to provide full access to the secret.
* _[optional]_ Metadata token, which can be used to retrieve only the metadata.

Helvetia will then do the following to ensure that the secret is stored
securely:

* Hash the secret's name and tokens.
* Encrypt the secret using a single-use key, derived by Helvetia's encryption
  key and the secret's name.
* Store the key-value pair to the underlying key-value store.

Helvetia has **not** undergone a security audit and is **not** ready for use in
production. Prefer using other services such as Hashicorp's [Vault], if you
have a use-case that requires such guarantees. If you're feeling adventurous
though and like some of the following features, you are more than welcome to try
Helvetia out:

1. No accounts; allow everyone to create a secret using just a token.
2. Optionally provide different access to a secret's metadata via a more limited
   token.
3. Encryption at rest with name hashing.
4. Single binary with no dependencies, so it's easy to deploy.
5. Allow users to create secrets with memorable names.
6. [Weak perfect forward secrecy]; if the encryption keys are compromised after
   the secret has been stored, the secret can be decrypted only if the attacker
   guesses the secret's name.
7. Provide data integrity assurance every time the secret is accessed, because
   it must be decrypted first.
8. Written in Rust, thus we are protected against a class of problems.
9. Easy to cryptographically destroy the stored secrets, even if the storage
   backend is compromised; simply delete the encryption key.
10. Supports an easy to expand list of encryption algorithms (through
   [Tindercrypt]) and storage backends (through [Caves]).
11. Allow limits on the uploaded secret size.

## Usage

In order to run the Helvetia API server, you need to create an encryption key
and provide a directory to store the encrypted secrets. For instance, you can
do:

```console
$ mkdir ~/.helvetia
$ cd ~/.helvetia
$ head -c 32 /dev/urandom > key
$ helvetia -k key --store-dir data
```

By default, Helvetia will store the secrets in a RocksDB database, and encrypt
them using AES-256-GCM. To see the rest of the available options, you can do
`helvetia --help`.

## Documentation

You can read the latest docs in https://docs.rs/helvetia. The following sections
may be of interest:

* [Architecture]
* [REST API]
* [Security]

## Installation

### As a library

When adding this crate to your `Cargo.toml`, add it with `default-features =
false`, to ensure that CLI specific dependencies are not added to your
dependency tree:

```toml
helvetia = { version = "x.y.z", default-features = false }
```

### As a binary

You can run Helvetia using one of the binaries of the [stable releases], or
the [nightly builds]. Alternatively, you can install it with one of the
following methods:

* From cargo:

  ```
  $ cargo install helvetia
  ```

* From source:

  ```
  $ git clone https://github.com/apyrgio/helvetia
  $ cd helvetia
  $ cargo build --release
  $ ./target/release/helvetia --help
  Helvetia: Anonymous and secure storage of secrets...
  ```

## Contributing

You can read the [`CONTRIBUTING.md`] guide for more info on how to contribute to
this project.

## Legal

Licensed under MPL-2.0. Please read the [`NOTICE.md`] and [`LICENSE`] files for
the full copyright and license information.

[Vault]: https://www.vaultproject.io/
[`vault`]: https://docs.rs/helvetia/latest/helvetia/vault/
[Weak perfect forward secrecy]: https://en.wikipedia.org/wiki/Forward_secrecy#Weak_perfect_forward_secrecy
[Tindercrypt]: https://github.com/apyrgio/tindercrypt
[Caves]: https://github.com/apyrgio/caves
[docs]: https://docs.rs/helvetia/latest/helvetia
[REST API]: https://docs.rs/helvetia/latest/helvetia/api/index.html
[Architecture]: https://docs.rs/helvetia/latest/helvetia/#architecture
[Security]: https://docs.rs/helvetia/latest/helvetia/vault/struct.Vault.html
[stable releases]: https://github.com/apyrgio/helvetia/releases
[nightly builds]: https://github.com/apyrgio/helvetia/actions?query=event%3Aschedule+branch%3Amaster
[`CONTRIBUTING.md`]: CONTRIBUTING.md
[`NOTICE.md`]: NOTICE.md
[`LICENSE`]: LICENSE
