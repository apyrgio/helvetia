//! # Helvetia CLI
//!
//! The Helvetia CLI allows the user to spin up the Helvetia API server.

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

use std::fs;
use std::net::SocketAddr;
use std::path;
use std::sync::Arc;
use tokio;

#[macro_use]
extern crate clap;
#[macro_use]
extern crate strum_macros;
#[macro_use]
extern crate anyhow;

use caves;
use clap::{App, Arg, ArgMatches};
use strum::VariantNames;
use strum_macros::{AsRefStr, EnumString, EnumVariantNames, IntoStaticStr};
use warp;

use helvetia::{api, vault};

#[derive(
    Display,
    Debug,
    EnumString,
    EnumVariantNames,
    AsRefStr,
    IntoStaticStr,
    PartialEq,
)]
#[strum(serialize_all = "lowercase")]
enum Algo {
    AES256GCM,
    ChaCha20Poly1305,
}

#[derive(
    Display,
    Debug,
    EnumString,
    EnumVariantNames,
    AsRefStr,
    IntoStaticStr,
    PartialEq,
)]
#[strum(serialize_all = "lowercase")]
enum KV {
    Memory,
    File,
    RocksDB,
}

fn create_parser<'a, 'b>() -> App<'a, 'b> {
    App::new("Helvetia: Anonymous and secure storage of secrets")
        .version(crate_version!())
        .arg(
            Arg::with_name("keyfile")
                .short("k")
                .long("keyfile")
                .takes_value(true)
                .required(true)
                .help(
                    "A file where the encryption key for the Helvetia server \
                     is stored. The key is read as raw bytes, so no \
                     formatting is necessary.",
                ),
        )
        .arg(
            Arg::with_name("kv")
                .long("kv")
                .takes_value(true)
                .default_value(KV::RocksDB.as_ref())
                .possible_values(&KV::VARIANTS)
                .help("The type of the key-value store that will be used"),
        )
        .arg(
            Arg::with_name("store_dir")
                .long("store-dir")
                .takes_value(true)
                .help(
                    "The directory to store secrets. Applicable only to \
                     file/rocksdb key-value stores",
                ),
        )
        .arg(
            Arg::with_name("algo")
                .long("algo")
                .takes_value(true)
                .default_value(Algo::AES256GCM.as_ref())
                .possible_values(&Algo::VARIANTS)
                .help("The encryption algorithm to be used"),
        )
        .arg(
            Arg::with_name("address")
                .long("address")
                .takes_value(true)
                .default_value("0.0.0.0:1134")
                .help("The host address to listen on"),
        )
        .arg(
            Arg::with_name("max_size")
                .short("s")
                .long("max-size")
                .takes_value(true)
                .help("The maximum allowed size for the provided secret"),
        )
}

/// Create a key-value store based on the provided arguments.
fn create_kv<'a>(m: &ArgMatches<'a>) -> anyhow::Result<Box<dyn caves::Cave>> {
    let store_dir = m.value_of("store_dir");

    // We can safely unwrap and parse the `kv` argument, because:
    // * It always has a default value.
    // * The check for the proper type is already performed by clap.
    let kv = m.value_of("kv").unwrap().parse::<KV>().unwrap();

    // Ensure that the user has provided a directory for key-value stores that
    // are not in-memory.
    if store_dir == None && kv != KV::Memory {
        return Err(anyhow!(
            "Key-value store `{}` requires the `--store-dir` argument",
            kv
        ));
    };

    let store_dir = path::Path::new(store_dir.unwrap_or_default());

    match kv {
        KV::Memory => Ok(Box::new(caves::MemoryCave::new())),
        KV::File => Ok(Box::new(caves::FileCave::new(&store_dir)?)),
        KV::RocksDB => Ok(Box::new(caves::RocksDBCave::new(&store_dir)?)),
    }
}

/// Convert the provided algorithm to the proper enum.
fn parse_algo<'a>(m: &ArgMatches<'a>) -> vault::EncryptionAlgorithm {
    // We can safely unwrap and parse the `algo` argument, because:
    // * It always has a default value.
    // * The check for the proper type is already performed by clap.
    let algo = m.value_of("algo").unwrap().parse::<Algo>().unwrap();
    match algo {
        Algo::AES256GCM => vault::EncryptionAlgorithm::AES256GCM,
        Algo::ChaCha20Poly1305 => vault::EncryptionAlgorithm::ChaCha20Poly1305,
    }
}

/// Read the vault key from the provided file.
fn read_key<'a>(m: &ArgMatches<'a>) -> anyhow::Result<Vec<u8>> {
    // The keyfile is a required argument, so we can safely unwrap it.
    let keyfile = m.value_of("keyfile").unwrap();
    Ok(fs::read(keyfile)?)
}

#[tokio::main]
async fn run<'a>(m: &ArgMatches<'a>) -> anyhow::Result<()> {
    let kv = create_kv(&m)?;
    let algo = parse_algo(&m);
    let key = read_key(&m)?;
    let vault = vault::Vault::new(&key, algo, kv);

    let handlers = api::Handlers::new(vault);
    let handlers = match m.value_of("max_size") {
        Some(size) => {
            // FIXME: We should parse the size in a prettier way, e.g., accept
            // strings with units.
            handlers.with_content_length_limit(size.parse::<usize>()?)
        }
        None => handlers,
    };
    let routes = api::routes(Arc::new(handlers));
    // The address argument always has a default, so we can safely unwrap it.
    let addr = m.value_of("address").unwrap().parse::<SocketAddr>()?;

    warp::serve(routes).run(addr).await;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let parser = create_parser();
    let matches = parser.get_matches();
    run(&matches)
}
