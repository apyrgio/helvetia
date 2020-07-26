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
    // XXX: Disabled because the assert functions of `assert_cmd` always
    // returns self.
    //unused_results,
    variant_size_differences
)]

use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use predicates::prelude::*;

use assert_cmd::Command;
use std::net;
use std::panic;
use std::thread;
use std::time;

use reqwest;

/// Simply run the CLI command.
fn cli() -> Command {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    cmd.env_clear();
    cmd
}

/// Check if the Helvetia server can accept requests.
///
/// The check is pretty simple:
///
/// 1. Ensure that the command is running.
/// 2. Ensure that we can establish a TCP connection to the server.
/// 3. Ensure that a request on a wrong URL fails with HTTP 404.
fn is_ready(srv: &mut std::process::Child, port: u16) -> bool {
    match srv.try_wait() {
        Ok(None) => (),
        Ok(Some(status)) => {
            panic!("Server {:?} exited with status: {:?}", srv, status)
        }
        Err(e) => {
            panic!("Waiting for server {:?} failed with error: {:?}", srv, e)
        }
    };

    let client = reqwest::blocking::Client::new();
    let res = client
        .get(&format!("http://127.0.0.1:{}/nonexistent", port))
        .send();

    match res {
        //XXX: Previously, we had a check that would ensure that the TCP
        //connection works, before sending an HTTP request. This way, we could
        //just check if the HTTP response is 404, else panic. However, our
        //CI tests in Github Actions would sometimes fail with the following
        //error:
        //
        //     thread 'test_server' panicked at
        //     'called `Result::unwrap()` on an `Err` value: reqwest::Error
        //     {
        //         kind: Request,
        //         url: "http://127.0.0.1:40841/nonexistent",
        //         source: hyper::Error(
        //             Connect,
        //             ConnectError(
        //                 "tcp connect error",
        //                 Os {
        //                     code: 111,
        //                     kind: ConnectionRefused,
        //                     message: "Connection refused"
        //                  }
        //              )
        //          )
        //      }'
        //
        // We never found a way to reproduce the above error locally, so we
        // decided instead to treat every HTTP error as a benign error, and
        // retry instead of panicking. Even if the error is fatal, the retry
        // should last for 5 seconds, so in the end we will be notified.
        Err(_) => false,
        Ok(response) => response.status().as_u16() == 404,
    }
}

/// Start the Helvetia server.
///
/// Start the Helvetia server in a way that even when restarted, we can still
/// query its state. To do this, we require:
///
/// 1. A directory to store the RocksDB files.
/// 2. A Helvetia key.
fn serve(store_dir: &str, key: &str, port: u16) -> std::process::Child {
    // XXX: We start the command this way so that we can get an
    // `std::process::Child` as result.
    let mut cmd =
        std::process::Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    cmd.args(&["--keyfile", key])
        .args(&["--address", &format!("127.0.0.1:{}", port)])
        .args(&["--store-dir", store_dir])
        .args(&["--kv", "rocksdb"])
        .args(&["--max-size", "1000"])
        .spawn()
        .unwrap()
}

/// Ensure that the Helvetia server is running and is healthy.
fn ensure_server_ready(srv: &mut std::process::Child, port: u16) {
    // Check every 10 ms if the Helvetia server is ready, for a total of 5
    // seconds.
    for _ in 0..500 {
        if is_ready(srv, port) {
            return ();
        }
        thread::sleep(time::Duration::from_millis(10));
    }

    kill_server(srv);
    panic!("The server could not become ready after 5 seconds")
}

/// Kill a running Helvetia server.
fn kill_server(srv: &mut std::process::Child) {
    srv.kill().unwrap();
    srv.wait().unwrap();
}

/// Attempt to get a random port to listen on.
///
/// This is the common "bind to 0" trick, adapted for Rust and taken from here:
/// https://rust-lang-nursery.github.io/rust-cookbook/net/server.html
fn get_random_port() -> u16 {
    // XXX: We have put this code block in a separate function since the
    // listener socket closes only when `TcpListener` goes out of scope.
    let loopback = net::Ipv4Addr::new(127, 0, 0, 1);
    let socket = net::SocketAddrV4::new(loopback, 0);
    let listener = net::TcpListener::bind(socket).unwrap();
    let port = listener.local_addr().unwrap().port();
    port
}

/// Start an Helvetia server and run a funtion.
///
/// In order to always stop the server when the function aborts, the easiest
/// way is to use `panic::catch_unwind()` function [1].
///
/// [1] https://medium.com/@ericdreichert/test-setup-and-teardown-in-rust-without-a-framework-ba32d97aa5ab
fn with_server<F>(temp_dir: &assert_fs::TempDir, f: F)
where
    F: Fn(u16) + std::panic::RefUnwindSafe,
{
    let temp_store_dir = temp_dir.child("store");
    let temp_key_file = temp_dir.child("key");
    temp_key_file.write_str("secret").unwrap();

    let port = get_random_port();

    let mut srv = serve(
        &temp_store_dir.path().to_str().unwrap(),
        &temp_key_file.path().to_str().unwrap(),
        port,
    );

    ensure_server_ready(&mut srv, port);
    let result = panic::catch_unwind(|| f(port));

    kill_server(&mut srv);
    assert!(result.is_ok());
}

#[test]
fn test_server() {
    let temp_dir = assert_fs::TempDir::new().unwrap();

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "Helvetia-Token",
        reqwest::header::HeaderValue::from_static("owner_token"),
    );

    // Test 1 - Check that we can run a server and store a secret successfully.
    with_server(&temp_dir, |port: u16| {
        let mut map = std::collections::HashMap::new();
        map.insert("owner_token", "owner_token");
        map.insert("data", "data");

        let client = reqwest::blocking::Client::new();
        client
            .put(&format!("http://127.0.0.1:{}/v0/secrets/secret", port))
            .headers(headers.clone())
            .json(&map)
            .send()
            .unwrap()
            .error_for_status()
            .unwrap();

        let body = client
            .get(&format!("http://127.0.0.1:{}/v0/secrets/secret/data", port))
            .headers(headers.clone())
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .unwrap();

        assert_eq!(body, "data")
    });

    // Test 2 - Check that we can restart the server and retrieve the stored
    // secret.
    with_server(&temp_dir, |port: u16| {
        let client = reqwest::blocking::Client::new();
        let body = client
            .get(&format!("http://127.0.0.1:{}/v0/secrets/secret/data", port))
            .headers(headers.clone())
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .unwrap();

        assert_eq!(body, "data")
    });

    // Test 3 - Check that the max size is respected.
    with_server(&temp_dir, |port: u16| {
        let large_data = "a".repeat(1000);
        let mut map = std::collections::HashMap::new();
        map.insert("owner_token", "owner_token");
        map.insert("data", &large_data);

        let client = reqwest::blocking::Client::new();
        let res = client
            .put(&format!("http://127.0.0.1:{}/v0/secrets/large", port))
            .headers(headers.clone())
            .json(&map)
            .send()
            .unwrap();

        assert_eq!(res.status().as_u16(), 413)
    });
}

#[test]
fn test_invalid_args() {
    let temp_dir = assert_fs::TempDir::new().unwrap();
    temp_dir.child("key").write_str("secret").unwrap();

    // Test required arguments:
    //
    // * Test not provided key
    cli()
        .current_dir(temp_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("required arguments"))
        .stderr(predicate::str::contains("--keyfile <keyfile>"));

    // Test invalid choices:
    //
    // * Test bad kv
    // * Test bad algo
    cli()
        .args(&["--kv", "badkv"])
        .args(&["--keyfile", "nonexistent"])
        .current_dir(temp_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "'badkv' isn't a valid value for '--kv <kv>'",
        ));

    cli()
        .args(&["--algo", "badalgo"])
        .args(&["--keyfile", "nonexistent"])
        .current_dir(temp_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "'badalgo' isn't a valid value for '--algo <algo>'",
        ));

    // Test requirements for key-value stores.
    //
    // * Test no store dir
    // * Test non-existent store dir
    // * Test bad store dir
    for kv in &["file", "rocksdb"] {
        cli()
            .args(&["--kv", kv])
            .args(&["--keyfile", "nonexistent"])
            .current_dir(temp_dir.path())
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "requires the `--store-dir` argument",
            ));

        cli()
            .args(&["--kv", kv])
            .args(&["--store-dir", "/this/is/a/bad/file"])
            .current_dir(temp_dir.path())
            .assert()
            .failure();

        cli()
            .args(&["--kv", kv])
            .args(&["--store-dir", "key"])
            .current_dir(temp_dir.path())
            .assert()
            .failure();
    }

    // Test bad key
    cli()
        .args(&["--keyfile", "nonexistent"])
        .args(&["--kv", "memory"])
        .current_dir(temp_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("No such file or directory"));

    // Test bad address
    cli()
        .args(&["--keyfile", "key"])
        .args(&["--kv", "memory"])
        .args(&["--address", "bad"])
        .current_dir(temp_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid IP address syntax"));

    // Test bad max size
    cli()
        .args(&["--keyfile", "key"])
        .args(&["--max-size", "badsize"])
        .args(&["--kv", "memory"])
        .current_dir(temp_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid digit found in string"));
}
