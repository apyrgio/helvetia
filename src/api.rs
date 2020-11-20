//! # Helvetia API
//!
//! This module contains the API logic of Helvetia, which is basically a
//! thin layer over Helvetia's [`Vault`]. We use [warp] for the handling of
//! HTTP requests/responses and [serde] for the (de)serialization of JSON
//! strings.
//!
//! ## API calls
//!
//! All API calls expect the header `Helvetia-Token`, with the token for each
//! operation. If the header is not provided, the request will fail with `401
//! Unauthorized`. Also, all request data are in JSON format so make sure to
//! encode any binary payloads first, e.g., in Base64.
//!
//! Below is a list of the supported API calls. We use the `v0/` prefix because
//! the API is not finalized yet, and things may break.
//!
//! ### PUT v0/secrets/{secret}
//!
//! Create or replace a secret with name `{secret}`.
//!
//! ##### Request
//!
//! Expects the following request body in JSON:
//!
//! ```text
//! {
//!     "owner_token": string,
//!     "meta_token": string, // optional
//!     "data": string,
//!     "meta": string,  // optional
//! }
//! ```
//!
//! ##### Response
//!
//! Returns `204 No Content` for successful operations. Else, returns one of
//! the following error codes:
//!
//! * `400 Bad Request`:
//!   * When a required field is not present in the request body, or is empty.
//!   * When the request body is not valid JSON.
//! * `401 Unauthorized`: When the `Helvetia-Token` header is not provided.
//! * `403 Forbidden`: When `Helvetia-Token` does not match the stored token.
//! * `411 Length Required`: When the `Content-Length` header is missing.
//! * `413 Payload Too Large`: When the request body is larger than a
//!   deployment-specific limit.
//!
//! ### GET v0/secrets/{secret}/data
//!
//! Get the data of a secret with name `{secret}`.
//!
//! ##### Response
//!
//! Returns `200 OK` for successful operations, with the secret's data in the
//! response's body. Else, returns one of the following error codes:
//!
//! * `401 Unauthorized`: When the `Helvetia-Token` header is not provided.
//! * `403 Forbidden`: When `Helvetia-Token` does not match the stored token.
//! * `404 Not Found`: When the secret with name `{secret}` does not exist.
//!
//! ### GET v0/secrets/{secret}/meta
//!
//! Get the metadata of a secret with name `{secret}`. For this operation and
//! only, the user can provide the metadata token.
//!
//! ##### Response
//!
//! Returns `200 OK` for successful operations, with the secret's metadata in
//! the response's body. Else, returns one of the following error codes:
//!
//! * `401 Unauthorized`: When the `Helvetia-Token` header is not provided.
//! * `403 Forbidden`: When `Helvetia-Token` does not match the stored token.
//! * `404 Not Found`: When the secret with name `{secret}` does not exist.
//!
//! ### DELETE v0/secrets/{secret}
//!
//! Delete a secret with name `{secret}`.
//!
//! ##### Response
//!
//! Returns `204 No Content` for successful operations. Else, returns one of
//! the following error codes:
//!
//! * `401 Unauthorized`: When the `Helvetia-Token` header is not provided.
//! * `403 Forbidden`: When `Helvetia-Token` does not match the stored token.
//! * `404 Not Found`: When the secret with name `{secret}` does not exist.
//!
//! [`Vault`]: ../vault/struct.Vault.html
//! [warp]: https://github.com/seanmonstar/warp
//! [serde]: https://serde.rs/
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use warp::filters::BoxedFilter;
use warp::Filter;

use crate::{res, secret, vault};

/// The name of the HTTP header for the Helvetia token.
pub const HELVETIA_TOKEN_HEADER: &str = "Helvetia-Token";

/// The JSON body of the PUT request.
///
/// This struct represents the JSON body of the PUT request. It is
/// (de)serialized to/from JSON using [serde].
///
/// [serde]: https://serde.rs/
#[derive(Deserialize, Serialize, Debug)]
pub struct PutSecretReq {
    /// The token used to grant full access to the secret.
    pub owner_token: String,

    /// (optional) The token used to access only the secret's metadata.
    #[serde(default)]
    pub meta_token: String,

    /// The secret's data.
    pub data: String,

    /// (optional) The secret's metadata.
    #[serde(default)]
    pub meta: String,
}

/// An enumeration of all the possible API actions
///
/// Any API action that expects additional fields, e.g., like Create which
/// expects the body of the request, should specify them in their variant.
enum Action {
    GetData,
    GetMeta,
    Create(PutSecretReq),
    Delete,
}

/// Constructor for [warp] routes.
///
/// This function:
///
/// * accepts a [`Handlers`] struct, which contains the logic for handling each
///   HTTP request,
/// * internally creates the necessary [warp] filters to handle each request,
///   and
/// * returns a `warp::BoxedFilter` instance, which can be used to start a
///   [warp] server.
///
/// The [`Handlers`] struct must be behind an `Arc` reference, since it will
/// be used by multiple threads.
///
/// [warp]: https://github.com/seanmonstar/warp
/// [`Handlers`]: struct.Handlers.html
pub fn routes(handlers: Arc<Handlers>) -> BoxedFilter<(impl warp::Reply,)> {
    // XXX: Warp rejections are a bit hard to work with [1], so we prefer to
    // implement a decorator pattern, instead of using the `.recover()` method.
    // In this case, this is required to ensure that a missing token header
    // returns HTTP 401, instead of HTTP 400, which is the default behavior in
    // warp.
    //
    // [1]: https://github.com/seanmonstar/warp/issues/451
    let token =
        warp::filters::header::optional::<String>(HELVETIA_TOKEN_HEADER);
    let path = path!("v0" / "secrets" / String / ..);

    let main_rules = token.and(path);

    // GET /v0/secrets/<secret>/data
    let h1 = Arc::clone(&handlers);
    let secret_data_get_route = main_rules
        .and(path!("data"))
        .and(warp::get())
        .map(move |h, n| h1.handle(Action::GetData, h, n));

    // GET /v0/secrets/<secret>/data
    let h2 = Arc::clone(&handlers);
    let secret_meta_get_route = main_rules
        .and(path!("meta"))
        .and(warp::get())
        .map(move |h, n| h2.handle(Action::GetMeta, h, n));

    // PUT /v0/secrets/<secret>
    let body_limit = match handlers.content_length_limit {
        Some(size) => warp::body::content_length_limit(size as u64).boxed(),
        None => warp::any().boxed(),
    };

    let body_type = warp::body::json();
    let h3 = Arc::clone(&handlers);
    let secret_put_route = main_rules
        .and(warp::path::end())
        .and(warp::put())
        .and(body_limit)
        .and(body_type)
        .map(move |h, n, b| h3.handle(Action::Create(b), h, n));

    // DELETE /v0/secrets/<secret>
    let h4 = Arc::clone(&handlers);
    let secret_delete_route = main_rules
        .and(warp::path::end())
        .and(warp::delete())
        .map(move |h, n| h4.handle(Action::Delete, h, n));

    secret_data_get_route
        .or(secret_meta_get_route)
        .or(secret_put_route)
        .or(secret_delete_route)
        .boxed()
}

/// The handlers for each API request.
#[allow(missing_debug_implementations)]
pub struct Handlers {
    vault: vault::Vault,
    content_length_limit: Option<usize>,
}

impl Handlers {
    /// Initialize a handler using a Vault.
    pub fn new(vault: vault::Vault) -> Self {
        Self {
            vault,
            content_length_limit: None,
        }
    }

    /// Specify a limit for the content length.
    pub fn with_content_length_limit(self, size: usize) -> Self {
        let mut handlers = Self::new(self.vault);
        handlers.content_length_limit = Some(size);
        handlers
    }

    fn empty(&self) -> res::Data {
        Ok(Vec::new())
    }

    fn unauthorized(&self) -> res::WarpResponse {
        res::Error::Unauthorized.into()
    }

    fn reply(&self, res: res::Data) -> res::WarpResponse {
        match res {
            Ok(t) => {
                let status = match t.is_empty() {
                    true => 204,
                    false => 200,
                };
                let body = warp::hyper::Body::from(t);
                warp::http::Response::builder()
                    .status(status)
                    .body(body)
                    .unwrap()
            }
            Err(e) => e.into(),
        }
    }

    /// Handle all API requests.
    fn handle(
        &self,
        action: Action,
        token: Option<String>,
        name: String,
    ) -> res::WarpResponse {
        let token = match token {
            Some(t) => t,
            None => return self.unauthorized(),
        };

        let res = match action {
            Action::GetData => self.get_secret_data(&token, &name),
            Action::GetMeta => self.get_secret_meta(&token, &name),
            Action::Create(b) => self.put_secret(&token, &name, b),
            Action::Delete => self.delete_secret(&token, &name),
        };

        self.reply(res)
    }

    /// Handler for `GET v0/secrets/{secret}/data`
    fn get_secret_data(&self, token: &str, name: &str) -> res::Data {
        self.vault.get_secret_data(&name, &token)
    }

    /// Handler for `GET v0/secrets/{secret}/meta`
    fn get_secret_meta(&self, token: &str, name: &str) -> res::Data {
        self.vault.get_secret_meta(&name, &token)
    }

    /// Handler for `PUT v0/secrets/{secret}`
    fn put_secret(
        &self,
        token: &str,
        name: &str,
        body: PutSecretReq,
    ) -> res::Data {
        let owner_token = body.owner_token;
        let meta_token = match body.meta_token.is_empty() {
            true => None,
            false => Some(body.meta_token),
        };
        let data = body.data;
        let meta = match body.meta.is_empty() {
            true => None,
            false => Some(body.meta),
        };

        let secret = secret::Secret::new(owner_token, meta_token, data, meta)?;
        let res = self.vault.create_secret(&name, &token, &secret);
        res.and(self.empty())
    }

    /// Handler for `DELETE v0/secrets/{secret}`
    pub fn delete_secret(&self, token: &str, name: &str) -> res::Data {
        self.vault.delete_secret(&name, &token).and(self.empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{thread_rng, Rng};

    const NAME: &str = "secret";

    /// Helper for creating a vault.
    fn create_vault() -> vault::Vault {
        let kv = caves::MemoryCave::new();
        let mut key = [0u8; 32];
        thread_rng().fill(&mut key);
        vault::Vault::new(
            &key,
            vault::EncryptionAlgorithm::AES256GCM,
            Box::new(kv),
        )
    }

    /// Helper for creating and storing a secret in a vault.
    fn create_secret(vault: &vault::Vault) -> secret::Secret {
        let s = secret::tests::create_secret(&[]).unwrap();
        let _ = vault.create_secret(NAME, &s.owner_token, &s).unwrap();
        s
    }

    /// Helper for creating the HTTP routes.
    fn create_routes(
        vault: vault::Vault,
        limit: Option<usize>,
    ) -> BoxedFilter<(impl warp::Reply,)> {
        let handlers = Handlers {
            vault,
            content_length_limit: limit,
        };
        let handlers = Arc::new(handlers);
        routes(handlers)
    }

    /// Helper for performing a PUT request with a generic secret.
    fn _put() -> warp::test::RequestBuilder {
        let (owner_token, meta_token, data, meta) =
            secret::tests::default_secret_fields();
        let req_body = PutSecretReq {
            owner_token: owner_token,
            meta_token: meta_token.unwrap(),
            data: data,
            meta: meta.unwrap(),
        };

        warp::test::request()
            .method("PUT")
            .json(&req_body)
            .header(HELVETIA_TOKEN_HEADER, &req_body.owner_token)
            .path(&format!("/v0/secrets/{}", NAME))
    }

    /// Helper for performing a GET (data) request.
    fn _get_data() -> warp::test::RequestBuilder {
        let (owner_token, _, _, _) = secret::tests::default_secret_fields();
        warp::test::request()
            .method("GET")
            .header(HELVETIA_TOKEN_HEADER, owner_token)
            .path(&format!("/v0/secrets/{}/data", NAME))
    }

    /// Helper for performing a GET (metadata) request.
    fn _get_meta() -> warp::test::RequestBuilder {
        let (_, meta_token, _, _) = secret::tests::default_secret_fields();
        warp::test::request()
            .method("GET")
            .header(HELVETIA_TOKEN_HEADER, &meta_token.unwrap())
            .path(&format!("/v0/secrets/{}/meta", NAME))
    }

    /// Helper for performing a DELETE request.
    fn _delete() -> warp::test::RequestBuilder {
        let (owner_token, _, _, _) = secret::tests::default_secret_fields();
        warp::test::request()
            .method("DELETE")
            .header(HELVETIA_TOKEN_HEADER, owner_token)
            .path(&format!("/v0/secrets/{}", NAME))
    }

    #[tokio::test]
    async fn test_put_secret() {
        let vault = create_vault();
        let routes = create_routes(vault, Some(1 << 10));
        let (_, _, data, meta) = secret::tests::default_secret_fields();

        // Test 1 - Test successful operations [204].
        //
        // Check that create/replace return 204 and an empty body as a
        // response. Also, check if the generic secret has been stored as
        // expected.
        let res = _put().reply(&routes).await;
        assert_eq!(res.status(), 204);
        assert_eq!(res.body(), "");
        let res = _put().reply(&routes).await;
        assert_eq!(res.status(), 204);
        assert_eq!(res.body(), "");

        let res = _get_data().reply(&routes).await;
        assert_eq!(res.body(), &data);
        let res = _get_meta().reply(&routes).await;
        assert_eq!(res.body(), &meta.unwrap());

        // Check that missing meta/meta_token fields are tolerated.
        let res = _put()
            .body(r#"{"owner_token": "owner_token", "data": "data"}"#)
            .path("/v0/secrets/secret2")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 204);

        let res = _get_meta()
            .header(HELVETIA_TOKEN_HEADER, "owner_token")
            .path("/v0/secrets/secret2/meta")
            .reply(&routes)
            .await;
        assert_eq!(res.body(), "");

        // Check that we can replace the tokens of a secret, by providing the
        // old owner token.
        let res = _put()
            // Provide the previous token...
            .header(HELVETIA_TOKEN_HEADER, "owner_token")
            // ... but specify a new one.
            .body(r#"{"owner_token": "owner_token_new", "data": "data"}"#)
            .path("/v0/secrets/secret2")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 204);

        // Test 2 - Test bad requests [400].
        //
        // Check that request bodies that don't contain a valid JSON fail.
        let res = _put().body(vec![0u8; 9]).reply(&routes).await;
        assert_eq!(res.status(), 400);

        // Check that empty required fields are detected.
        let bad_secret = PutSecretReq {
            owner_token: "".to_string(),
            meta_token: "meta_token".to_string(),
            data: "data".to_string(),
            meta: "meta".to_string(),
        };

        let res = _put().json(&bad_secret).reply(&routes).await;
        assert_eq!(res.status(), 400);
        assert_eq!(
            res.body(),
            "Cannot create secret due to an empty field: owner_token"
        );

        // Test 3 - Test forbidden requests [403].
        //
        // Check that we can't replace a secret, using a wrong token.
        let res = _put()
            .header(HELVETIA_TOKEN_HEADER, "badtoken")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 403);

        // Test 4 - Length checks [411, 413].
        //
        // Check that missing `Content-Length` headers are detected.
        let res = warp::test::request()
            .method("PUT")
            .path("/v0/secrets/secret")
            .reply(&routes)
            .await;

        assert_eq!(res.status(), 411);

        // Check that request bodies are detected, if they pass a certain
        // limit.
        let res = _put().body(vec![0u8; 2 << 10]).reply(&routes).await;
        assert_eq!(res.status(), 413);
    }

    #[tokio::test]
    async fn test_get_secret_data() {
        let vault = create_vault();
        let secret = create_secret(&vault);
        let routes = create_routes(vault, None);

        // Test 1 - Test successful operations [200].
        let res = _get_data().reply(&routes).await;
        assert_eq!(res.status(), 200);
        assert_eq!(res.body(), &secret.data);

        // Test 2 - Test forbidden requests [403].
        let res = _get_data()
            .header(HELVETIA_TOKEN_HEADER, "bad_token")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 403);

        // Test 3 - Test not found [404].
        let res = _get_data()
            .path("/v0/secrets/nonexistent/data")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 404);
    }

    #[tokio::test]
    async fn test_get_secret_meta() {
        let vault = create_vault();
        let secret = create_secret(&vault);
        let routes = create_routes(vault, None);

        // Test 1 - Test successful operations [200].
        let res = _get_meta().reply(&routes).await;
        assert_eq!(res.status(), 200);
        assert_eq!(res.body(), &secret.meta.unwrap());

        // Test 2 - Test forbidden requests [403].
        let res = _get_meta()
            .header(HELVETIA_TOKEN_HEADER, "bad_token")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 403);

        // Test 3 - Test not found [404].
        let res = _get_meta()
            .path("/v0/secrets/nonexistent/meta")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 404);
    }

    #[tokio::test]
    async fn test_delete_secret() {
        let vault = create_vault();
        let _ = create_secret(&vault);
        let routes = create_routes(vault, None);

        // Test 1 - Test forbidden requests [403].
        let res = _delete()
            .header(HELVETIA_TOKEN_HEADER, "bad_token")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 403);

        // Test 2 - Test not found [404].
        let res = _delete()
            .path("/v0/secrets/nonexistent")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 404);

        // Test 3 - Test successful operations [204].
        let res = _delete().reply(&routes).await;
        assert_eq!(res.status(), 204);
    }

    #[tokio::test]
    async fn test_generic() {
        let vault = create_vault();
        let _ = create_secret(&vault);
        let routes = create_routes(vault, None);

        // Below follow some tests for issues that apply to every endpoint.
        // For brevity, we test only the GET data enpoint.
        //
        // Test 1 - Ensure that an extra slash at the end of the URL does not
        // cause a problem in the routing.
        let res = _get_data()
            .path(&format!("/v0/secrets/{}/data/", NAME))
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 200);

        // Test 2 - Check that a missing token header returns 401.
        let res = warp::test::request()
            .method("GET")
            .path(&format!("/v0/secrets/{}/data", NAME))
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 401);

        // Test 3 - Ensure that an extra suffix to an endpoint leads to a 404.
        // Note that we test PUT here as well, since it has a slightly
        // different check for this type of errors.
        let res = _get_data()
            .path(&format!("/v0/secrets/{}/data/badsuffix", NAME))
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 404);

        let res = _put()
            .path(&format!("/v0/secrets/{}/badsuffix", NAME))
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 404);

        // Test 4 - Ensure that an incorrect method on an endpoint returns
        // 405 Method Not Allowed.
        let res = _get_data().method("PUT").reply(&routes).await;
        assert_eq!(res.status(), 405);
    }
}
