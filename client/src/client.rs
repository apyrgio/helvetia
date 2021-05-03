use crate::errors::{Error, Res};
use reqwest;
use std;
use url;

const HELVETIA_TOKEN_HEADER: &'static str = "Helvetia-Token";
const HELVETIA_API_PREFIX: &'static str = "v0/secrets/";

/// The required data for creating a Helvetia secret.
#[derive(Debug, Clone)]
pub struct Data {
    /// The owner token for the secret.
    pub token: String,
    /// The data of the secret.
    pub data: String,
}

impl Data {
    /// Initialize the [`Data`] struct.
    pub fn new<T, D>(token: T, data: D) -> Self
    where
        T: Into<String>,
        D: Into<String>,
    {
        Self {
            token: token.into(),
            data: data.into(),
        }
    }
}

/// The optional metadata for a Helvetia secret.
#[derive(Debug, Clone)]
pub struct Meta {
    /// The metadata token for the secret.
    pub token: String,
    /// The metadata of the secret.
    pub meta: String,
}

impl Meta {
    /// Initialize the [`Meta`] struct.
    pub fn new<T, M>(token: T, meta: M) -> Self
    where
        T: Into<String>,
        M: Into<String>,
    {
        Self {
            token: token.into(),
            meta: meta.into(),
        }
    }
}

#[derive(Debug)]
/// The HTTP client for the Helvetia API.
///
/// This client provides a Rust interface on top of the Helvetia API.
pub struct HelvetiaClient {
    url: url::Url,
    client: reqwest::Client,
}

impl HelvetiaClient {
    /// Initialize a Helvetia client from a URL and a `reqwest` client.
    pub fn new(mut url: url::Url, client: reqwest::Client) -> Res<Self> {
        let _ = url
            .path_segments_mut()
            .map_err(|_| Error::InvalidUrl)?
            .pop_if_empty()
            .push("");
        Ok(Self {
            url: url,
            client: client,
        })
    }

    /// Initialize a Helvetia client from a URL.
    pub fn from_url(_url: url::Url) -> Res<Self> {
        let client = reqwest::Client::new();
        Self::new(_url, client)
    }

    fn create_auth_header(
        &self,
        token: &str,
    ) -> Res<reqwest::header::HeaderMap> {
        let mut headers = reqwest::header::HeaderMap::new();
        let value = reqwest::header::HeaderValue::from_str(token)?;

        let _ = headers.insert(HELVETIA_TOKEN_HEADER, value);
        Ok(headers)
    }

    /// Create a secret, optionally with metadata.
    pub async fn create_secret<N>(
        &self,
        name: N,
        data: Data,
        meta: Option<Meta>,
    ) -> Res<()>
    where
        N: AsRef<str>,
    {
        let meta_token;
        let meta_data;
        let headers = self.create_auth_header(&data.token)?;
        let mut map = std::collections::HashMap::new();

        let _ = map.insert("owner_token", &data.token);
        let _ = map.insert("data", &data.data);

        // XXX: Why can't I point into Some<meta>?
        match meta {
            Some(m) => {
                meta_data = m.meta.clone();
                meta_token = m.token.clone();
                let _ = map.insert("meta", &meta_data);
                let _ = map.insert("meta_token", &meta_token);
            }
            None => (),
        };

        let url = self.url.join(HELVETIA_API_PREFIX)?.join(name.as_ref())?;

        let res = self
            .client
            .put(url)
            .headers(headers)
            .json(&map)
            .send()
            .await?;

        let _res = res.error_for_status()?;

        Ok(())
    }

    /// Get the data of a secret.
    pub async fn get_secret_data<N, T>(&self, name: N, token: T) -> Res<String>
    where
        N: AsRef<str>,
        T: AsRef<str>,
    {
        let headers = self.create_auth_header(token.as_ref())?;

        let mut url = self.url.join(HELVETIA_API_PREFIX)?;
        let _ = url
            .path_segments_mut()
            .map_err(|_| Error::InvalidUrl)?
            .pop_if_empty()
            .push(name.as_ref())
            .push("data");

        let res = self.client.get(url).headers(headers).send().await?;
        Ok(res.error_for_status()?.text().await?)
    }

    /// Get the metadata of a secret.
    pub async fn get_secret_meta<N, T>(&self, name: N, token: T) -> Res<String>
    where
        N: AsRef<str>,
        T: AsRef<str>,
    {
        let headers = self.create_auth_header(token.as_ref())?;

        let mut url = self.url.join(HELVETIA_API_PREFIX)?;

        let _ = url
            .path_segments_mut()
            .map_err(|_| Error::InvalidUrl)?
            .pop_if_empty()
            .push(name.as_ref())
            .push("meta");

        let res = self.client.get(url).headers(headers).send().await?;
        Ok(res.error_for_status()?.text().await?)
    }

    /// Delete a secret.
    pub async fn delete_secret<N, T>(&self, name: N, token: T) -> Res<()>
    where
        N: AsRef<str>,
        T: AsRef<str>,
    {
        let headers = self.create_auth_header(token.as_ref())?;
        let url = self.url.join(HELVETIA_API_PREFIX)?.join(name.as_ref())?;
        let res = self.client.delete(url).headers(headers).send().await?;
        let _res = res.error_for_status()?;

        Ok(())
    }
}

// The when/then variables of MockServer are not used, so we opt to switch this
// off.
#[allow(unused_results)]
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::errors::Error;
    use httpmock;
    use serde_json::json;
    use tokio;

    #[tokio::test]
    async fn test_errors() {
        let server = httpmock::MockServer::start();
        let server_url = url::Url::parse(&server.base_url()).unwrap();
        let client = HelvetiaClient::from_url(server_url).unwrap();
        let name = "secret".to_string();
        let token = "data_token".to_string();

        // Handle invalid server URLs.
        let _server_url = url::Url::parse("http://0.0.0.0/").unwrap();
        let _client = HelvetiaClient::from_url(_server_url).unwrap();
        let res = _client.get_secret_data(name.clone(), token.clone()).await;
        assert!(matches!(res, Err(Error::RequestError { .. })));

        // A token with an ASCII character that can't be used in HTTP headers
        // should be rejected.
        let res = client.get_secret_data(name.clone(), "\0".to_string()).await;
        assert!(matches!(res, Err(Error::InvalidToken { .. })));

        // Handle 403 errors.
        let mut mock_403 = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/v0/secrets/secret/data");
            then.status(403);
        });

        let res = client.get_secret_data(name.clone(), token.clone()).await;
        mock_403.assert();
        mock_403.delete();
        assert!(matches!(res, Err(Error::TokenMismatch { .. })));

        // Handle 404 errors.
        let mut mock_404 = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/v0/secrets/secret/data");
            then.status(404);
        });

        let res = client.get_secret_data(name.clone(), token.clone()).await;
        mock_404.assert();
        mock_404.delete();
        assert!(matches!(res, Err(Error::SecretNotFound { .. })));

        // Handle 413 errors.
        let mut mock_413 = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/v0/secrets/secret/data");
            then.status(413);
        });

        let res = client.get_secret_data(name.clone(), token.clone()).await;
        mock_413.assert();
        mock_413.delete();
        assert!(matches!(res, Err(Error::SecretTooLarge { .. })));

        // Handle unexpected errors that a client may get from the server.
        let mut mock_429 = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/v0/secrets/secret/data");
            then.status(429);
        });

        let res = client.get_secret_data(name.clone(), token.clone()).await;
        mock_429.assert();
        mock_429.delete();
        assert!(matches!(res, Err(Error::ClientError { .. })));

        // Handle server errors.
        let mut mock_500 = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/v0/secrets/secret/data");
            then.status(500);
        });

        let res = client.get_secret_data(name.clone(), token.clone()).await;
        mock_500.assert();
        mock_500.delete();
        assert!(matches!(res, Err(Error::ServerError { .. })));
    }

    #[tokio::test]
    async fn test_redirects() {
        let server = httpmock::MockServer::start();
        let server_url = url::Url::parse(&server.base_url()).unwrap();
        let client = HelvetiaClient::from_url(server_url).unwrap();
        let name = "secret".to_string();
        let token = "data_token".to_string();

        // Handle simple redirects.
        let mut mock_301 = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/v0/secrets/secret/data");
            then.status(301)
                .header("Location", "/v1/secrets/secret/data");
        });

        let mut mock_200 = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/v1/secrets/secret/data");
            then.status(200);
        });

        let res = client.get_secret_data(name.clone(), token.clone()).await;
        mock_301.assert();
        mock_200.assert();
        mock_301.delete();
        mock_200.delete();
        assert!(res.is_ok());

        // Handle redirect loops.
        let mut mock_infinite_301 = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/v0/secrets/secret/data");
            then.status(301)
                .header("Location", "/v0/secrets/secret/data");
        });

        let res = client.get_secret_data(name.clone(), token.clone()).await;
        assert!(mock_infinite_301.hits() > 1);
        mock_infinite_301.delete();
        assert!(matches!(res, Err(Error::RequestError { .. })));
    }

    #[tokio::test]
    async fn test_trailing_slash() {
        let server = httpmock::MockServer::start();
        let server_url = url::Url::parse(&server.base_url())
            .unwrap()
            .join("prefix")
            .unwrap();
        let client = HelvetiaClient::from_url(server_url).unwrap();
        assert!(client.url.as_str().ends_with("prefix/"));

        let owner_token = "owner_token";
        let data = "data";
        let secret_name = "secret";

        let get_data_mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/prefix/v0/secrets/{}/data", secret_name));
            then.status(200).body("data");
        });

        let res = client
            .get_secret_data(secret_name, owner_token.to_string())
            .await;
        get_data_mock.assert();
        assert_eq!(res.unwrap(), data);

        let server_url = url::Url::parse(&server.base_url())
            .unwrap()
            .join("prefix/")
            .unwrap();
        let client = HelvetiaClient::from_url(server_url).unwrap();
        assert!(client.url.as_str().ends_with("prefix/"));

        let res = client
            .get_secret_data(secret_name, owner_token.to_string())
            .await;
        assert_eq!(get_data_mock.hits(), 2);
        assert_eq!(res.unwrap(), data);
    }

    #[tokio::test]
    async fn test_ops() {
        let server = httpmock::MockServer::start();
        let server_url = url::Url::parse(&server.base_url()).unwrap();
        let client = HelvetiaClient::from_url(server_url).unwrap();

        let owner_token = "owner_token";
        let meta_token = "meta_token";
        let data = "data";
        let meta = "meta";
        let secret_name = "secret";

        let mut put_partial_mock = server.mock(|when, then| {
            when.method(httpmock::Method::PUT)
                .path(format!("/v0/secrets/{}", secret_name))
                .header("Content-Type", "application/json")
                .header(HELVETIA_TOKEN_HEADER, &owner_token)
                .json_body(json!(
                { "owner_token": &owner_token,
                  "data": &data,
                }));
            then.status(204);
        });

        let mut put_full_mock = server.mock(|when, then| {
            when.method(httpmock::Method::PUT)
                .path(format!("/v0/secrets/{}", secret_name))
                .header("Content-Type", "application/json")
                .header(HELVETIA_TOKEN_HEADER, &owner_token)
                .json_body(json!(
                { "owner_token": &owner_token,
                  "meta_token": &meta_token,
                  "data": &data,
                  "meta": &meta,
                }));
            then.status(200).body("");
        });

        let mut get_data_mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .header(HELVETIA_TOKEN_HEADER, &owner_token)
                .path(format!("/v0/secrets/{}/data", secret_name));
            then.status(200).body("data");
        });

        let mut get_meta_mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .header(HELVETIA_TOKEN_HEADER, &meta_token)
                .path(format!("/v0/secrets/{}/meta", secret_name));
            then.status(200).body("meta");
        });

        let mut delete_mock = server.mock(|when, then| {
            when.method(httpmock::Method::DELETE)
                .header(HELVETIA_TOKEN_HEADER, &owner_token)
                .path(format!("/v0/secrets/{}", secret_name));
            then.status(200);
        });

        let data_req = Data::new(owner_token.to_string(), data.to_string());
        let meta_req = Meta::new(meta_token.to_string(), meta.to_string());

        let res = client
            .create_secret(secret_name, data_req.clone(), None)
            .await;
        put_partial_mock.assert();
        put_partial_mock.delete();
        assert_eq!(res.unwrap(), ());

        let res = client
            .create_secret(secret_name, data_req, Some(meta_req))
            .await;
        put_full_mock.assert();
        put_full_mock.delete();
        assert_eq!(res.unwrap(), ());

        let res = client
            .get_secret_data(secret_name, owner_token.to_string())
            .await;
        get_data_mock.assert();
        get_data_mock.delete();
        assert_eq!(res.unwrap(), data);

        let res = client
            .get_secret_meta(secret_name, meta_token.to_string())
            .await;
        get_meta_mock.assert();
        get_meta_mock.delete();
        assert_eq!(res.unwrap(), meta);

        let res = client
            .delete_secret(secret_name, owner_token.to_string())
            .await;
        delete_mock.assert();
        delete_mock.delete();
        assert_eq!(res.unwrap(), ());
    }
}
