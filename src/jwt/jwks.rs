use std::time::Duration;

use bytes::Bytes;
use jwtea::{Jwks, VerifyingKey};

use super::Kid;
use crate::{jwt::JwksUrl, prelude::*, util::SimpleHttpClient};


const FETCH_TIMEOUT: Duration = Duration::from_secs(20);


pub(super) struct FetchedKey {
    pub(super) key: VerifyingKey,
    pub(super) kid: Option<Kid>,
}

pub(super) struct FetchedData {
    pub(super) keys: Vec<FetchedKey>,
    // TODO: expiration
}

/// Fetches the given JWKS URL and returns valid keys that were found.
pub async fn fetch(uri: &JwksUrl, http_client: &SimpleHttpClient) -> Result<FetchedData> {
    use http_body_util::BodyExt;

    trace!(?uri, "fetching JWKS");
    let response = tokio::select! {
        r = http_client.get(uri.0.clone()) => r.context("failed to fetch JWKS")?,
        _ = tokio::time::sleep(FETCH_TIMEOUT) => bail!("timeout {FETCH_TIMEOUT:?}"),
    };

    if !response.status().is_success() {
        bail!("JWKS URL returned non 2xx-code");
    }


    // Download and deserialize body
    let body: Bytes = response.into_body().collect().await
        .context("failed to download HTTP body of JWKS")?
        .to_bytes();
    let jwks: Jwks = serde_json::from_slice(&body)
        .context("could not deserialize JWKS response as valid JWKS")?;

    // Read as crypto keys
    let mut keys = Vec::new();
    for jwk in jwks.keys {
        match VerifyingKey::from_jwk(&jwk) {
            Err(e) => debug!("key from JWKS invalid: {e}"),
            Ok(key) => {
                keys.push(FetchedKey {
                    key,
                    kid: jwk.kid.map(|c| Kid(c.into_owned())),
                });
            }
        }
    }

    Ok(FetchedData { keys })
}
