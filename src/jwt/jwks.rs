use std::borrow::Cow;

use bytes::Bytes;
use serde::Deserialize;

use super::{Kid, crypto};
use crate::{jwt::JwksUrl, prelude::*, util::SimpleHttpClient};


/// A JSON Web Key Set, defined by RFC 7517 (see section 5 and 4). The following
/// types don't fully implement the RFC, as we only support we few keys anyway.
/// We also ignore some fields that are not mandatory.
#[derive(Debug, Deserialize)]
pub struct Jwks<'a> {
    pub(super) keys: Vec<Jwk<'a>>,
}

/// Single key in a JWKS.
#[derive(Debug, Deserialize)]
pub struct Jwk<'a> {
    #[serde(rename = "use")]
    pub(super) use_: Option<KeyUsage>,
    pub(super) alg: Option<Cow<'a, str>>,
    pub(super) kid: Option<Cow<'a, str>>,

    #[serde(flatten)]
    pub(super) key_data: KeyData,

    // Ignoring: kid, key_ops, x5u, x5c, x5t, x5t#S256
}

/// Represents the actual cryptographic data of a JWK. See section 6 in RFC 7518
/// for more information.
#[derive(Debug, Deserialize)]
#[serde(tag = "kty")]
pub(super) enum KeyData {
    // The following two we don't support, so we don't bother deserializing the
    // fields.
    #[serde(rename = "RSA")]
    Rsa,
    #[serde(rename = "oct")]
    Oct,

    // Elliptic curves
    #[serde(rename = "EC")]
    Ec {
        crv: String,
        x: String,
        y: Option<String>,
    },

    // EdDSA
    #[serde(rename = "OKP")]
    Okp {
        crv: String,
        x: String,
    },
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(super) enum KeyUsage {
    #[serde(rename = "sig")]
    Signature,
    #[serde(rename = "enc")]
    Encryption,
}

pub(super) struct FetchedKey {
    pub(super) key: crypto::Key,
    pub(super) kid: Option<Kid>,
}

pub(super) struct FetchedData {
    pub(super) keys: Vec<FetchedKey>,
    // TODO: expiration
}

/// Fetches the given JWKS URL and returns valid keys that were found.
pub async fn fetch(uri: &JwksUrl, http_client: &SimpleHttpClient) -> Result<FetchedData> {
    use http_body_util::BodyExt;

    let response = http_client.get(uri.0.clone()).await
        .context("failed to fetch JWKS")?;

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
        match crypto::Key::from_jwk(&jwk) {
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
