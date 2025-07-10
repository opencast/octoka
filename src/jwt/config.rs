use std::{borrow::Cow, net::IpAddr, time::Duration};

use hyper::Uri;


#[derive(Debug, Clone, confique::Config)]
pub struct JwtConfig {
    /// URL to a JWKS containing public keys used for verifying JWT signatures.
    /// Example: `https://tobira.example.com/.well-known/jwks.json`
    #[config(deserialize_with = deserialize_uri)]
    pub jwks_url: Uri,

    /// Where to look for a JWT in the HTTP request. First source has highest
    /// priority. Each array element is an object. Possible sources:
    ///
    /// - `{ source = "query", name = "jwt" }`: from URL query parameter "jwt".
    ///   `name` can be chosen arbitrarily. The first parameter with that name
    ///   is used.
    /// - `{ source = "header", name = "Authorization", prefix = "Bearer " }`:
    ///   from HTTP header with the given name. The optional `prefix` is
    ///   stripped from the header value.
    #[config(
        default = [{ "source": "query", "name": "jwt" }],
        validate(sources.len() > 0, "must not be empty"),
    )]
    pub sources: Vec<JwtSource>,

    /// For how long keys fetched from JWKS URLs are considered valid. After
    /// this time, they are considered stale and won't be used anymore.
    #[config(default = "10min", deserialize_with = crate::config::deserialize_duration)]
    pub key_cache_duration: Duration,

    /// When checking `exp` and `nbf`, allow this amount of leeway to account
    /// for possible clock skew.
    #[config(default = "3s", deserialize_with = crate::config::deserialize_duration)]
    pub allowed_clock_skew: Duration,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum JwtSource {
    Query {
        name: String,
    },
    Header {
        name: String,
        prefix: Option<String>,
    },
}

/// Deserialize a `Uri` from string and makes sure it uses HTTPS, has no
/// username, password or query part.
pub fn deserialize_uri<'de, D>(deserializer: D) -> Result<Uri, D::Error>
    where D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    macro_rules! err {
        ($($t:tt)*) => {
            <D::Error as serde::de::Error>::custom(format!($($t)*))
        };
    }

    // Parse string as URI
    let s = <Cow<'de, str>>::deserialize(deserializer)?;
    let uri: Uri = s.parse().map_err(|e| err!("invalid URI: {e}"))?;

    // Must have host (and optional port), but no user information.
    match uri.authority() {
        None => return Err(err!("must have authority part")),
        Some(authority) if authority.as_str().contains('@')
            => return Err(err!("must not contain user part")),
        _ => {}
    }

    // Non-local URLs must use HTTPS
    let host = uri.host().unwrap();
    let is_local = host == "localhost"
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    if !is_local && uri.scheme() != Some(&hyper::http::uri::Scheme::HTTPS) {
        return Err(err!("must use HTTPS"));
    }

    // Must not have fragment part
    if s.contains('#') {
        return Err(err!("must not contain fragment part (#...)"));
    }

    Ok(uri)
}
