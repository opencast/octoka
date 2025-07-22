use std::{net::IpAddr, time::Duration};

use hyper::Uri;


#[derive(Debug, Clone, confique::Config)]
pub struct JwtConfig {
    /// List of URLs to a JWKS containing public keys used for verifying JWT
    /// signatures. IMPORTANT: this is where the trust of the whole operation
    /// stems from! Only specify URLs to services that you fully trust to give
    /// access to Opencast resources.
    ///
    /// Example: ["https://tobira.example.com/.well-known/jwks.json"]
    #[config(validate = validate_trusted_keys)]
    pub trusted_keys: Vec<JwksUrl>,

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

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize)]
#[serde(try_from = "String")]
pub struct JwksUrl(pub Uri);

impl TryFrom<String> for JwksUrl {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let uri: Uri = s.parse().map_err(|e| format!("invalid URI: {e}"))?;

        // Must have host (and optional port), but no user information.
        match uri.authority() {
            None => return Err("must have authority part".into()),
            Some(authority) if authority.as_str().contains('@')
                => return Err("must not contain user part".into()),
            _ => {}
        }

        // Non-local URLs must use HTTPS
        let host = uri.host().unwrap();
        let is_local = host == "localhost"
            || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if !is_local && uri.scheme() != Some(&hyper::http::uri::Scheme::HTTPS) {
            return Err("must use HTTPS".into());
        }

        // Must not have fragment part
        if s.contains('#') {
            return Err("must not contain fragment part (#...)".into());
        }

        Ok(Self(uri))
    }
}

fn validate_trusted_keys(keys: &Vec<JwksUrl>) -> Result<(), &'static str> {
    crate::config::validate_not_empty(keys)?;
    crate::config::validate_unique(keys)?;
    Ok(())
}
