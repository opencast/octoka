use std::time::Duration;
use anyhow::{Context as _, Error};
use confique::{serde::{self, Deserialize as _}, Config as _};

use crate::{http::HttpConfig, opencast::OpencastConfig};



pub fn load() -> Result<Config, Error> {
    Config::from_file("config.toml")
        .context("failed to load config file")
}


#[derive(Debug, confique::Config)]
pub struct Config {
    #[config(nested)]
    pub opencast: OpencastConfig,

    #[config(nested)]
    pub jwt: JwtConfig,

    #[config(nested)]
    pub http: HttpConfig,
}




#[derive(Debug, confique::Config)]
pub struct JwtConfig {
    /// URL to a JWKS containing public keys used for verifying JWT signatures.
    /// Example: `https://tobira.example.com/.well-known/jwks.json`
    pub jwks_url: String,

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
}

#[derive(Debug, serde::Deserialize)]
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


/// Makes sure that the given string is a valid URL path.
pub fn validate_url_path(value: &String) -> Result<(), &'static str> {
    match hyper::http::uri::PathAndQuery::try_from(value) {
        Ok(pq) if pq.query().is_none() => Ok(()),
        _ => Err("not a valid URI path"),
    }
}


/// Custom format for durations. We allow a couple useful units and required
/// a unit to increase readability of config files.
pub fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let s = String::deserialize(deserializer)?;

    // Allow unit-less zeroes
    if s == "0" {
        return Ok(Duration::ZERO);
    }

    let start_unit = s.find(|c: char| !c.is_digit(10))
        .ok_or_else(|| D::Error::custom("no time unit for duration"))?;
    let (num, unit) = s.split_at(start_unit);
    let num: u32 = num.parse()
        .map_err(|e| D::Error::custom(format!("invalid integer for duration: {}", e)))?;
    let num: u64 = num.into();

    match unit {
        "ms" => Ok(Duration::from_millis(num)),
        "s" => Ok(Duration::from_secs(num)),
        "min" => Ok(Duration::from_secs(num * 60)),
        "h" => Ok(Duration::from_secs(num * 60 * 60)),
        "d" => Ok(Duration::from_secs(num * 60 * 60 * 24)),
        _ => Err(D::Error::custom("invalid unit of time for duration")),
    }
}
