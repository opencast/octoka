use std::{net::IpAddr, time::Duration};

use anyhow::anyhow;
use serde::Deserialize;


#[derive(Debug, confique::Config)]
pub struct HttpConfig {
    /// Specifies how to respond to requests that are considered authorized.
    /// - "empty": status 204, empty body, no special headers.
    /// - "file": act as a file server, i.e. send the file in response. Requires
    ///   `opencast.downloads_path` to be set!
    /// - "x-accel-redirect:<prefix>": status 204, empty body, `X-Accel-Redirect`
    ///   header is set to `<prefix>/<stripped_path>` where `stripped_path` is
    ///   therequest path stripped of `opencast.path_prefixes`.
    #[config(default = "file")]
    pub on_allow: OnAllow,

    /// Specifies how to respond to requests that are considered unauthorized.
    /// - "empty": status 403, empty body, no special headers.
    /// - "x-accel-redirect:<prefix>": status 204, empty body, `X-Accel-Redirect`
    ///   header is set to `<prefix>/<path>` where `path` is the full request
    ///   path.
    #[config(default = "empty")]
    pub on_forbidden: OnForbidden,

    /// Origins from which CORS requests are allowed. Web apps that load assets
    /// with the 'Authorization' header must be listed here. If empty, no CORS
    /// requests are allowed.
    #[config(
        default = [],
        validate(crate::config::is_unique(cors_allowed_origins), "has duplicates"),
    )]
    pub cors_allowed_origins: Vec<CorsOrigin>,

    /// Where to look for a JWT in the HTTP request. First source has highest
    /// priority. Each array element is an object. Possible sources:
    ///
    /// - `{ source = "query", name = "jwt" }`: from URL query parameter "jwt".
    ///   `name` can be chosen arbitrarily. The first parameter with that name
    ///   is used.
    /// - `{ source = "header", name = "Authorization", prefix = "Bearer " }`:
    ///   from first HTTP header with the given name. The optional `prefix` is
    ///   stripped from the header value.
    #[config(
        default = [
            { "source": "header", "name": "Authorization", "prefix": "Bearer " },
            { "source": "query", "name": "jwt" },
        ],
        validate(!jwt_sources.is_empty(), "must not be empty"),
    )]
    pub jwt_sources: Vec<JwtSource>,

    /// The TCP port the HTTP server should listen on.
    #[config(default = 4050)]
    pub port: u16,

    /// The bind address to listen on.
    #[config(default = "127.0.0.1")]
    pub address: IpAddr,

    /// How long to wait for active connections to terminate when shutting down.
    #[config(default = "3s", deserialize_with = crate::config::deserialize_duration)]
    pub shutdown_timeout: Duration,
}


#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(try_from = "String")]
pub enum OnAllow {
    Empty,
    File,
    XAccelRedirect(String),
}

impl TryFrom<String> for OnAllow {
    type Error = anyhow::Error;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        if value == "empty" {
            Ok(Self::Empty)
        } else if value == "file" {
            Ok(Self::File)
        } else if let Some(path) = value.strip_prefix("x-accel-redirect:") {
            crate::config::validate_url_path(path).map_err(|e| anyhow!(e))?;
            Ok(Self::XAccelRedirect(path.into()))
        } else {
            Err(anyhow!("invalid value, check docs for possible options"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(try_from = "String")]
pub enum OnForbidden {
    Empty,
    XAccelRedirect(String),
}

impl TryFrom<String> for OnForbidden {
    type Error = anyhow::Error;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        if value == "empty" {
            Ok(Self::Empty)
        } else if let Some(path) = value.strip_prefix("x-accel-redirect:") {
            crate::config::validate_url_path(path).map_err(|e| anyhow!(e))?;
            Ok(Self::XAccelRedirect(path.into()))
        } else {
            Err(anyhow!("invalid value, check docs for possible options"))
        }
    }
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

#[derive(Debug, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct CorsOrigin(String);

impl CorsOrigin {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CorsOrigin {
    type Error = &'static str;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.trim() != s {
            return Err("origin has trailing or leading whitespace");
        }
        let Some((scheme, authority)) = s.split_once("://") else {
            return Err("invalid URI: does not contain scheme");
        };
        if scheme != "http" && scheme != "https" {
            return Err("origin must have HTTP or HTTPS scheme");
        }
        if ['/', '?', '#', '@'].iter().any(|c| authority.contains(*c)) {
            return Err("origin must not contain path, query, fragment or user path");
        }

        Ok(Self(s))
    }
}
