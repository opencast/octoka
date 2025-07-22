use std::{net::IpAddr, time::Duration};

use serde::Deserialize;


#[derive(Debug, confique::Config)]
#[config(validate = Self::validate)]
pub struct HttpConfig {
    /// Whether files are directly served, making sfs operate as fully
    /// functional file server. If `false`, all HTTP responses have an empty
    /// body and a separate HTTP server needs to perform the actual file
    /// serving. It can be used to implement "auth sub-requests", for example.
    #[config(default = true)]
    pub serve_files: bool,

    /// If set, HTTP responses will have the header `X-Accel-Redirect` set to
    /// the specified string joined with the path stripped of the prefix (see
    /// `opencast.path_prefixes`. Example: "/protected".
    #[config(validate = crate::config::validate_url_path)]
    pub x_accel_redirect: Option<String>,

    /// Origins from which CORS requests are allowed. Web apps that load assets
    /// with the 'Authorization' header must be listed here. If empty, no CORS
    /// requests are allowed.
    #[config(default = [])]
    pub cors_allowed_origins: Vec<CorsOrigin>,

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

impl HttpConfig {
    fn validate(&self) -> Result<(), &'static str> {
        if self.serve_files && self.x_accel_redirect.is_some() {
            return Err("x_accel_redirect cannot be set when serve_files = true");
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
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

        Ok(Self(s.into()))
    }
}
