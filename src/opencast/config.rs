use std::{borrow::Cow, path::PathBuf};

use anyhow::ensure;
use serde::Deserialize;

use crate::{config::HttpHost, prelude::*};

#[derive(Debug, confique::Config)]
pub struct OpencastConfig {
    /// Path to the Opencast `downloads/` folder, e.g. `/mnt/opencast/downloads`.
    /// Setting this is required if `http.on_allow` is `"file"`.
    pub downloads_path: Option<PathBuf>,

    /// Host of Opencast. Currently used for `fallback`.
    #[config(default = "http://localhost:8080")]
    pub host: HttpHost,

    /// Specifies if/how Opencast is used as a fallback when requests cannot be
    /// authorized by octoka itself (purely based on JWT).
    ///
    /// - "none": no fallback, Opencast is not contacted.
    /// - "head": an HTTP HEAD request is sent to Opencast, with the same URI
    ///   and headers as the incoming request. Octoka's behavior depends on
    ///   Opencast's response:
    ///   - 2xx: treat request as allowed
    ///   - 404: respond with 404
    ///   - 401: respond with 401, forwarding the www-authenticate header
    ///   - everything else: treat as forbidden
    /// - "get": like "head", but with HTTP method GET. This exists only for
    ///   older Opencast which had incorrect responses to HEAD requests. If you
    ///   use this, set `x.accel.redirect` in OC, in order to not send the file.
    ///   This option will get deprecated and removed in the future.
    #[config(default = "head")]
    pub fallback: FallbackMode,

    /// List of possible path prefixes that should be handled by octoka. For
    /// most Opencast systems, the default is fine as all paths start with
    /// `/static/...`.
    ///
    /// This corresponds to `org.opencastproject.download.url` in `custom.properties`
    /// or `org.opencastproject.distribution.aws.s3.distribution.base` in
    /// `org.opencastproject.distribution.aws.s3.AwsS3DistributionServiceImpl.cfg`.
    #[config(
        default = ["/static"],
        validate = validate_path_prefixes,
    )]
    pub path_prefixes: Vec<String>,
}

fn validate_path_prefixes(paths: &Vec<String>) -> Result<(), &'static str> {
    crate::config::validate_not_empty(paths)?;
    crate::config::validate_unique(paths)?;

    for path in paths {
        crate::config::validate_url_path(path)?;
        if path.trim_matches('/').is_empty() {
            return Err("prefix must not be empty");
        }
        match percent_encoding::percent_decode_str(path).decode_utf8() {
            Ok(Cow::Borrowed(_)) => {}
            _ => return Err("prefix must not contain percent-encoded characters"),
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FallbackMode {
    None,
    Head,
    Get,
}

impl OpencastConfig {
    /// Makes sure that `downloads_path` is a directory and canonicalizes.
    /// However, if it's missing, that just produces a warning and `Ok(_)`.
    pub fn check_downloads_path(&self) -> Result<()> {
        if let Some(path) = &self.downloads_path {
            match path.canonicalize() {
                Ok(canonical) => {
                    ensure!(canonical.is_dir(), "`opencast.downloads_path` is not a directory");
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    warn!("`opencast.downloads_path` does not exist (yet)");
                }
                Err(e) => return Err(e).context("could not canonicalize `opencast.downloads_path`"),
            }
        }

        Ok(())
    }
}
