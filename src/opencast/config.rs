use std::path::PathBuf;

use crate::config::HttpHost;

#[derive(Debug, confique::Config)]
pub struct OpencastConfig {
    /// Path to the Opencast `downloads/` folder, e.g. `/mnt/opencast/downloads`.
    /// Settings this is required in some situations (e.g. if `http.serve_files`
    /// is enabled).
    pub downloads_path: Option<PathBuf>,

    /// Host of Opencast. Currently used for `use_as_fallback`.
    #[config(default = "http://localhost:8080")]
    pub host: HttpHost,

    /// If set, requests that cannot be authorized by octoka itself (purely
    /// based on JWT) will be forwarded to OC and octoka will use OC's response
    /// as indication of whether the request is authorized.
    #[config(default = true)]
    pub use_as_fallback: bool,

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
    }

    Ok(())
}
