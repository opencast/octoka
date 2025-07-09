use std::path::PathBuf;

#[derive(Debug, confique::Config)]
pub struct OpencastConfig {
    /// Path to the Opencast `downloads/` folder, e.g. `/mnt/opencast/downloads`.
    // TODO: any reasonable default we can set?
    pub downloads_path: PathBuf,

    /// List of possible path prefixes that should be handled by sfs. For most
    /// Opencast systems, the default is fine as all paths start with
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
    if paths.is_empty() {
        return Err("must not be empty");
    }

    if paths.iter().collect::<std::collections::HashSet<_>>().len() != paths.len() {
        return Err("contains duplicate entries");
    }

    for path in paths {
        crate::config::validate_url_path(path)?;
    }

    Ok(())
}
