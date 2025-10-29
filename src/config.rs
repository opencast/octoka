use std::{path::{Path, PathBuf}, time::Duration};

use anyhow::{ensure, Context as _, Error};
use confique::{
    Config as _,
    serde::{self, Deserialize as _},
};

use crate::{
    http::{HttpConfig, OnAllow},
    jwt::JwtConfig,
    log::LogConfig,
    opencast::OpencastConfig,
    prelude::*,
};


/// Paths that are checked for a config file.
const DEFAULT_PATHS: &[&str] = &[
    // For better DX, we include this special path here, but just in debug mode.
    #[cfg(debug_assertions)]
    "util/config.toml",

    "config.toml",
    "/etc/octoka/config.toml",
];

/// Env var that can be used to set the config path.
const CONFIG_PATH_ENV: &str = "OCTOKA_CONFIG_PATH";


pub fn load() -> Result<Config, Error> {
    let path = if let Some(path) = std::env::var_os(CONFIG_PATH_ENV) {
        PathBuf::from(path)
    } else {
        DEFAULT_PATHS.iter()
            .map(PathBuf::from)
            .find(|p| p.exists())
            .ok_or(anyhow!(
                "no configuration file found at any of the following locations: {}",
                DEFAULT_PATHS.join(", "),
            ))?
    };

    load_from(path)
}

pub fn load_from(path: impl AsRef<Path>) -> Result<Config, Error> {
    let path = path.as_ref();
    let mut config = Config::from_file(path)
        .with_context(|| format!("failed to load config file '{}", path.display()))?;
    config.fix_paths(path)?;
    Ok(config)
}

pub fn template() -> String {
    let mut options = confique::toml::FormatOptions::default();
    options.general.nested_field_gap = 2;
    confique::toml::template::<Config>(options)
}

/// Configuration for octoka.
///
/// All relative paths are relative to the location of this configuration file.
/// Duration values are specified as string with a unit, e.g. "27s". Valid
/// units: 'ms', 's', 'min', 'h' and 'd'.
#[derive(Debug, confique::Config)]
#[config(validate = Self::validate)]
pub struct Config {
    #[config(nested)]
    pub opencast: OpencastConfig,

    #[config(nested)]
    pub jwt: JwtConfig,

    #[config(nested)]
    pub http: HttpConfig,

    #[config(nested)]
    pub log: LogConfig,
}

impl Config {
    fn validate(&self) -> Result<(), &'static str> {
        if self.http.on_allow == OnAllow::File && self.opencast.downloads_path.is_none() {
            return Err("`http.on_allow` is 'file', but `opencast.downloads_path` is not set");
        }
        Ok(())
    }

    pub(crate) fn fix_paths(&mut self, config_path: &Path) -> Result<()> {
        let absolute_config_path = config_path.canonicalize()
            .context("failed to canonicalize config path")?;
        let base_path = absolute_config_path.parent()
            .expect("config file path has no parent");

        if let Some(path) = &mut self.opencast.downloads_path {
            if path.is_relative() {
                *path = base_path.join(&path);
            }
            *path = path.canonicalize()
                .context("could not canonicalize `opencast.downloads_path`")?;
            ensure!(path.is_dir(), "`opencast.downloads_psth` is not a directory");
        }

        Ok(())
    }
}



/// Makes sure that the given string is a valid URL path.
pub fn validate_url_path(value: &str) -> Result<(), &'static str> {
    match hyper::http::uri::PathAndQuery::try_from(value) {
        Ok(pq) if pq.query().is_none() => Ok(()),
        _ => Err("not a valid URI path"),
    }
}

pub fn is_unique<T: std::hash::Hash + Eq>(list: &[T]) -> bool {
    <std::collections::HashSet<_>>::from_iter(list).len() == list.len()
}

pub fn validate_unique<T: std::hash::Hash + Eq>(list: &[T]) -> Result<(), &'static str> {
    if !is_unique(list) {
        return Err("duplicate entries");
    }
    Ok(())
}

pub fn validate_not_empty<T>(list: &[T]) -> Result<(), &'static str> {
    if list.is_empty() {
        return Err("must not be empty");
    }
    Ok(())
}


/// Custom format for durations. We allow a couple useful units and required
/// a unit to increase readability of config files.
pub fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let s = String::deserialize(deserializer)?;

    // Allow unit-less zeroes
    if s == "0" {
        return Ok(Duration::ZERO);
    }

    let start_unit = s.find(|c: char| !c.is_ascii_digit())
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
