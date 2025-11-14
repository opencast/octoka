use std::{
    collections::HashMap,
    fs::OpenOptions,
    path::PathBuf,
};
use serde::Deserialize;
use tracing_subscriber::{
    filter::{FilterFn, LevelFilter},
    prelude::*,
};

use crate::prelude::*;


#[derive(Debug, confique::Config)]
pub(crate) struct LogConfig {
    /// Specifies what log messages to emit, based on the module path and log level.
    ///
    /// This is a map where the key specifies a module path prefix, and the
    /// value specifies a minimum log level. For each log message, the map
    /// entry with the longest prefix matching the log's module path is chosen.
    /// If no such entry exists, the log is not emitted. Otherwise, that
    /// entry's level is used to check whether the log message should be
    /// emitted. Valid log levels: off, error, warn, info, debug, trace.
    ///
    /// Take the following example: the following config only allows ≥"info"
    /// logs from octoka generally, but also ≥"trace" messages from the `http`
    /// submodule. But it completely disables all logs from `tobira::http::fs`.
    /// Finally, it also enabled ≥"debug" messages from one of octoka's
    /// dependencies, the HTTP library `hyper`.
    ///
    ///    [log]
    ///    filters.octoka = "info"
    ///    filters."octoka::http" = "trace"
    ///    filters."octoka::http::fs" = "off"
    ///    filters.hyper = "debug"
    #[config(default = { "octoka": "info" })]
    pub(crate) filters: Filters,

    /// If this is set, log messages are also written to this file.
    pub(crate) file: Option<PathBuf>,

    /// If this is set to `false`, log messages are not written to stdout.
    #[config(default = true)]
    pub(crate) stdout: bool,
}

#[derive(Debug, Deserialize)]
#[serde(try_from = "HashMap<String, String>")]
pub(crate) struct Filters(HashMap<String, LevelFilter>);

impl TryFrom<HashMap<String, String>> for Filters {
    type Error = String;
    fn try_from(value: HashMap<String, String>) -> Result<Self, Self::Error> {
        value.into_iter()
            .map(|(target_prefix, level)| {
                let level = parse_level_filter(&level)?;
                Ok((target_prefix, level))
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

fn parse_level_filter(s: &str) -> Result<LevelFilter, String> {
    match s {
        "off" => Ok(LevelFilter::OFF),
        "trace" => Ok(LevelFilter::TRACE),
        "debug" => Ok(LevelFilter::DEBUG),
        "info" => Ok(LevelFilter::INFO),
        "warn" => Ok(LevelFilter::WARN),
        "error" => Ok(LevelFilter::ERROR),
        other => Err(format!("invalid log level '{other}'")),
    }
}

pub(crate) fn init(config: &LogConfig) -> Result<()> {
    let filter = {
        let filters = config.filters.0.clone();
        let max_level = filters.values().max().copied().unwrap_or(LevelFilter::OFF);
        let filter = FilterFn::new(move |metadata| {
            // If there are many filters, it might be worth to build an extra
            // prefix data structure, but in practice we only expect very few
            // entries.
            //
            // See the config doc comment to see the logic behind this filter.
            filters.iter()
                .filter(|(target_prefix, _)| metadata.target().starts_with(*target_prefix))
                .max_by_key(|(target_prefix, _)| target_prefix.len())
                .map(|(_, level_filter)| metadata.level() <= level_filter)
                .unwrap_or(false)
        });
        filter.with_max_level_hint(max_level)
    };

    macro_rules! subscriber {
        ($writer:expr) => {
            tracing_subscriber::fmt::layer().with_writer($writer)
        };
    }

    let stdout_output = if config.stdout {
        Some(subscriber!(std::io::stdout))
    } else {
        None
    };

    let file_output = if let Some(path) = &config.file {
        use std::io::Write;

        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .with_context(|| format!("failed to open/create log file '{}'", path.display()))?;

        // Add an empty line separator to see process restarts easier.
        file.write_all(b"\n\n").context("could not write to log file")?;

        Some(subscriber!(file))
    } else {
        None
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(file_output)
        .with(stdout_output)
        .init();

    Ok(())
}
