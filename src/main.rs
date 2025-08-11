use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

use clap::Parser as _;

use crate::prelude::*;


mod auth;
mod config;
mod http;
mod jwt;
mod opencast;
mod prelude;
mod util;


#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match cli.cmd {
        Command::Check => {
            todo!()
        }

        Command::GenConfigTemplate { out } => {
            let template = config::template();
            match out {
                Some(path) => fs::write(path, &template)?,
                None => io::stdout().write_all(template.as_bytes())?,
            }
        }

        Command::Run => {
            let config = match cli.config {
                None => config::load()?,
                Some(path) => config::load_from(path)?,
            };
            let downloads_path = config.opencast.downloads_path.as_ref().map(|path| {
                path.canonicalize().context("could not canonicalize `opencast.downloads_path`")
            }).transpose()?;
            let ctx = http::Context {
                jwt: jwt::Context::new(&config.jwt).await?,
                config,
                downloads_path,
            };
            http::serve(ctx).await?;
        }
    }

    Ok(())
}

#[derive(clap::Parser)]
#[command(version, about)]
struct Cli {
    #[clap(subcommand)]
    cmd: Command,

    /// Specifies config file location. Default locations are: 'config.toml' and
    /// '/etc/octoka/config.toml'. Can also be set via env `OCTOKA_CONFIG_PATH`.
    #[clap(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, clap::Parser)]
enum Command {
    /// Starts the HTTP server.
    Run,

    /// Checks config, paths, URLs and other stuff. Useful to run before
    /// restarting the main server after a config update.
    Check,

    /// Outputs a template of the configuration, including all config options
    /// with descriptions, great as a starting point.
    GenConfigTemplate {
        /// File to write it to. If unspecified, written to stdout.
        #[clap(short, long)]
        out: Option<PathBuf>,
    },
}
