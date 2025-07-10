use std::{fs, io::{self, Write}, path::PathBuf};

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

        Command::GenConfigTemplate { target } => {
            let template = config::template();
            match target {
                Some(path) => fs::write(path, &template)?,
                None => io::stdout().write_all(template.as_bytes())?,
            }
        }

        Command::Run => {
            let config = config::load()?;
            let ctx = http::Context {
                jwt: jwt::Context::new(&config.jwt).await?,
                config,
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
    pub(crate) cmd: Command,
}

#[derive(Debug, clap::Parser)]
pub(crate) enum Command {
    /// Starts the HTTP server.
    Run,

    /// Checks config, paths, URLs and other stuff. Useful to run before
    /// restarting the main server after a config update.
    Check,

    /// Outputs a template of the configuration, including all config options
    /// with descriptions, great as a starting point.
    GenConfigTemplate {
        /// File to write it to. If unspecified, written to stdout.
        target: Option<PathBuf>,
    },
}
