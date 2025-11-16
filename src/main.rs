use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

use clap::Parser as _;

use crate::{config::Config, prelude::*};


mod auth;
mod config;
mod http;
mod jwt;
mod log;
mod opencast;
mod prelude;
mod util;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;


#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Check => {
            run_check(&cli).await?;
        }

        Command::GenConfigTemplate { out } => {
            let template = config::template();
            match out {
                Some(path) => fs::write(path, &template)?,
                None => io::stdout().write_all(template.as_bytes())?,
            }
        }

        Command::Run => {
            let config = load_config_and_init_logger(&cli)?;
            let ctx = http::Context::new(config).await?;
            http::serve(ctx).await?;
        }
    }

    Ok(())
}

fn load_config_and_init_logger(cli: &Cli) -> Result<Config> {
    let config = match &cli.config {
        None => config::load()?,
        Some(path) => config::load_from(path)?,
    };
    log::init(&config.log).context("failed to setup logger")?;
    info!("Loaded config");
    info!("Initialized logger");
    trace!("Configuration: {config:#?}");
    Ok(config)
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

async fn run_check(cli: &Cli) -> Result<()> {
    let config = load_config_and_init_logger(cli)
        .context("failed to load config: cannot proceed with `check` command")?;


    fn print_outcome<T>(label: &str, res: Result<T>) {
        match res {
            Ok(_) => println!(" ▸ {label}: ✔ ok"),
            Err(e) => {
                println!(" ▸ {label}: ✘ error");
                println!("    {e:#}");
            }
        }
    }

    let jwks_checks = jwt::run_check(&config.jwt).await;

    println!();
    println!();
    print_outcome("Configuration", Ok(()));
    for (url, outcome) in jwks_checks {
        print_outcome(&format!("Fetch '{url}'"), outcome);
    }

    Ok(())
}
