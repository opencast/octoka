use std::{
    fs,
    io::{self, Write},
};

use anyhow::ensure;
use clap::Parser as _;

use octoka::{cli::{Cli, Command}, config::{self, Config}, jwt, log, prelude::*};


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
            config.opencast.check_downloads_path()?;
            octoka::run_http_server(config).await?;
        }
    }

    Ok(())
}

fn load_config_and_init_logger(cli: &Cli) -> Result<Config> {
    let config = match &cli.config {
        None => config::load()?,
        Some(path) => config::load_from(path)?,
    };
    log::init(&config.log, false).context("failed to setup logger")?;
    info!("Loaded config");
    info!("Initialized logger");
    trace!("Configuration: {config:#?}");
    Ok(config)
}

/// Runs the `check` subcommand.
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

    let downloads_path_check = match &config.opencast.downloads_path {
        None => Ok(()),
        Some(path) => path.canonicalize()
            .context("failed to canonicalize downloads_path")
            .and_then(|path| {
                ensure!(path.is_dir(), "downloads_path is not a directory");
                Ok(())
            })
    };
    let jwks_checks = jwt::run_check(&config.jwt).await;

    println!();
    println!();
    print_outcome("Configuration", Ok(()));
    print_outcome("opencast.downloads_path", downloads_path_check);
    for (url, outcome) in jwks_checks {
        print_outcome(&format!("Fetch '{url}'"), outcome);
    }

    Ok(())
}
