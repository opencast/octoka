use std::path::PathBuf;


#[derive(clap::Parser)]
#[command(version, about)]
pub struct Cli {
    #[clap(subcommand)]
    pub cmd: Command,

    /// Specifies config file location. Default locations are: 'config.toml' and
    /// '/etc/octoka/config.toml'. Can also be set via env `OCTOKA_CONFIG_PATH`.
    #[clap(long)]
    pub config: Option<PathBuf>,
}

#[derive(Debug, clap::Parser)]
pub enum Command {
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
