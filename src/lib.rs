use std::net::SocketAddr;

use anyhow::Result;
use tokio::net::TcpListener;

use crate::config::Config;


pub mod auth;
pub mod cli;
pub mod config;
pub mod http;
pub mod jwt;
pub mod log;
pub mod opencast;
pub mod prelude;
pub mod util;

pub async fn run_http_server(config: Config) -> Result<()> {
    let ctx = http::Context::new(config).await?;
    http::serve(ctx).await?;
    Ok(())
}

pub async fn test_http_server(
    config: Config,
) -> Result<(SocketAddr, impl Future<Output = Result<()>>)> {
    let ctx = http::Context::new(config).await?;
    let listener = TcpListener::bind(ctx.config.http.socket_addr()).await?;
    let addr = listener.local_addr()?;
    let server = http::serve_on(ctx, listener);
    Ok((addr, server))
}
