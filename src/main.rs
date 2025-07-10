use crate::prelude::*;


mod auth;
mod config;
mod http;
mod jwt;
mod opencast;
mod prelude;
mod util;


#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();

    let config = config::load()?;
    http::serve(config).await?;
    let ctx = http::Context {
        jwt: jwt::Context::new(&config.jwt).await?,
        config,
    };

    http::serve(ctx).await?;

    Ok(())
}
