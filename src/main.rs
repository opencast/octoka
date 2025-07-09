use crate::prelude::*;


mod auth;
mod config;
mod http;
mod opencast;
mod prelude;


#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();

    let config = config::load()?;
    http::serve(config).await?;


    Ok(())
}
