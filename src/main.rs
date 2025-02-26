use crate::prelude::*;


mod config;
mod http;
mod prelude;


#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();

    let config = config::load()?;
    http::serve(&config.http).await?;


    Ok(())
}
