use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::{Client as HyperClient, connect::HttpConnector};

use crate::prelude::*;


pub type EmptyHttpBody = http_body_util::Empty<&'static [u8]>;

/// HTTP client to send GET requests without body.
pub type SimpleHttpClient = HyperClient<HttpsConnector<HttpConnector>, EmptyHttpBody>;

pub fn http_client() -> Result<SimpleHttpClient> {
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .context("failed to load native certificate roots")?
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let out = HyperClient::builder(hyper_util::rt::TokioExecutor::new()).build(https);
    Ok(out)
}
