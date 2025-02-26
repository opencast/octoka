use std::{convert::Infallible, net::{IpAddr, SocketAddr}, panic::AssertUnwindSafe, time::Duration};

use futures::FutureExt as _;
use http_body_util::Full;
use hyper::{body::{Bytes, Incoming}, server::conn::http1, service::service_fn, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;


use crate::prelude::*;


#[derive(Debug, confique::Config)]
pub struct HttpConfig {
    /// The TCP port the HTTP server should listen on.
    #[config(default = 4050)]
    pub port: u16,

    /// The bind address to listen on.
    #[config(default = "127.0.0.1")]
    pub address: IpAddr,

    // How long to wait for active connections to terminate when shutting down.
    #[config(default = "3s", deserialize_with = crate::config::deserialize_duration)]
    pub shutdown_timeout: Duration,
}

type OurResponse = Response<Full<Bytes>>;

async fn handle(req: Request<Incoming>) -> OurResponse {
    Response::new(Full::new(Bytes::from("Hello, World!")))
}

/// Main entry point: starting the HTTP server.
pub async fn serve(config: &HttpConfig) -> Result<(), Error> {
    let addr = SocketAddr::from((config.address, config.port));

    let listener = TcpListener::bind(addr).await?;
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut signal = std::pin::pin!(shutdown_signal());

    let http = http1::Builder::new();

    info!("Listening on http://{}", addr);
    loop {
        tokio::select! {
            Ok((stream, _addr)) = listener.accept() => {
                let io = TokioIo::new(stream);
                let conn = http.serve_connection(io, service_fn(move |req| {
                    handle_internal_errors(handle(req))
                }));
                let fut = graceful.watch(conn);
                tokio::spawn(async move {
                    if let Err(e) = fut.await {
                        error!("Error serving connection: {:?}", e);
                    }
                });
            },

            _ = &mut signal => {
                info!("Shutdown signal received");
                break;
            }
        }
    }

    tokio::select! {
        _ = graceful.shutdown() => {
            info!("All HTTP connections gracefully closed");
        },
        _ = tokio::time::sleep(config.shutdown_timeout) => {
            eprintln!("Timed out wait for all HTTP connections to close");
        }
    }

    Ok(())
}

/// Future that resolves when a shutdown signal is received by our app.
async fn shutdown_signal() {
    // Wait for the CTRL+C signal
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}

/// This just wraps another future and catches all panics that might occur when
/// resolving/polling that given future. This ensures that we always answer with
/// `500` instead of just crashing the thread and closing the connection.
async fn handle_internal_errors(
    future: impl Future<Output = OurResponse>,
) -> Result<OurResponse, Infallible> {
    // TODO: We want to log lots of information about the exact HTTP request in
    // the error case.

    // The `AssertUnwindSafe` is unfortunately necessary. The whole story of
    // unwind safety is strange. What we are basically saying here is: "if the
    // future panicks, the global/remaining application state is not 'broken'.
    // It is safe to continue with the program in case of a panic."
    //
    // Hyper catches panics for us anyway, so this changes nothing except that
    // our response is better.
    match AssertUnwindSafe(future).catch_unwind().await {
        Ok(response) => Ok(response),
        Err(panic) => {
            // The `panic` information is just an `Any` object representing the
            // value the panic was invoked with. For most panics (which use
            // `panic!` like `println!`), this is either `&str` or `String`.
            let msg = panic.downcast_ref::<String>()
                .map(|s| s.as_str())
                .or(panic.downcast_ref::<&str>().map(|s| *s));

            // TODO: It would be great to also log everything the panic hook
            // would print, namely: location information and a backtrace. Do we
            // install our own panic hook? Or is stdout piped into the log file
            // anyway?
            match msg {
                Some(msg) => error!("INTERNAL SERVER ERROR: HTTP handler panicked: '{}'", msg),
                None => error!("INTERNAL SERVER ERROR: HTTP handler panicked"),
            }

            Ok(
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal server error: panic".into())
                    .unwrap()
            )
        }
    }
}
