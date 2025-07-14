use std::{borrow::Cow, convert::Infallible, net::SocketAddr, panic::AssertUnwindSafe, path::PathBuf, pin::Pin, sync::Arc, task::Poll};

use futures::FutureExt as _;
use http_body_util::Full;
use hyper::{body::{Bytes, Incoming}, header::HeaderValue, server::conn::http1, service::service_fn, HeaderMap, Method, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::{auth, config::Config, jwt::{self, JwtSource}, opencast::PathParts, prelude::*};

mod config;
mod fs;

pub use self::{
    config::HttpConfig,
};


async fn handle(req: Request<Incoming>, ctx: Arc<Context>) -> Response {
    trace!("incoming req: {} {}", req.method(), req.uri().path());

    if req.method() != &Method::GET {
        return error_response(StatusCode::METHOD_NOT_ALLOWED);
    }

    // Parse path and split it into meaningful chunks. And return 400 if the
    // incoming path is not one we can handle.
    let Some(path) = PathParts::parse(req.uri().path(), &ctx.config.opencast) else {
        trace!(path = req.uri().path(), "response: 400 Bad Request due to bad path");
        // TODO: improve error message in body
        return error_response(StatusCode::BAD_REQUEST);
    };


    // Find JWT in query parameter and/or header.
    let jwt = ctx.config.jwt.sources.iter().find_map(|source| match source {
        JwtSource::Query { name } => {
            find_jwt_in_query(req.uri(), name)
        }
        JwtSource::Header { name, prefix } => {
            find_jwt_in_header(req.headers(), name, prefix.as_deref())
                .map(Cow::Borrowed)
        }
    });
    let jwt = jwt.as_ref().map(|cow| cow.as_ref());

    // Perform auth check
    let is_allowed = auth::is_allowed(path, jwt, &ctx).await;
    if !is_allowed {
        trace!(path = req.uri().path(), jwt, "response: 403 Forbidden");
        return error_response(StatusCode::FORBIDDEN);
    }

    // Access is allowed: reply 200 and potentially serve file/add headers.
    if ctx.config.http.serve_files {
        fs::serve_file(path, req.headers(), &ctx).await
    } else {
        let mut builder = Response::builder();

        // Potentially add `X-Accel-Redirect` header.
        if let Some(prefix) = &ctx.config.http.x_accel_redirect {
            // Converting to `HeaderValue` should never panic as path parts are
            // verified to be valid URI paths, which is a stricter grammar than
            // what's allowed inside header values.
            let redirect_path = format!("/{}/{}", prefix.trim_matches('/'), path.without_prefix());
            let value = HeaderValue::try_from(redirect_path)
                .expect("invalid redirect_path for X-Accel-Redirect");
            builder = builder.header("X-Accel-Redirect", value);
        }

        builder
            .body(Body::Empty)
            .expect("failed to build response with empty body")
    }
}

/// Returns the value of the first query parameter with the given name.
fn find_jwt_in_query<'uri>(
    uri: &'uri Uri,
    parameter_name: &str,
) -> Option<Cow<'uri, str>> {
    let raw_query = uri.query().unwrap_or("");
    form_urlencoded::parse(raw_query.as_bytes())
        .find(|(key, _)| key == parameter_name)
        .map(|(_, value)| value)
}

/// Returns the first value of the given header, with `prefix` stripped. If the
/// value is not valid UTF8, `None` is returned.
fn find_jwt_in_header<'h>(
    headers: &'h HeaderMap,
    header_name: &str,
    prefix: Option<&str>,
) -> Option<&'h str> {
    headers.get(header_name).and_then(|value| {
        let bytes = value.as_bytes();
        let stripped = match prefix {
            Some(prefix) => bytes.strip_prefix(prefix.as_bytes()).unwrap_or(bytes),
            None => bytes,
        };
        match str::from_utf8(stripped) {
            Ok(s) => Some(s),
            Err(_) => {
                warn!(header_name, prefix, raw_header = bytes, "ignoring non-UTF8 header value");
                None
            }
        }
    })
}


fn error_response(status: StatusCode) -> Response {
    let body = format!("{} {}", status.as_u16(), status.canonical_reason().unwrap_or_default());
    Response::builder()
        .status(status)
        .body(Body::tiny(body))
        .unwrap()
}

/// Data available to each request handler via reference.
pub struct Context {
    pub config: Config,
    pub jwt: jwt::Context,
    pub downloads_path: PathBuf,
}

/// Main entry point: starting the HTTP server.
///
/// This is mainly plumbing code and does not contain much interesting logic.
pub async fn serve(ctx: Context) -> Result<(), Error> {
    let addr = SocketAddr::from((ctx.config.http.address, ctx.config.http.port));

    let listener = TcpListener::bind(addr).await?;
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut signal = std::pin::pin!(shutdown_signal());

    let http = http1::Builder::new();

    let shutdown_timeout = ctx.config.http.shutdown_timeout;
    let ctx = Arc::new(ctx);

    info!("Listening on http://{}", addr);
    loop {
        tokio::select! {
            Ok((stream, _addr)) = listener.accept() => {
                let io = TokioIo::new(stream);
                let ctx = Arc::clone(&ctx);
                let conn = http.serve_connection(io, service_fn(move |req| {
                    handle_internal_errors(handle(req, Arc::clone(&ctx)))
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
        _ = tokio::time::sleep(shutdown_timeout) => {
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
    future: impl Future<Output = Response>,
) -> Result<Response, Infallible> {
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
                    .body(Body::tiny("Internal server error: panic"))
                    .unwrap()
            )
        }
    }
}

type Response<B = Body> = hyper::Response<B>;

enum Body {
    Empty,
    Tiny(Full<Bytes>),
    File(fs::FileBody),
}

impl Body {
    fn tiny(s: impl Into<String>) -> Self {
        Self::Tiny(Full::new(s.into().into()))
    }
}

impl hyper::body::Body for Body {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::result::Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        match *self {
            Self::Empty => return Poll::Ready(None),
            Self::Tiny(ref mut inner) => return Pin::new(inner).poll_frame(cx)
                .map_err(|never| match never {}),
            Self::File(ref mut file) => Pin::new(&mut file.0).poll_frame(cx),
        }
    }
}
