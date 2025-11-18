use std::{
    borrow::Cow, convert::Infallible, error::Error, net::SocketAddr, panic::AssertUnwindSafe,
    pin::Pin, sync::Arc, task::Poll, time::Duration,
};

use futures::FutureExt as _;
use http_body_util::Full;
use hyper::{
    Method, Request, StatusCode,
    body::{Bytes, Incoming},
    header::{self, HeaderValue},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::{
    auth,
    config::Config,
    jwt,
    opencast::{FallbackMode, PathParts},
    prelude::*,
    util::{EmptyHttpBody, SimpleHttpClient}
};

mod config;
mod fs;

pub use self::config::{HttpConfig, JwtSource, OnAllow};


const ALLOWED_METHODS: &str = "GET, OPTIONS";


/// Main entry point for a single incoming request
async fn handle(req: Request<Incoming>, ctx: Arc<Context>) -> Response {
    trace!("incoming req: {} {}", req.method(), req.uri().path());

    // Handle OPTIONS requests
    if req.method() == Method::OPTIONS {
        let mut builder = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(header::ALLOW, ALLOWED_METHODS);

        add_cors_headers(&req, &mut builder, &ctx.config.http);

        return builder.body(Body::Empty).unwrap();
    }

    if req.method() != Method::GET {
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
    let jwt = ctx.config.http.jwt_sources.iter().find_map(|source| source.extract(&req));
    let jwt = jwt.as_ref().map(|cow| cow.as_ref());

    // Perform auth check
    let mut is_allowed = auth::is_allowed(path, jwt, &ctx).await;

    // If we cannot authorize the request, maybe Opencast can.
    if !is_allowed && ctx.config.opencast.fallback != FallbackMode::None {
        match ask_opencast(&req, &ctx).await {
            Ok(allowed) => is_allowed = allowed,
            Err(r) => return r,
        }
    }

    // If we deny access, reply according to the config.
    if !is_allowed {
        return match &ctx.config.http.on_deny {
            config::OnDeny::Empty => {
                trace!(path = req.uri().path(), jwt, "not allowed -> response: 403 Forbidden");
                error_response(StatusCode::FORBIDDEN)
            }
            config::OnDeny::XAccelRedirect(prefix) => {
                trace!(path = req.uri().path(), jwt,
                    "not allowed -> response: 204 with X-Accel-Redirect");

                Response::builder()
                    .header("X-Accel-Redirect", x_accel_redirect_header(prefix, path.full_path()))
                    .status(StatusCode::NO_CONTENT)
                    .body(Body::Empty)
                    .expect("failed to build response with empty body")
            }
        };
    }

    // Access is allowed: reply 200 and potentially serve file/add headers.
    trace!(path = req.uri().path(),
        "allowing access -> responding with {:?}", ctx.config.http.on_allow);
    if ctx.config.http.on_allow == OnAllow::File {
        fs::serve_file(path, &req, &ctx).await
    } else {
        let mut builder = Response::builder();

        // Potentially add `X-Accel-Redirect` header.
        if let OnAllow::XAccelRedirect(prefix) = &ctx.config.http.on_allow {
            let value = x_accel_redirect_header(prefix, path.without_prefix());
            builder = builder.header("X-Accel-Redirect", value);
        }

        add_cors_headers(&req, &mut builder, &ctx.config.http);
        builder
            .status(StatusCode::NO_CONTENT)
            .body(Body::Empty)
            .expect("failed to build response with empty body")
    }
}

/// Adds CORS headers IF we allow cors for the request's Origin.
fn add_cors_headers(
    req: &Request<Incoming>,
    response: &mut http::response::Builder,
    config: &HttpConfig,
) {
    // Note: header values returned here have no leading or trailing
    // whitespace. See https://github.com/seanmonstar/httparse/pull/48
    // and RFC 7230 section 3.2.3.

    // Only allow CORS if Origin is allowed by the config. This also excludes
    // `null`.
    let origin = match req.headers().get(header::ORIGIN) {
        Some(h) if config.cors_allowed_origins.iter().any(|o| h == o.as_str()) => h,
        Some(origin) => {
            trace!(?origin, "CORS denied as origin not whitelisted");
            return;
        }
        None => {
            trace!("not setting CORS headers as 'Origin' header is not set");
            return;
        }
    };

    if req.method() == Method::OPTIONS {
        // Only allow 'Authorization' header.
        match req.headers().get(header::ACCESS_CONTROL_REQUEST_HEADERS) {
            Some(h) if h.as_bytes()
                .split(|b| *b == b',')
                .all(|rh| rh.trim_ascii().eq_ignore_ascii_case(b"Authorization")) => {}
            req_headers => {
                trace!(?req_headers, "CORS denied due to disallowed headers");
                return;
            }
        }

        // Require this header to be "GET".
        match req.headers().get(header::ACCESS_CONTROL_REQUEST_METHOD) {
            Some(h) if h == "GET" => {}
            method => {
                trace!(?method, "CORS denied due to disallowed method");
                return;
            }
        }
    }

    // At this point, we allow the CORS request
    trace!(?origin, "Adding CORS headers");
    response.headers_mut().unwrap().extend([
        (header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone()),
        (header::ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true")),
        (header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static(ALLOWED_METHODS)),
        (header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Authorization")),

        // We allow browser to cache this CORS result for 24h. We allow it for the same
        // input all the time, so nothing here will change, except if the config is
        // changed, which happens very rarely. I cannot really think of anything that
        // would make this caching unsafe.
        (header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("86400")),
    ]);
}

/// Sends a HEAD request to Opencast with the headers and path/query of `req`.
/// Returns whether OC replied with 2xx.
async fn ask_opencast(orig_req: &Request<Incoming>, ctx: &Context) -> Result<bool, Response> {
    let uri = ctx.config.opencast.host.clone()
        .with_path_and_query(orig_req.uri().path_and_query().unwrap().clone());
    trace!(?uri, "asking OC for auth-info");


    let mut req = Request::builder()
        .uri(uri)
        .method(match ctx.config.opencast.fallback {
            FallbackMode::Head => Method::HEAD,
            FallbackMode::Get => Method::GET,
            FallbackMode::None => unreachable!(),
        })
        .body(EmptyHttpBody::new())
        // There should be no reason building this request can fail.
        .expect("failed to build request for OC");
    *req.headers_mut() = orig_req.headers().clone();

    let response = tokio::select! {
        res = ctx.oc_client.request(req) => match res {
            Ok(r) => r,
            Err(e) => {
                debug!("error sending request to OC: {e}");
                return Err(error_response(StatusCode::BAD_GATEWAY));
            }
        },
        _ = tokio::time::sleep(Duration::from_secs(3)) => {
            debug!("timeout waiting for OC");
            return Err(error_response(StatusCode::GATEWAY_TIMEOUT));
        }
    };

    // If OC replies 404, then it doesn't make a lot of sense for use to treat
    // it as 403. For `on_allow = "file"` and `"x-accel-redirect"`, replying
    // with 404 is certainly the correct thing to do.
    //
    // TODO: think about `on_allow = "empty"` more! Nginx treats auth_requests
    // answering 404 as error.
    if response.status() == StatusCode::NOT_FOUND {
        trace!("OC replied 404 -> replying with that");
        return Err(error_response(StatusCode::NOT_FOUND));
    }

    // If OC replies 2xx, the request is treated as authorized.
    let is_allowed = response.status().is_success();
    trace!(is_allowed, status = ?response.status(), "OC replied");
    Ok(is_allowed)
}

impl JwtSource {
    /// Tries to extract a JWT from the given request according to `self`.
    fn extract<'r>(&self, req: &'r Request<Incoming>) -> Option<Cow<'r, str>> {
        match self {
            JwtSource::Query { name } => {
                let raw_query = req.uri().query().unwrap_or("");
                form_urlencoded::parse(raw_query.as_bytes())
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value)
            }
            JwtSource::Header { name, prefix } => {
                let value = req.headers().get(name)?;
                let bytes = value.as_bytes();
                let stripped = match prefix {
                    Some(prefix) => bytes.strip_prefix(prefix.as_bytes()).unwrap_or(bytes),
                    None => bytes,
                };
                match str::from_utf8(stripped) {
                    Ok(s) => Some(s.into()),
                    Err(_) => {
                        warn!(name, prefix, raw_header = bytes, "ignoring non-UTF8 header value");
                        None
                    }
                }
            },
        }
    }
}

fn x_accel_redirect_header(prefix: &str, path: &str) -> HeaderValue {
    // Converting to `HeaderValue` should never panic as the prefix and path
    // parts are verified to be valid URI paths, which is a stricter grammar
    // than what's allowed inside header values.
    let redirect_path = format!("/{}/{}", prefix.trim_matches('/'), path);
    HeaderValue::try_from(redirect_path)
        .expect("invalid redirect_path for X-Accel-Redirect")
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
    pub oc_client: SimpleHttpClient,
}

impl Context {
    pub async fn new(config: Config) -> Result<Self> {
        Ok(Self {
            jwt: jwt::Context::new(&config.jwt).await?,
            oc_client: crate::util::http_client()?,
            config,
        })
    }
}

/// Main entry point: starting the HTTP server.
///
/// This is mainly plumbing code and does not contain much interesting logic.
pub async fn serve(ctx: Context) -> Result<()> {
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
                        log_hyper_error(e);
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
                .or(panic.downcast_ref::<&str>().copied());

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

fn log_hyper_error(err: hyper::Error) {
    // Many errors are really not critical and some are unfortunately expected
    // to occur. For example, browsers often close connections prematurely,
    // especially when loading video. Such an error doesn't require attention
    // from us at all.
    //
    // I'm not 100% sure what exactly is fine to ignore and what not, but this
    // code can adjusted over time. Also see:
    // https://github.com/hyperium/hyper/discussions/3915
    let warn = if let Some(io) = err.source().and_then(|s| s.downcast_ref::<std::io::Error>()) {
        match io.kind() {
            std::io::ErrorKind::ConnectionReset => false,
            std::io::ErrorKind::NotConnected => false,
            _ => true,
        }
    } else {
        err.is_timeout() || err.is_user() || err.is_closed() || err.is_canceled()
    };

    macro_rules! debug_or_warn {
        ($($t:tt)*) => {
            if warn {
                warn!($($t)*);
            } else {
                debug!($($t)*);
            }
        };
    }

    let full_chain = anyhow::Chain::new(&err)
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(", caused by ");

    debug_or_warn!("HTTP error: {full_chain} ({err:?})");
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
            Self::Empty => Poll::Ready(None),
            Self::Tiny(ref mut inner) => Pin::new(inner).poll_frame(cx)
                .map_err(|never| match never {}),
            Self::File(ref mut file) => Pin::new(file).poll_frame(cx),
        }
    }
}
