use bytes::Bytes;
use futures::TryStreamExt as _;
use http_body_util::StreamBody;
use http_range::{HttpRange, HttpRangeParseError};
use hyper::{header, HeaderMap, StatusCode};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
use tokio_util::codec::{BytesCodec, FramedRead};

use crate::{opencast::PathParts, prelude::*};
use super::{Body, Context, Response};


/// Serves the file referred to by `path` directly from the file system.
pub async fn serve_file(
    path: PathParts<'_>,
    headers: &HeaderMap,
    ctx: &Context,
) -> Response {
    macro_rules! handle_io_err {
        ($e:expr, $action:literal $(,)?) => {
            match $e {
                Ok(v) => v,
                Err(e) => return handle_io_error(&e, $action),
            }
        };
    }


    // Join, resolve and canonicalize path. Check for path traversal attacks.
    let fs_path = handle_io_err!(
        ctx.downloads_path.join(path.without_prefix()).canonicalize(),
        "canonicalizing path",
    );
    let event_dir = ctx.downloads_path.join(path.rel_event_dir());
    if !fs_path.starts_with(&event_dir) {
        warn!(path = path.full_path(), "Directory traversal attack detected, responding 400 Bad Request");
        return super::error_response(StatusCode::BAD_REQUEST);
    }

    // Open file and check size
    let mut file = handle_io_err!(tokio::fs::File::open(&fs_path).await, "opening file");
    let file_size = handle_io_err!(file.metadata().await, "reading file metadata").len();

    let mut response = Response::builder()
        .header(header::ACCEPT_RANGES, "bytes");
    if let Some(mime) = mime_guess::from_path(&fs_path).first() {
        response = response.header("Content-Type", mime.to_string());
    }

    // Check if this is a `Range` request.
    let body = if let Some(range_header) = headers.get(header::RANGE) {
        let range = match HttpRange::parse_bytes(range_header.as_bytes(), file_size) {
            Ok(ranges) if ranges.len() == 1 => ranges[0],
            Ok(_) => {
                debug!(?range_header, path= path.full_path(), "received multi range request");
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::tiny("multiple ranges in 'Range' header not supported"))
                    .expect("bug: invalid response")
            }
            Err(HttpRangeParseError::InvalidRange) => {
                debug!(?range_header, path = path.full_path(), "invalid `Range` header");
                return super::error_response(StatusCode::BAD_REQUEST);
            }
            Err(HttpRangeParseError::NoOverlap) => {
                debug!(?range_header, file_size, path = path.full_path(),
                    "unsatisfiable `Range` header");
                return super::error_response(StatusCode::RANGE_NOT_SATISFIABLE);
            }
        };

        handle_io_err!(file.seek(std::io::SeekFrom::Start(range.start)).await, "seeking in file");
        response = response
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_LENGTH, range.length)
            .header(header::CONTENT_RANGE, format!(
                "bytes {}-{}/{}",
                range.start,
                range.start + range.length - 1,
                file_size,
            ));

        FileBody::new(file, range.length)
    } else {
        response = response.header(header::CONTENT_LENGTH, file_size);
        FileBody::new(file, file_size)
    };

    response.body(Body::File(body)).expect("invalid response")
}

/// `Body` to stream a file as HTTP response.
pub(super) struct FileBody(
    pub(super) Box<
        dyn Sync + Send + Unpin + hyper::body::Body<Error = std::io::Error, Data = Bytes>
    >,
);

impl FileBody {
    fn new(file: tokio::fs::File, limit: u64) -> Self {
        let reader = FramedRead::new(file.take(limit), BytesCodec::new())
            .map_ok(|bytes| hyper::body::Frame::data(bytes.freeze()));
        Self(Box::new(StreamBody::new(reader)))
    }
}

fn handle_io_error(e: &std::io::Error, action: &str) -> Response {
    let code = match e.kind() {
        | std::io::ErrorKind::NotFound
        | std::io::ErrorKind::IsADirectory => StatusCode::NOT_FOUND,

        | std::io::ErrorKind::InvalidData
        | std::io::ErrorKind::InvalidFilename => StatusCode::BAD_REQUEST,

        | std::io::ErrorKind::TimedOut
        | std::io::ErrorKind::ResourceBusy => StatusCode::SERVICE_UNAVAILABLE,

        // It seems like 403 would be the perfect response, but 403
        // means the HTTP client is not allowed to read. This server
        // process not being allowed to read the file is a configuration
        // error.
        std::io::ErrorKind::PermissionDenied => StatusCode::INTERNAL_SERVER_ERROR,

        // Everything else is handled as internal server error. Most of
        // the remaining error kinds are in fact just internal errors.
        // And for a few, one could reply with some more specific 5xx
        // status code, but it's not worth the hassle and might reveal
        // too much about the server.
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };

    if e.kind() == std::io::ErrorKind::NotFound {
        debug!("NotFound error while {action} -> 404 Not Found");
    } else {
        error!(
            "Error while {action} -> {} {}. Error: {e}",
            code,
            code.canonical_reason().unwrap_or_default(),
        );
    }

    super::error_response(code)
}
