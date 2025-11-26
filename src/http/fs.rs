use std::time::SystemTime;

use bytes::Bytes;
use futures::TryStreamExt as _;
use http::Request;
use http_body_util::combinators::BoxBody;
use http_range::{HttpRange, HttpRangeParseError};
use hyper::{HeaderMap, StatusCode, body::Incoming, header};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncSeekExt as _};

use super::{Body, Context, Response};
use crate::{http::add_cors_headers, opencast::PathParts, prelude::*};


/// Serves the file referred to by `path` directly from the file system.
pub async fn serve_file(
    path: PathParts<'_>,
    req: &Request<Incoming>,
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

    // This is checked by `Config::validate`
    let downloads_path = ctx.config.opencast.downloads_path.as_ref()
        .expect("no downloads_path in serve_files");

    // Join, resolve and canonicalize path. Check for path traversal attacks.
    let fs_path = handle_io_err!(
        downloads_path.join(path.without_prefix()).canonicalize(),
        "canonicalizing path",
    );
    let event_dir = downloads_path.join(path.rel_event_dir());
    if !fs_path.starts_with(&event_dir) {
        warn!(
            path = path.full_path(),
            "Directory traversal attack detected, responding 400 Bad Request",
        );
        return super::error_response(StatusCode::BAD_REQUEST);
    }

    // Open file and check size
    let mut file = handle_io_err!(tokio::fs::File::open(&fs_path).await, "opening file");
    let metadata = handle_io_err!(file.metadata().await, "reading file metadata");
    let file_size = metadata.len();

    // We `unwrap` here as this will always return `Ok` on most platforms.
    // Specifically, Unix and Windows always return `Ok` to the best of my
    // knowledge.
    let mtime = metadata.modified()
        .expect("platform does not support 'modified' timestamp");
    let etag = etag(mtime, file_size, &metadata);



    let mut response = Response::builder()
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::LAST_MODIFIED, httpdate::fmt_http_date(mtime))
        .header(header::ETAG, &etag);
    add_cors_headers(req, &mut response, &ctx.config.http);
    if let Some(mime) = mime_guess::from_path(&fs_path).first() {
        response = response.header("Content-Type", mime.to_string());
    }

    // If the `download=1` parameter is set, we add a header to make browsers
    // download a file instead of showing it inline.
    if form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
        .any(|(key, value)| key == "download" && value == "1")
    {
        response = response.header(header::CONTENT_DISPOSITION, "attachment");
    }

    if is_unmodified(req.headers(), &etag, mtime) {
        return response.status(StatusCode::NOT_MODIFIED).body(Body::Empty).unwrap();
    }

    // Check if this is a `Range` request.
    let body = if let Some(range_header) = req.headers().get(header::RANGE) {
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

        handle_io_err!(
            file.seek(std::io::SeekFrom::Start(range.start)).await,
            "seeking in file"
        );
        response = response
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_LENGTH, range.length)
            .header(header::CONTENT_RANGE, format!(
                "bytes {}-{}/{}",
                range.start,
                range.start + range.length - 1,
                file_size,
            ));

        make_file_body(file.take(range.length))
    } else {
        response = response.header(header::CONTENT_LENGTH, file_size);
        make_file_body(file)
    };

    response.body(Body::File(body)).expect("invalid response")
}

/// `Body` to stream a file as HTTP response.
pub(super) type FileBody = BoxBody<Bytes, std::io::Error>;

fn make_file_body<R: AsyncRead + Send + Sync + 'static>(reader: R) -> FileBody {
    let reader = tokio_util::io::ReaderStream::new(reader)
        .map_ok(hyper::body::Frame::data);
    let body = http_body_util::StreamBody::new(reader);
    BoxBody::new(body)
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

/// Returns a file's value for the `ETag` header, which contains the mtime, size
/// and, on Unix, also the inode number. Opencast itself uses mtime, size and
/// filename. The filename is not necessary though, as the ETag only needs to
/// be unique for the same URI. ETags of different filenames (and thus URIs) are
/// never compared by browsers.
///
/// Of course, hashing the actual file content would be best, but is not viable
/// for the huge files we are dealing with.
fn etag(mtime: SystemTime, size: u64, metadata: &std::fs::Metadata) -> String {
    // On unix, we also add the inode number to the ETag. It can protect against
    // "content change, same etag" situations when a new file is moved to the
    // new location. It's not that important, but helps a bit. Including the
    // raw inode number in a public response does not seem to be a security
    // problem: https://security.stackexchange.com/a/178149/147555
    #[cfg(target_family = "unix")]
    fn etag_extra(out: &mut String, metadata: &std::fs::Metadata) {
        use std::{fmt::Write, os::unix::fs::MetadataExt};

        write!(out, ":{}", metadata.ino()).unwrap();
    }

    #[cfg(not(target_family = "unix"))]
    fn etag_extra(_: &mut String, _: &std::fs::Metadata) {}

    let mtime_ms = match mtime.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => duration.as_millis() as i128,
        Err(e) => -(e.duration().as_millis() as i128),
    };


    let mut out = format!("\"{mtime_ms}:{size}");
    etag_extra(&mut out, metadata);
    out.push('"');
    out
}

/// Checks `If-None-Match` and `If-Modified-Since` headers and returns whether
/// we should reply with "304 Unmodified".
fn is_unmodified(
    headers: &HeaderMap,
    etag: &str,
    mtime: SystemTime,
) -> bool {
    // The `If-None-Match` header has priority over `If-Unmodified-Since`.
    if let Some(if_none_match) = headers.get(header::IF_NONE_MATCH) {
        // Makes no sense to set in this case, but we still handle it.
        if if_none_match == "*" {
            return true;
        }

        // We ignore the "/W" prefix as we need to perform a weak comparison. We
        // don't exactly check for a well-formed header,  but the spec doesn't
        // mandate that. If we find the actual etag somewhere, that's fine.
        return if_none_match.as_bytes()
            .split(|b| *b == b',')
            .map(|tag| tag.trim_ascii())
            .map(|tag| tag.strip_prefix(b"W/").unwrap_or(tag))
            .any(|tag| tag == etag.as_bytes());
    }


    // If the value is not valid, the spec says we should ignore the header.
    let if_modified_since = headers.get(header::IF_MODIFIED_SINCE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| httpdate::parse_http_date(s.trim()).ok());
    if let Some(if_modified_since) = if_modified_since {
        return mtime < if_modified_since;
    }

    // If no header is present, we reply with normal 200.
    false
}
