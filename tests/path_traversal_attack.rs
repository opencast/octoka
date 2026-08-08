//----------------------------------------------------------------------------//
//              A path traversal attack (also known as directory              //
//              traversal) aims to access files and directories               //
//                that are stored outside the web root folder.                //
//                                   Cite:                                    //
//             https://owasp.org/www-community/attacks/Path_Traversal         //
//----------------------------------------------------------------------------//

use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HEADER_EDDSA: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9";
const PAYLOAD_ADMIN: &str = "eyJleHAiOjQwMTIzNDU2NzgsInJvbGVzIjpbIlJPTEVfQURNSU4iXX0";
const SIG_ADMIN: &str =
    "6Bs6wdvBdWbszV38Lj81OmtW5ibutzUfTc8_X6k3yiwOHNQm5xQrWiILXGRP7eHFiI4Ju1FHu_NxufSUPiELAw";

fn admin_jwt() -> String {
    format!("{HEADER_EDDSA}.{PAYLOAD_ADMIN}.{SIG_ADMIN}")
}

struct FileSetup {
    addr: std::net::SocketAddr,
    _dir: tempfile::TempDir,
}

async fn setup_files(body: &[u8]) -> anyhow::Result<FileSetup> {
    use confique::Config as _;

    // 1. lay out ephemeral file structure: <tmp>/org/channel/abc123/path.mp4
    let dir = tempfile::tempdir()?;
    let event_dir = dir.path().join("org/channel/abc123");
    std::fs::create_dir_all(&event_dir)?;
    std::fs::write(event_dir.join("path.mp4"), body)?;

    // 2. config: serve files, no OC fallback, ephemeral port
    let downloads = dir.path().display();
    let config = format!(
        r#"
        opencast.fallback = "none"
        opencast.downloads_path = "{downloads}"
        jwt.trusted_keys = ["http://127.0.0.1:4055/ed25519.json"]
        http.on_allow = "file"
        http.port = 0
        log.filters.octoka = "trace"
    "#
    );
    let config = octoka::config::Config::builder()
        .preloaded(toml::from_str(&config)?)
        .load()?;
    let _ = octoka::log::init(&config.log, true);

    let (addr, server) = octoka::test_http_server(config).await?;
    tokio::spawn(server);
    Ok(FileSetup { addr, _dir: dir })
}

impl FileSetup {
    fn url(&self) -> String {
        format!(
            "http://{}/static/org/channel/abc123/path.mp4?jwt={}",
            self.addr,
            admin_jwt()
        )
    }
}

// raw_get offers full control over the URL format instead of reqwest which would
// normalize our dotdot requests before calling the API, making the tests moot since we
// want to harden against malicious intent whereby clients send unusual path segments.
async fn raw_get(addr: std::net::SocketAddr, raw_target: &str) -> anyhow::Result<String> {
    let mut s = tokio::net::TcpStream::connect(addr).await?;
    let req = format!("GET {raw_target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).await?;
    Ok(buf.lines().next().unwrap_or_default().to_string()) // e.g. "HTTP/1.1 400 Bad Request"
}

#[tokio::test]
async fn traversal_dotdot_is_rejected() -> anyhow::Result<()> {
    // Given
    let s = setup_files(b"hello").await?;
    let jwt = admin_jwt();

    // When
    let target = format!("/static/org/channel/abc123/../../../../../../etc/passwd?jwt={jwt}");
    let status = raw_get(s.addr, &target).await?;

    // Then
    assert!(
        status.contains(" 400 ") || status.contains(" 404 "),
        "got: {status}"
    );
    Ok(())
}

#[tokio::test]
async fn traversal_percent_encoded_dotdot() -> anyhow::Result<()> {
    // Given
    let s = setup_files(b"hello").await?;
    let jwt = admin_jwt();

    // When
    // %2e%2e = ".."
    let target = format!("/static/org/channel/abc123/%2e%2e/%2e%2e/etc/passwd?jwt={jwt}");
    let status = raw_get(s.addr, &target).await?;

    // Then
    assert!(
        status.contains(" 400 ") || status.contains(" 404 "),
        "got: {status}"
    );
    Ok(())
}

#[tokio::test]
async fn legit_happy_path_serves() -> anyhow::Result<()> {
    // Given
    let s = setup_files(b"hello").await?;

    // When
    let r = reqwest::get(s.url()).await?;

    // Then
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    assert_eq!(r.bytes().await?, &b"hello"[..]);
    Ok(())
}
