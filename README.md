# 🐙 octoka - Opencast Token Authenticator

octoka is a small HTTP server that can answer [JWT-authenticated](https://docs.opencast.org/develop/admin/#configuration/security.jwt/#standard-oc-schema-for-jwts) requests for Opencast static files.
Run it alongside Opencast to enable faster auth-checked file serving, even while Opencast is down (e.g. for updates).

> **Note**: octoka is still young and there are no stable releases yet. It is currently being tested and evaluated. Consider it experimental software at the moment.

## Quick start

- Get the octoka executable [from the releases page](https://github.com/opencast/octoka/releases) or by [building it yourself](#building).
- Get the config template [from the releases page](https://github.com/opencast/octoka/releases) or by running `./octoka gen-config-template -o config.toml`.
- Go through the config and adjust as required (search for "required" to see values you have to set).
- octoka expects the config at `/etc/octoka/config.toml` or `config.toml` in the working directory.
  This can be overwritten via `--config` flag or `OCTOKA_CONFIG_PATH` env var.
- Run `octoka check` to check if the configuration is correct.
- Run `octoka run` to actually run the service.

In production, octoka should always be paired with another HTTP server like nginx, to provide TLS and only forward certain requests to octoka.
For information on how to set this up, see [`docs/reverse-proxy.md`](https://github.com/opencast/octoka/blob/main/docs/reverse-proxy.md).


## Features

- JWT:
  - Signing algorithms: `EdDSA` (ed25519), `ED256`, `ED384`
  - Fetching public keys from multiple JWKS URLs
  - Key caching & automatic refresh
- Opencast fallback: if JWT don't grant access, ask Opencast by forwarding request
- HTTP:
  - Efficient file server (if configured)
  - `X-Accel-Redirect` (if configured)
  - Configurable CORS replies
- Fast & efficient: >50k req/s while using only a few MB of memory (with `http.serve_files = false`)

### HTTP file server details

The built-in file server should be fast and feature-complete enough for basically all use cases.
It supports `Range` requests, `ETag` and `Last-Modified` headers, `If-None-Match` and `If-Modified-Since` conditional requests, protection against path traversal attacks, and streamed responses.
It does *not* support: multi-`Range` requests or conditional `If-Unmodified-Since`, `If-Match`, and `If-Range` headers.
These are very rarely used for static files in the real world and often unimplemented in many HTTP servers.
Obviously, servers like nginx are still better file servers and you should let them serve the files for the best performance and obscure features.


## How it works

octoka can only deal with HTTP requests for OC static files, specifically requests that look like this:

```
GET /<prefix>/<org>/<channel>/<event-id>/<suffix...>
```

`prefix` and `suffix` can contain slashes, all other parts are a single path segment.
`prefix` is configurable in octoka, but for most OC installations, it is just `static`.

After splitting the path into these components, octoka will check if the request has an attached JWT.
It could be passed as query parameter (e.g. `?jwt=...`) or in a header (e.g. `Authorization: Bearer ...`).
If there is no JWT found, the request is treated as unauthorized.

Next, the JWT is decoded and its signature verified.
octoka then checks the claims to see if they grant `read` access to this event, which can happen in two ways (cf. ["Standard OC Schema for JWTs"](https://docs.opencast.org/develop/admin/#configuration/security.jwt/#standard-oc-schema-for-jwts)):
- The `roles` claim contains `ROLE_ADMIN`
- The `oc` claim contains an the event ID with `read` access, e.g. `"oc": { "e:<event-id>": ["read"] }`

Note that octoka has no access to the event's ACL or series information, it only knows the event ID from checking the path!
This is important to understand and explains why the JWT has to grant access directly.

If the JWT grants access as explained above, the request is treated as authenticated; and as unauthenticated otherwise.
In the latter case, octoka can just forward the request to Opencast to see what it thinks (see `opencast.fallback` config).
Octoka's final response depends on the configuration.
In the authenticated case, either the file is actually served, or it's a 200 with empty body, or it can include an `X-Accel-Redirect` header.
In the unauthenticated case, either 403 is replied or 204 with an `X-Accel-Redirect`.


## Building

To build octoka yourself, you need to [install Rust with `rustup`](https://www.rust-lang.org/learn/get-started).

- MUSL release build (our releases are `x86_64-unknown-linux-musl`):
  - `rustup target add x86_64-unknown-linux-musl`
  - `./util/build-release.sh` (creates `deploy/` folder with binary and config)
- Normal release build:
  - `cargo build --release` (binary at `target/release/octoka`)
- Development:
  - Build: `cargo build` (binary at `target/debug/octoka`)
  - Just run compiler checks: `cargo check`
  - Immediately run: `cargo run` (pass argument likes `cargo run -- run`)
