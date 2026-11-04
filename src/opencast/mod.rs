mod config;

use std::borrow::Cow;

use percent_encoding::percent_decode_str;

pub use self::config::{FallbackMode, OpencastConfig};


/// Represents a path to a static Opencast file split into its relevant
/// components.
#[derive(Debug, Clone)]
pub struct PathParts<'a> {
    /// Original raw path, always with leading '/', NOT percent-decoded.
    raw_path: &'a str,
    without_prefix_decoded: Option<Box<str>>,

    // The following are indices into the path, each pointing to a slash.
    // `start_org` refers to `raw_path`:
    //
    //     /static/mh_default_org/engage-player/eb4f3b14-3953-4c17-957d-6e4c5868206b/suffix...
    //            ^
    //            start_org
    //
    // The other indices refer to the `without_prefix` path (which is either
    // stored explicitly in `without_prefix_decoded` in case of any encoded
    // characters, or implicitly in raw_path + start_org).
    //
    //             mh_default_org/engage-player/eb4f3b14-3953-4c17-957d-6e4c5868206b/suffix...
    //                           ^             ^                                    ^
    //                           |             start_event_id                       start_suffix
    //                           start_channel
    start_org: u16,
    start_channel: u16,
    start_event_id: u16,
    start_suffix: u16,
}

#[allow(dead_code)] // TODO
impl<'a> PathParts<'a> {
    /// Parses the given path into its components.
    ///
    /// Returns `None` if the path is malformed or does not start with any
    /// prefixes configured in `opencast.path_prefixes`.
    pub fn parse(path: &'a str, config: &OpencastConfig) -> Option<Self> {
        Self::parse_impl(path, &config.path_prefixes)
    }

    fn parse_impl(path: &'a str, path_prefixes: &[String]) -> Option<Self> {
        if !path.starts_with('/') {
            return None;
        }

        // Check if it starts with any of the configured prefixes and split
        // `path` into prefix part and rest. This is done on the non-encoded
        // path: prefixes are checked to not contain encoded characters.
        //
        // The prefix must be followed by a slash, otherwise `/staticfoo/...`
        // would match the prefix `static`. Prefixes are never empty, as checked
        // by the config validation.
        let prefix = path_prefixes.iter()
            .map(|prefix| prefix.trim_matches('/'))
            .find(|prefix| {
                path[1..].strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
            })?;
        let start_org = u16::try_from(prefix.len()).ok()? + 1;
        let rest_raw = &path[start_org as usize + 1..];

        // Percent-decode the rest. Reject non-UTF8, encoded slashes (%2f) and
        // encoded ASCII control characters (%00-%1f, %7f). The latter can
        // only appear via decoding: hyper already rejects them in raw paths.
        let rest = percent_decode_str(rest_raw).decode_utf8().ok()?;
        if let Cow::Owned(rest) = &rest {
            if rest.bytes().any(|b| b.is_ascii_control()) {
                return None;
            }
            if rest.matches('/').count() != rest_raw.matches('/').count() {
                return None;
            }
        }

        // Returns the index of the next slash after the slash at `start`. Fails
        // if there is no further slash, or if the segment in between is empty.
        // Empty segments must be rejected: an empty org would make
        // `without_prefix()` start with a slash, i.e. an absolute path.
        let find_after = |start: u16| {
            let segment_start = start as usize;
            let pos = rest[segment_start..].find('/')?;
            if pos == 0 {
                return None;
            }
            u16::try_from(segment_start + pos).ok()
        };

        let start_channel = find_after(0)?;
        let start_event_id = find_after(start_channel + 1)?;
        let start_suffix = find_after(start_event_id + 1)?;

        // The suffix must not be empty either.
        if start_suffix as usize + 1 >= rest.len() {
            return None;
        }

        Some(Self {
            raw_path: path,
            without_prefix_decoded: match rest {
                Cow::Borrowed(_) => None,
                Cow::Owned(s) => Some(s.into()),
            },
            start_org,
            start_channel,
            start_event_id,
            start_suffix,
        })
    }

    /// Full path, as passed to `parse`, not percent-decoded!
    pub fn full_path_raw(&self) -> &'a str {
        self.raw_path
    }

    /// Prefix without leading or trailing slashes. See `opencast.path_prefixes`.
    /// Not decoded, but percent-encoding in prefixes is disallowed, so it makes
    /// no difference.
    pub fn prefix(&self) -> &'a str {
        &self.raw_path[1..self.start_org as usize]
    }

    /// Full raw (non-decoded) path without prefix and without leading slash. Do
    /// NOT use for file system operations! Only useful to pass via
    /// X-Accel-Redirect.
    pub fn without_prefix_raw(&self) -> &'a str {
        &self.raw_path[self.start_org as usize + 1..]
    }

    /// Full path without prefix and without leading slash, percent-decoded. May
    /// be used for file system operations.
    pub fn without_prefix_decoded(&self) -> &str {
        self.without_prefix_decoded.as_deref().unwrap_or(self.without_prefix_raw())
    }

    /// Percent-decoded Path without prefix or suffix, i.e. pointing to the
    /// event directory inside the downloads directory.
    pub fn rel_event_dir(&self) -> &str {
        &self.without_prefix_decoded()[..self.start_suffix as usize]
    }

    /// The organization, e.g. `mh_default_org` in single-tenant systems.
    /// Percent-decoded.
    pub fn org(&self) -> &str {
        &self.without_prefix_decoded()[..self.start_channel as usize]
    }

    /// The publication channel, e.g. `engage-player` for most standard files.
    /// Percent-decoded
    pub fn channel(&self) -> &str {
        &self.without_prefix_decoded()[self.start_channel as usize + 1..self.start_event_id as usize]
    }

    /// The event ID.
    pub fn event_id(&self) -> &str {
        &self.without_prefix_decoded()[self.start_event_id as usize + 1..self.start_suffix as usize]
    }

    /// Path inside the event's directory, without leading slash.
    pub fn suffix(&self) -> &str {
        &self.without_prefix_decoded()[self.start_suffix as usize + 1..]
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! assert_path_parse {
        ($path:expr, $prefixes:expr, {
            prefix: $prefix:expr,
            org: $org:expr,
            channel: $channel:expr,
            event_id: $event_id:expr,
            suffix: $suffix:expr,
            without_prefix_raw: $without_prefix_raw:expr,
            without_prefix_decoded: $without_prefix_decoded:expr,
            rel_event_dir: $rel_event_dir:expr,
        }) => {
            let parsed = PathParts::parse_impl($path, &prefixes($prefixes))
                .expect("failed to parse path");
            assert_eq!(parsed.full_path_raw(), $path);
            assert_eq!(parsed.prefix(), $prefix);
            assert_eq!(parsed.org(), $org);
            assert_eq!(parsed.channel(), $channel);
            assert_eq!(parsed.event_id(), $event_id);
            assert_eq!(parsed.suffix(), $suffix);
            assert_eq!(parsed.without_prefix_raw(), $without_prefix_raw);
            assert_eq!(parsed.without_prefix_decoded(), $without_prefix_decoded);
            assert_eq!(parsed.rel_event_dir(), $rel_event_dir);
        };
    }

    macro_rules! assert_no_parse {
        ($path:expr, $prefixes:expr $(,)?) => {
            assert!(
                PathParts::parse_impl($path, &prefixes($prefixes)).is_none(),
                "expected {:?} not to parse", $path,
            );
        };
    }

    fn prefixes<const N: usize>(prefixes: [&str; N]) -> Vec<String> {
        prefixes.iter().map(|s| s.to_string()).collect()
    }



    #[test]
    fn normal_path() {
        assert_path_parse!("/static/mh_default_org/engage-player/ev-id/a/b.mp4", ["/static"], {
            prefix: "static",
            org: "mh_default_org",
            channel: "engage-player",
            event_id: "ev-id",
            suffix: "a/b.mp4",
            without_prefix_raw: "mh_default_org/engage-player/ev-id/a/b.mp4",
            without_prefix_decoded: "mh_default_org/engage-player/ev-id/a/b.mp4",
            rel_event_dir: "mh_default_org/engage-player/ev-id",
        });
    }

    #[test]
    fn single_component_suffix() {
        assert_path_parse!("/static/org/ch/ev/file.mp4", ["/static"], {
            prefix: "static",
            org: "org",
            channel: "ch",
            event_id: "ev",
            suffix: "file.mp4",
            without_prefix_raw: "org/ch/ev/file.mp4",
            without_prefix_decoded: "org/ch/ev/file.mp4",
            rel_event_dir: "org/ch/ev",
        });
    }

    #[test]
    fn prefix_slash_variants() {
        // Leading/trailing slashes in the configured prefix don't matter.
        for prefix in ["static", "/static", "static/", "/static/"] {
            assert_path_parse!("/static/org/ch/ev/file", [prefix], {
                prefix: "static",
                org: "org",
                channel: "ch",
                event_id: "ev",
                suffix: "file",
                without_prefix_raw: "org/ch/ev/file",
                without_prefix_decoded: "org/ch/ev/file",
                rel_event_dir: "org/ch/ev",
            });
        }
    }

    #[test]
    fn multi_component_prefix() {
        assert_path_parse!("/foo/bar/org/ch/ev/file", ["/foo/bar"], {
            prefix: "foo/bar",
            org: "org",
            channel: "ch",
            event_id: "ev",
            suffix: "file",
            without_prefix_raw: "org/ch/ev/file",
            without_prefix_decoded: "org/ch/ev/file",
            rel_event_dir: "org/ch/ev",
        });
    }

    #[test]
    fn multiple_prefixes() {
        let prefixes = ["/static", "/files/", "foo/bar"];
        assert_path_parse!("/static/org/ch/ev/file", prefixes, {
            prefix: "static",
            org: "org",
            channel: "ch",
            event_id: "ev",
            suffix: "file",
            without_prefix_raw: "org/ch/ev/file",
            without_prefix_decoded: "org/ch/ev/file",
            rel_event_dir: "org/ch/ev",
        });
        assert_path_parse!("/files/org/ch/ev/file", prefixes, {
            prefix: "files",
            org: "org",
            channel: "ch",
            event_id: "ev",
            suffix: "file",
            without_prefix_raw: "org/ch/ev/file",
            without_prefix_decoded: "org/ch/ev/file",
            rel_event_dir: "org/ch/ev",
        });
        assert_path_parse!("/foo/bar/org/ch/ev/file", prefixes, {
            prefix: "foo/bar",
            org: "org",
            channel: "ch",
            event_id: "ev",
            suffix: "file",
            without_prefix_raw: "org/ch/ev/file",
            without_prefix_decoded: "org/ch/ev/file",
            rel_event_dir: "org/ch/ev",
        });
    }

    #[test]
    fn rejects_too_few_components() {
        assert_no_parse!("/static/org/ch/ev", ["/static"]);
        assert_no_parse!("/static/org/ch", ["/static"]);
        assert_no_parse!("/static/org", ["/static"]);
        assert_no_parse!("/static/", ["/static"]);
    }

    #[test]
    fn rejects_wrong_or_missing_prefix() {
        assert_no_parse!("/other/org/ch/ev/file", ["/static"]);
        assert_no_parse!("/org/ch/ev/file", ["/static"]);
        assert_no_parse!("static/org/ch/ev/file", ["/static"]);
        assert_no_parse!("", ["/static"]);
        assert_no_parse!("/", ["/static"]);
    }

    #[test]
    fn rejects_empty_segments() {
        assert_no_parse!("/static//etc/x/passwd", ["/static"]);
        assert_no_parse!("/static//etc/x/y/passwd", ["/static"]);
        assert_no_parse!("/static///x/passwd", ["/static"]);
        assert_no_parse!("/static///x/y/passwd", ["/static"]);
        assert_no_parse!("/static/org//ev/file", ["/static"]);
        assert_no_parse!("/static/org/ch//file", ["/static"]);
        assert_no_parse!("/static/org/ch/ev/", ["/static"]);
    }

    /// Invariant that `http::fs::serve_file` relies on.
    #[test]
    fn without_prefix_never_absolute() {
        let paths = [
            "/static//a/b/c",
            "/static//a/b/c/d",
            "/static///b/c",
            "/static///b/c/d/e",
            "/static/a//b/c/d",
            "/static/%2Fa/b/c/d",
        ];
        for path in paths {
            if let Some(p) = PathParts::parse_impl(path, &prefixes(["/static"])) {
                assert!(!p.without_prefix_decoded().starts_with('/'), "{path:?}");
                assert!(!p.rel_event_dir().starts_with('/'), "{path:?}");
            }
        }
    }

    /// The prefix must be followed by a slash, otherwise `start_org` points
    /// into the middle of a segment.
    #[test]
    fn prefix_must_be_followed_by_slash() {
        assert_no_parse!("/staticfoo/org/ch/ev/file", ["/static"]);
        assert_no_parse!("/static-2/org/ch/ev/file", ["/static"]);
    }

    #[test]
    fn bare_prefix() {
        assert_no_parse!("/static", ["/static"]);
    }

    /// `/static` must not match `/static2/...`, regardless of config order.
    #[test]
    fn overlapping_prefixes() {
        assert_path_parse!("/static2/org/ch/ev/file", ["/static", "/static2"], {
            prefix: "static2",
            org: "org",
            channel: "ch",
            event_id: "ev",
            suffix: "file",
            without_prefix_raw: "org/ch/ev/file",
            without_prefix_decoded: "org/ch/ev/file",
            rel_event_dir: "org/ch/ev",
        });
    }

    #[test]
    fn single_char_segments() {
        assert_path_parse!("/static/a/b/c/d", ["/static"], {
            prefix: "static",
            org: "a",
            channel: "b",
            event_id: "c",
            suffix: "d",
            without_prefix_raw: "a/b/c/d",
            without_prefix_decoded: "a/b/c/d",
            rel_event_dir: "a/b/c",
        });
        assert_path_parse!("/x/a/b/c/d", ["/x"], {
            prefix: "x",
            org: "a",
            channel: "b",
            event_id: "c",
            suffix: "d",
            without_prefix_raw: "a/b/c/d",
            without_prefix_decoded: "a/b/c/d",
            rel_event_dir: "a/b/c",
        });
    }

    #[test]
    fn decodes_percent_encoding() {
        assert_path_parse!("/static/org/ch/ev/a%20b.mp4", ["/static"], {
            prefix: "static",
            org: "org",
            channel: "ch",
            event_id: "ev",
            suffix: "a b.mp4",
            without_prefix_raw: "org/ch/ev/a%20b.mp4",
            without_prefix_decoded: "org/ch/ev/a b.mp4",
            rel_event_dir: "org/ch/ev",
        });

        // Encoded characters in every segment, including multi-byte UTF-8 and
        // escapes that shrink the string, so all indices shift.
        assert_path_parse!(
            "/static/%C3%B6rg/c%2Bh/ev%2Did/dir%20x/f%25.mp4",
            ["/static"],
            {
                prefix: "static",
                org: "örg",
                channel: "c+h",
                event_id: "ev-id",
                suffix: "dir x/f%.mp4",
                without_prefix_raw: "%C3%B6rg/c%2Bh/ev%2Did/dir%20x/f%25.mp4",
                without_prefix_decoded: "örg/c+h/ev-id/dir x/f%.mp4",
                rel_event_dir: "örg/c+h/ev-id",
            }
        );
    }

    /// `+` is only a space in query strings, never in paths.
    #[test]
    fn plus_is_not_space() {
        assert_path_parse!("/static/org/ch/ev/a+b.mp4", ["/static"], {
            prefix: "static",
            org: "org",
            channel: "ch",
            event_id: "ev",
            suffix: "a+b.mp4",
            without_prefix_raw: "org/ch/ev/a+b.mp4",
            without_prefix_decoded: "org/ch/ev/a+b.mp4",
            rel_event_dir: "org/ch/ev",
        });
    }

    /// Decoding happens exactly once: `%25` becomes a literal `%` and the
    /// following characters are not decoded again. In particular `%252F` is
    /// not an encoded slash.
    #[test]
    fn decodes_only_once() {
        assert_path_parse!("/static/org/ch/ev/a%2520b%252Fc", ["/static"], {
            prefix: "static",
            org: "org",
            channel: "ch",
            event_id: "ev",
            suffix: "a%20b%2Fc",
            without_prefix_raw: "org/ch/ev/a%2520b%252Fc",
            without_prefix_decoded: "org/ch/ev/a%20b%2Fc",
            rel_event_dir: "org/ch/ev",
        });
    }

    /// Invalid escape sequences are passed through literally.
    #[test]
    fn invalid_escapes_are_literal() {
        assert_path_parse!("/static/org/ch/ev/100%.mp4", ["/static"], {
            prefix: "static",
            org: "org",
            channel: "ch",
            event_id: "ev",
            suffix: "100%.mp4",
            without_prefix_raw: "org/ch/ev/100%.mp4",
            without_prefix_decoded: "org/ch/ev/100%.mp4",
            rel_event_dir: "org/ch/ev",
        });
        assert_path_parse!("/static/org/ch/ev/a%zzb", ["/static"], {
            prefix: "static",
            org: "org",
            channel: "ch",
            event_id: "ev",
            suffix: "a%zzb",
            without_prefix_raw: "org/ch/ev/a%zzb",
            without_prefix_decoded: "org/ch/ev/a%zzb",
            rel_event_dir: "org/ch/ev",
        });
    }

    /// An encoded slash is data, not a separator, but we don't support it
    /// anywhere in the path.
    #[test]
    fn rejects_encoded_slash() {
        assert_no_parse!("/static/org/ch/ev/a%2Fb", ["/static"]);
        assert_no_parse!("/static/org/ch/ev/a%2fb", ["/static"]);
        assert_no_parse!("/static/org%2Fx/ch/ev/file", ["/static"]);
        assert_no_parse!("/static/org/ch/ev%2Fx/file", ["/static"]);
        assert_no_parse!("/static/org/ch/ev/dir/%2F", ["/static"]);
        // Would have exactly four segments only after decoding.
        assert_no_parse!("/static/org/ch/ev%2Ffile", ["/static"]);
        assert_no_parse!("/static/org/ch%2Fev/file", ["/static"]);
    }

    #[test]
    fn rejects_encoded_control_characters() {
        assert_no_parse!("/static/org/ch/ev/a%00b", ["/static"]);
        assert_no_parse!("/static/org/ch/ev%00/file", ["/static"]);
        assert_no_parse!("/static/%00/ch/ev/file", ["/static"]);
        assert_no_parse!("/static/org/ch/ev/a%0Ab", ["/static"]);
        assert_no_parse!("/static/org/ch/ev/a%0d%0ab", ["/static"]);
        assert_no_parse!("/static/org/ch/ev/a%09b", ["/static"]);
        assert_no_parse!("/static/org/ch/ev/a%1Bb", ["/static"]);
        assert_no_parse!("/static/org/ch/ev/a%1fb", ["/static"]);
        assert_no_parse!("/static/org/ch/ev/a%7Fb", ["/static"]);
        assert_no_parse!("/static/org/ch%7f/ev/file", ["/static"]);
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_no_parse!("/static/org/ch/ev/%ff", ["/static"]);
        assert_no_parse!("/static/org/ch/ev/a%C3", ["/static"]);
        assert_no_parse!("/static/%C3%28/ch/ev/file", ["/static"]);
    }

    /// The prefix is matched on the raw path, so encoding it does not match.
    #[test]
    fn encoded_prefix_does_not_match() {
        assert_no_parse!("/st%61tic/org/ch/ev/file", ["/static"]);
        assert_no_parse!("/%73tatic/org/ch/ev/file", ["/static"]);
    }
}
