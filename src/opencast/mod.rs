mod config;

pub use self::config::{FallbackMode, OpencastConfig};


/// Represents a path to a static Opencast file split into its relevant
/// components.
#[derive(Debug, Clone, Copy)]
pub struct PathParts<'a> {
    /// Original path, always with leading '/'.
    path: &'a str,

    // The following are indices into `path`, each pointing to a slash.
    //
    //     /static/mh_default_org/engage-player/eb4f3b14-3953-4c17-957d-6e4c5868206b/suffix...
    //            ^              ^             ^                                    ^
    //            start_org      |             start_event_id                       start_suffix
    //                           start_channel
    start_org: u16,
    start_channel: u16,
    start_event_id: u16,
    start_suffix: u16,
}

#[allow(dead_code)] // TODO
impl<'a> PathParts<'a> {
    /// Parses the given path into its components. Returns `None` if the path
    /// is not understood, does not start with `/` or does not start with any
    /// prefixes configured in `opencast.path_prefixes`.
    pub fn parse(path: &'a str, config: &OpencastConfig) -> Option<Self> {
        Self::parse_impl(path, &config.path_prefixes)
    }

    fn parse_impl(path: &'a str, path_prefixes: &[String]) -> Option<Self> {
        if !path.starts_with('/') {
            return None;
        }

        // Check if it starts with any of the configured prefixes and split
        // `path` into prefix part and rest. The prefix must be followed by a
        // slash, otherwise `/staticfoo/...` would match the prefix `static`.
        // Prefixes are never empty, as checked by the config validation.
        let prefix = path_prefixes.iter()
            .map(|prefix| prefix.trim_matches('/'))
            .find(|prefix| {
                path[1..].strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
            })?;
        let start_org = u16::try_from(prefix.len()).unwrap() + 1;

        // Returns the index of the next slash after the slash at `start`. Fails
        // if there is no further slash, or if the segment in between is empty.
        // Empty segments must be rejected: an empty org would make
        // `without_prefix()` start with a slash, i.e. an absolute path.
        let find_after = |start: u16| {
            let segment_start = start as usize + 1;
            let pos = path[segment_start..].find('/')?;
            if pos == 0 {
                return None;
            }
            u16::try_from(segment_start + pos).ok()
        };

        let start_channel = find_after(start_org)?;
        let start_event_id = find_after(start_channel)?;
        let start_suffix = find_after(start_event_id)?;

        // The suffix must not be empty either.
        if start_suffix as usize + 1 >= path.len() {
            return None;
        }

        Some(Self { path, start_org, start_channel, start_event_id, start_suffix })
    }

    /// Full path, as passed to `parse`.
    pub fn full_path(&self) -> &'a str {
        self.path
    }

    /// Prefix without leading or trailing slashes. See `opencast.path_prefixes`.
    pub fn prefix(&self) -> &'a str {
        &self.path[1..self.start_org as usize]
    }

    /// Full path without prefix. This is usually the file system path inside
    /// the "downloads"-directory. Without leading slash.
    pub fn without_prefix(&self) -> &'a str {
        &self.path[self.start_org as usize + 1..]
    }

    /// Path without prefix or suffix, i.e. pointing to the event directory
    /// inside the downloads directory.
    pub fn rel_event_dir(&self) -> &'a str {
        &self.path[self.start_org as usize + 1..self.start_suffix as usize]
    }

    /// The organization, e.g. `mh_default_org` in single-tenant systems.
    pub fn org(&self) -> &'a str {
        &self.path[self.start_org as usize + 1..self.start_channel as usize]
    }

    /// The publication channel, e.g. `engage-player` for most standard files.
    pub fn channel(&self) -> &'a str {
        &self.path[self.start_channel as usize + 1..self.start_event_id as usize]
    }

    /// The event ID.
    pub fn event_id(&self) -> &'a str {
        &self.path[self.start_event_id as usize + 1..self.start_suffix as usize]
    }

    /// Path inside the event's directory, without leading slash.
    pub fn suffix(&self) -> &'a str {
        &self.path[self.start_suffix as usize + 1..]
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
            without_prefix: $without_prefix:expr,
            rel_event_dir: $rel_event_dir:expr,
        }) => {
            let parsed = PathParts::parse_impl($path, &prefixes($prefixes))
                .expect("failed to parse path");
            assert_eq!(parsed.full_path(), $path);
            assert_eq!(parsed.prefix(), $prefix);
            assert_eq!(parsed.org(), $org);
            assert_eq!(parsed.channel(), $channel);
            assert_eq!(parsed.event_id(), $event_id);
            assert_eq!(parsed.suffix(), $suffix);
            assert_eq!(parsed.without_prefix(), $without_prefix);
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
            without_prefix: "mh_default_org/engage-player/ev-id/a/b.mp4",
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
            without_prefix: "org/ch/ev/file.mp4",
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
                without_prefix: "org/ch/ev/file",
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
            without_prefix: "org/ch/ev/file",
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
            without_prefix: "org/ch/ev/file",
            rel_event_dir: "org/ch/ev",
        });
        assert_path_parse!("/files/org/ch/ev/file", prefixes, {
            prefix: "files",
            org: "org",
            channel: "ch",
            event_id: "ev",
            suffix: "file",
            without_prefix: "org/ch/ev/file",
            rel_event_dir: "org/ch/ev",
        });
        assert_path_parse!("/foo/bar/org/ch/ev/file", prefixes, {
            prefix: "foo/bar",
            org: "org",
            channel: "ch",
            event_id: "ev",
            suffix: "file",
            without_prefix: "org/ch/ev/file",
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
        assert_no_parse!("/static///x/passwd", ["/static"]);
        assert_no_parse!("/static/org//ev/file", ["/static"]);
        assert_no_parse!("/static/org/ch//file", ["/static"]);
        assert_no_parse!("/static/org/ch/ev/", ["/static"]);
    }

    /// Invariant that `http::fs::serve_file` relies on.
    #[test]
    fn without_prefix_never_absolute() {
        for path in ["/static//a/b/c", "/static///b/c", "/static/a//b/c/d"] {
            if let Some(p) = PathParts::parse_impl(path, &prefixes(["/static"])) {
                assert!(!p.without_prefix().starts_with('/'), "{path:?}");
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

    /// With overlapping prefixes, the longer one must match regardless of
    /// config order.
    #[test]
    fn overlapping_prefixes() {
        assert_path_parse!("/static2/org/ch/ev/file", ["/static", "/static2"], {
            prefix: "static2",
            org: "org",
            channel: "ch",
            event_id: "ev",
            suffix: "file",
            without_prefix: "org/ch/ev/file",
            rel_event_dir: "org/ch/ev",
        });
    }
}
