mod config;

pub use self::config::OpencastConfig;


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

impl<'a> PathParts<'a> {
    /// Parses the given path into its components. Returns `None` if the path
    /// is not understood, does not start with `/` or does not start with any
    /// prefxies configured in `opencast.path_prefixes`.
    pub fn parse(path: &'a str, config: &OpencastConfig) -> Option<Self> {
        if !path.starts_with('/') {
            return None;
        }

        // Check if it starts with any of the configured prefixes and split
        // `path` into prefix part and rest.
        let prefix = config.path_prefixes.iter()
            .map(|prefix| prefix.trim_matches('/'))
            .find(|prefix| path[1..].starts_with(prefix))?;
        let start_org = u16::try_from(prefix.len()).unwrap() + 1;

        let find_after = |start: u16| path[start as usize + 1..]
            .find('/')
            .map(|pos| u16::try_from(pos).unwrap() + start + 1);

        let start_channel = find_after(start_org)?;
        let start_event_id = find_after(start_channel)?;
        let start_suffix = find_after(start_event_id)?;

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
