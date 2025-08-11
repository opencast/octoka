//! Key management, fetching and refreshing.

use std::{collections::HashMap, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use futures::future::join_all;
use tokio::{
    sync::{RwLock, Semaphore, TryAcquireError},
    time::Instant,
};

use super::{JwksUrl, JwtConfig, Kid, crypto, decode::JwtError, jwks};
use crate::{
    prelude::*,
    util::{self, SimpleHttpClient},
};


/// How much before the expiration time of keys are we refetching them?
pub(super) const BACKGROUND_REFRESH_LEAD_TIME: Duration = Duration::from_secs(3);

/// When we cannot find any matching keys for the JWT, we refetch all sources,
/// but only if the last backup refresh was more than this duration ago.
const BACKUP_REFRESH_RATE_LIMIT: Duration = Duration::from_secs(15);


/// A single cryptographic key fetched from a JWKS, with some metadata.
#[derive(Debug, Clone)]
pub(super) struct Key {
    pub(super) key: crypto::Key,
    pub(super) source: Arc<KeySource>,
}

#[derive(Debug, Clone)]
pub(super) struct KeySource {
    pub(super) last_fetch: Instant,
    pub(super) url: JwksUrl,
    // TODO: expiration
}

/// All cryptographic keys we know of.
#[derive(Clone)]
pub(super) struct Keys {
    with_id: HashMap<Kid, Key>,
    without_id: Vec<Key>,
    sources: Vec<Arc<KeySource>>,
}

impl KeySource {
    pub(super) fn is_stale(&self, config: &JwtConfig) -> bool {
        // TODO: expiration
        self.last_fetch.elapsed() > config.key_cache_duration
    }

    pub(super) fn expiry(&self, config: &JwtConfig) -> Instant {
        // TODO: expiration
        self.last_fetch + config.key_cache_duration
    }
}

impl Keys {
    /// Returns an empty set of keys.
    fn empty() -> Self {
        Self {
            with_id: HashMap::new(),
            without_id: Vec::new(),
            sources: Vec::new(),
        }
    }

    /// Returns the number of keys.
    fn len(&self) -> usize {
        self.with_id.len() + self.without_id.len()
    }

    /// Returns keys that could be used to verify a JWT with the given `kid` and
    /// `alg`.
    ///
    /// - If `kid` is `Some` and there is...
    ///     - ... a key with that kid: only that key is returned.
    ///     - ... NOT a key with that kid: all `without_id` are returned.
    /// - Else: All keys are returned
    ///
    /// If the is a key with the given `kid`, but the algo mismatches, `Err` is
    /// returned. All other keys with mismatched algo are filtered out. Does
    /// not filter stale keys, so stale keys can be returned!
    ///
    /// The Iterator returns a pair of `Key` and a bool that described if the
    /// key is a `kid` match.
    pub(super) fn keys_for(
        &self,
        kid: Option<&str>,
        alg: crypto::Algo,
    ) -> Result<impl Iterator<Item = (&Key, bool)>, JwtError> {
        let perfect_match = kid.and_then(|kid| self.with_id.get(kid));

        if let Some(key) = perfect_match && key.key.algo() != alg {
            return Err(JwtError::AlgoMismatch);
        }

        let without_ids = perfect_match.is_none().then(|| self.without_id.iter());
        let with_ids = kid.is_none().then(|| self.with_id.values());
        let rest = without_ids.into_iter().flatten()
            .chain(with_ids.into_iter().flatten())
            .filter(move |key| key.key.algo() == alg)
            .map(|key| (key, false));

        Ok(perfect_match.into_iter().map(|key| (key, true)).chain(rest))
    }

    /// Removes all keys of the given source.
    fn prune_keys_of(&mut self, source: &JwksUrl) {
        self.with_id.retain(|_kid, key| &key.source.url != source);
        self.without_id.retain(|key| &key.source.url != source);
    }

    fn update_source_metadata(&mut self, v: Arc<KeySource>) {
        if let Some(src) = self.sources.iter_mut().find(|src| src.url == v.url) {
            *src = v;
        } else {
            self.sources.push(v);
        }
    }

    /// Removes all old keys of the given source, then inserts all freshly
    /// fetched keys.
    fn update_source(&mut self, source: &JwksUrl, data: &jwks::FetchedData) {
        self.prune_keys_of(source);
        let source = Arc::new(KeySource {
            url: source.clone(),
            last_fetch: Instant::now(),
        });

        for key in &data.keys {
            let v = Key {
                key: key.key.clone(),
                source: source.clone(),
            };
            match &key.kid {
                Some(kid) => {
                    self.with_id.insert(kid.clone(), v);
                }
                None => self.without_id.push(v),
            }
        }
        self.update_source_metadata(source);
    }
}


pub(super) struct KeyManager {
    keys: ArcSwap<Keys>,
    http_client: SimpleHttpClient,
    fetch_guards: HashMap<JwksUrl, Semaphore>,
    last_backup_refresh: RwLock<Instant>,
}

impl KeyManager {
    pub(super) async fn new(config: &JwtConfig) -> Result<Arc<Self>> {
        let http_client = util::http_client()?;
        let fetch_guards = config.trusted_keys.iter()
            .map(|url| (url.clone(), Semaphore::new(1)))
            .collect();

        let this = Arc::new(Self {
            keys: ArcSwap::from_pointee(Keys::empty()),
            fetch_guards,
            http_client,
            last_backup_refresh: RwLock::new(Instant::now()),
        });

        // Fetching all sources once
        info!("Fetching trusted keys for initialization");
        this.refresh(&config.trusted_keys).await;
        info!("Fetched {} trusted keys", this.keys.load().len());

        // Start background refresh task, if configured.
        if config.background_key_refresh {
            let this = this.clone();
            let config = config.clone();
            tokio::spawn(async move {
                this.background_refresh(&config).await;
            });
        }

        Ok(this)
    }

    pub fn keys(&self) -> &ArcSwap<Keys> {
        &self.keys
    }

    /// Refetches and updates keys for a single JWKS URL.
    ///
    /// If there is already a fetch ongoing for the given URL, no new fetch is
    /// started, but the ongoing fetch is awaited. After this function returns,
    /// the fetch results are visible in `keys`.
    async fn refresh_single(&self, source: &JwksUrl) {
        trace!(%source, "Refreshing keys");
        let semaphore = self.fetch_guards.get(source).expect("no semaphore for JWKS url");
        match semaphore.try_acquire() {
            // We could acquire a permit -> no other task is fetching for this URL.
            Ok(_permit) => {
                let res = jwks::fetch(source, &self.http_client).await;
                self.keys.rcu(|keys| {
                    let mut out = Keys::clone(keys);
                    match &res {
                        Ok(data) => {
                            trace!(%source, num_keys = data.keys.len(), "done fetching keys");
                            if data.keys.is_empty() {
                                warn!(%source, "JWKS URL had no valid keys");
                            }
                            out.update_source(source, data);
                        }
                        Err(e) => {
                            error!(?source, "Error fetching JWKS: {e}");
                            out.prune_keys_of(source);
                            out.update_source_metadata(Arc::new(KeySource {
                                last_fetch: Instant::now(),
                                url: source.clone(),
                            }));
                        }
                    }
                    out
                });
            }

            // If there are currently not permits, that means another task is
            // currently fetching this URL. In that case we do nothing, except
            // to acquiring a permit and immediately discarding it. This makes
            // sure that this function returns only when the source has been
            // refreshed (regardless of initiator: our caller or another task).
            Err(TryAcquireError::NoPermits) => {
                trace!(%source, "waiting for already running refresh task");
                let _ = semaphore.acquire().await;
            }

            Err(TryAcquireError::Closed) => unreachable!("semaphore is closed for: {source}"),
        }
    }

    /// Refreshes all given sources, returning once all fetch operations are
    /// done and the results are written into `self.keys`.
    pub(super) async fn refresh<'a>(
        self: &Arc<Self>,
        sources: impl IntoIterator<Item = &'a JwksUrl>,
    ) {
        let fetch_tasks = sources.into_iter().map(|source| {
            let this = self.clone();
            let source = source.clone();
            tokio::spawn(async move {
                this.refresh_single(&source).await;
            })
        });

        join_all(fetch_tasks).await;
    }

    pub(super) async fn backup_refresh<'a>(
        self: &Arc<Self>,
        sources: impl IntoIterator<Item = &'a JwksUrl>,
    ) -> bool {
        match self.last_backup_refresh.try_read() {
            // There is no current backup refresh running but the last one
            // is also not long ago.
            Ok(last_refresh) if last_refresh.elapsed() < BACKUP_REFRESH_RATE_LIMIT => {
                trace!("Last backup refresh too recent -> not doing it again");
                false
            }

            // There is no current backup refresh running, but the last one
            // is long enough ago to do a new one.
            Ok(last_refresh) => {
                // Acquire write lock first and recheck condition.
                drop(last_refresh);
                let mut last_refresh = self.last_backup_refresh.write().await;
                if last_refresh.elapsed() < BACKUP_REFRESH_RATE_LIMIT {
                    trace!("Last backup refresh too recent -> not doing it again");
                    return false;
                }

                // Refresh everything that hasn't been refreshed above
                self.refresh(sources).await;
                *last_refresh = Instant::now();
                true
            }

            // There is currently already a backup refresh running. Wait for it.
            Err(_) => {
                let _ = self.last_backup_refresh.read().await;
                true
            }
        }
    }

    pub(super) async fn background_refresh(self: &Arc<Self>, config: &JwtConfig) {
        loop {
            // Find source that is expiring next.
            let keys = self.keys.load();
            let next_expiry = keys.sources.iter()
                .map(|src| src.expiry(config))
                .min()
                .expect("no key sources in BG refresh");
            drop(keys);

            // Sleep till it is time to refetch
            tokio::time::sleep_until(next_expiry - BACKGROUND_REFRESH_LEAD_TIME).await;

            // Refresh all keys that need to be refreshed soon. There is a tiny
            // chance that this will refresh a source twice if a refetch
            // operation finishes between the `filter` expiry check and the
            // semaphore acquisition in `refresh_single`. That's no big deal,
            // so we ignore it.
            let keys = self.keys.load();
            let threshold = Instant::now()
                - BACKGROUND_REFRESH_LEAD_TIME
                - Duration::from_millis(500);
            let to_be_refreshed = keys.sources.iter()
                .filter(|src| src.expiry(config) > threshold)
                .map(|src| &src.url);

            debug!("background-refreshing some keys");
            self.refresh(to_be_refreshed).await;
        }
    }
}
