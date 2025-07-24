use std::{sync::Arc, time::{Duration, Instant}};

use arc_swap::ArcSwap;

use crate::{prelude::*, util::{self, SimpleHttpClient}};

mod config;
mod crypto;
mod decode;
mod jwks;

pub use self::config::{JwtConfig, JwksUrl};


const BACKGROUND_REFRESH_LEAD_TIME: Duration = Duration::from_secs(3);

/// Processed information from a JWT relevant for authorization.
#[derive(Debug)]
pub struct TokenInfo {
    /// Whether the `roles` claim contained `ROLE_ADMIN`.
    pub is_admin: bool,

    /// All events that have been granted at least `read` access to in the `oc`
    /// claim.
    pub readable_events: Vec<String>,
}


pub struct Context {
    config: JwtConfig,
    http_client: SimpleHttpClient,
    keys: Arc<ArcSwap<Keys>>,
}

struct Keys {
    keys: Vec<crypto::Key>,
    last_fetch: Instant,
}


impl Context {
    pub async fn new(config: &JwtConfig) -> Result<Self> {
        let http_client = util::http_client()?;
        info!("Fetching trusted keys for initialization");
        let keys = Self::fetch_keys(&config.trusted_keys, &http_client).await;
        let keys = Arc::new(ArcSwap::from_pointee(keys));

        if config.background_key_refresh {
            let http_client = http_client.clone();
            let config = config.clone();
            let keys = Arc::clone(&keys);
            tokio::spawn(async move {
                let sleep_time = config.key_cache_duration - BACKGROUND_REFRESH_LEAD_TIME;
                loop {
                    tokio::time::sleep(sleep_time).await;

                    debug!("Refreshing trusted keys");
                    let new_keys = Self::fetch_keys(&config.trusted_keys, &http_client).await;
                    keys.store(Arc::new(new_keys));
                }
            });
        }

        Ok(Self {
            config: config.clone(),
            keys,
            http_client,
        })
    }

    /// Refreshes keys by refetching the JWKS URLs. In case of errors, warnings
    /// are logged, but old keys are invalidated in any case.
    pub async fn refresh_keys(&self) {
        debug!("Refreshing trusted keys");
        let keys = Self::fetch_keys(&self.config.trusted_keys, &self.http_client).await;
        self.keys.store(Arc::new(keys));
    }

    pub async fn refresh_keys_if_expired(&self) {
        if self.keys.load().last_fetch.elapsed() > self.config.key_cache_duration {
            trace!("Keys are expired -> need to refresh");
            self.refresh_keys().await;
        }
    }

    async fn fetch_keys(urls: &[JwksUrl], http_client: &SimpleHttpClient) -> Keys {
        let mut keys_out = Vec::new();
        for url in urls {
            let url = &url.0;
            match jwks::fetch(url, http_client).await {
                Err(e) => warn!(%url, "failed to fetch keys: {e}"),
                Ok(keys) => {
                    if keys.is_empty() {
                        warn!(%url, "JWKS URL had no valid keys");
                    }
                    keys_out.extend(keys);
                }
            };
        }

        Keys {
            keys: keys_out,
            last_fetch: Instant::now(),
        }
    }
}
