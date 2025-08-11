use std::{borrow::Borrow, collections::HashSet, sync::Arc};

use arc_swap::ArcSwap;

use crate::{
    jwt::{
        decode::JwtError,
        keys::{KeyManager, Keys},
    },
    prelude::*,
};

mod config;
mod crypto;
mod decode;
mod jwks;
mod keys;

pub use self::config::{JwksUrl, JwtConfig};


/// Processed information from a JWT relevant for authorization.
#[derive(Debug)]
pub struct TokenInfo {
    /// Whether the `roles` claim contained `ROLE_ADMIN`.
    pub is_admin: bool,

    /// All events that have been granted at least `read` access to in the `oc`
    /// claim.
    pub readable_events: Vec<String>,
}

/// Key ID, just an arbitrary string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Kid(String);

impl Borrow<str> for Kid {
    fn borrow(&self) -> &str {
        &self.0
    }
}


pub struct Context {
    config: JwtConfig,
    key_manager: Arc<KeyManager>,
}

impl Context {
    pub async fn new(config: &JwtConfig) -> Result<Self> {
        let key_manager = KeyManager::new(config).await?;
        Ok(Self {
            config: config.clone(),
            key_manager,
        })
    }

    fn keys(&self) -> &ArcSwap<Keys> {
        self.key_manager.keys()
    }

    /// Attempts to verify a JWT's signature, potentially refetching keys.
    async fn verify_signature(
        &self,
        // The first two parts of the JWT, i.e. the signed message.
        msg: &str,
        // The base64 encoded signature
        signature: &str,
        // The raw `alg` field of the JWT
        alg: &str,
        // The raw `kid` field of the JWT
        kid: Option<&str>,
    ) -> Result<(), JwtError> {
        trace!(alg, msg, signature, "Verifying signature...");
        let algo = crypto::Algo::from_str(alg).ok_or(JwtError::UnsupportedAlg)?;
        let signature = decode::decode_base64(signature)?;
        let mut tried_some_keys = false;

        // Tries to verify the given key. Early exits on success. If `kid_match`
        // is true, an error is returned on failure, otherwise failure is ignored.
        macro_rules! try_verify {
            ($key:expr, $kid_match:expr) => {
                tried_some_keys = true;
                let key = $key;
                match key.verify(msg, &signature) {
                    Ok(()) => {
                        trace!(?key, "Key successfully verified signature");
                        return Ok(());
                    }
                    Err(_) => {
                        trace!(?key, "Key could not verify signature");
                        if ($kid_match) {
                            return Err(JwtError::InvalidSignature);
                        }
                    }
                }
            };
        }


        // First: check all non-stale keys. This is a fast pass to make sure we
        // don't do any unneeded expensive operation.
        let keys = self.keys().load();
        let mut stale_sources = HashSet::new();
        for (key, kid_match) in keys.keys_for(kid, algo)? {
            if key.source.is_stale(&self.config) {
                stale_sources.insert(&key.source.url);
            } else {
                try_verify!(&key.key, kid_match);
            }
        }

        // Next: if we found any stale sources, we refresh them and try those
        // keys now.
        if stale_sources.len() > 0 {
            // Refresh stale sources/keys
            self.key_manager
                .refresh(stale_sources.iter().copied())
                .await;

            // Try all keys that were just refreshed
            let keys = self.keys().load();
            for (key, kid_match) in keys.keys_for(kid, algo)? {
                if stale_sources.contains(&key.source.url) {
                    try_verify!(&key.key, kid_match);
                }
            }
        }

        // Finally: we have gone through all keys that we know, but couldn't
        // verify the JWT. It could be that a source we consider fresh rotated a
        // key. To not show failures in this case, we do refetch everything that
        // hasn't been refetched above. This is rate limited however, so that
        // an attacker cannot force this service to always refetch.
        if stale_sources.len() == self.config.trusted_keys.len() {
            trace!("Already just refetched all sources -> no backup refetch");
        } else {
            let not_refreshed_yet = self
                .config
                .trusted_keys
                .iter()
                .filter(|url| !stale_sources.contains(url));
            let try_again = self.key_manager.backup_refresh(not_refreshed_yet).await;

            if try_again {
                // Try all keys that were just refreshed
                let keys = self.keys().load();
                for (key, kid_match) in keys.keys_for(kid, algo)? {
                    if !stale_sources.contains(&key.source.url) {
                        try_verify!(&key.key, kid_match);
                    }
                }
            }
        }

        // After all that, the signature truly cannot be verified
        if tried_some_keys {
            Err(JwtError::InvalidSignature)
        } else {
            Err(JwtError::NoSuitableKey)
        }
    }
}
