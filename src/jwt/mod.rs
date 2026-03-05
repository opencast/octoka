use std::{borrow::{Borrow, Cow}, collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use jwtea::{Payload, RawJwt};
use serde::Deserialize;

use crate::{
    jwt::keys::{KeyManager, Keys},
    prelude::*,
};

mod config;
mod jwks;
mod keys;

pub use self::config::{JwksUrl, JwtConfig};



/// Key ID, just an arbitrary string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Kid(String);

impl Borrow<str> for Kid {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// Claims in the payload we are interested in.
#[derive(Debug, Deserialize)]
struct PayloadExtras<'a> {
    roles: Option<Vec<Cow<'a, str>>>,
    oc: Option<HashMap<Cow<'a, str>, Vec<Cow<'a, str>>>>,
}

/// Processed information from a JWT relevant for authorization.
#[derive(Debug)]
pub struct TokenInfo {
    /// Whether the `roles` claim contained `ROLE_ADMIN`.
    pub is_admin: bool,

    /// All events that have been granted at least `read` access to in the `oc`
    /// claim.
    pub readable_events: Vec<String>,
}

impl TokenInfo {
    fn from_payload(payload: Payload<PayloadExtras>) -> Self {
        let mut readable_events = Vec::new();
        for (item, actions) in payload.extra_fields.oc.unwrap_or_default() {
            let Some((prefix, id)) = item.split_once(':') else {
                debug!("`oc` claim contained key without colon -> ignoring");
                continue;
            };

            match prefix {
                "e" => {
                    if actions.iter().any(|action| action == "read") {
                        readable_events.push(id.to_owned());
                    }
                }
                "s" | "p" => {} // Ignore
                _ => {
                    debug!("`oc` claim contained unknown item kind: '{prefix}'");
                }
            }
        }

        Self {
            is_admin: payload.extra_fields.roles
                .unwrap_or_default()
                .iter()
                .any(|role| role == "ROLE_ADMIN"),
            readable_events,
        }
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

    pub async fn decode_and_verify(&self, raw: &str) -> Result<TokenInfo, jwtea::Error> {
        let raw = RawJwt::new(raw)?;
        let validator = jwtea::BasicValidator {
            allowed_clock_skew: self.config.allowed_clock_skew.as_secs() as u32,
        };
        let callback = |_header: jwtea::Header, payload| TokenInfo::from_payload(payload);
        raw.decode(self, &validator, callback).await
    }
}


pub(crate) async fn run_check(config: &JwtConfig) -> Vec<(&JwksUrl, Result<()>)> {
    let http_client = crate::util::http_client().expect("failed to create HTTP client");
    let mut out = Vec::new();
    for url in &config.trusted_keys {
        out.push((url, jwks::fetch(url, &http_client).await.map(|_| ())));
    }

    out
}
