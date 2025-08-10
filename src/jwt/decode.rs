use std::{borrow::Cow, collections::HashMap, time::SystemTime};

use serde::Deserialize;

use crate::prelude::*;
use super::{Context, TokenInfo};



#[derive(Debug, Deserialize)]
struct Header<'a> {
    alg: Cow<'a, str>,
    kid: Option<Cow<'a, str>>,
    // We are not interested in any other fields, it's fine to ignore them.
}

#[derive(Debug, Deserialize)]
struct Payload<'a> {
    // Optional here to not count it missing as parse error.
    exp: Option<u64>,
    nbf: Option<u64>,

    #[allow(dead_code)]
    sub: Option<Cow<'a, str>>,
    #[allow(dead_code)]
    name: Option<Cow<'a, str>>,
    #[allow(dead_code)]
    email: Option<Cow<'a, str>>,

    roles: Option<Vec<Cow<'a, str>>>,
    oc: Option<HashMap<Cow<'a, str>, Vec<Cow<'a, str>>>>,
}

impl Context {
    pub async fn decode_and_verify(&self, raw: &str) -> Result<TokenInfo, JwtError> {
        // Split into parts
        let (message, signature) = raw.rsplit_once('.').ok_or(JwtError::InvalidJwt)?;
        let (header, payload) = message.split_once('.').ok_or(JwtError::InvalidJwt)?;
        if payload.contains('.') {
            return Err(JwtError::InvalidJwt);
        }

        // Decode & deserialize header
        let header = decode_base64(header)?;
        let header: Header = serde_json::from_slice(&header)
            .map_err(|_| JwtError::InvalidJson)?;

        // Verify signature
        self.verify_signature(message, signature, &header.alg, header.kid.as_deref()).await?;

        // Decode and deserialize payload
        let payload = decode_base64(payload)?;
        let payload: Payload = serde_json::from_slice(&payload)
            .map_err(|_| JwtError::InvalidJson)?;

        // Verify claims in payload
        self.verify_claims(&payload)?;

        // Read claims to extract relevant infos.
        Ok(TokenInfo::from_payload(payload))
    }

    fn verify_claims(&self, payload: &Payload) -> Result<(), JwtError> {
        // This returns exactly the POSIX `time_t` timestamp used by JWT.
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time is before unix epoch, interesting")
            .as_secs();

        let Some(exp) = payload.exp else {
            return Err(JwtError::ExpMissing);
        };
        if exp + self.config.allowed_clock_skew.as_secs() < now {
            return Err(JwtError::Expired);
        }
        if payload.nbf.is_some_and(|nbf| nbf > now + self.config.allowed_clock_skew.as_secs()) {
            return Err(JwtError::NotValidYet);
        }

        Ok(())
    }
}

impl TokenInfo {
    fn from_payload(payload: Payload) -> Self {
        let mut readable_events = Vec::new();
        for (item, actions) in payload.oc.unwrap_or_default() {
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
                "s" | "p" => {}, // Ignore
                _ => {
                    debug!("`oc` claim contained unknown item kind: '{prefix}'");
                }
            }
        }

        Self {
            is_admin: payload.roles.unwrap_or_default().iter().any(|role| role == "ROLE_ADMIN"),
            readable_events,
        }
    }
}

pub(super) fn decode_base64(base64: &str) -> Result<Vec<u8>, JwtError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(base64)
        .map_err(|_| JwtError::InvalidJwt)
}

/// Reasons to reject a JWT.
#[derive(Debug, Clone)]
pub enum JwtError {
    /// Surface format incorrect (three dots, base64).
    InvalidJwt,

    /// Header or payload contained invalid JSON.
    InvalidJson,

    /// Algorithm not supported by this application.
    UnsupportedAlg,

    /// There is no suitable key for the given `alg`.
    NoSuitableKey,

    /// Signature could not be validated with the available keys.
    InvalidSignature,

    /// Required `exp` claim missing in token.
    ExpMissing,

    /// The token has expired according to the `exp` claim.
    Expired,

    /// The key's algorithm does not match the JWT's algorithm.
    AlgoMismatch,

    /// The token is not valid yet according to the `nbf` claim.
    NotValidYet,
}
