use std::fmt;

use base64::Engine;
use signature::Verifier;

use crate::{jwt::jwks::KeyUsage, prelude::*};
use super::{Context, decode::JwtError, jwks::{self, Jwk}};


/// Accepted signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algo {
    ES256,
    ES384,
}

impl Algo {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "ES256" => Some(Self::ES256),
            "ES384" => Some(Self::ES384),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(super) enum Key {
    ES256(p256::ecdsa::VerifyingKey),
    ES384(p384::ecdsa::VerifyingKey),
}

impl Key {
    fn algo(&self) -> Algo {
        match self {
            Self::ES256(_) => Algo::ES256,
            Self::ES384(_) => Algo::ES384,
        }
    }
}

// Some way to print keys to distinguish them. It's fine to print it, as we are
// only dealing with public keys.
impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b64 = |bytes| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

        match self {
            Key::ES256(key) => write!(f, "ES256({})", b64(key.to_sec1_bytes())),
            Key::ES384(key) => write!(f, "ES384({})", b64(key.to_sec1_bytes())),
        }
    }
}

impl Context {
    pub(super) async fn verify_signature(
        &self,
        message: &str,
        signature: &str,
        alg: &str,
    ) -> Result<(), JwtError> {
        trace!(alg, message, signature, "Verifying signature...");
        let algo = Algo::from_str(alg).ok_or(JwtError::UnsupportedAlg)?;

        self.refresh_keys_if_expired().await;
        let keys = self.keys.load();
        let signature = super::decode::decode_base64(signature)?;
        let mut found_a_key = false;
        for key in &keys.keys {
            if key.algo() != algo {
                trace!(alg, %key, "Key does not fit algo of JWT");
                continue;
            }

            found_a_key = true;
            match key.verify(message, &signature) {
                Ok(_) => {
                    trace!(%key, "Key successfully verified signature");
                    return Ok(());
                }
                Err(_) => trace!(%key, "Key could not verify signature"),
            }
        }

        // TODO: refetch keys when no fitting one is found

        if found_a_key {
            Err(JwtError::InvalidSignature)
        } else {
            Err(JwtError::NoSuitableKey)
        }
    }
}

impl Key {
    pub(super) fn from_jwk(jwk: Jwk<'_>) -> Result<Self> {
        if jwk.use_.is_some_and(|usage| usage != KeyUsage::Signature) {
            bail!("Field `use` of key is not 'sig'");
        }

        match jwk.key_data {
            jwks::KeyData::Ec(data) => {
                match data.crv() {
                    "P-256" => {
                        if jwk.alg.as_ref().is_some_and(|alg| alg != "ES256") {
                            bail!("curve type P-256 does not match 'alg' field {:?}", jwk.alg);
                        }

                        let key = p256::PublicKey::from_jwk(&data)
                            .context("failed to convert JWK to public key")?;
                        Ok(Self::ES256(key.into()))
                    }

                    "P-384" => {
                        if jwk.alg.as_ref().is_some_and(|alg| alg != "ES384") {
                            bail!("curve type P-384 does not match 'alg' field {:?}", jwk.alg);
                        }

                        let key = p384::PublicKey::from_jwk(&data)
                            .context("failed to convert JWK to public key")?;
                        Ok(Self::ES384(key.into()))
                    }

                    crv => bail!("Curve type '{crv}' not supported"),
                }
            }

            jwks::KeyData::Oct => bail!("symmetric keys not supported"),
            jwks::KeyData::Rsa => bail!("RSA keys not supported"),
        }
    }

    fn verify(&self, message: &str, signature: &[u8]) -> Result<(), signature::Error> {
        match self {
            Key::ES256(key) => {
                let signature = p256::ecdsa::Signature::from_slice(&signature)?;
                key.verify(message.as_bytes(), &signature)?;
            }
            Key::ES384(key) => {
                let signature = p384::ecdsa::Signature::from_slice(&signature)?;
                key.verify(message.as_bytes(), &signature)?;
            }
        }

        Ok(())
    }
}
