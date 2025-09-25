use aws_lc_rs::{error::Unspecified, signature::ParsedPublicKey};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

use super::jwks::{self, Jwk};
use crate::{jwt::jwks::KeyUsage, prelude::*};


/// Accepted signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Algo {
    ES256,
    ES384,
    EdDSA,
}

impl Algo {
    pub(super) fn from_str(s: &str) -> Option<Self> {
        match s {
            "ES256" => Some(Self::ES256),
            "ES384" => Some(Self::ES384),
            "EdDSA" => Some(Self::EdDSA),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct Key {
    /// The actual key. It is indeed just a wrapper for arbitrary bytes paired
    /// with an algorithm. No verification is done, which is unfortunate. See
    /// https://github.com/aws/aws-lc-rs/issues/849
    key: ParsedPublicKey,
    algo: Algo,
}

impl Key {
    pub(super) fn algo(&self) -> Algo {
        self.algo
    }

    pub(super) fn from_jwk(jwk: &Jwk<'_>) -> Result<Self> {
        if jwk.use_.as_ref().is_some_and(|usage| *usage != KeyUsage::Signature) {
            bail!("Field `use` of key is not 'sig'");
        }

        fn ecdsa_sec1_key(x: &str, y: &str) -> Result<Vec<u8>> {
            let mut out = vec![4]; // Header for SEC1 uncompressed form
            BASE64_URL_SAFE_NO_PAD.decode_vec(x, &mut out)?;
            BASE64_URL_SAFE_NO_PAD.decode_vec(y, &mut out)?;
            Ok(out)
        }

        match &jwk.key_data {
            jwks::KeyData::Ec { crv, x, y } if crv == "P-256" => {
                if jwk.alg.as_ref().is_some_and(|alg| alg != "ES256") {
                    bail!("curve type P-256 does not match 'alg' field {:?}", jwk.alg);
                }
                let Some(y) = y else {
                    bail!("P-256 curve missing y coordinate");
                };

                Ok(Self {
                    algo: Algo::ES256,
                    key: ParsedPublicKey::new(
                        &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED,
                        ecdsa_sec1_key(x, y).context("invalid key")?,
                    ).context("invalid key for algorithm ES256")?,
                })
            }
            jwks::KeyData::Ec { crv, x, y } if crv == "P-384" => {
                if jwk.alg.as_ref().is_some_and(|alg| alg != "ES384") {
                    bail!("curve type P-384 does not match 'alg' field {:?}", jwk.alg);
                }
                let Some(y) = y else {
                    bail!("P-384 curve missing y coordinate");
                };

                Ok(Self {
                    algo: Algo::ES384,
                    key: ParsedPublicKey::new(
                        &aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED,
                        ecdsa_sec1_key(x, y).context("invalid key")?,
                    ).context("invalid key for algorithm ES384")?,
                })
            }

            jwks::KeyData::Okp { crv, x } if crv == "Ed25519" => {
                if jwk.alg.as_ref().is_some_and(|alg| alg != "EdDSA") {
                    bail!("curve type Ed25519 does not match 'alg' field {:?}", jwk.alg);
                }
                let key_data = BASE64_URL_SAFE_NO_PAD.decode(x).context("invalid key")?;

                Ok(Self {
                    algo: Algo::EdDSA,
                    key: ParsedPublicKey::new(&aws_lc_rs::signature::ED25519, key_data)
                        .context("invalid key for algorithm ED25519")?,
                })
            }

            jwks::KeyData::Ec { crv, .. } => bail!("Curve type '{crv}' not supported"),
            jwks::KeyData::Okp { crv, .. } => bail!("Curve type '{crv}' not supported"),
            jwks::KeyData::Oct => bail!("symmetric keys not supported"),
            jwks::KeyData::Rsa => bail!("RSA keys not supported"),
        }
    }

    pub(super) fn verify(&self, message: &str, signature: &[u8]) -> Result<(), Unspecified> {
        self.key.verify_sig(message.as_bytes(), signature)
    }
}
