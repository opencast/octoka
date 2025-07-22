use std::hint::black_box;

use divan::Bencher;
use elliptic_curve::JwkEcKey;
use signature::{SignerMut, Verifier};


fn main() {
    divan::main();
}


mod es256 {
    use super::*;

    #[divan::bench]
    fn verify_signature_success(bencher: Bencher) {
        let signature = sig(SIGNATURE);
        let key = public_key();

        // Just make sure it is a success before running benchmark
        key.verify(MESSAGE, &signature).unwrap();

        bencher.bench_local(move || {
            black_box(key).verify(black_box(MESSAGE), black_box(&signature))
        });
    }

    #[divan::bench]
    fn verify_signature_fail(bencher: Bencher) {
        // Just change the signature somehow
        let signature = sig(&SIGNATURE.replace('g', "F"));
        let key = public_key();

        // Just make sure it is a fail before running benchmark
        key.verify(MESSAGE, &signature).unwrap_err();

        bencher.bench_local(move || {
            black_box(key).verify(black_box(MESSAGE), black_box(&signature))
        });
    }

    #[divan::bench]
    fn sign(bencher: Bencher) {
        let mut key = private_key();

        bencher.bench_local(move || {
            let sig: p256::ecdsa::Signature = key.sign(MESSAGE);
            sig
        });
    }

    const MESSAGE: &[u8] = b"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.\
        eyJleHAiOjE3NjE4MzcyNDEsIm9jIjp7ImU6ZWI0ZjNiMTQtMzk1My00YzE3LTk1N2QtNmU0YzU4NjgyMDZiIjpbInJlYWQiXX19";
    const SIGNATURE: &str = "QHhTbrRJCgo_ge149uDzl7iFwlu-sdSzQtLWy_3YKgDkzTf9BmbfbrZdDObIFyzAnbooQjtabSbX1QnHSpUasQ";

    fn public_key() -> p256::ecdsa::VerifyingKey {
        let jwk:JwkEcKey = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "XVse8zm2oet6T3beliT8vgPayI64gCJkEH1giUWt-ys",
            "y": "LK2VpICalQ8sRR5bfV8OLAPrrKmHIJ40eB4V88P-3Do",
        })).unwrap();
        p256::PublicKey::from_jwk(&jwk).unwrap().into()
    }

    fn private_key() -> p256::ecdsa::SigningKey {
        let pem_encoded = "-----BEGIN PRIVATE KEY-----\n\
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg66Zp9DgrYgT6H/dJ\n\
            p3zkos361IC2DJchnd0ArvCFofihRANCAARdWx7zObah63pPdt6WJPy+A9rIjriA\n\
            ImQQfWCJRa37KyytlaSAmpUPLEUeW31fDiwD66yphyCeNHgeFfPD/tw6\n\
            -----END PRIVATE KEY-----\n\
        ";
        let key: p256::SecretKey = pem_encoded.parse().unwrap();
        key.into()
    }

    fn sig(s: &str) -> p256::ecdsa::Signature {
        let signature = base64_decode(s);
        p256::ecdsa::Signature::from_slice(&signature).unwrap()
    }
}

mod es384 {
    use super::*;

    #[divan::bench]
    fn verify_signature_success(bencher: Bencher) {
        let signature = sig(SIGNATURE);
        let key = public_key();

        // Just make sure it is a success before running benchmark
        key.verify(MESSAGE, &signature).unwrap();

        bencher.bench_local(move || {
            black_box(key).verify(black_box(MESSAGE), black_box(&signature))
        });
    }

    #[divan::bench]
    fn verify_signature_fail(bencher: Bencher) {
        // Just change the signature somehow
        let signature = sig(&SIGNATURE.replace('g', "F"));
        let key = public_key();

        // Just make sure it is a fail before running benchmark
        key.verify(MESSAGE, &signature).unwrap_err();

        bencher.bench_local(move || {
            black_box(key).verify(black_box(MESSAGE), black_box(&signature))
        });
    }

    #[divan::bench]
    fn sign(bencher: Bencher) {
        let mut key = private_key();

        bencher.bench_local(move || {
            let sig: p384::ecdsa::Signature = key.sign(MESSAGE);
            sig
        });
    }

    const MESSAGE: &[u8] = b"eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.\
        eyJleHAiOjE3NjE4NTEyMDIsIm9jIjp7ImU6ZWI0ZjNiMTQtMzk1My00YzE3LTk1N2QtNmU0YzU4NjgyMDZiIjpbInJlYWQiXX19";
    const SIGNATURE: &str = "8bT8sEy0VIxwP-YoK-JxJc_yYfXXty6Lth9qeJTdWqkxnUMnVfhLAQyV1u2eNgxBg2vsi2KCuIWYY8B4XYAeype7LqPZSZLhHQKnJdtdukIcobWgXeXX5BfRGCN1QVjU";

    fn public_key() -> p384::ecdsa::VerifyingKey {
        let jwk:JwkEcKey = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-384",
            "x": "6WS2SeRMtW_El-OaQA191OEge_OpVp_RJ1_1lsIcMEAz8TpwxZYCKmix0N7fzhqm",
            "y": "G8qsd6MvMqAdy-efJE13J94ATZnw9GpEuhAoSk2EWcQmz1feg37pEe_Th-jCddmr",
        })).unwrap();
        p384::PublicKey::from_jwk(&jwk).unwrap().into()
    }

    fn private_key() -> p384::ecdsa::SigningKey {
        let pem_encoded = "-----BEGIN PRIVATE KEY-----\n\
        MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDFqsxSqjZ6mm25GVGs\n\
        v5yClcHAEYriv7P3UlwnRx0EwEIq/aXXprHvGtw5S58hSSmhZANiAAT3FXl8SIm9\n\
        y9dVb7LH3uvPfTEYGvauhcud494n9Hu4kCyFfuN0bihRZM7/1AZ4pTrBdxzdRyUb\n\
        SVgNoFT2sFcitoQEJPwAYk1LWnIWx3EMVMM4ArlAGvIWMuMR/peFwC8=\n\
        -----END PRIVATE KEY-----\n\
        ";
        let key: p384::SecretKey = pem_encoded.parse().unwrap();
        key.into()
    }

    fn sig(s: &str) -> p384::ecdsa::Signature {
        let signature = base64_decode(s);
        p384::ecdsa::Signature::from_slice(&signature).unwrap()
    }
}



fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()
}
