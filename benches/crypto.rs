use std::hint::black_box;

use divan::Bencher;
use signature::{SignerMut, Verifier};


fn main() {
    divan::main();
}


mod es256 {
    use super::*;

    const MESSAGE: &[u8] = b"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.\
        eyJleHAiOjE3NjE4MzcyNDEsIm9jIjp7ImU6ZWI0ZjNiMTQtMzk1My00YzE3LTk1N2QtNmU0YzU4NjgyMDZiIjpbInJlYWQiXX19";
    const SIGNATURE: &str = "QHhTbrRJCgo_ge149uDzl7iFwlu-sdSzQtLWy_3YKgDkzTf9BmbfbrZdDObIFyzAnbooQjtabSbX1QnHSpUasQ";
    const PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg66Zp9DgrYgT6H/dJ\n\
        p3zkos361IC2DJchnd0ArvCFofihRANCAARdWx7zObah63pPdt6WJPy+A9rIjriA\n\
        ImQQfWCJRa37KyytlaSAmpUPLEUeW31fDiwD66yphyCeNHgeFfPD/tw6\n\
        -----END PRIVATE KEY-----\n\
    ";


    mod rust_crypto {
        use super::*;

        #[divan::bench]
        fn verify_ok(bencher: Bencher) {
            let signature = sig(SIGNATURE);
            let key = public_key();

            // Just make sure it is a success before running benchmark
            key.verify(MESSAGE, &signature).unwrap();

            bencher.bench_local(move || {
                black_box(key).verify(black_box(MESSAGE), black_box(&signature))
            });
        }

        #[divan::bench]
        fn verify_fail(bencher: Bencher) {
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

        fn public_key() -> p256::ecdsa::VerifyingKey {
            private_key().verifying_key().clone()
        }

        fn private_key() -> p256::ecdsa::SigningKey {
            let key: p256::SecretKey = PRIVATE_KEY.parse().unwrap();
            key.into()
        }

        fn sig(s: &str) -> p256::ecdsa::Signature {
            let signature = base64_decode(s);
            p256::ecdsa::Signature::from_slice(&signature).unwrap()
        }
    }

    mod aws_lc {
        use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair, VerificationAlgorithm};

        use super::*;

        #[divan::bench]
        fn verify_ok(bencher: Bencher) {
            let key = public_key();
            let signature = base64_decode(SIGNATURE);
            signature::ECDSA_P256_SHA256_FIXED.verify_sig(&key, MESSAGE, &signature).unwrap();

            bencher.bench_local(move || {
                signature::ECDSA_P256_SHA256_FIXED.verify_sig(&key, MESSAGE, &signature)
            });
        }

        #[divan::bench]
        fn verify_fail(bencher: Bencher) {
            let key = public_key();
            let signature = base64_decode(&SIGNATURE.replace('g', "F"));
            signature::ECDSA_P256_SHA256_FIXED.verify_sig(&key, MESSAGE, &signature).unwrap_err();

            bencher.bench_local(move || {
                signature::ECDSA_P256_SHA256_FIXED.verify_sig(&key, MESSAGE, &signature)
            });
        }

        #[divan::bench]
        fn sign(bencher: Bencher) {
            let key = private_key();
            let mut rng = aws_lc_rs::rand::SystemRandom::new();

            bencher.bench_local(move || {
                key.sign(&mut rng, MESSAGE)
            });
        }

        fn private_key() -> EcdsaKeyPair {
            let (_, pkcs8_bytes) = pem_rfc7468::decode_vec(PRIVATE_KEY.as_bytes()).unwrap();
            EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &pkcs8_bytes,
            ).unwrap()
        }

        fn public_key() -> Vec<u8> {
            private_key().public_key().as_ref().to_vec()
        }
    }
}

mod es384 {
    use super::*;

    const MESSAGE: &[u8] = b"eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.\
        eyJleHAiOjE3NjE4NTUzNDcsIm9jIjp7ImU6MGJjZWRhNzItYmUxZS00MTVkLWE3M2QtYTM0NTE5ZjBmZTYzIjpbInJlYWQiXX19";
    const SIGNATURE: &str = "EpKxK9jzvpmmiYxOOrLHmgs-C2Ox5bAX7i6KUy8NdO0VlInHHBVQnaaMsAhqZ_LN1rvP3Z4GR3306960wVYDBm2bu6JjgVd2TTImzIJkZlitdWwJC0tGAXqDH9Mkg4PP";
    const PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
        MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDFqsxSqjZ6mm25GVGs\n\
        v5yClcHAEYriv7P3UlwnRx0EwEIq/aXXprHvGtw5S58hSSmhZANiAAT3FXl8SIm9\n\
        y9dVb7LH3uvPfTEYGvauhcud494n9Hu4kCyFfuN0bihRZM7/1AZ4pTrBdxzdRyUb\n\
        SVgNoFT2sFcitoQEJPwAYk1LWnIWx3EMVMM4ArlAGvIWMuMR/peFwC8=\n\
        -----END PRIVATE KEY-----\n\
    ";

    mod rust_crypto {
        use super::*;

        #[divan::bench]
        fn verify_ok(bencher: Bencher) {
            let signature = sig(SIGNATURE);
            let key = public_key();

            // Just make sure it is a success before running benchmark
            key.verify(MESSAGE, &signature).unwrap();

            bencher.bench_local(move || {
                black_box(key).verify(black_box(MESSAGE), black_box(&signature))
            });
        }

        #[divan::bench]
        fn verify_fail(bencher: Bencher) {
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


        fn public_key() -> p384::ecdsa::VerifyingKey {
            private_key().verifying_key().clone()
        }

        fn private_key() -> p384::ecdsa::SigningKey {
            let key: p384::SecretKey = PRIVATE_KEY.parse().unwrap();
            key.into()
        }

        fn sig(s: &str) -> p384::ecdsa::Signature {
            let signature = base64_decode(s);
            p384::ecdsa::Signature::from_slice(&signature).unwrap()
        }
    }

    mod aws_lc {
        use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair, VerificationAlgorithm};

        use super::*;

        #[divan::bench]
        fn verify_ok(bencher: Bencher) {
            let key = public_key();
            let signature = base64_decode(SIGNATURE);
            signature::ECDSA_P384_SHA384_FIXED.verify_sig(&key, MESSAGE, &signature).unwrap();

            bencher.bench_local(move || {
                signature::ECDSA_P384_SHA384_FIXED.verify_sig(&key, MESSAGE, &signature)
            });
        }

        #[divan::bench]
        fn verify_fail(bencher: Bencher) {
            let key = public_key();
            let signature = base64_decode(&SIGNATURE.replace('g', "F"));
            signature::ECDSA_P384_SHA384_FIXED.verify_sig(&key, MESSAGE, &signature).unwrap_err();

            bencher.bench_local(move || {
                signature::ECDSA_P384_SHA384_FIXED.verify_sig(&key, MESSAGE, &signature)
            });
        }

        #[divan::bench]
        fn sign(bencher: Bencher) {
            let key = private_key();
            let mut rng = aws_lc_rs::rand::SystemRandom::new();

            bencher.bench_local(move || {
                key.sign(&mut rng, MESSAGE)
            });
        }

        fn private_key() -> EcdsaKeyPair {
            let (_, pkcs8_bytes) = pem_rfc7468::decode_vec(PRIVATE_KEY.as_bytes()).unwrap();
            EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                &pkcs8_bytes,
            ).unwrap()
        }

        fn public_key() -> Vec<u8> {
            private_key().public_key().as_ref().to_vec()
        }
    }
}



fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()
}
