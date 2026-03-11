use std::net::SocketAddr;

use anyhow::Result;
use confique::Config as _;
use http::StatusCode;
use octoka::config::Config;
use reqwest::Response;


// ==============================================================================================
// ===== Test setup stuff and utilities
// ==============================================================================================

const FETCH_EVENT_ID: &str = "abc123";

struct TestSetup {
    addr: SocketAddr,
    keys: Vec<jwtea::VerifyingKey>,
}

impl TestSetup {
    /// Sends an HTTP GET request to the static file path, with the given JWT.
    async fn fetch(&self, jwt: &str) -> Result<Response> {
        let addr = self.addr;
        let url = format!("http://{addr}/static/org/channel/{FETCH_EVENT_ID}/path.mp4?jwt={jwt}");
        reqwest::get(&url).await.map_err(Into::into)
    }

    /// Makes sure that the JWT is generally correct, i.e. has the right syntax and
    /// a correct signature. Does not check claims.
    async fn check_jwt_basic(&self, jwt: &str) -> Result<()> {
        struct NullValidator;
        impl<H, P> jwtea::Validator<H, P> for NullValidator {
            fn validate(&self, _: &jwtea::Header<H>, _: &jwtea::Payload<P>) -> Result<(), jwtea::Error> {
                Ok(())
            }
        }
        jwtea::decode::<(), (), ()>(jwt, &self.keys, &NullValidator, |_, _| ())
            .await
            .map_err(Into::into)
    }
}

async fn setup(trusted_keys: &[&str]) -> Result<TestSetup> {
    // Load trusted keys
    let keys = trusted_keys.iter().flat_map(|key_file| {
        let path = format!("{}/tests/jwks/{key_file}", env!("CARGO_MANIFEST_DIR"));
        let key_set = std::fs::read_to_string(path).unwrap();
        jwtea::Jwks::from_str(&key_set)
            .unwrap()
            .to_verifying_keys()
            .map(Result::unwrap)
            .collect::<Vec<_>>()
    }).collect::<Vec<_>>();

    let trusted_keys = trusted_keys.iter()
        .map(|file| format!("\"http://127.0.0.1:4055/{file}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config = format!(r#"
        opencast.fallback = "none"
        jwt.trusted_keys = [{trusted_keys}]
        http.on_allow = "empty"
        http.port = 0
        log.filters.octoka = "trace"
    "#);

    let config = Config::builder()
        .preloaded(toml::from_str(&config)?)
        .load()?;
    let _ = octoka::log::init(&config.log, true);

    let (addr, server) = octoka::test_http_server(config).await?;
    tokio::spawn(server);
    Ok(TestSetup {
        addr,
        keys,
    })
}

macro_rules! assert_status {
    ($resp:expr, $code:expr) => {
        assert_eq!($resp.await?.status(), $code);
    };
}
macro_rules! assert_jwt_ok_but_forbidden {
    ($setup:expr, $jwt:expr) => {
        assert!($setup.check_jwt_basic($jwt).await.is_ok());
        assert_eq!($setup.fetch($jwt).await?.status(), StatusCode::FORBIDDEN);
    };
}



// ==============================================================================================
// ===== Tests
// ==============================================================================================

/// Encoded header: `{ "alg": "EdDSA", "typ": "JWT" }`
const HEADER_EDDSA: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9";

/// Encoded payload: `{ "exp": 4012345678, "roles": ["ROLE_ADMIN"] }` (exp is Feb 2097)
const PAYLOAD_ADMIN: &str = "eyJleHAiOjQwMTIzNDU2NzgsInJvbGVzIjpbIlJPTEVfQURNSU4iXX0";

/// With only `ed25519` key.
#[tokio::test]
async fn ed25519() -> Result<()> {
    let setup = setup(&["ed25519.json"]).await?;

    // Valid signature
    let jwt = format!("{HEADER_EDDSA}.{PAYLOAD_ADMIN}.\
        6Bs6wdvBdWbszV38Lj81OmtW5ibutzUfTc8_X6k3yiwOHNQm5xQrWiILXGRP7eHFiI4Ju1FHu_NxufSUPiELAw");
    assert_status!(setup.fetch(&jwt), StatusCode::NO_CONTENT);

    // Invalid signatures
    let jwt = format!("{HEADER_EDDSA}.{PAYLOAD_ADMIN}.\
        6Bs6wdvBdWbszV38Lj81OmtW5ibutzUfTc8_X6k3yiwOHNQm5xQrWiILXGRP7eHFiI4Ju1FHu_NxufSUPiELA");
    assert_status!(setup.fetch(&jwt), StatusCode::FORBIDDEN);
    let jwt = format!("{HEADER_EDDSA}.{PAYLOAD_ADMIN}.\
        Bs6wdvBdWbszV38Lj81OmtW5ibutzUfTc8_X6k3yiwOHNQm5xQrWiILXGRP7eHFiI4Ju1FHu_NxufSUPiELAw");
    assert_status!(setup.fetch(&jwt), StatusCode::FORBIDDEN);
    let jwt = format!("{HEADER_EDDSA}.{PAYLOAD_ADMIN}.\
        yftxGDuDRHgWz8WUifYRmwtI9RkMkWv6OmS0Pezx39MHA2w-lAsCdGv01fIK1xBvp1F1BO5WnyZsJZmQaovQCA");
    assert_status!(setup.fetch(&jwt), StatusCode::FORBIDDEN);


    Ok(())
}

#[tokio::test]
async fn time_validations() -> Result<()> {
    let setup = setup(&["ed25519.json"]).await?;

    // No `exp` claim. Payload: `{ "roles": ["ROLE_ADMIN"] }`
    let jwt = format!("{HEADER_EDDSA}.eyJyb2xlcyI6WyJST0xFX0FETUlOIl19.\
        28ykRHCGRaiC6jQgLOuJU39sg-ZylYAjs3O5pMduR91YloluSF2XBTyZHEO0fgUeMOS-IFYl9ys_9bo2Un3WAA");
    assert_jwt_ok_but_forbidden!(setup, &jwt);

    // `exp` is expired. Payload: `{ "exp": 123456789, "roles": ["ROLE_ADMIN"] }`
    let jwt = format!("{HEADER_EDDSA}.eyJleHAiOjEyMzQ1Njc4OSwicm9sZXMiOlsiUk9MRV9BRE1JTiJdfQ.\
        JjhGu-NlU7RPecV-MW4fd6Fhabce8BNQZ2T6MrBYEhvIFF_lm7J8ZHdO_3NHufwtInu4YhIifOQjqM2NJO2rCg");
    assert_jwt_ok_but_forbidden!(setup, &jwt);

    // `nbf` is in the future. Payload: `{ "exp": 4012345678, "nbf": 3912345678, "roles": ["ROLE_ADMIN"] }`
    let jwt = format!("{HEADER_EDDSA}.eyJleHAiOjQwMTIzNDU2NzgsIm5iZiI6MzkxMjM0NTY3OCwicm9sZXMiOlsiUk9MRV9BRE1JTiJdfQ.\
        hR4WlsEqT1BTMISJmA05axiXWG9_dmzJ-E9MxQ9O-wvdeaNOon0RRKQEP-wfOsJzx-QRqI_NoEU3-Ej9kqprDg");
    assert_jwt_ok_but_forbidden!(setup, &jwt);

    // `nbf` is set and fine! Payload: `{ "exp": 4012345678, "nbf": 123456789, "roles": ["ROLE_ADMIN"] }`
    let jwt = format!("{HEADER_EDDSA}.eyJleHAiOjQwMTIzNDU2NzgsIm5iZiI6MTIzNDU2Nzg5LCJyb2xlcyI6WyJST0xFX0FETUlOIl19.\
        KGY8LO9voQqR7Ey1G-Aq9UN_62_yNnb5EuAEQICIgzl0Iy8wUpaP8JaaJW0JBgKYbldpP04izphYQno35ZPECA");
    assert_status!(setup.fetch(&jwt), StatusCode::NO_CONTENT);

    Ok(())
}


#[tokio::test]
async fn oc_claims() -> Result<()> {
    let setup = setup(&["ed25519.json"]).await?;

    // Just a non admin role: `{ "exp": 4012345678, "roles": ["ROLE_USER"] }`
    let jwt = format!("{HEADER_EDDSA}.eyJleHAiOjQwMTIzNDU2NzgsInJvbGVzIjpbIlJPTEVfVVNFUiJdfQ.\
        _wHBNPRKhR2xSKRYwyXCRLEUQ0JCrnhUfFn380YwsqSLydxY0qHzxWkUB5CkCsrMLysorkyKxYHx-M9NyyGRCg");
    assert_status!(setup.fetch(&jwt), StatusCode::FORBIDDEN);

    // Admin role and other roles: { "exp": 4012345678, "roles": ["ROLE_USER", "ROLE_ADMIN"] }
    let jwt = format!("{HEADER_EDDSA}.eyJleHAiOjQwMTIzNDU2NzgsInJvbGVzIjpbIlJPTEVfVVNFUiIsIlJPTEVfQURNSU4iXX0.\
        GATALWsFAp1wyaOm-P3wQC5mTyj1dp5zIdcFHFWIP4_JUebMHgKMttKrmqJ6EUXh_eNq6_4MTeZeEAodY9BeAA");
    assert_status!(setup.fetch(&jwt), StatusCode::NO_CONTENT);

    // `oc` claim with correct ID: { "exp": 4012345678, "oc": { "e:abc123": ["read"] } }
    let jwt = format!("{HEADER_EDDSA}.eyJleHAiOjQwMTIzNDU2NzgsIm9jIjp7ImU6YWJjMTIzIjpbInJlYWQiXX19.\
        IxELHyc6u-G56-FAjoyZJdRL-X0i4VFHWsm0SqJZHFZ4Ff2c6dls_UkeAV1dE4bPBplyWRa9SnyetvUSx-DbBg");
    assert_status!(setup.fetch(&jwt), StatusCode::NO_CONTENT);

    // `oc` claim with incorrect ID: { "exp": 4012345678, "oc": { "e:ffff": ["read"] } }
    let jwt = format!("{HEADER_EDDSA}.eyJleHAiOjQwMTIzNDU2NzgsIm9jIjp7ImU6ZmZmZiI6WyJyZWFkIl19fQ.\
        jJUzVbnuKpCysCduTZyqi7_IPIpjE4Z-kyP7C-gGk5XTPg5v8cmViWjkUUNr1YySOETrbtU6xgHPYktAgTasBw");
    assert_status!(setup.fetch(&jwt), StatusCode::FORBIDDEN);

    // `oc` claim with incorrect and correct ID: { "exp": 4012345678, "oc": { "e:ffff": ["read"], "e:abc123": ["read"] } }
    let jwt = format!("{HEADER_EDDSA}.eyJleHAiOjQwMTIzNDU2NzgsIm9jIjp7ImU6ZmZmZiI6WyJyZWFkIl0sImU6YWJjMTIzIjpbInJlYWQiXX19.\
        OKXJJJPztNijrkLQSJ67isUZo9ktGJkotMlidHe6Foo1yHtcEyA9967XljohpVZKPgtQf9Q7yJ-pbM8Eto2WAQ");
    assert_status!(setup.fetch(&jwt), StatusCode::NO_CONTENT);

    // `oc` claim wrong action: { "exp": 4012345678, "oc": { "e:abc123": ["banana"] } }
    let jwt = format!("{HEADER_EDDSA}.eyJleHAiOjQwMTIzNDU2NzgsIm9jIjp7ImU6YWJjMTIzIjpbImJhbmFuYSJdfX0.\
        3mUEQlYzOSAEoIhjbxl-hZhZLKmaf5_5cqjnXwFs5SSiSBcad5BotRsNVn1yETRwuDwQWCKSbXnaqjweWW7BDg");
    assert_status!(setup.fetch(&jwt), StatusCode::FORBIDDEN);

    // `oc` claim write action only: { "exp": 4012345678, "oc": { "e:abc123": ["write"] } }
    let jwt = format!("{HEADER_EDDSA}.eyJleHAiOjQwMTIzNDU2NzgsIm9jIjp7ImU6YWJjMTIzIjpbIndyaXRlIl19fQ.\
        G6por97AZb7upyCE5W-e5YWFBwzNG8mNiYYa9t7U4UOA_bd-tnPlqrbX8wQ1IgoG4pUHfApnK5wM_7YPPaC6AA");
    assert_status!(setup.fetch(&jwt), StatusCode::FORBIDDEN);

    // No related claim: { "exp": 4012345678, "event": "abc123" }
    let jwt = format!("{HEADER_EDDSA}.eyJleHAiOjQwMTIzNDU2NzgsInN1YiI6ImFiYzEyMyJ9.\
        tAKXmXwSodREEkm2c7q6ZRI8X0WRWa3a3YPsd51x3HLBgTwxIDkzfjNqRzlcWUafQ8w1Bv4BSdBmVZPz_AwgCw");
    assert_status!(setup.fetch(&jwt), StatusCode::FORBIDDEN);

    Ok(())
}

// TODO:
// - kid: key has it, jwt has it, combinations
// - incorrect alg in JWK
// - RSA key: with alg, without alg
// - multiple keys: none valid, one valid, ...
