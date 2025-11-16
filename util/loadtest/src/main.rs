use goose::prelude::*;


#[tokio::main]
async fn main() -> Result<(), GooseError> {
    GooseAttack::initialize()?
        .register_scenario(scenario!("GET foo.txt")
            .register_transaction(transaction!(get_foo_txt_ok))
        )
        .execute()
        .await?;

    Ok(())
}

/// Long lived JWT for the event `362c07...` in `test-downloads` with `keys/ed25519`.
const JWT_362_ED25519: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJleHAiOjI3NjMyOTQ2OTYsIm9jIjp7ImU6MzYyYzA3YWYtN2U2MS00NWI2LWIzYmYtNDE2ZGY3NWVkMWIwIjpbInJlYWQiXX19.2Wzwy0HRBd4bfHv6sR5PsPT3wyjQQvVh_fqnwyL2GglR84iAP98zQxdhB2ybaZrlYWZ29NCqL1bfUxMarZPCBA";


async fn get_foo_txt_ok(user: &mut GooseUser) -> TransactionResult {
    let path = "/static/mh_default_org/engage-player/362c07af-7e61-45b6-b3bf-416df75ed1b0/43dc7605-8f6f-4451-ab26-6d07031ce07b/foo.txt";
    let request_builder = user.get_request_builder(&GooseMethod::Get, path)?
        .header("Authorization", format!("Bearer {}", JWT_362_ED25519));
    let request = GooseRequest::builder()
        .set_request_builder(request_builder)
        .build();
    let _ = user.request(request).await?;

    Ok(())
}
