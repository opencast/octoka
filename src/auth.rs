use std::time::Duration;

use crate::{http::Context, opencast::PathParts, prelude::*};


const JWT_VERIFY_TIMEOUT: Duration = Duration::from_millis(2500);

pub async fn is_allowed(
    path: PathParts<'_>,
    jwt: Option<&str>,
    ctx: &Context,
) -> bool {
    let Some(jwt) = jwt else {
        trace!("no JWT found in request");
        return false;
    };

    let res = tokio::select! {
        res = ctx.jwt.decode_and_verify(jwt) => res,
        _ = tokio::time::sleep(JWT_VERIFY_TIMEOUT) => {
            warn!(?JWT_VERIFY_TIMEOUT, "could not verify JWT in time");
            return false;
        }
    };

    let info = match res {
        Ok(info) => info,
        Err(e) => {
            debug!("rejected JWT ({e:?})");
            return false;
        }
    };

    if info.is_admin {
        trace!("JWT grants ROLE_ADMIN -> allowing access");
        return true;
    }
    if info.readable_events.iter().any(|e| e == path.event_id()) {
        trace!(event = path.event_id(), "JWT grants read access to event -> allowing access");
        return true;
    }

    debug!("JWT valid but does not grant access to event");
    false
}
