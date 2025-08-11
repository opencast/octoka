use crate::{http::Context, opencast::PathParts, prelude::*};



pub async fn is_allowed(
    path: PathParts<'_>,
    jwt: Option<&str>,
    ctx: &Context,
) -> bool {
    let Some(jwt) = jwt else {
        debug!("no JWT found in request -> denying access");
        return false;
    };

    let info = match ctx.jwt.decode_and_verify(jwt).await {
        Ok(info) => info,
        Err(e) => {
            debug!("rejected JWT ({e:?}) -> denying access");
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

    debug!("JWT valid but does not grant access to event -> denying access");
    false
}
