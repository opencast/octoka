use std::sync::Arc;

use hyper::{Request, StatusCode, body::Incoming};

use crate::{http::OnAllow, prelude::*};
use super::{Context, CorsInfo, Response};


pub async fn handle(mut req: Request<Incoming>, ctx: Arc<Context>) -> Response {
    let cors = CorsInfo::new(&req, &ctx.config.http);

    // Change the URI to the proxy target. We can unwrap the path, as we know
    // for sure there is one.
    *req.uri_mut() = ctx.config.opencast.host.clone()
        .with_path_and_query(req.uri().path_and_query().unwrap().clone());

    let mut r = match ctx.oc_client.request(req).await {
        Ok(r) => r,
        Err(e) => {
            debug!("error proxying request to OC: {e}");
            return super::error_response(StatusCode::BAD_GATEWAY);
        }
    };

    trace!(status = ?r.status(), "got reply from OC");

    // We treat this as a special case. Opencast does not have a
    // built-in way to work nicely with `auth_request`: either it
    // responds with the file or with X-Accel-Redirect. If used with
    // auth_request, the latter mode should be chosen, but this still
    // leaves the `X-Accel-Redirect` header. So instead, we just look
    // at the status code and then craft our own response.
    if ctx.config.http.on_allow == OnAllow::Empty && r.status().is_success(){
        trace!("OC response is success and http.on_allow = \"empty\" -> responding 204");
        super::empty_204_response(cors)
    } else {
        trace!("passing on OC response (mostly) as is");
        if r.status().is_success() {
            cors.add_headers(r.headers_mut());
        }

        // TODO: adjust `location` header?
        r.map(super::Body::Proxy)
    }
}
