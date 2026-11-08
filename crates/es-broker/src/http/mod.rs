pub mod admin;
pub mod admin_keys;
pub mod admin_producers;
pub mod admin_tiered;
pub mod auth_ext;
pub mod consume;
pub mod coord;
pub mod error;
pub mod groups;
pub mod healthz;
pub mod metrics;
pub mod produce;
pub mod raft_status;
pub mod schemas;
pub mod topics;

use std::net::IpAddr;
use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::auth::AuthMode;
use crate::broker::Broker;
use crate::config::Config;

pub fn router(broker: Arc<Broker>) -> Router {
    let max_body_bytes = broker.config.max_request_body_bytes;

    let router = Router::new()
        .route("/healthz", get(healthz::healthz))
        .route("/readyz", get(healthz::readyz))
        .route("/metrics", get(metrics::metrics))
        .route("/raft", get(raft_status::raft_status))
        .route("/topics", get(topics::list).post(topics::create))
        .route(
            "/topics/:name",
            get(topics::describe).delete(topics::delete_topic),
        )
        .route(
            "/topics/:name/config",
            get(topics::get_config).put(topics::update_config),
        )
        .route("/topics/:name/produce", post(produce::produce))
        .route("/topics/:name/consume", get(consume::consume))
        .route("/groups/:group/consume", get(consume::group_consume))
        .route("/groups/:group/commit", post(groups::commit))
        .route("/groups/:group/offsets", get(groups::offsets))
        .route("/groups/:group/join", post(coord::join))
        .route("/groups/:group/heartbeat", post(coord::heartbeat))
        .route("/groups/:group/leave", post(coord::leave))
        .route("/groups/:group/assignment", get(coord::assignment))
        .route("/admin/run-retention", post(admin::run_retention))
        .route("/admin/run-compaction", post(admin::run_compaction))
        .route(
            "/admin/keys",
            get(admin_keys::list).post(admin_keys::create),
        )
        .route("/admin/keys/:key_id", delete(admin_keys::revoke))
        .route("/admin/producers", get(admin_producers::list))
        .route(
            "/admin/producers/:producer_id",
            delete(admin_producers::revoke),
        )
        .route("/admin/reset-offsets", post(admin_producers::reset_offsets))
        .route("/schemas", get(schemas::list).post(schemas::register))
        .route("/schemas/:id", get(schemas::get))
        .route(
            "/subjects/:subject/versions/latest",
            get(schemas::latest_version),
        )
        .route(
            "/admin/tiered/:topic/:partition",
            get(admin_tiered::list_remote),
        )
        .layer(middleware::from_fn_with_state(broker.clone(), guard_host))
        .layer((
            TraceLayer::new_for_http(),
            CatchPanicLayer::new(),
            RequestBodyLimitLayer::new(max_body_bytes),
        ));

    // CORS only for origins the operator listed. `CorsLayer::permissive()`
    // let any web page an operator visited drive the broker from their
    // browser — with auth disabled, as admin.
    let router = match cors_layer(&broker.config) {
        Some(cors) => router.layer(cors),
        None => router,
    };
    router.with_state(broker)
}

fn cors_layer(config: &Config) -> Option<CorsLayer> {
    if config.cors_allowed_origins.is_empty() {
        return None;
    }
    let origins: Vec<HeaderValue> = config
        .cors_allowed_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::HeaderName::from_static("x-es-key"),
            ]),
    )
}

/// With auth disabled every caller is an admin, so who can reach the port is
/// the whole security model. A browser can be made to reach it too: a page the
/// operator visits can point a hostname it controls at 127.0.0.1 (DNS
/// rebinding) and read the responses as same-origin. The `Host` header is the
/// one thing such a request cannot fake, so it must name this machine.
///
/// A request that names no host at all (HTTP/1.0 without `Host`) is refused
/// too: it used to skip the check. Over HTTP/2 the host travels as the
/// `:authority` pseudo-header, which hyper puts in the URI, not in `Host`;
/// whichever of the two is present must pass, and at least one must be.
async fn guard_host(State(broker): State<Arc<Broker>>, req: Request, next: Next) -> Response {
    if broker.config.auth_mode == AuthMode::Disabled && !request_host_allowed(&req, &broker.config)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(es_protocol::ApiError {
                error: "Host not allowed: authentication is disabled, so only loopback \
                        host names (or --allowed-host) are accepted"
                    .to_string(),
            }),
        )
            .into_response();
    }
    next.run(req).await
}

fn request_host_allowed(req: &Request, config: &Config) -> bool {
    let header = req.headers().get(header::HOST);
    let authority = req.uri().authority();
    if header.is_none() && authority.is_none() {
        return false;
    }
    let header_ok =
        header.is_none_or(|h| h.to_str().map(|h| host_allowed(h, config)).unwrap_or(false));
    let authority_ok = authority.is_none_or(|a| host_allowed(a.as_str(), config));
    header_ok && authority_ok
}

/// Whether `host` (a `Host` value, port optional) names this machine.
///
/// Addresses are compared as addresses: a textual `starts_with("127.")` let
/// `127.rebind.attacker.com` through — a name the attacker controls and can
/// point anywhere. Names are compared exactly.
fn host_allowed(host: &str, config: &Config) -> bool {
    let name = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            Some((inside, _)) => inside,
            None => return false,
        }
    } else {
        host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host)
    };
    let name = name.to_ascii_lowercase();
    if name == "localhost" {
        return true;
    }
    if let Ok(ip) = name.parse::<IpAddr>() {
        if ip.is_loopback() {
            return true;
        }
        let bind_ip = config.bind.ip();
        if !bind_ip.is_unspecified() && ip == bind_ip {
            return true;
        }
    }
    config
        .allowed_hosts
        .iter()
        .any(|h| h.eq_ignore_ascii_case(&name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_check_accepts_loopback_and_listed_names_only() {
        let mut c = Config::new("/tmp".into(), "127.0.0.1:9000".parse().unwrap(), 1024);
        assert!(host_allowed("127.0.0.1:9000", &c));
        assert!(host_allowed("localhost:9000", &c));
        assert!(host_allowed("[::1]:9000", &c));
        assert!(!host_allowed("evil.example:9000", &c));
        c.allowed_hosts.push("broker.internal".into());
        assert!(host_allowed("broker.internal:9000", &c));
    }

    #[test]
    fn host_check_compares_addresses_not_text() {
        let c = Config::new("/tmp".into(), "127.0.0.1:9000".parse().unwrap(), 1024);
        // Names that merely look like loopback are attacker-controlled DNS.
        assert!(!host_allowed("127.rebind.attacker.com", &c));
        assert!(!host_allowed("127.rebind.attacker.com:9000", &c));
        assert!(!host_allowed("127.0.0.1.attacker.com", &c));
        assert!(!host_allowed("localhost.attacker.com", &c));
        assert!(!host_allowed("[::1", &c));
        // The whole of 127/8 is loopback.
        assert!(host_allowed("127.0.0.2", &c));
        assert!(host_allowed("127.1.2.3:9000", &c));
        assert!(host_allowed("LOCALHOST", &c));
    }

    #[test]
    fn host_check_accepts_the_bind_address() {
        let c = Config::new("/tmp".into(), "10.1.2.3:9000".parse().unwrap(), 1024);
        assert!(host_allowed("10.1.2.3:9000", &c));
        assert!(!host_allowed("10.1.2.4:9000", &c));
        let c = Config::new("/tmp".into(), "[fd00::1]:9000".parse().unwrap(), 1024);
        assert!(host_allowed("[fd00::1]:9000", &c));
    }

    #[test]
    fn a_request_without_any_host_is_refused() {
        let c = Config::new("/tmp".into(), "127.0.0.1:9000".parse().unwrap(), 1024);
        let req = |uri: &str, host: Option<&str>| {
            let mut b = axum::http::Request::builder().uri(uri);
            if let Some(h) = host {
                b = b.header(header::HOST, h);
            }
            b.body(axum::body::Body::empty()).unwrap()
        };
        assert!(!request_host_allowed(&req("/topics", None), &c));
        assert!(request_host_allowed(&req("/topics", Some("localhost")), &c));
        // HTTP/2: the authority is in the URI.
        assert!(request_host_allowed(
            &req("http://127.0.0.1:9000/topics", None),
            &c
        ));
        assert!(!request_host_allowed(
            &req("http://evil.example/topics", None),
            &c
        ));
        // Both present: both must pass.
        assert!(!request_host_allowed(
            &req("http://evil.example/topics", Some("localhost")),
            &c
        ));
    }
}
