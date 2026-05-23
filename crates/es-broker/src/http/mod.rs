pub mod admin;
pub mod admin_keys;
pub mod admin_producers;
pub mod auth_ext;
pub mod consume;
pub mod coord;
pub mod error;
pub mod groups;
pub mod metrics;
pub mod produce;
pub mod topics;

use std::sync::Arc;

use axum::{Router, routing::{delete, get, post}};
use tower_http::trace::TraceLayer;

use crate::broker::Broker;

pub fn router(broker: Arc<Broker>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(metrics::metrics))
        .route("/topics", get(topics::list).post(topics::create))
        .route("/topics/:name", get(topics::describe))
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
        .route("/admin/keys", get(admin_keys::list).post(admin_keys::create))
        .route("/admin/keys/:key_id", delete(admin_keys::revoke))
        .route(
            "/admin/producers",
            get(admin_producers::list),
        )
        .route(
            "/admin/producers/:producer_id",
            delete(admin_producers::revoke),
        )
        .route(
            "/admin/reset-offsets",
            post(admin_producers::reset_offsets),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(broker)
}
