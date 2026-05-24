use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;

use crate::broker::Broker;

#[derive(Serialize)]
pub struct HealthStatus {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    topics_count: Option<usize>,
}

pub async fn healthz(State(broker): State<Arc<Broker>>) -> (StatusCode, Json<HealthStatus>) {
    let topics_count = broker.list_topics().len();
    (
        StatusCode::OK,
        Json(HealthStatus {
            status: "ok",
            topics_count: Some(topics_count),
        }),
    )
}

#[derive(Serialize)]
pub struct ReadyzStatus {
    status: &'static str,
    message: &'static str,
}

pub async fn readyz() -> Json<ReadyzStatus> {
    Json(ReadyzStatus {
        status: "ready",
        message: "accepting traffic",
    })
}
