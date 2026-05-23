use std::sync::Arc;

use axum::{extract::State, http::StatusCode};
use tokio_util::sync::CancellationToken;

use crate::broker::Broker;

use super::auth_ext::AuthedKey;
use super::error::{AppError, AppResult};

pub async fn run_retention(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
) -> AppResult<StatusCode> {
    if !key.is_admin() {
        return Err(AppError::forbidden("admin grant required"));
    }
    let cancel = CancellationToken::new();
    let grace = broker.config.segment_delete_grace;
    crate::retention::run_pass(&broker, grace, &cancel).await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn run_compaction(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
) -> AppResult<StatusCode> {
    if !key.is_admin() {
        return Err(AppError::forbidden("admin grant required"));
    }
    let cancel = CancellationToken::new();
    let grace = broker.config.segment_delete_grace;
    crate::compaction::run_pass(&broker, grace, &cancel).await;
    Ok(StatusCode::NO_CONTENT)
}
