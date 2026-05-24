use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;

use crate::broker::Broker;

use super::auth_ext::AuthedKey;
use super::error::{AppError, AppResult};

#[derive(Serialize)]
pub struct TieredSegmentsResponse {
    segments: Vec<u64>,
}

pub async fn list_remote(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path((topic, partition)): Path<(String, u32)>,
) -> AppResult<Json<TieredSegmentsResponse>> {
    if !key.is_admin() {
        return Err(AppError::forbidden("admin access required"));
    }
    let segments = match &broker.tiered_store {
        Some(store) => store
            .list_remote(&topic, partition)
            .map_err(|e| AppError::internal(format!("tiered list: {}", e)))?,
        None => Vec::new(),
    };
    Ok(Json(TieredSegmentsResponse { segments }))
}
