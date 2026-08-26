use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
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
    // Validate the topic name before it reaches the tiered store, where it is
    // joined into a filesystem path — otherwise a `../` name could enumerate
    // directories outside the cold-storage root.
    crate::topic::validate_topic_name(&topic).map_err(|e| AppError::bad_request(e.to_string()))?;
    let segments = match &broker.tiered_store {
        Some(store) => store
            .list_remote(&topic, partition)
            .map_err(|e| AppError::internal(format!("tiered list: {}", e)))?,
        None => Vec::new(),
    };
    Ok(Json(TieredSegmentsResponse { segments }))
}
