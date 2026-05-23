use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use es_protocol::{ListProducersResponse, ResetOffsetsRequest, ResetOffsetsResponse};

use crate::broker::Broker;

use super::auth_ext::AuthedKey;
use super::error::{AppError, AppResult};

pub async fn list(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
) -> AppResult<Json<ListProducersResponse>> {
    if !key.is_admin() {
        return Err(AppError::forbidden("admin grant required"));
    }
    let producers = broker.producers.list().await;
    Ok(Json(ListProducersResponse { producers }))
}

pub async fn revoke(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(producer_id): Path<String>,
) -> AppResult<StatusCode> {
    if !key.is_admin() {
        return Err(AppError::forbidden("admin grant required"));
    }
    broker.producers.revoke(&producer_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn reset_offsets(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Json(req): Json<ResetOffsetsRequest>,
) -> AppResult<Json<ResetOffsetsResponse>> {
    if !key.is_admin() {
        return Err(AppError::forbidden("admin grant required"));
    }
    let topic = broker
        .topic(&req.topic)
        .ok_or_else(|| AppError::not_found(format!("topic '{}' not found", req.topic)))?;

    // Reset every group's committed offset on this topic to the partition's
    // current start_offset.
    let group_names = broker.groups.iter_group_names();
    let mut entries_reset: u32 = 0;
    let mut groups_affected: u32 = 0;
    for group in &group_names {
        let snapshot = broker.groups.snapshot(group).await;
        let parts = match snapshot.get(&req.topic) {
            Some(p) => p.clone(),
            None => continue,
        };
        let mut any = false;
        for (pid, _committed) in parts {
            let part = match topic.partitions.get(pid as usize) {
                Some(p) => p,
                None => continue,
            };
            broker
                .groups
                .commit(group, &req.topic, pid, part.start_offset())
                .await?;
            entries_reset += 1;
            any = true;
        }
        if any {
            groups_affected += 1;
        }
    }
    Ok(Json(ResetOffsetsResponse {
        groups_affected,
        entries_reset,
    }))
}
