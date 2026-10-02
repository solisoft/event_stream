use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use es_protocol::{CommitRequest, GroupOffsetsResponse};

use crate::auth::AclAction;
use crate::broker::Broker;

use super::auth_ext::AuthedKey;
use super::error::{AppError, AppResult};

pub async fn commit(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(group): Path<String>,
    Json(req): Json<CommitRequest>,
) -> AppResult<StatusCode> {
    // Commits act on a topic — require read on that topic.
    if !key.can(AclAction::Read, &req.topic) {
        return Err(AppError::forbidden(format!(
            "key '{}' does not have read access to topic '{}'",
            key.key_id, req.topic
        )));
    }
    // Only real partitions: arbitrary topic names and partition numbers used
    // to be stored as given, growing the group's file without limit.
    let topic = broker
        .topic(&req.topic)
        .ok_or_else(|| AppError::not_found(format!("topic '{}' not found", req.topic)))?;
    if req.partition as usize >= topic.partitions.len() {
        return Err(AppError::bad_request(format!(
            "partition {} out of range",
            req.partition
        )));
    }
    broker
        .groups
        .commit(&group, &key, &req.topic, req.partition, req.offset)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn offsets(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(group): Path<String>,
) -> AppResult<Json<GroupOffsetsResponse>> {
    broker.groups.check_access(&group, &key).await?;
    let snapshot = broker.groups.snapshot(&group).await;
    // Only expose committed offsets for topics the caller can read.
    let offsets = snapshot
        .into_iter()
        .filter(|(topic, _)| key.can(AclAction::Read, topic))
        .collect();
    Ok(Json(GroupOffsetsResponse { offsets }))
}
