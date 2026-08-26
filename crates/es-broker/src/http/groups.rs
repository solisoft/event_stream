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
    broker
        .groups
        .commit(&group, &req.topic, req.partition, req.offset)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn offsets(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(group): Path<String>,
) -> Json<GroupOffsetsResponse> {
    let snapshot = broker.groups.snapshot(&group).await;
    // Only expose committed offsets for topics the caller can read, so one
    // principal can't enumerate another tenant's group positions.
    let offsets = snapshot
        .into_iter()
        .filter(|(topic, _)| key.can(AclAction::Read, topic))
        .collect();
    Json(GroupOffsetsResponse { offsets })
}
