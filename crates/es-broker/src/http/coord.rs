use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;

use es_protocol::{
    AssignmentResponse, HeartbeatRequest, HeartbeatResponse, JoinGroupRequest, JoinGroupResponse,
    LeaveGroupRequest, TopicPartitionDto,
};

use crate::auth::AclAction;
use crate::broker::Broker;
use crate::coord::{AssignmentReply, HeartbeatReply};

use super::auth_ext::AuthedKey;
use super::error::{AppError, AppResult};

fn check_read_on_all(key: &crate::auth::ApiKey, topics: &[String]) -> AppResult<()> {
    for t in topics {
        if !key.can(AclAction::Read, t) {
            return Err(AppError::forbidden(format!(
                "key '{}' has no read access to topic '{}'",
                key.key_id, t
            )));
        }
    }
    Ok(())
}

/// Authorize a group operation: the caller must have read access to every topic
/// the group is subscribed to. Prevents an unrelated principal from disrupting
/// or inspecting another tenant's consumer group.
async fn check_group_access(
    broker: &Arc<Broker>,
    key: &crate::auth::ApiKey,
    group: &str,
) -> AppResult<()> {
    let topics = broker.coordinator.group_topics(group).await;
    check_read_on_all(key, &topics)
}

fn to_tp(v: Vec<(String, u32)>) -> Vec<TopicPartitionDto> {
    v.into_iter()
        .map(|(topic, partition)| TopicPartitionDto { topic, partition })
        .collect()
}

pub async fn join(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(group): Path<String>,
    Json(req): Json<JoinGroupRequest>,
) -> AppResult<Json<JoinGroupResponse>> {
    check_read_on_all(&key, &req.topics)?;
    let reply = broker
        .coordinator
        .join(&broker, &group, req.member_id, req.topics)
        .await?;
    Ok(Json(JoinGroupResponse {
        member_id: reply.member_id,
        generation: reply.generation,
        assignment: to_tp(reply.assignment),
    }))
}

pub async fn heartbeat(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(group): Path<String>,
    Json(req): Json<HeartbeatRequest>,
) -> AppResult<Json<HeartbeatResponse>> {
    check_group_access(&broker, &key, &group).await?;
    let reply = broker
        .coordinator
        .heartbeat(&group, &req.member_id, req.generation)
        .await?;
    Ok(Json(match reply {
        HeartbeatReply::Ok { generation } => HeartbeatResponse::Ok { generation },
        HeartbeatReply::RebalanceRequired { current_generation } => {
            HeartbeatResponse::RebalanceRequired { current_generation }
        }
        HeartbeatReply::UnknownMember { current_generation } => {
            HeartbeatResponse::UnknownMember { current_generation }
        }
    }))
}

pub async fn leave(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(group): Path<String>,
    Json(req): Json<LeaveGroupRequest>,
) -> AppResult<StatusCode> {
    check_group_access(&broker, &key, &group).await?;
    broker
        .coordinator
        .leave(&broker, &group, &req.member_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct AssignmentQuery {
    pub member_id: String,
}

pub async fn assignment(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(group): Path<String>,
    Query(q): Query<AssignmentQuery>,
) -> AppResult<Json<AssignmentResponse>> {
    check_group_access(&broker, &key, &group).await?;
    let reply = broker.coordinator.assignment(&group, &q.member_id).await;
    match reply {
        AssignmentReply::Ok {
            generation,
            assignment,
        } => Ok(Json(AssignmentResponse {
            generation,
            assignment: to_tp(assignment),
        })),
        AssignmentReply::UnknownMember { current_generation } => Err(AppError::not_found(format!(
            "member not in group (current generation {})",
            current_generation
        ))),
    }
}
