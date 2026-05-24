use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;

use es_protocol::{
    CreateTopicRequest, DescribeTopicResponse, ListTopicsResponse, PartitionInfo, TopicConfigDto,
    TopicConfigPatch, TopicSummary,
};

use crate::auth::AclAction;
use crate::broker::Broker;

use super::auth_ext::AuthedKey;
use super::error::{AppError, AppResult};

pub async fn create(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Json(req): Json<CreateTopicRequest>,
) -> AppResult<(StatusCode, Json<TopicSummary>)> {
    if !key.is_admin() {
        return Err(AppError::forbidden("create topic requires admin grant"));
    }
    let topic = broker.create_topic(&req.name, req.partitions, req.config.as_ref())?;
    Ok((
        StatusCode::CREATED,
        Json(TopicSummary {
            name: topic.name.clone(),
            partitions: topic.partitions.len() as u32,
        }),
    ))
}

pub async fn list(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
) -> Json<ListTopicsResponse> {
    let all = broker.list_topics();
    let visible: Vec<String> = all
        .into_iter()
        .filter(|name| key.can(AclAction::Read, name))
        .collect();
    Json(ListTopicsResponse { topics: visible })
}

pub async fn describe(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(name): Path<String>,
) -> AppResult<Json<DescribeTopicResponse>> {
    if !key.can(AclAction::Read, &name) {
        return Err(AppError::forbidden(format!(
            "key '{}' does not have read access to topic '{}'",
            key.key_id, name
        )));
    }
    let topic = broker
        .topic(&name)
        .ok_or_else(|| AppError::not_found(format!("topic '{}' not found", name)))?;
    let partitions = topic
        .partitions
        .iter()
        .map(|p| PartitionInfo {
            id: p.id(),
            start_offset: p.start_offset(),
            end_offset: p.end_offset(),
            segment_count: p.segment_count(),
            size_bytes: p.total_size_bytes(),
        })
        .collect();
    Ok(Json(DescribeTopicResponse {
        name: topic.name.clone(),
        partitions,
        config: topic.resolved_config().to_dto(),
    }))
}

pub async fn get_config(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(name): Path<String>,
) -> AppResult<Json<TopicConfigDto>> {
    if !key.can(AclAction::Read, &name) {
        return Err(AppError::forbidden(format!(
            "key '{}' does not have read access to topic '{}'",
            key.key_id, name
        )));
    }
    let topic = broker
        .topic(&name)
        .ok_or_else(|| AppError::not_found(format!("topic '{}' not found", name)))?;
    Ok(Json(topic.resolved_config().to_dto()))
}

pub async fn update_config(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(name): Path<String>,
    Json(patch): Json<TopicConfigPatch>,
) -> AppResult<Json<TopicConfigDto>> {
    if !key.is_admin() {
        return Err(AppError::forbidden("update config requires admin grant"));
    }
    let resolved = broker.update_topic_config(&name, &patch)?;
    Ok(Json(resolved.to_dto()))
}

#[derive(Serialize)]
pub struct DeleteTopicResponse {
    name: String,
    partitions: u32,
}

pub async fn delete_topic(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(name): Path<String>,
) -> AppResult<Json<DeleteTopicResponse>> {
    if !key.is_admin() {
        return Err(AppError::forbidden("delete topic requires admin grant"));
    }
    let topic = broker
        .delete_topic(&name)
        .map_err(|e| AppError::not_found(format!("{}", e)))?;
    Ok(Json(DeleteTopicResponse {
        name: topic.name.clone(),
        partitions: topic.partitions.len() as u32,
    }))
}
