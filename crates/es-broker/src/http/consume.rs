use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;

use es_protocol::ConsumeResponse;

use crate::auth::AclAction;
use crate::broker::Broker;

use super::auth_ext::AuthedKey;
use super::error::{AppError, AppResult};

#[derive(Debug, Deserialize)]
pub struct ConsumeQuery {
    pub partition: u32,
    pub offset: u64,
    #[serde(default = "default_max_records")]
    pub max_records: usize,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
}

fn default_max_records() -> usize {
    100
}
fn default_max_bytes() -> usize {
    1 << 20
}

pub async fn consume(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(topic_name): Path<String>,
    Query(q): Query<ConsumeQuery>,
) -> AppResult<Json<ConsumeResponse>> {
    if !key.can(AclAction::Read, &topic_name) {
        return Err(AppError::forbidden(format!(
            "key '{}' does not have read access to topic '{}'",
            key.key_id, topic_name
        )));
    }

    let topic = broker
        .topic(&topic_name)
        .ok_or_else(|| AppError::not_found(format!("topic '{}' not found", topic_name)))?;
    let partition = topic
        .partitions
        .get(q.partition as usize)
        .ok_or_else(|| AppError::bad_request(format!("partition {} out of range", q.partition)))?;

    let (records, next_offset, high_watermark) =
        partition.read_records(q.offset, q.max_records, q.max_bytes)?;
    let consumed_bytes: u64 = records
        .iter()
        .map(|r| r.key.as_ref().map(|k| k.len() as u64).unwrap_or(0) + r.value.len() as u64)
        .sum();

    // Post-charge consume bytes. If this overdrew the bucket, the *next* call
    // will be rejected — we don't reject this one mid-flight.
    let _ = broker
        .keys
        .check_consume(&key.key_id, consumed_bytes as u32);

    topic
        .records_consumed_total
        .fetch_add(records.len() as u64, Ordering::Relaxed);
    topic
        .bytes_consumed_total
        .fetch_add(consumed_bytes, Ordering::Relaxed);

    Ok(Json(ConsumeResponse {
        records,
        next_offset,
        high_watermark,
    }))
}

#[derive(Debug, Deserialize)]
pub struct GroupConsumeQuery {
    pub topic: String,
    pub partition: u32,
    #[serde(default = "default_max_records")]
    pub max_records: usize,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
}

pub async fn group_consume(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(group): Path<String>,
    Query(q): Query<GroupConsumeQuery>,
) -> AppResult<Json<ConsumeResponse>> {
    if !key.can(AclAction::Read, &q.topic) {
        return Err(AppError::forbidden(format!(
            "key '{}' does not have read access to topic '{}'",
            key.key_id, q.topic
        )));
    }

    let topic = broker
        .topic(&q.topic)
        .ok_or_else(|| AppError::not_found(format!("topic '{}' not found", q.topic)))?;
    let partition = topic
        .partitions
        .get(q.partition as usize)
        .ok_or_else(|| AppError::bad_request(format!("partition {} out of range", q.partition)))?;

    let committed = broker
        .groups
        .fetch(&group, &q.topic, q.partition)
        .await
        .unwrap_or(partition.start_offset());

    let (records, next_offset, high_watermark) =
        partition.read_records(committed, q.max_records, q.max_bytes)?;
    let consumed_bytes: u64 = records
        .iter()
        .map(|r| r.key.as_ref().map(|k| k.len() as u64).unwrap_or(0) + r.value.len() as u64)
        .sum();
    let _ = broker
        .keys
        .check_consume(&key.key_id, consumed_bytes as u32);

    topic
        .records_consumed_total
        .fetch_add(records.len() as u64, Ordering::Relaxed);
    topic
        .bytes_consumed_total
        .fetch_add(consumed_bytes, Ordering::Relaxed);

    Ok(Json(ConsumeResponse {
        records,
        next_offset,
        high_watermark,
    }))
}
