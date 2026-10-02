use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;

use es_protocol::ConsumeResponse;

use crate::auth::AclAction;
use crate::broker::Broker;
use crate::dataplane::{self, Fetched};
use crate::partition::records_to_dtos;

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
    /// `base64` to receive keys and values base64-encoded — the only way to
    /// read bytes that are not UTF-8 (e.g. produced over the binary protocol)
    /// without them being replaced.
    #[serde(default)]
    pub encoding: Option<String>,
}

fn default_max_records() -> usize {
    100
}
fn default_max_bytes() -> usize {
    1 << 20
}

fn wants_base64(encoding: Option<&str>) -> AppResult<bool> {
    match encoding {
        None | Some("utf8") | Some("utf-8") => Ok(false),
        Some("base64") => Ok(true),
        Some(other) => Err(AppError::bad_request(format!(
            "unknown encoding '{}' (use 'utf8' or 'base64')",
            other
        ))),
    }
}

fn respond(f: Fetched, partition: u32, base64: bool) -> Json<ConsumeResponse> {
    Json(ConsumeResponse {
        records: records_to_dtos(partition, f.records, base64),
        next_offset: f.next_offset,
        high_watermark: f.high_watermark,
        encoding: base64.then(|| "base64".to_string()),
    })
}

pub async fn consume(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(topic_name): Path<String>,
    Query(q): Query<ConsumeQuery>,
) -> AppResult<Json<ConsumeResponse>> {
    let base64 = wants_base64(q.encoding.as_deref())?;
    let f = dataplane::consume(
        &broker,
        &key,
        &topic_name,
        q.partition,
        q.offset,
        q.max_records,
        q.max_bytes,
    )
    .await?;
    Ok(respond(f, q.partition, base64))
}

#[derive(Debug, Deserialize)]
pub struct GroupConsumeQuery {
    pub topic: String,
    pub partition: u32,
    #[serde(default = "default_max_records")]
    pub max_records: usize,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
    #[serde(default)]
    pub encoding: Option<String>,
}

pub async fn group_consume(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(group): Path<String>,
    Query(q): Query<GroupConsumeQuery>,
) -> AppResult<Json<ConsumeResponse>> {
    let base64 = wants_base64(q.encoding.as_deref())?;
    if !key.can(AclAction::Read, &q.topic) {
        return Err(AppError::forbidden(format!(
            "key '{}' does not have read access to topic '{}'",
            key.key_id, q.topic
        )));
    }
    broker.groups.check_access(&group, &key).await?;
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
    let f = dataplane::consume(
        &broker,
        &key,
        &q.topic,
        q.partition,
        committed,
        q.max_records,
        q.max_bytes,
    )
    .await?;
    Ok(respond(f, q.partition, base64))
}
