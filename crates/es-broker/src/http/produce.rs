use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};

use es_protocol::{ProduceRequest, ProduceResponse, ProduceResult};

use crate::auth::AclAction;
use crate::broker::Broker;
use crate::producers::DedupeOutcome;

use super::auth_ext::AuthedKey;
use super::error::{AppError, AppResult};

pub async fn produce(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(topic_name): Path<String>,
    Json(req): Json<ProduceRequest>,
) -> AppResult<Json<ProduceResponse>> {
    if !key.can(AclAction::Write, &topic_name) {
        return Err(AppError::forbidden(format!(
            "key '{}' does not have write access to topic '{}'",
            key.key_id, topic_name
        )));
    }

    let topic = broker
        .topic(&topic_name)
        .ok_or_else(|| AppError::not_found(format!("topic '{}' not found", topic_name)))?;

    let request_bytes: u64 = req
        .records
        .iter()
        .map(|r| r.key.as_ref().map(|k| k.len() as u64).unwrap_or(0) + r.value.len() as u64)
        .sum();
    if let Err(retry_after) = broker.keys.check_produce(&key.key_id, request_bytes as u32) {
        return Err(AppError::too_many_requests(format!(
            "produce rate limit exceeded; retry in {:.1}s",
            retry_after
        )));
    }

    // Idempotent path is opt-in via the request-level producer_id.
    let producer_id = req.producer_id.as_deref();
    if let Some(pid) = producer_id {
        broker
            .producers
            .check_admission(pid)
            .map_err(|e| AppError::bad_request(e.to_string()))?;
        for (idx, r) in req.records.iter().enumerate() {
            match r.sequence {
                None => {
                    return Err(AppError::bad_request(format!(
                        "record {} missing sequence (required when producer_id is set)",
                        idx
                    )));
                }
                Some(s) if s < 0 => {
                    return Err(AppError::bad_request(format!(
                        "record {} has negative sequence {}",
                        idx, s
                    )));
                }
                Some(_) => {}
            }
        }
    }

    let mut results = Vec::with_capacity(req.records.len());
    let mut total_bytes_appended: u64 = 0;
    let mut records_appended: u64 = 0;

    for r in req.records {
        let key_bytes: Option<Vec<u8>> = r.key.as_ref().map(|k| k.as_bytes().to_vec());
        let partition_id = topic.route(key_bytes.as_deref(), r.partition)?;

        if let Some(pid) = producer_id {
            let seq = r.sequence.unwrap();
            match broker
                .producers
                .check_and_advance(pid, &topic_name, partition_id, seq)
                .await
            {
                DedupeOutcome::Duplicate { prev_offset } => {
                    results.push(ProduceResult {
                        partition: partition_id,
                        offset: prev_offset,
                        duplicate: true,
                    });
                    continue;
                }
                DedupeOutcome::Accept => { /* fall through to append */ }
                DedupeOutcome::SequenceTooLow { last_seen } => {
                    return Err(AppError::bad_request(format!(
                        "producer '{}' partition {} sequence {} below last_seen {}",
                        pid, partition_id, seq, last_seen
                    )));
                }
                DedupeOutcome::Gap { expected, got } => {
                    return Err(AppError::bad_request(format!(
                        "producer '{}' partition {} sequence gap: expected {}, got {}",
                        pid, partition_id, expected, got
                    )));
                }
                DedupeOutcome::NeedsInit => {
                    return Err(AppError::bad_request(format!(
                        "producer '{}' state missing — start fresh sequence",
                        pid
                    )));
                }
            }
        }

        let partition = &topic.partitions[partition_id as usize];
        let value_bytes = r.value.as_bytes();
        let offset = partition.append(key_bytes.as_deref(), value_bytes).await?;
        if let Some(pid) = producer_id {
            broker
                .producers
                .record_offset(pid, &topic_name, partition_id, r.sequence.unwrap(), offset)
                .await;
        }
        total_bytes_appended +=
            key_bytes.as_ref().map(|k| k.len() as u64).unwrap_or(0) + value_bytes.len() as u64;
        records_appended += 1;
        results.push(ProduceResult {
            partition: partition_id,
            offset,
            duplicate: false,
        });
    }

    topic
        .records_produced_total
        .fetch_add(records_appended, Ordering::Relaxed);
    topic
        .bytes_produced_total
        .fetch_add(total_bytes_appended, Ordering::Relaxed);

    Ok(Json(ProduceResponse { results }))
}
