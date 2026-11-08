use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use es_protocol::{
    ListProducersResponse, ProducerPartitionStateDto, ProducerStateDto, ResetOffsetsRequest,
    ResetOffsetsResponse,
};

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
    let mut producers = broker.producers.list().await;
    // A Raft partition keeps its producers' windows itself, replicated; they
    // stand in for whatever this broker's registry remembers of it.
    for name in broker.list_topics() {
        let Some(topic) = broker.topic(&name) else {
            continue;
        };
        for part in &topic.partitions {
            let Some(rp) = part.as_raft() else {
                continue;
            };
            let id = rp.partition().id;
            for (producer_id, w) in rp.producer_windows() {
                let dto = ProducerPartitionStateDto {
                    topic: name.clone(),
                    partition: id,
                    last_seen_sequence: w.last_seen(),
                    last_offset: w.last_offset(),
                };
                let at = match producers.iter().position(|p| p.producer_id == producer_id) {
                    Some(i) => i,
                    None => {
                        producers.push(ProducerStateDto {
                            producer_id,
                            partitions: Vec::new(),
                        });
                        producers.len() - 1
                    }
                };
                let parts = &mut producers[at].partitions;
                parts.retain(|q| !(q.topic == name && q.partition == id));
                parts.push(dto);
            }
        }
    }
    producers.sort_by(|a, b| a.producer_id.cmp(&b.producer_id));
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
    let revoked = broker.producers.revoke(&producer_id).await;
    // On a Raft partition the producer's windows are replicated: forgetting
    // them is a write, made by the partition's leader. Partitions led
    // elsewhere are forgotten by sending the same call to their leaders.
    let mut forgotten = false;
    for name in broker.list_topics() {
        let Some(topic) = broker.topic(&name) else {
            continue;
        };
        for part in &topic.partitions {
            if let Some(rp) = part.as_raft() {
                forgotten |= rp.forget_producer(&producer_id).await?;
            }
        }
    }
    if !forgotten {
        revoked?;
    }
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
                .reset(group, &req.topic, pid, part.start_offset())
                .await;
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
