//! Produce and consume, shared by the HTTP and binary protocols.
//!
//! The two protocols used to carry their own copies of this logic, and the
//! copies drifted (the binary path's error strings, its unchecked `u32`
//! casts). Now each protocol only translates its request in and the result
//! out.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::auth::{AclAction, ApiKey};
use crate::broker::Broker;
use crate::partition::AppendRecord;
use crate::producers::{AdmitError, DedupeOutcome};
use crate::storage::record::Record;
use crate::topic::Topic;

/// Most records accepted in one produce request.
pub const MAX_RECORDS_PER_REQUEST: usize = 100_000;

/// A record as a client submitted it.
#[derive(Debug, Clone)]
pub struct IncomingRecord {
    pub key: Option<Vec<u8>>,
    pub value: Vec<u8>,
    pub partition: Option<u32>,
    pub sequence: Option<i64>,
}

#[derive(Debug, Clone, Copy)]
pub struct Produced {
    pub partition: u32,
    pub offset: u64,
    pub duplicate: bool,
}

#[derive(Debug)]
pub enum DataError {
    Forbidden(String),
    NotFound(String),
    BadRequest(String),
    /// Retry after this many seconds.
    RateLimited(f64),
    Internal(anyhow::Error),
}

impl std::fmt::Display for DataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forbidden(m) => write!(f, "forbidden: {m}"),
            Self::NotFound(m) => write!(f, "not found: {m}"),
            Self::BadRequest(m) => write!(f, "bad request: {m}"),
            Self::RateLimited(s) => write!(f, "rate limited: retry in {s:.1}s"),
            Self::Internal(e) => write!(f, "internal error: {e}"),
        }
    }
}

impl From<anyhow::Error> for DataError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

fn record_bytes(key: Option<&[u8]>, value: &[u8]) -> u64 {
    key.map(|k| k.len() as u64).unwrap_or(0) + value.len() as u64
}

/// Write `records` to `topic_name` as `key`.
///
/// With `producer_id`, every record must carry a sequence; the whole request
/// is checked before anything is written, and the producer's lock is held
/// until the offsets are recorded and journaled.
pub async fn produce(
    broker: &Arc<Broker>,
    key: &ApiKey,
    topic_name: &str,
    records: Vec<IncomingRecord>,
    producer_id: Option<&str>,
) -> Result<Vec<Produced>, DataError> {
    if !key.can(AclAction::Write, topic_name) {
        return Err(DataError::Forbidden(format!(
            "key '{}' does not have write access to topic '{}'",
            key.key_id, topic_name
        )));
    }
    let topic = broker
        .topic(topic_name)
        .ok_or_else(|| DataError::NotFound(format!("topic '{}' not found", topic_name)))?;
    if records.is_empty() {
        return Ok(Vec::new());
    }
    if records.len() > MAX_RECORDS_PER_REQUEST {
        return Err(DataError::BadRequest(format!(
            "{} records in one request; the limit is {}",
            records.len(),
            MAX_RECORDS_PER_REQUEST
        )));
    }
    // One limit for both protocols, enforced before anything is stored: a
    // record larger than a consumer can be sent is a record nobody can read.
    let max_record = broker.config.max_record_bytes as u64;
    let mut request_bytes = 0u64;
    for (i, r) in records.iter().enumerate() {
        let n = record_bytes(r.key.as_deref(), &r.value);
        if n > max_record {
            return Err(DataError::BadRequest(format!(
                "record {} is {} bytes; the limit is {}",
                i, n, max_record
            )));
        }
        request_bytes += n;
    }
    if let Err(retry_after) = broker.keys.check_produce(&key.key_id, request_bytes) {
        return Err(DataError::RateLimited(retry_after));
    }
    if producer_id.is_some() {
        for (idx, r) in records.iter().enumerate() {
            match r.sequence {
                None => {
                    return Err(DataError::BadRequest(format!(
                        "record {} missing sequence (required when producer_id is set)",
                        idx
                    )))
                }
                Some(s) if s < 0 => {
                    return Err(DataError::BadRequest(format!(
                        "record {} has negative sequence {}",
                        idx, s
                    )))
                }
                Some(_) => {}
            }
        }
    }

    let mut routed = Vec::with_capacity(records.len());
    for r in &records {
        let p = topic
            .route(r.key.as_deref(), r.partition)
            .map_err(|e| DataError::BadRequest(e.to_string()))?;
        routed.push(p);
    }

    let mut results: Vec<Option<Produced>> = vec![None; records.len()];
    let mut guard = None;
    if let Some(pid) = producer_id {
        let g = broker
            .producers
            .admit(pid, &key.key_id)
            .await
            .map_err(|e| match e {
                AdmitError::Forbidden(m) => DataError::Forbidden(m),
                AdmitError::Invalid(m) | AdmitError::Limit(m) => DataError::BadRequest(m),
            })?;
        // Decide every record before writing any of them.
        let mut tentative: BTreeMap<u32, i64> = BTreeMap::new();
        for (i, r) in records.iter().enumerate() {
            let p = routed[i];
            let seq = r.sequence.unwrap_or_default();
            let outcome = match tentative.get(&p) {
                Some(prev) if seq == prev + 1 => DedupeOutcome::Accept,
                Some(prev) => {
                    return Err(DataError::BadRequest(format!(
                        "producer '{}' partition {}: sequences within one request must be \
                         consecutive (got {} after {})",
                        pid, p, seq, prev
                    )))
                }
                None => g.check(topic_name, p, seq),
            };
            match outcome {
                DedupeOutcome::Accept => {
                    tentative.insert(p, seq);
                }
                DedupeOutcome::Duplicate { prev_offset } => {
                    results[i] = Some(Produced {
                        partition: p,
                        offset: prev_offset,
                        duplicate: true,
                    });
                }
                DedupeOutcome::SequenceTooLow { last_seen } => {
                    return Err(DataError::BadRequest(format!(
                        "producer '{}' partition {} sequence {} below last_seen {}",
                        pid, p, seq, last_seen
                    )))
                }
                DedupeOutcome::Gap { expected, got } => {
                    return Err(DataError::BadRequest(format!(
                        "producer '{}' partition {} sequence gap: expected {}, got {}",
                        pid, p, expected, got
                    )))
                }
            }
        }
        guard = Some(g);
    }

    // Group what is to be written by partition, keeping order within each.
    let mut per_partition: BTreeMap<u32, (Vec<usize>, Vec<AppendRecord>)> = BTreeMap::new();
    let mut appended_bytes = 0u64;
    let mut sequences: Vec<Option<i64>> = Vec::with_capacity(records.len());
    for (i, r) in records.into_iter().enumerate() {
        sequences.push(r.sequence);
        if results[i].is_some() {
            continue;
        }
        appended_bytes += record_bytes(r.key.as_deref(), &r.value);
        let slot = per_partition.entry(routed[i]).or_default();
        slot.0.push(i);
        slot.1.push(AppendRecord::new(r.key, r.value));
    }

    // Partitions are independent: write them concurrently.
    let writes = per_partition.into_iter().map(|(p, (idxs, recs))| {
        let topic = topic.clone();
        async move {
            let offsets = topic.partitions[p as usize].append_batch(recs).await?;
            Ok::<_, anyhow::Error>((p, idxs, offsets))
        }
    });
    let written = futures::future::try_join_all(writes).await?;
    let mut records_appended = 0u64;
    let mut journal = Vec::new();
    for (p, idxs, offsets) in written {
        for (i, off) in idxs.into_iter().zip(offsets) {
            records_appended += 1;
            results[i] = Some(Produced {
                partition: p,
                offset: off,
                duplicate: false,
            });
            if let (Some(g), Some(seq)) = (guard.as_mut(), sequences[i]) {
                g.record(topic_name, p, seq, off);
                journal.push((topic_name.to_string(), p, seq, off));
            }
        }
    }
    if let (Some(pid), Some(_g)) = (producer_id, guard.as_ref()) {
        let producers = broker.producers.clone();
        let pid = pid.to_string();
        let owner = key.key_id.clone();
        tokio::task::spawn_blocking(move || producers.journal(&pid, &owner, &journal))
            .await
            .map_err(|e| anyhow::anyhow!("producer journal task: {e}"))??;
    }
    drop(guard);

    topic
        .records_produced_total
        .fetch_add(records_appended, Ordering::Relaxed);
    topic
        .bytes_produced_total
        .fetch_add(appended_bytes, Ordering::Relaxed);

    Ok(results
        .into_iter()
        .map(|r| r.expect("every record decided"))
        .collect())
}

/// What a consume returns.
pub struct Fetched {
    pub topic: Arc<Topic>,
    pub records: Vec<Record>,
    pub next_offset: u64,
    pub high_watermark: u64,
}

/// Read from `topic_name`/`partition` as `key`. Limits are clamped to the
/// broker's; the consume quota is checked before and charged after.
pub async fn consume(
    broker: &Arc<Broker>,
    key: &ApiKey,
    topic_name: &str,
    partition: u32,
    offset: u64,
    max_records: usize,
    max_bytes: usize,
) -> Result<Fetched, DataError> {
    if !key.can(AclAction::Read, topic_name) {
        return Err(DataError::Forbidden(format!(
            "key '{}' does not have read access to topic '{}'",
            key.key_id, topic_name
        )));
    }
    let topic = broker
        .topic(topic_name)
        .ok_or_else(|| DataError::NotFound(format!("topic '{}' not found", topic_name)))?;
    let part = topic
        .partitions
        .get(partition as usize)
        .ok_or_else(|| DataError::BadRequest(format!("partition {} out of range", partition)))?;
    if let Err(retry_after) = broker.keys.check_consume(&key.key_id) {
        return Err(DataError::RateLimited(retry_after));
    }
    let max_records = max_records.clamp(1, broker.config.max_fetch_records);
    let max_bytes = max_bytes.clamp(1, broker.config.max_fetch_bytes);
    let (records, next_offset, high_watermark) =
        part.read_raw(offset, max_records, max_bytes).await?;
    let consumed_bytes: u64 = records
        .iter()
        .map(|r| record_bytes(r.key.as_deref(), &r.value))
        .sum();
    broker.keys.charge_consume(&key.key_id, consumed_bytes);
    topic
        .records_consumed_total
        .fetch_add(records.len() as u64, Ordering::Relaxed);
    topic
        .bytes_consumed_total
        .fetch_add(consumed_bytes, Ordering::Relaxed);
    Ok(Fetched {
        topic,
        records,
        next_offset,
        high_watermark,
    })
}
