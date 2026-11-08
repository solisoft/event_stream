//! Produce and consume, shared by the HTTP and binary protocols.
//!
//! The two protocols used to carry their own copies of this logic, and the
//! copies drifted (the binary path's error strings, its unchecked `u32`
//! casts). Now each protocol only translates its request in and the result
//! out.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::auth::{AclAction, ApiKey};
use crate::broker::Broker;
use crate::partition::AppendRecord;
use crate::producers::{AdmitError, DedupeOutcome};
use crate::raft::NodeId;
use crate::raft_partition::{Leadership, NotLeader};
use crate::storage::record::Record;
use crate::topic::Topic;

/// Most records accepted in one produce request.
pub const MAX_RECORDS_PER_REQUEST: usize = 100_000;

/// How long a linearizable read waits for its leader to confirm leadership
/// and apply through the read index before it is refused as retryable. A
/// healthy cluster needs one heartbeat round trip; only a leader cut off from
/// its majority, or one just elected, gets near this.
pub const LINEARIZABLE_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// What a consume promises about freshness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadConsistency {
    /// Whatever this replica has applied — possibly behind the leader. The
    /// default, and the only behavior before 0.3.
    #[default]
    Local,
    /// Sees every write acknowledged before the read began. Served by the
    /// partition's leader only, after a read-index round.
    Linearizable,
}

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
    /// Not served now, but a retry may be: later, or at the broker the
    /// message names (a partition led elsewhere, an election in progress, a
    /// linearizable read sent to a follower, or one whose leader could not
    /// confirm its leadership in time).
    Unavailable(String),
    Internal(anyhow::Error),
}

impl std::fmt::Display for DataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forbidden(m) => write!(f, "forbidden: {m}"),
            Self::NotFound(m) => write!(f, "not found: {m}"),
            Self::BadRequest(m) => write!(f, "bad request: {m}"),
            Self::RateLimited(s) => write!(f, "rate limited: retry in {s:.1}s"),
            Self::Unavailable(m) => write!(f, "unavailable: {m}"),
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

/// Where a produce came from, for leader routing.
#[derive(Debug, Clone, Copy, Default)]
pub struct Origin<'a> {
    /// The caller's credential as it presented it, sent on with a produce
    /// forwarded to a partition's leader so the leader authenticates the
    /// caller itself. `None` when auth is disabled.
    pub credential: Option<&'a str>,
    /// A follower already forwarded this produce. It is written here or
    /// refused with "not leader", never forwarded a second time.
    pub forwarded: bool,
}

/// Write `records` to `topic_name` as `key`.
///
/// With `producer_id`, every record must carry a sequence; the whole request
/// is checked before anything is written, and the producer's lock is held
/// until the offsets are recorded and journaled.
///
/// On a Raft broker, records for a partition this broker does not lead are
/// forwarded to the leader (see [`crate::forward`]); the rest are written
/// here. The leader checks, dedupes and charges what it is sent, so the
/// idempotence and atomicity guarantees above hold per leader.
pub async fn produce(
    broker: &Arc<Broker>,
    key: &ApiKey,
    topic_name: &str,
    records: Vec<IncomingRecord>,
    producer_id: Option<&str>,
    origin: Origin<'_>,
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
    for (i, r) in records.iter().enumerate() {
        let n = record_bytes(r.key.as_deref(), &r.value);
        if n > max_record {
            return Err(DataError::BadRequest(format!(
                "record {} is {} bytes; the limit is {}",
                i, n, max_record
            )));
        }
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

    let mut leaders: BTreeMap<u32, Leadership> = BTreeMap::new();
    for p in &routed {
        if !leaders.contains_key(p) {
            leaders.insert(*p, topic.partitions[*p as usize].leadership().await);
        }
    }
    let remote: BTreeMap<u32, Option<NodeId>> = leaders
        .into_iter()
        .filter_map(|(p, l)| match l {
            Leadership::Local => None,
            Leadership::Remote(hint) => Some((p, hint)),
        })
        .collect();
    if remote.is_empty() {
        return write_local(broker, key, &topic, records, routed, producer_id).await;
    }

    // Some partition is led elsewhere. Every one of them must have a leader
    // this broker can forward to, or nothing is written.
    let forwarder = broker.forwarder.as_deref();
    for (&p, &hint) in &remote {
        let reachable = match (hint, forwarder) {
            (Some(l), Some(f)) => !origin.forwarded && f.address(l).is_some(),
            _ => false,
        };
        if !reachable {
            return Err(not_leader(broker, topic_name, p, hint, origin.forwarded));
        }
    }
    let forwarder = forwarder.expect("checked above");

    let mut local: (Vec<usize>, Vec<IncomingRecord>, Vec<u32>) = Default::default();
    let mut by_leader: BTreeMap<NodeId, (Vec<usize>, Vec<IncomingRecord>)> = BTreeMap::new();
    for (i, (mut r, p)) in records.into_iter().zip(routed).enumerate() {
        match remote.get(&p) {
            None => {
                local.0.push(i);
                local.1.push(r);
                local.2.push(p);
            }
            Some(hint) => {
                // Pinned, so the leader routes it exactly as this broker did.
                r.partition = Some(p);
                let slot = by_leader.entry(hint.expect("checked above")).or_default();
                slot.0.push(i);
                slot.1.push(r);
            }
        }
    }
    let total = local.0.len() + by_leader.values().map(|v| v.0.len()).sum::<usize>();
    tracing::debug!(
        topic = topic_name,
        local = local.0.len(),
        leaders = by_leader.len(),
        "produce: forwarding to partition leaders"
    );

    let (local_idx, local_records, local_routed) = local;
    let write_here = async {
        if local_records.is_empty() {
            return Ok(Vec::new());
        }
        write_local(
            broker,
            key,
            &topic,
            local_records,
            local_routed,
            producer_id,
        )
        .await
    };
    let forwards = by_leader
        .into_iter()
        .map(|(leader, (idx, recs))| async move {
            forwarder
                .produce(leader, topic_name, origin.credential, recs, producer_id)
                .await
                .map(|produced| (idx, produced))
        });
    let (here, there) = tokio::join!(write_here, futures::future::join_all(forwards));

    let mut results: Vec<Option<Produced>> = vec![None; total];
    for (i, p) in local_idx.into_iter().zip(here?) {
        results[i] = Some(p);
    }
    for part in there {
        let (idx, produced) = part?;
        for (i, p) in idx.into_iter().zip(produced) {
            results[i] = Some(p);
        }
    }
    Ok(results
        .into_iter()
        .map(|r| r.expect("every record answered"))
        .collect())
}

/// The retryable refusal for a partition this broker cannot write or forward.
fn not_leader(
    broker: &Broker,
    topic: &str,
    partition: u32,
    hint: Option<NodeId>,
    forwarded: bool,
) -> DataError {
    let hint = match hint {
        None => "no leader is known yet; an election may be in progress".to_string(),
        Some(l) => match broker.forwarder.as_deref().and_then(|f| f.address(l)) {
            Some(addr) => format!("node {l} at {addr}"),
            None => format!("node {l}"),
        },
    };
    let why = if forwarded {
        "; this produce was already forwarded once and is not forwarded again"
    } else {
        ""
    };
    DataError::Unavailable(format!(
        "not leader for '{topic}' partition {partition} (hint: {hint}){why}; retry"
    ))
}

/// A write that failed because leadership moved between the check and the
/// proposal is as retryable as one refused up front.
fn write_error(e: anyhow::Error) -> DataError {
    match e.downcast_ref::<NotLeader>() {
        Some(n) => DataError::Unavailable(format!("{n}; retry")),
        None => DataError::Internal(e),
    }
}

/// Write `records`, already validated and routed to partitions this broker
/// leads (or plain ones), charging the caller's produce quota for them.
async fn write_local(
    broker: &Arc<Broker>,
    key: &ApiKey,
    topic: &Arc<Topic>,
    records: Vec<IncomingRecord>,
    routed: Vec<u32>,
    producer_id: Option<&str>,
) -> Result<Vec<Produced>, DataError> {
    let topic_name = topic.name.as_str();
    let request_bytes: u64 = records
        .iter()
        .map(|r| record_bytes(r.key.as_deref(), &r.value))
        .sum();
    if let Err(retry_after) = broker.keys.check_produce(&key.key_id, request_bytes) {
        return Err(DataError::RateLimited(retry_after));
    }

    let mut results: Vec<Option<Produced>> = vec![None; records.len()];
    let mut guard = None;
    if let Some(pid) = producer_id {
        let g = broker
            .producers
            .admit(pid, &key.key_id, key.may_claim(pid))
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
    let written = futures::future::try_join_all(writes)
        .await
        .map_err(write_error)?;
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
/// broker's; the consume quota is reserved before the read and settled after.
/// A linearizable read first waits on the partition's read barrier.
#[allow(clippy::too_many_arguments)]
pub async fn consume(
    broker: &Arc<Broker>,
    key: &ApiKey,
    topic_name: &str,
    partition: u32,
    offset: u64,
    max_records: usize,
    max_bytes: usize,
    consistency: ReadConsistency,
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
    if consistency == ReadConsistency::Linearizable {
        // Before the quota is reserved: a read refused here costs nothing.
        part.read_barrier(LINEARIZABLE_READ_TIMEOUT)
            .await
            .map_err(|e| DataError::Unavailable(e.to_string()))?;
    }
    let max_records = max_records.clamp(1, broker.config.max_fetch_records);
    let max_bytes = max_bytes.clamp(1, broker.config.max_fetch_bytes);
    // Reserve the quota before reading and read no more than was reserved;
    // settle with the actual size after. The storage layer returns the first
    // record whatever its size, so a consumer progresses on a budget smaller
    // than a record — but only a read holding a full second of budget may
    // take such a record (and the debt it leaves). Any concurrent read would
    // otherwise hold a sliver of budget and return one whole record each.
    let reservation = broker
        .keys
        .reserve_consume(&key.key_id, max_bytes as u64)
        .map_err(DataError::RateLimited)?;
    let read_bytes = match reservation {
        Some(r) => max_bytes.min(usize::try_from(r.granted).unwrap_or(usize::MAX)),
        None => max_bytes,
    };
    let read = part.read_raw(offset, max_records, read_bytes).await;
    let mut consumed_bytes: u64 = match &read {
        Ok((records, _, _)) => records
            .iter()
            .map(|r| record_bytes(r.key.as_deref(), &r.value))
            .sum(),
        Err(_) => 0,
    };
    let overshoot = matches!(reservation, Some(r) if !r.whole && consumed_bytes > r.granted);
    if overshoot {
        consumed_bytes = 0;
    }
    if let Some(r) = reservation {
        broker
            .keys
            .settle_consume(&key.key_id, r.granted, consumed_bytes);
    }
    if overshoot {
        // A bucket not in debt is full again within a second.
        return Err(DataError::RateLimited(1.0));
    }
    let (records, next_offset, high_watermark) = read?;
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
