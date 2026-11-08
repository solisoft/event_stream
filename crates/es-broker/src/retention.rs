use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::broker::Broker;
use crate::partition::Partition;
use crate::storage::segment::Segment;
use crate::topic::TopicConfig;

pub fn spawn_reaper(
    broker: &Arc<Broker>,
    interval: Duration,
    grace: Duration,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    let weak = Arc::downgrade(broker);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(interval) => {}
            }
            let broker = match weak.upgrade() {
                Some(b) => b,
                None => break,
            };
            run_pass(&broker, grace, &cancel).await;
        }
        tracing::info!("reaper: stopped");
    })
}

/// Offload `victims` to cold storage when tiered storage is configured.
///
/// Returns the victims that may now be deleted. Without a cold store that is
/// all of them; with one, only those whose copy succeeded. A failed offload
/// used to fall through to deletion — tiered storage existed precisely so the
/// data would not be lost, and then it was.
///
/// A victim no longer in the partition's snapshot (compaction replaced it
/// while an earlier offload ran) is skipped: its path may now hold the merged
/// segment, and it will be planned afresh on the next pass.
async fn offload_victims(
    broker: &Arc<Broker>,
    partition: &Arc<Partition>,
    topic_name: &str,
    partition_id: u32,
    victims: Vec<Arc<Segment>>,
) -> Vec<Arc<Segment>> {
    let store = match &broker.tiered_store {
        Some(s) => s.clone(),
        None => return victims,
    };
    let mut deletable = Vec::with_capacity(victims.len());
    for seg in victims {
        if !partition
            .segments_snapshot()
            .iter()
            .any(|s| Arc::ptr_eq(s, &seg))
        {
            continue;
        }
        let base = seg.base_offset;
        let store = store.clone();
        let topic_owned = topic_name.to_string();
        let s = seg.clone();
        let res = tokio::task::spawn_blocking(move || {
            store.offload(&topic_owned, partition_id, base, &s.log_path, &s.index_path)
        })
        .await;
        match res {
            Ok(Ok(bytes)) => {
                tracing::info!(
                    topic = %topic_name,
                    partition = partition_id,
                    base_offset = base,
                    bytes,
                    "reaper: segment offloaded to cold storage"
                );
                deletable.push(seg);
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    topic = %topic_name,
                    partition = partition_id,
                    base_offset = base,
                    error = %e,
                    "reaper: offload failed; segment kept and retried on the next pass"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "reaper: offload task panicked; segment kept");
            }
        }
    }
    deletable
}

pub async fn run_pass(broker: &Arc<Broker>, grace: Duration, cancel: &CancellationToken) {
    let topic_names: Vec<String> = broker.topics.iter().map(|kv| kv.key().clone()).collect();
    for name in topic_names {
        let topic = match broker.topic(&name) {
            Some(t) => t,
            None => continue,
        };
        let config = topic.resolved_config();
        if !config.cleanup_policy.includes_delete() {
            continue;
        }
        if config.retention_ms.is_none() && config.retention_bytes.is_none() {
            continue;
        }
        for partition in &topic.partitions {
            if cancel.is_cancelled() {
                return;
            }
            let victims = plan_victims(partition.inner(), &config);
            if victims.is_empty() {
                continue;
            }
            // Offload to cold storage before deleting (if configured).
            let victims =
                offload_victims(broker, partition.inner(), &name, partition.id(), victims).await;
            if victims.is_empty() {
                continue;
            }
            let victim_count = victims.len() as u64;
            match partition
                .drop_sealed_segments(&victims, grace, cancel)
                .await
            {
                Err(e) => {
                    tracing::warn!(topic = %name, partition = partition.id(), error = %e, "reaper: drop failed");
                }
                Ok(reclaimed) => {
                    partition
                        .retention_segments_deleted()
                        .fetch_add(victim_count, Ordering::Relaxed);
                    partition
                        .retention_bytes_reclaimed()
                        .fetch_add(reclaimed, Ordering::Relaxed);
                    tracing::info!(
                        topic = %name,
                        partition = partition.id(),
                        victims = victim_count,
                        bytes_reclaimed = reclaimed,
                        "reaper: retention enforced"
                    );
                }
            }
        }
    }
}

/// The sealed segments retention would remove, oldest first.
///
/// The segments themselves are returned, not their base offsets, so the drop
/// can tell a planned segment from one compaction put in its place since.
fn plan_victims(partition: &Partition, config: &TopicConfig) -> Vec<Arc<Segment>> {
    let snapshot = partition.segments_snapshot();
    if snapshot.len() <= 1 {
        return Vec::new();
    }
    let active_base = snapshot.last().unwrap().base_offset;
    let sealed: Vec<&Arc<Segment>> = snapshot
        .iter()
        .filter(|s| s.base_offset < active_base)
        .collect();
    if sealed.is_empty() {
        return Vec::new();
    }

    let mut victims: Vec<u64> = Vec::new();
    let now = now_ms();

    // Time-based.
    if let Some(retention_ms) = config.retention_ms {
        let cutoff = now.saturating_sub(retention_ms as i64);
        for s in &sealed {
            let max_ts = s.max_timestamp_ms.load(Ordering::Acquire);
            // i64::MIN means "no records observed" — skip; the segment is effectively empty.
            if max_ts != i64::MIN && max_ts < cutoff {
                victims.push(s.base_offset);
            }
        }
    }

    // Size-based: walk oldest-first, mark until under budget.
    if let Some(retention_bytes) = config.retention_bytes {
        let total: u64 = snapshot
            .iter()
            .map(|s| s.size_bytes.load(Ordering::Acquire))
            .sum();
        if total > retention_bytes {
            let mut over = total - retention_bytes;
            for s in &sealed {
                if victims.contains(&s.base_offset) {
                    let sz = s.size_bytes.load(Ordering::Acquire);
                    over = over.saturating_sub(sz);
                    continue;
                }
                if over == 0 {
                    break;
                }
                let sz = s.size_bytes.load(Ordering::Acquire);
                victims.push(s.base_offset);
                over = over.saturating_sub(sz);
            }
        }
    }

    // `sealed` is in offset order with unique bases; keep that order.
    sealed
        .into_iter()
        .filter(|s| victims.contains(&s.base_offset))
        .cloned()
        .collect()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partition::{AppendRecord, Durability};
    use crate::storage::record::Record;
    use crate::topic::CleanupPolicy;

    /// Bonfire #708: the reaper plans, then awaits its offload; compaction
    /// merges the sealed segments into one that reuses the lowest victim's
    /// base offset; then the reaper drops its plan. Matching by base offset
    /// unlinked the compacted segment — every surviving record of the sealed
    /// range. Matching by identity leaves it alone.
    #[tokio::test]
    async fn a_segment_compaction_rebuilt_survives_a_stale_retention_plan() {
        let dir = tempfile::tempdir().unwrap();
        let p = Partition::open(dir.path().to_path_buf(), 0, 300, 1).unwrap();
        // Four keys rewritten many times: plenty of sealed segments, and most
        // records superseded so compaction has something to reclaim.
        let recs: Vec<AppendRecord> = (0..60u32)
            .map(|i| AppendRecord::new(Some(vec![(i % 4) as u8]), i.to_be_bytes().to_vec()))
            .collect();
        p.append_batch(&recs, Durability::Policy).unwrap();
        assert!(p.segment_count() > 3, "300-byte segments must roll");

        let config = TopicConfig {
            retention_ms: None,
            retention_bytes: Some(1),
            cleanup_policy: CleanupPolicy::CompactDelete,
            segment_bytes: 300,
            tombstone_retention_ms: 0,
        };

        // 1. Retention plans every sealed segment, segment 0 among them.
        let victims = plan_victims(&p, &config);
        assert!(victims.len() > 1);
        assert_eq!(victims[0].base_offset, 0);

        // 2. Compaction runs while the reaper is awaiting its offload.
        let compacted = crate::compaction::compact_partition(&p, &config).unwrap();
        assert!(
            compacted.is_some(),
            "compaction had superseded records to drop"
        );
        let compacted = p.segments_snapshot()[0].clone();
        assert_eq!(compacted.base_offset, 0, "merged segment reuses base 0");
        let (before, _, _) = p.read_records_raw(0, 1000, 1 << 20).unwrap();
        assert!(!before.is_empty());

        // 3. The reaper drops what it planned.
        let reclaimed = p
            .drop_sealed_segments(&victims, Duration::ZERO, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(reclaimed, 0, "nothing the plan named is still there");

        let snap = p.segments_snapshot();
        assert!(
            snap.iter().any(|s| Arc::ptr_eq(s, &compacted)),
            "the compacted segment is still in the snapshot"
        );
        assert!(compacted.log_path.exists(), "its file was not unlinked");
        assert_eq!(p.start_offset(), 0);
        let (after, _, _) = p.read_records_raw(0, 1000, 1 << 20).unwrap();
        let offs = |v: &[Record]| v.iter().map(|r| r.offset).collect::<Vec<_>>();
        assert_eq!(offs(&after), offs(&before), "no compacted record lost");

        // A fresh plan still enforces retention on the merged segment.
        let victims = plan_victims(&p, &config);
        assert!(victims.iter().any(|v| Arc::ptr_eq(v, &compacted)));
        let reclaimed = p
            .drop_sealed_segments(&victims, Duration::ZERO, &CancellationToken::new())
            .await
            .unwrap();
        assert!(reclaimed > 0);
        assert!(!compacted.log_path.exists());
    }
}
