use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::broker::Broker;
use crate::partition::Partition;
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

async fn offload_victims(
    broker: &Arc<Broker>,
    topic_name: &str,
    partition_id: u32,
    victims: &[u64],
) {
    let store = match &broker.tiered_store {
        Some(s) => s.clone(),
        None => return,
    };
    for &base in victims {
        if let Some(topic) = broker.topic(topic_name) {
            if let Some(ph) = topic.partitions.get(partition_id as usize) {
                let inner = ph.inner();
                let snapshot = inner.segments_snapshot();
                if let Some(seg) = snapshot.iter().find(|s| s.base_offset == base) {
                    match store.offload(
                        topic_name,
                        partition_id,
                        base,
                        &seg.log_path,
                        &seg.index_path,
                    ) {
                        Ok(bytes) => {
                            tracing::info!(
                                topic = %topic_name,
                                partition = partition_id,
                                base_offset = base,
                                bytes,
                                "reaper: segment offloaded to cold storage"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                topic = %topic_name,
                                partition = partition_id,
                                base_offset = base,
                                error = %e,
                                "reaper: offload failed, segment will be deleted instead"
                            );
                        }
                    }
                }
            }
        }
    }
}

pub async fn run_pass(broker: &Arc<Broker>, grace: Duration, cancel: &CancellationToken) {
    let topic_names: Vec<String> = broker
        .topics
        .iter()
        .map(|kv| kv.key().clone())
        .collect();
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
            offload_victims(broker, &name, partition.id(), &victims).await;
            let victim_count = victims.len() as u64;
            match partition.drop_sealed_segments(&victims, grace, cancel).await {
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

fn plan_victims(partition: &Partition, config: &TopicConfig) -> Vec<u64> {
    let snapshot = partition.segments_snapshot();
    if snapshot.len() <= 1 {
        return Vec::new();
    }
    let active_base = snapshot.last().unwrap().base_offset;
    let sealed: Vec<_> = snapshot
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

    victims.sort_unstable();
    victims.dedup();
    victims
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
