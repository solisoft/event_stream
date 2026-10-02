use std::collections::HashMap;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::broker::Broker;
use crate::partition::Partition;
use crate::storage::index::{SparseIndex, INDEX_INTERVAL_BYTES};
use crate::storage::record::{encode_record, Record, RecordDecodeError};
use crate::storage::recover::{compaction_tmp_names, CompactionMarker, COMPACTION_MARKER};
use crate::storage::segment::{segment_index_name, segment_log_name, Segment, READ_WINDOW_BYTES};
use crate::topic::TopicConfig;

pub fn spawn_compactor(
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
        tracing::info!("compactor: stopped");
    })
}

/// One compaction pass over every compacted topic.
///
/// `_grace` is kept for API compatibility: segments hold their own read handles,
/// so the files a compaction replaces can be unlinked at once — readers of the
/// old snapshot keep reading the old inodes — and there is no window in which
/// the compacted segment and the originals coexist on disk.
pub async fn run_pass(broker: &Arc<Broker>, _grace: Duration, cancel: &CancellationToken) {
    let topic_names: Vec<String> = broker.topics.iter().map(|kv| kv.key().clone()).collect();
    for name in topic_names {
        let topic = match broker.topic(&name) {
            Some(t) => t,
            None => continue,
        };
        let config = topic.resolved_config();
        if !config.cleanup_policy.includes_compact() {
            continue;
        }
        for partition in &topic.partitions {
            if cancel.is_cancelled() {
                return;
            }
            let p = partition.inner().clone();
            let cfg = (*config).clone();
            let res = tokio::task::spawn_blocking(move || compact_partition(&p, &cfg)).await;
            match res {
                Ok(Ok(Some(report))) => {
                    partition.compaction_runs().fetch_add(1, Ordering::Relaxed);
                    partition
                        .compaction_records_dropped()
                        .fetch_add(report.records_dropped as u64, Ordering::Relaxed);
                    tracing::info!(
                        topic = %name,
                        partition = partition.id(),
                        kept = report.records_kept,
                        dropped = report.records_dropped,
                        sealed_merged = report.sealed_merged,
                        "compactor: pass complete"
                    );
                }
                Ok(Ok(None)) => {}
                Ok(Err(e)) => {
                    tracing::warn!(topic = %name, partition = partition.id(), error = %e, "compactor: pass failed");
                }
                Err(e) => {
                    tracing::error!(topic = %name, partition = partition.id(), error = %e, "compactor: task panicked");
                }
            }
        }
    }
}

struct CompactionReport {
    records_kept: usize,
    records_dropped: usize,
    sealed_merged: usize,
}

/// What survives for one key: the offset of its newest record, and whether
/// that record is a tombstone old enough to drop.
struct Latest {
    offset: u64,
    drop: bool,
}

/// Iterate every record of a sealed segment, failing on anything unreadable.
///
/// Compaction deletes the originals once the output is in place, so a record it
/// could not read is a record it would destroy. An error aborts the pass; the
/// old code treated any error as "end of segment" and silently dropped the rest.
fn for_each_record(seg: &Segment, mut f: impl FnMut(Record) -> Result<()>) -> Result<()> {
    let size = seg.size_bytes.load(Ordering::Acquire);
    let mut c = seg.cursor(0, size, READ_WINDOW_BYTES);
    loop {
        match c.next_record() {
            Ok(Some(r)) => f(r)?,
            Ok(None) => return Ok(()),
            Err(RecordDecodeError::Eof) => return Ok(()),
            Err(e) => {
                return Err(anyhow!(
                    "segment {:?} unreadable at byte {}: {}",
                    seg.log_path,
                    c.position(),
                    e
                ))
            }
        }
    }
}

/// Compact the sealed segments of one partition. Blocking.
///
/// Two streaming passes: the first keeps only `key -> newest offset`, the
/// second copies the surviving records. Memory is proportional to the number of
/// distinct keys, not to the bytes in the partition.
fn compact_partition(
    partition: &Partition,
    config: &TopicConfig,
) -> Result<Option<CompactionReport>> {
    let snapshot = partition.segments_snapshot();
    if snapshot.len() < 2 {
        return Ok(None);
    }
    let active_base = snapshot.last().unwrap().base_offset;
    let sealed: Vec<Arc<Segment>> = snapshot
        .iter()
        .filter(|s| s.base_offset < active_base)
        .cloned()
        .collect();
    if sealed.is_empty() {
        return Ok(None);
    }
    let lowest_base = sealed[0].base_offset;
    let tombstone_cutoff = now_ms().saturating_sub(config.tombstone_retention_ms as i64);

    // Pass 1: newest offset per key.
    let mut latest: HashMap<Vec<u8>, Latest> = HashMap::new();
    let mut total_read = 0usize;
    let mut keyless = 0usize;
    for seg in &sealed {
        for_each_record(seg, |r| {
            total_read += 1;
            match r.key {
                None => keyless += 1,
                Some(k) => {
                    let drop = r.value.is_empty() && r.timestamp_ms < tombstone_cutoff;
                    match latest.get_mut(&k) {
                        Some(l) if l.offset > r.offset => {}
                        Some(l) => {
                            l.offset = r.offset;
                            l.drop = drop;
                        }
                        None => {
                            latest.insert(
                                k,
                                Latest {
                                    offset: r.offset,
                                    drop,
                                },
                            );
                        }
                    }
                }
            }
            Ok(())
        })?;
    }
    let kept = keyless + latest.values().filter(|l| !l.drop).count();
    let dropped = total_read - kept;
    if dropped == 0 {
        // Nothing to reclaim. Rewriting every sealed byte just to merge
        // segments would cost a full copy of the partition on every pass.
        return Ok(None);
    }

    // Pass 2: write the survivors, in offset order (segments are in order and
    // so are the records within them).
    let dir = &partition.dir;
    let (tmp_log_name, tmp_idx_name) = compaction_tmp_names(lowest_base);
    let tmp_log_path = dir.join(&tmp_log_name);
    let tmp_idx_path = dir.join(&tmp_idx_name);
    let written = write_survivors(&sealed, &latest, &tmp_log_path, &tmp_idx_path, lowest_base);
    let (new_size, new_index, new_min_ts, new_max_ts) = match written {
        Ok(v) => v,
        Err(e) => {
            let _ = fs::remove_file(&tmp_log_path);
            let _ = fs::remove_file(&tmp_idx_path);
            return Err(e);
        }
    };

    // Swap, under the appender lock so no roll or retention pass interleaves.
    let _guard = partition.lock_appender();
    let cur = partition.segments.load_full();
    let cur_active = cur.last().unwrap().base_offset;
    let cur_sealed: Vec<&Arc<Segment>> =
        cur.iter().filter(|s| s.base_offset < cur_active).collect();
    // The sealed set must be exactly the one that was read. A roll adds a
    // segment; retention removes one — and renaming the output over a segment
    // retention already dropped would hand its pending unlink our data.
    let unchanged = cur_active == active_base
        && cur_sealed.len() == sealed.len()
        && cur_sealed
            .iter()
            .zip(&sealed)
            .all(|(a, b)| Arc::ptr_eq(a, b));
    if !unchanged {
        let _ = fs::remove_file(&tmp_log_path);
        let _ = fs::remove_file(&tmp_idx_path);
        return Ok(None);
    }

    let victims: Vec<u64> = sealed
        .iter()
        .map(|s| s.base_offset)
        .filter(|b| *b != lowest_base)
        .collect();
    let marker = CompactionMarker {
        base: lowest_base,
        victims: victims.clone(),
    };
    crate::fsutil::write_atomic(&dir.join(COMPACTION_MARKER), &serde_json::to_vec(&marker)?)?;

    // From here a crash is finished by recovery from the marker.
    let dst_log = dir.join(segment_log_name(lowest_base));
    let dst_idx = dir.join(segment_index_name(lowest_base));
    fs::rename(&tmp_log_path, &dst_log)?;
    fs::rename(&tmp_idx_path, &dst_idx)?;
    for v in &victims {
        let _ = fs::remove_file(dir.join(segment_log_name(*v)));
        let _ = fs::remove_file(dir.join(segment_index_name(*v)));
    }
    crate::fsutil::fsync_dir(dir)?;

    let new_seg = Arc::new(Segment::open(
        dir,
        lowest_base,
        new_size,
        SparseIndex::from_entries(new_index),
        new_min_ts,
        new_max_ts,
    )?);
    let new_vec: Vec<Arc<Segment>> = vec![new_seg, cur.last().unwrap().clone()];
    partition.segments.store(Arc::new(new_vec));

    fs::remove_file(dir.join(COMPACTION_MARKER))?;
    crate::fsutil::fsync_dir(dir)?;

    Ok(Some(CompactionReport {
        records_kept: kept,
        records_dropped: dropped,
        sealed_merged: sealed.len(),
    }))
}

#[allow(clippy::type_complexity)]
fn write_survivors(
    sealed: &[Arc<Segment>],
    latest: &HashMap<Vec<u8>, Latest>,
    log_path: &Path,
    index_path: &Path,
    base_offset: u64,
) -> Result<(u64, Vec<(u64, u64)>, i64, i64)> {
    let mut log = BufWriter::with_capacity(1 << 20, crate::fsutil::create_private(log_path)?);
    let mut index_entries: Vec<(u64, u64)> = Vec::new();
    let mut size_bytes: u64 = 0;
    let mut last_indexed: Option<u64> = None;
    let mut min_ts: i64 = i64::MAX;
    let mut max_ts: i64 = i64::MIN;
    let mut buf = Vec::new();

    for seg in sealed {
        for_each_record(seg, |r| {
            let keep = match &r.key {
                None => true,
                Some(k) => latest
                    .get(k)
                    .map(|l| l.offset == r.offset && !l.drop)
                    .unwrap_or(false),
            };
            if !keep {
                return Ok(());
            }
            if r.offset < base_offset {
                return Err(anyhow!(
                    "compaction emit has offset {} below base_offset {}",
                    r.offset,
                    base_offset
                ));
            }
            buf.clear();
            encode_record(
                &mut buf,
                r.offset,
                r.timestamp_ms,
                r.key.as_deref(),
                &r.value,
            );
            let file_pos = size_bytes;
            log.write_all(&buf)?;
            size_bytes += buf.len() as u64;
            if last_indexed.is_none_or(|p| file_pos >= p + INDEX_INTERVAL_BYTES) {
                index_entries.push((r.offset - base_offset, file_pos));
                last_indexed = Some(file_pos);
            }
            min_ts = min_ts.min(r.timestamp_ms);
            max_ts = max_ts.max(r.timestamp_ms);
            Ok(())
        })?;
    }
    log.flush()?;
    log.get_ref().sync_all()?;
    SparseIndex::write_all_to(index_path, &index_entries)?;
    Ok((size_bytes, index_entries, min_ts, max_ts))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
