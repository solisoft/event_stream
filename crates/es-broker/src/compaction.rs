use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::broker::Broker;
use crate::partition::Partition;
use crate::storage::index::SparseIndex;
use crate::storage::record::{Record, RecordDecodeError, encode_record, read_record};
use crate::storage::segment::{Segment, segment_index_name, segment_log_name};
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
        if !config.cleanup_policy.includes_compact() {
            continue;
        }
        for partition in &topic.partitions {
            if cancel.is_cancelled() {
                return;
            }
            match compact_partition(partition.inner(), &config, grace, cancel).await {
                Ok(Some(report)) => {
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
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(topic = %name, partition = partition.id(), error = %e, "compactor: pass failed");
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

async fn compact_partition(
    partition: &Partition,
    config: &TopicConfig,
    grace: Duration,
    cancel: &CancellationToken,
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

    // If there's only one sealed segment and the topic has no tombstone-aging
    // pressure (a freshly-compacted single segment), skip — nothing to merge.
    // We still proceed if there are tombstones eligible for expiry.
    let lowest_base = sealed[0].base_offset;
    let tombstone_cutoff = now_ms().saturating_sub(config.tombstone_retention_ms as i64);

    // Read every record from sealed segments into memory. The dedupe map keeps
    // the latest record per key by offset; keyless records are passed through.
    let mut latest: HashMap<Vec<u8>, Record> = HashMap::new();
    let mut keyless: Vec<Record> = Vec::new();
    let mut total_read: usize = 0;

    for seg in &sealed {
        let mut file = match File::open(&seg.log_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        loop {
            match read_record(&mut file) {
                Ok(r) => {
                    total_read += 1;
                    match &r.key {
                        Some(k) => {
                            // Replace if r.offset is higher than current.
                            match latest.get(k) {
                                Some(prev) if prev.offset > r.offset => {}
                                _ => {
                                    latest.insert(k.clone(), r);
                                }
                            }
                        }
                        None => keyless.push(r),
                    }
                }
                Err(RecordDecodeError::Eof) => break,
                Err(_) => break, // recovery-style stop on torn tail
            }
        }
    }

    // Build emit list.
    let mut emit: Vec<Record> = Vec::with_capacity(latest.len() + keyless.len());
    let mut dropped: usize = 0;
    for (_, r) in latest {
        let is_tombstone = r.value.is_empty();
        if is_tombstone && r.timestamp_ms < tombstone_cutoff {
            dropped += 1;
            continue;
        }
        emit.push(r);
    }
    emit.extend(keyless);

    // Early skip: if compaction wouldn't change anything (zero dropped, single
    // sealed segment), bail.
    if dropped == 0 && sealed.len() == 1 && emit.len() == total_read {
        return Ok(None);
    }

    emit.sort_by_key(|r| r.offset);

    // Write to tmp files.
    let tmp_log_name = format!("{:020}.compact.tmp.log", lowest_base);
    let tmp_idx_name = format!("{:020}.compact.tmp.index", lowest_base);
    let tmp_log_path = partition.dir.join(&tmp_log_name);
    let tmp_idx_path = partition.dir.join(&tmp_idx_name);

    let (new_size, new_index, new_min_ts, new_max_ts) =
        write_compacted_segment(&tmp_log_path, &tmp_idx_path, &emit, lowest_base)?;

    // Atomic swap under appender lock.
    let report = {
        let _guard = partition.appender.lock().await;
        let cur = partition.segments.load_full();
        // If a roll happened mid-compaction (a new segment got appended to the
        // sealed range), the active_base would have shifted but our sealed list
        // would not include any new sealed segments. Re-check.
        let cur_active = cur.last().unwrap().base_offset;
        if cur_active != active_base {
            let _ = fs::remove_file(&tmp_log_path);
            let _ = fs::remove_file(&tmp_idx_path);
            return Ok(None);
        }

        // Atomic rename of tmp files over <lowest_base>.{log,index}.
        let dst_log = partition.dir.join(segment_log_name(lowest_base));
        let dst_idx = partition.dir.join(segment_index_name(lowest_base));
        fs::rename(&tmp_log_path, &dst_log)?;
        fs::rename(&tmp_idx_path, &dst_idx)?;

        let new_seg = Arc::new(Segment::with_state(
            &partition.dir,
            lowest_base,
            new_size,
            SparseIndex::from_entries(new_index),
            new_min_ts,
            new_max_ts,
        ));

        // New snapshot: replace the sealed range with [new_seg], keep the active.
        let new_vec: Vec<Arc<Segment>> = vec![new_seg, cur.last().unwrap().clone()];
        partition.segments.store(Arc::new(new_vec));

        CompactionReport {
            records_kept: emit.len(),
            records_dropped: total_read - emit.len() + dropped,
            sealed_merged: sealed.len(),
        }
    };

    // Grace + unlink the other victim files (everything in sealed except lowest_base).
    tokio::select! {
        _ = cancel.cancelled() => return Ok(Some(report)),
        _ = tokio::time::sleep(grace) => {}
    }
    for s in &sealed {
        if s.base_offset == lowest_base {
            continue;
        }
        let _ = fs::remove_file(&s.log_path);
        let _ = fs::remove_file(&s.index_path);
    }

    Ok(Some(report))
}

#[allow(clippy::type_complexity)]
fn write_compacted_segment(
    log_path: &Path,
    index_path: &Path,
    records: &[Record],
    base_offset: u64,
) -> Result<(u64, Vec<(u64, u64)>, i64, i64)> {
    if records.is_empty() {
        // Edge case: nothing left after compaction (everything was a stale
        // tombstone). We still need a valid empty segment file.
        let _ = File::create(log_path)?;
        let _ = File::create(index_path)?;
        return Ok((0, Vec::new(), i64::MAX, i64::MIN));
    }

    // The first emitted record's offset must be >= base_offset (it's `lowest_base`).
    if records[0].offset < base_offset {
        return Err(anyhow!(
            "compaction emit has offset {} below base_offset {}",
            records[0].offset,
            base_offset
        ));
    }

    let log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(log_path)?;
    let mut log = BufWriter::new(log_file);

    let mut index_entries: Vec<(u64, u64)> = Vec::with_capacity(records.len());
    let mut size_bytes: u64 = 0;
    let mut min_ts: i64 = i64::MAX;
    let mut max_ts: i64 = i64::MIN;

    let mut buf = Vec::new();
    for r in records {
        buf.clear();
        encode_record(&mut buf, r.offset, r.timestamp_ms, r.key.as_deref(), &r.value);
        let file_pos = size_bytes;
        log.write_all(&buf)?;
        size_bytes += buf.len() as u64;
        index_entries.push((r.offset - base_offset, file_pos));
        if r.timestamp_ms < min_ts { min_ts = r.timestamp_ms; }
        if r.timestamp_ms > max_ts { max_ts = r.timestamp_ms; }
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

