use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use arc_swap::ArcSwap;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::storage::record::{Record, encode_record, record_disk_size};
use crate::storage::recover::recover_partition;
use crate::storage::segment::{Segment, SegmentAppender};
use es_protocol::RecordDto;

/// Per-partition runtime state.
///
/// Invariant: the `segments` ArcSwap can be read at any time, but it is only
/// **written** while holding `appender` (`tokio::sync::Mutex`). The appender
/// itself rolls under that lock, and the reaper / compactor mutate the snapshot
/// under the same lock. This serializes every snapshot transition.
pub struct Partition {
    pub id: u32,
    pub dir: PathBuf,
    pub segment_bytes: AtomicU64,
    pub next_offset: AtomicU64,
    pub start_offset: AtomicU64,
    pub segments: ArcSwap<Vec<Arc<Segment>>>,
    pub appender: Mutex<SegmentAppender>,

    /// Cumulative counters used by the `/metrics` endpoint.
    pub retention_segments_deleted_total: AtomicU64,
    pub retention_bytes_reclaimed_total: AtomicU64,
    pub compaction_runs_total: AtomicU64,
    pub compaction_records_dropped_total: AtomicU64,

    /// `fsync` policy: sync the active segment to disk every N appended records.
    /// 1 means "every record" (current behavior, safest).
    pub flush_every_records: AtomicU32,
    /// Count of records appended since the last fsync.
    pub flush_counter: AtomicU32,
}

impl Partition {
    pub fn open(
        dir: PathBuf,
        id: u32,
        segment_bytes: u64,
        flush_every_records: u32,
    ) -> Result<Arc<Self>> {
        let recovered = recover_partition(&dir)?;
        let start = recovered
            .segments
            .first()
            .map(|s| s.base_offset)
            .unwrap_or(0);
        Ok(Arc::new(Self {
            id,
            dir,
            segment_bytes: AtomicU64::new(segment_bytes),
            next_offset: AtomicU64::new(recovered.next_offset),
            start_offset: AtomicU64::new(start),
            segments: ArcSwap::from_pointee(recovered.segments),
            appender: Mutex::new(recovered.appender),
            retention_segments_deleted_total: AtomicU64::new(0),
            retention_bytes_reclaimed_total: AtomicU64::new(0),
            compaction_runs_total: AtomicU64::new(0),
            compaction_records_dropped_total: AtomicU64::new(0),
            flush_every_records: AtomicU32::new(flush_every_records.max(1)),
            flush_counter: AtomicU32::new(0),
        }))
    }

    pub fn start_offset(&self) -> u64 {
        self.start_offset.load(Ordering::Acquire)
    }

    pub fn end_offset(&self) -> u64 {
        self.next_offset.load(Ordering::Acquire)
    }

    pub fn segment_count(&self) -> u32 {
        self.segments.load().len() as u32
    }

    pub fn total_size_bytes(&self) -> u64 {
        self.segments
            .load()
            .iter()
            .map(|s| s.size_bytes.load(Ordering::Acquire))
            .sum()
    }

    pub fn segments_snapshot(&self) -> Arc<Vec<Arc<Segment>>> {
        self.segments.load_full()
    }

    pub async fn append(
        &self,
        key: Option<&[u8]>,
        value: &[u8],
    ) -> Result<u64> {
        let timestamp_ms = now_ms();
        let mut appender = self.appender.lock().await;
        let offset = self.next_offset.load(Ordering::Acquire);
        let needed = record_disk_size(key.map(|k| k.len()), value.len()) as u64;
        let segment_bytes = self.segment_bytes.load(Ordering::Acquire);

        if appender.size_bytes > 0 && appender.size_bytes + needed > segment_bytes {
            // Roll segment: flush old, create new, swap into snapshot.
            appender.flush()?;
            let new_base = offset;
            let new_appender = SegmentAppender::create(&self.dir, new_base)?;
            *appender = new_appender;
            let new_seg = Arc::new(Segment::new(&self.dir, new_base));
            let prev = self.segments.load_full();
            let mut next = (*prev).clone();
            next.push(new_seg);
            self.segments.store(Arc::new(next));
        }

        let mut buf = Vec::with_capacity(needed as usize);
        encode_record(&mut buf, offset, timestamp_ms, key, value);
        let file_pos = appender.append_bytes(&buf)?;
        let rel_offset = offset - appender.base_offset;
        appender.append_index_entry(rel_offset, file_pos)?;
        // Always make the record visible to readers via the OS page cache.
        appender.flush_buffers()?;
        // Optionally sync to disk every N records.
        let threshold = self.flush_every_records.load(Ordering::Relaxed).max(1);
        let count = self.flush_counter.fetch_add(1, Ordering::Relaxed) + 1;
        if count >= threshold {
            appender.sync()?;
            self.flush_counter.store(0, Ordering::Relaxed);
        }

        // Update the active segment's visible state.
        let segs = self.segments.load();
        if let Some(active) = segs.last() {
            active
                .size_bytes
                .store(appender.size_bytes, Ordering::Release);
            active.index.write().unwrap().push(offset - active.base_offset, file_pos);
            active.observe_timestamp(timestamp_ms);
        }

        self.next_offset.store(offset + 1, Ordering::Release);
        Ok(offset)
    }

    /// Read records preserving the original byte payloads. Used by the binary
    /// protocol where keys/values are kept as `Vec<u8>` rather than mangled
    /// through UTF-8.
    pub fn read_records_raw(
        &self,
        target_offset: u64,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<(Vec<Record>, u64, u64)> {
        let hwm = self.next_offset.load(Ordering::Acquire);
        if target_offset >= hwm || max_records == 0 {
            return Ok((Vec::new(), target_offset, hwm));
        }
        let start = self.start_offset.load(Ordering::Acquire);
        let target_offset = target_offset.max(start);

        let segs = self.segments.load();
        let mut start_idx = 0usize;
        for (i, s) in segs.iter().enumerate() {
            if s.base_offset <= target_offset {
                start_idx = i;
            } else {
                break;
            }
        }

        let mut idx = start_idx;
        let mut effective_next = target_offset;
        let mut out: Vec<Record> = Vec::new();
        while idx < segs.len() && out.len() < max_records {
            let remaining = max_records - out.len();
            let records = segs[idx].read_from(target_offset, remaining, max_bytes, hwm)?;
            if records.is_empty() {
                if let Some(next_seg) = segs.get(idx + 1) {
                    effective_next = next_seg.base_offset.max(effective_next);
                }
                idx += 1;
                continue;
            }
            out.extend(records);
            break;
        }
        let next_offset = out.last().map(|r| r.offset + 1).unwrap_or(effective_next);
        Ok((out, next_offset, hwm))
    }

    pub fn read_records(
        &self,
        target_offset: u64,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<(Vec<RecordDto>, u64, u64)> {
        let hwm = self.next_offset.load(Ordering::Acquire);
        let mut out: Vec<RecordDto> = Vec::new();
        if target_offset >= hwm || max_records == 0 {
            return Ok((out, target_offset, hwm));
        }

        // Clamp behind any retention deletion so a consumer whose committed
        // offset got reaped converges automatically.
        let start = self.start_offset.load(Ordering::Acquire);
        let target_offset = target_offset.max(start);

        let segs = self.segments.load();
        let mut start_idx = 0usize;
        for (i, s) in segs.iter().enumerate() {
            if s.base_offset <= target_offset {
                start_idx = i;
            } else {
                break;
            }
        }

        // Walk forward across segments until one returns records. (Compacted
        // segments may be sparse; the floor segment can be empty post-target.)
        let mut idx = start_idx;
        let mut effective_next = target_offset;
        while idx < segs.len() && out.len() < max_records {
            let remaining = max_records - out.len();
            let records = segs[idx].read_from(target_offset, remaining, max_bytes, hwm)?;
            if records.is_empty() {
                // No records >= target in this segment. The next segment's base_offset
                // is at least the next reachable offset; advance our reported
                // "next_offset" so a re-poll moves forward.
                if let Some(next_seg) = segs.get(idx + 1) {
                    effective_next = next_seg.base_offset.max(effective_next);
                }
                idx += 1;
                continue;
            }
            for r in records {
                out.push(RecordDto {
                    partition: self.id,
                    offset: r.offset,
                    timestamp_ms: r.timestamp_ms,
                    key: r.key.map(|k| String::from_utf8_lossy(&k).into_owned()),
                    value: String::from_utf8_lossy(&r.value).into_owned(),
                });
            }
            // One segment per call keeps response sizes bounded.
            break;
        }

        let next_offset = out
            .last()
            .map(|r| r.offset + 1)
            .unwrap_or(effective_next);
        Ok((out, next_offset, hwm))
    }

    /// Drop sealed segments from the snapshot, wait `grace`, then unlink files.
    ///
    /// Steps:
    ///   1. Acquire appender lock (serializes against the roll path).
    ///   2. Filter victims out of the snapshot, swap it in.
    ///   3. Update `start_offset` to the new oldest segment's base.
    ///   4. Release the lock so produce/consume unblock.
    ///   5. Sleep for `grace` (cancellable) so in-flight readers finish.
    ///   6. Unlink the victim files. Old `Arc<Segment>` instances kept by readers
    ///      still own a valid open File via the kernel's reference count.
    ///
    /// Returns bytes reclaimed.
    pub async fn drop_sealed_segments(
        &self,
        victim_bases: &[u64],
        grace: Duration,
        cancel: &CancellationToken,
    ) -> Result<u64> {
        use std::collections::HashSet;

        let victim_paths: Vec<(PathBuf, PathBuf, u64)>;
        {
            let _guard = self.appender.lock().await;
            let cur = self.segments.load_full();
            if cur.len() <= 1 {
                return Ok(0);
            }
            let active_base = cur.last().unwrap().base_offset;
            let victims: HashSet<u64> = victim_bases
                .iter()
                .copied()
                .filter(|b| *b < active_base)
                .collect();
            if victims.is_empty() {
                return Ok(0);
            }

            let mut reclaimed = 0u64;
            let mut paths = Vec::with_capacity(victims.len());
            let new_vec: Vec<Arc<Segment>> = cur
                .iter()
                .filter(|s| {
                    if victims.contains(&s.base_offset) {
                        reclaimed += s.size_bytes.load(Ordering::Acquire);
                        paths.push((s.log_path.clone(), s.index_path.clone(), s.base_offset));
                        false
                    } else {
                        true
                    }
                })
                .cloned()
                .collect();

            self.segments.store(Arc::new(new_vec));
            let new_start = self
                .segments
                .load()
                .first()
                .map(|s| s.base_offset)
                .unwrap_or(active_base);
            self.start_offset.store(new_start, Ordering::Release);

            victim_paths = paths;
            tracing::info!(
                partition = self.id,
                removed = victim_paths.len(),
                bytes_reclaimed = reclaimed,
                "retention: segments dropped from snapshot"
            );
        }

        // Grace period — bail cleanly on shutdown. Files stay on disk; the next
        // boot will retry deletion on the next reaper pass.
        tokio::select! {
            _ = cancel.cancelled() => return Ok(0),
            _ = tokio::time::sleep(grace) => {}
        }

        let mut reclaimed = 0u64;
        for (log_path, index_path, base) in &victim_paths {
            if let Ok(meta) = std::fs::metadata(log_path) {
                reclaimed += meta.len();
            }
            let _ = std::fs::remove_file(log_path);
            let _ = std::fs::remove_file(index_path);
            tracing::info!(
                partition = self.id,
                base_offset = base,
                "retention: segment files unlinked"
            );
        }
        Ok(reclaimed)
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

