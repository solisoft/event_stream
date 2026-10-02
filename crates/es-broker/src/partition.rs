use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use arc_swap::ArcSwap;
use base64::Engine;
use tokio_util::sync::CancellationToken;

use crate::storage::record::{encode_record, record_disk_size, Record};
use crate::storage::recover::recover_partition;
use crate::storage::segment::{encode_index_entry, Segment, SegmentAppender};
use es_protocol::RecordDto;

/// One record to append.
///
/// `offset` is `None` for an ordinary append (the partition assigns the next
/// offset). Raft replicas pass the offset the leader assigned, so every replica
/// stores a record under the same offset no matter what it already holds; an
/// offset below the partition's end is taken as already applied and skipped.
#[derive(Debug, Clone)]
pub struct AppendRecord {
    pub key: Option<Vec<u8>>,
    pub value: Vec<u8>,
    pub timestamp_ms: Option<i64>,
    pub offset: Option<u64>,
}

impl AppendRecord {
    pub fn new(key: Option<Vec<u8>>, value: Vec<u8>) -> Self {
        Self {
            key,
            value,
            timestamp_ms: None,
            offset: None,
        }
    }
}

/// When an append is made durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// Follow the partition's `flush_every_records` policy.
    Policy,
    /// Never fsync here. Used by the Raft apply path: the Raft log already
    /// holds the record durably, and the partition is fsynced before any Raft
    /// snapshot lets that log be compacted.
    Deferred,
}

/// The newest write, for group commit: whoever fsyncs these handles makes
/// every write up to `seq` durable.
struct WriteMark {
    seq: u64,
    log: Arc<std::fs::File>,
    index: Arc<std::fs::File>,
}

/// Per-partition runtime state.
///
/// Invariant: the `segments` ArcSwap can be read at any time, but it is only
/// **written** while holding `appender`. The appender rolls under that lock,
/// and the reaper / compactor mutate the snapshot under the same lock. This
/// serializes every snapshot transition.
///
/// `appender` is a `std::sync::Mutex` on purpose: every critical section under
/// it is file I/O, and runs on a blocking thread (see `PartitionHandle`). The
/// tokio worker threads never wait on disk.
pub struct Partition {
    pub id: u32,
    pub dir: PathBuf,
    pub segment_bytes: AtomicU64,
    pub next_offset: AtomicU64,
    pub start_offset: AtomicU64,
    pub segments: ArcSwap<Vec<Arc<Segment>>>,
    appender: Mutex<SegmentAppender>,

    /// Cumulative counters used by the `/metrics` endpoint.
    pub retention_segments_deleted_total: AtomicU64,
    pub retention_bytes_reclaimed_total: AtomicU64,
    pub compaction_runs_total: AtomicU64,
    pub compaction_records_dropped_total: AtomicU64,

    /// `fsync` policy: sync the active segment once at least N records are
    /// unsynced. 1 means "before acknowledging every append".
    pub flush_every_records: AtomicU32,
    /// Records appended since the last fsync.
    unsynced: AtomicU32,

    write_seq: AtomicU64,
    latest: ArcSwap<WriteMark>,
    /// Highest `write_seq` known to be on disk.
    synced: Mutex<u64>,
    /// Set after an I/O failure the partition could not undo. Every later
    /// append is refused until a restart re-runs recovery.
    poisoned: AtomicBool,
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
        let latest = WriteMark {
            seq: 0,
            log: recovered.appender.log.clone(),
            index: recovered.appender.index.clone(),
        };
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
            unsynced: AtomicU32::new(0),
            write_seq: AtomicU64::new(0),
            latest: ArcSwap::from_pointee(latest),
            synced: Mutex::new(0),
            poisoned: AtomicBool::new(false),
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

    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// The writer lock. Held for snapshot transitions (roll, retention,
    /// compaction swap). Never held across an `.await`.
    pub fn lock_appender(&self) -> MutexGuard<'_, SegmentAppender> {
        self.appender.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn poison(&self, why: &dyn std::fmt::Display) {
        if !self.poisoned.swap(true, Ordering::AcqRel) {
            tracing::error!(
                partition = self.id,
                dir = ?self.dir,
                error = %why,
                "partition fenced after an I/O failure; restart the broker to recover it"
            );
        }
    }

    /// Append records, blocking. Returns the offset of each record, in order.
    ///
    /// All records destined for one segment go out in a single `write(2)`, and
    /// the batch costs at most one fsync — shared, through group commit, with
    /// every other append waiting on the same partition.
    pub fn append_batch(
        &self,
        records: &[AppendRecord],
        durability: Durability,
    ) -> Result<Vec<u64>> {
        if self.is_poisoned() {
            return Err(anyhow!(
                "partition {} is fenced after an I/O failure; restart the broker",
                self.id
            ));
        }
        let now = now_ms();
        let mut offsets = Vec::with_capacity(records.len());
        let (seq, mark_log, mark_index, wrote) = {
            let mut app = self.lock_appender();
            let segment_bytes = self.segment_bytes.load(Ordering::Acquire);
            let mut next = self.next_offset.load(Ordering::Acquire);
            let mut batch = PendingBatch::default();
            let mut fresh = 0usize;
            for r in records {
                let offset = match r.offset {
                    Some(o) if o < next => {
                        offsets.push(o);
                        continue;
                    }
                    Some(o) => o,
                    None => next,
                };
                let need = record_disk_size(r.key.as_ref().map(|k| k.len()), r.value.len()) as u64;
                let pending = app.size_bytes + batch.log.len() as u64;
                if pending > 0 && pending + need > segment_bytes {
                    self.commit_batch(&mut app, &mut batch)?;
                    self.roll(&mut app, offset)?;
                }
                let file_pos = app.size_bytes + batch.log.len() as u64;
                let ts = r.timestamp_ms.unwrap_or(now);
                encode_record(&mut batch.log, offset, ts, r.key.as_deref(), &r.value);
                let wants_entry = match batch.last_index_pos.or(app.last_index_pos) {
                    None => true,
                    Some(p) => file_pos >= p + crate::storage::index::INDEX_INTERVAL_BYTES,
                };
                if wants_entry {
                    let rel = offset - app.base_offset;
                    encode_index_entry(&mut batch.index, rel, file_pos);
                    batch.entries.push((rel, file_pos));
                    batch.last_index_pos = Some(file_pos);
                }
                batch.min_ts = batch.min_ts.min(ts);
                batch.max_ts = batch.max_ts.max(ts);
                batch.next = offset + 1;
                batch.count += 1;
                fresh += 1;
                offsets.push(offset);
                next = offset + 1;
            }
            let wrote = fresh > 0;
            self.commit_batch(&mut app, &mut batch)?;
            let mark = self.latest.load();
            (mark.seq, mark.log.clone(), mark.index.clone(), wrote)
        };

        if durability == Durability::Policy && wrote {
            let threshold = self.flush_every_records.load(Ordering::Relaxed).max(1);
            // At threshold 1 every acknowledgement promises durability, so ask
            // "is *my* write synced?" — which waits out an fsync another writer
            // has in progress — rather than reading the shared counter, which
            // that writer zeroes *before* its fsync completes.
            if threshold == 1 || self.unsynced.load(Ordering::Acquire) >= threshold {
                self.sync_upto(seq, mark_log, mark_index)?;
            }
        }
        Ok(offsets)
    }

    /// Write `batch` to the active segment and publish it to readers.
    fn commit_batch(&self, app: &mut SegmentAppender, batch: &mut PendingBatch) -> Result<()> {
        if batch.count == 0 {
            return Ok(());
        }
        if let Err((e, rolled_back)) = app.write_batch(&batch.log, &batch.index) {
            if !rolled_back {
                self.poison(&e);
            }
            return Err(anyhow!("append to partition {}: {}", self.id, e));
        }
        if batch.last_index_pos.is_some() {
            app.last_index_pos = batch.last_index_pos;
        }
        // Publish: segment size and index first, the high watermark last, so a
        // reader that sees the new watermark also sees the bytes behind it.
        let segs = self.segments.load();
        if let Some(active) = segs.last() {
            active.size_bytes.store(app.size_bytes, Ordering::Release);
            {
                let mut idx = active.index.write().unwrap_or_else(|e| e.into_inner());
                for (rel, pos) in &batch.entries {
                    idx.push(*rel, *pos);
                }
            }
            if batch.min_ts != i64::MAX {
                active.observe_timestamp(batch.min_ts);
                active.observe_timestamp(batch.max_ts);
            }
        }
        self.next_offset.store(batch.next, Ordering::Release);
        let seq = self.write_seq.fetch_add(1, Ordering::AcqRel) + 1;
        self.latest.store(Arc::new(WriteMark {
            seq,
            log: app.log.clone(),
            index: app.index.clone(),
        }));
        self.unsynced.fetch_add(batch.count, Ordering::AcqRel);
        *batch = PendingBatch::default();
        Ok(())
    }

    /// Seal the active segment and start a new one at `new_base`.
    fn roll(&self, app: &mut SegmentAppender, new_base: u64) -> Result<()> {
        if let Err(e) = app.sync() {
            self.poison(&e);
            return Err(anyhow!("sync sealed segment: {}", e));
        }
        let new_appender = SegmentAppender::create(&self.dir, new_base)?;
        crate::fsutil::fsync_dir(&self.dir)?;
        let new_seg = Arc::new(Segment::open_empty(&self.dir, new_base)?);
        *app = new_appender;
        let prev = self.segments.load_full();
        let mut next = (*prev).clone();
        next.push(new_seg);
        self.segments.store(Arc::new(next));
        Ok(())
    }

    /// Group commit: make every write up to `seq` durable.
    ///
    /// The first waiter in fsyncs the newest handles it can see, which covers
    /// every write that reached them before the fsync started; the waiters
    /// queued behind it then find their sequence already covered and return
    /// without a syscall.
    fn sync_upto(
        &self,
        seq: u64,
        log: Arc<std::fs::File>,
        index: Arc<std::fs::File>,
    ) -> Result<()> {
        let mut synced = self.synced.lock().unwrap_or_else(|e| e.into_inner());
        if *synced >= seq {
            return Ok(());
        }
        let mark = self.latest.load_full();
        let (target, log, index) = if Arc::ptr_eq(&mark.log, &log) {
            (mark.seq, mark.log.clone(), mark.index.clone())
        } else {
            (seq, log, index)
        };
        self.unsynced.store(0, Ordering::Release);
        if let Err(e) = log.sync_data().and_then(|_| index.sync_data()) {
            // After a failed fsync the kernel may have dropped the dirty pages:
            // nothing written since the last good fsync can be trusted.
            self.poison(&e);
            return Err(anyhow!("fsync partition {}: {}", self.id, e));
        }
        *synced = (*synced).max(target);
        Ok(())
    }

    /// Fsync whatever is unsynced. Used by the interval flusher, so that with
    /// `flush_every_records > 1` an idle partition does not keep acknowledged
    /// records in the page cache indefinitely.
    pub fn sync_pending(&self) -> Result<()> {
        if self.unsynced.load(Ordering::Acquire) == 0 {
            return Ok(());
        }
        self.sync_all()
    }

    /// Fsync the active segment unconditionally.
    pub fn sync_all(&self) -> Result<()> {
        let mark = self.latest.load_full();
        self.sync_upto(mark.seq.max(1), mark.log.clone(), mark.index.clone())
    }

    /// Move the end offset forward without writing, leaving a gap. Raft
    /// replicas use it when a snapshot covers offsets that no longer exist
    /// anywhere (retention removed them, or the entries carried no records).
    pub fn advance_to(&self, offset: u64) {
        let _app = self.lock_appender();
        self.next_offset.fetch_max(offset, Ordering::AcqRel);
    }

    /// Async single-record append. Runs on a blocking thread.
    pub async fn append(self: &Arc<Self>, key: Option<&[u8]>, value: &[u8]) -> Result<u64> {
        let rec = AppendRecord::new(key.map(|k| k.to_vec()), value.to_vec());
        let me = self.clone();
        let offsets = tokio::task::spawn_blocking(move || {
            me.append_batch(std::slice::from_ref(&rec), Durability::Policy)
        })
        .await
        .map_err(|e| anyhow!("append task failed: {}", e))??;
        Ok(offsets[0])
    }

    /// Index of the segment holding `target_offset` (the last one whose base
    /// is at or below it).
    fn segment_index_for(segs: &[Arc<Segment>], target_offset: u64) -> usize {
        segs.partition_point(|s| s.base_offset <= target_offset)
            .saturating_sub(1)
    }

    /// Read records preserving the original byte payloads. Blocking.
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
        // Clamp behind any retention deletion so a consumer whose committed
        // offset got reaped converges automatically.
        let start = self.start_offset.load(Ordering::Acquire);
        let target_offset = target_offset.max(start);

        let segs = self.segments.load();
        let mut idx = Self::segment_index_for(&segs, target_offset);
        let mut effective_next = target_offset;
        let mut out: Vec<Record> = Vec::new();
        // Walk forward across segments until one returns records. (Compacted
        // segments may be sparse; the floor segment can be empty post-target.)
        while idx < segs.len() {
            let records = segs[idx].read_from(target_offset, max_records, max_bytes, hwm)?;
            if records.is_empty() {
                // No records >= target in this segment. The next segment's
                // base_offset is the next reachable offset; report it so a
                // re-poll moves forward.
                match segs.get(idx + 1) {
                    Some(next_seg) => effective_next = next_seg.base_offset.max(effective_next),
                    // Nothing at or after the target below the watermark: the
                    // range is a gap (compaction, or offsets a Raft replica
                    // skipped). Hand back the watermark so the consumer moves on.
                    None => effective_next = effective_next.max(hwm),
                }
                idx += 1;
                continue;
            }
            // One segment per call keeps response sizes bounded.
            out = records;
            break;
        }
        let next_offset = out.last().map(|r| r.offset + 1).unwrap_or(effective_next);
        Ok((out, next_offset, hwm))
    }

    /// Read records as JSON DTOs. Blocking.
    ///
    /// Keys and values are text when they are valid UTF-8 and `base64` is
    /// false. With `base64`, every key and value is base64 — the only way a
    /// JSON client can read back bytes that are not UTF-8 (anything produced
    /// over the binary protocol) without them being silently replaced.
    pub fn read_records(
        &self,
        target_offset: u64,
        max_records: usize,
        max_bytes: usize,
        base64: bool,
    ) -> Result<(Vec<RecordDto>, u64, u64)> {
        let (records, next, hwm) = self.read_records_raw(target_offset, max_records, max_bytes)?;
        Ok((records_to_dtos(self.id, records, base64), next, hwm))
    }

    /// Drop sealed segments from the snapshot, wait `grace`, then unlink files.
    ///
    /// Readers that captured the old snapshot hold their own file handles, so
    /// unlinking cannot pull data out from under them; the grace period only
    /// keeps the files visible to operators for a moment.
    ///
    /// Returns bytes reclaimed.
    pub async fn drop_sealed_segments(
        self: &Arc<Self>,
        victim_bases: &[u64],
        grace: Duration,
        cancel: &CancellationToken,
    ) -> Result<u64> {
        // The appender lock can be held across a roll's fsync; wait for it on
        // a blocking thread, not a runtime worker.
        let me = self.clone();
        let victims = victim_bases.to_vec();
        let victim_paths = tokio::task::spawn_blocking(move || me.unlink_plan(&victims))
            .await
            .map_err(|e| anyhow!("retention task: {e}"))?;
        if victim_paths.is_empty() {
            return Ok(0);
        }

        // Grace period — bail cleanly on shutdown. Files stay on disk; the next
        // boot will retry deletion on the next reaper pass.
        tokio::select! {
            _ = cancel.cancelled() => return Ok(0),
            _ = tokio::time::sleep(grace) => {}
        }

        let me = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut reclaimed = 0u64;
            for (log_path, index_path, base) in &victim_paths {
                if let Ok(meta) = std::fs::metadata(log_path) {
                    reclaimed += meta.len();
                }
                let _ = std::fs::remove_file(log_path);
                let _ = std::fs::remove_file(index_path);
                tracing::info!(
                    partition = me.id,
                    base_offset = base,
                    "retention: segment files unlinked"
                );
            }
            let _ = crate::fsutil::fsync_dir(&me.dir);
            reclaimed
        })
        .await
        .map_err(|e| anyhow!("retention task: {e}"))
    }

    /// Take `victim_bases` out of the snapshot; return their file paths.
    fn unlink_plan(&self, victim_bases: &[u64]) -> Vec<(PathBuf, PathBuf, u64)> {
        use std::collections::HashSet;

        let victim_paths: Vec<(PathBuf, PathBuf, u64)>;
        {
            let _guard = self.lock_appender();
            let cur = self.segments.load_full();
            if cur.len() <= 1 {
                return Vec::new();
            }
            let active_base = cur.last().unwrap().base_offset;
            let victims: HashSet<u64> = victim_bases
                .iter()
                .copied()
                .filter(|b| *b < active_base)
                .collect();
            if victims.is_empty() {
                return Vec::new();
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

            let new_start = new_vec
                .first()
                .map(|s| s.base_offset)
                .unwrap_or(active_base);
            self.segments.store(Arc::new(new_vec));
            self.start_offset.store(new_start, Ordering::Release);

            victim_paths = paths;
            tracing::info!(
                partition = self.id,
                removed = victim_paths.len(),
                bytes_reclaimed = reclaimed,
                "retention: segments dropped from snapshot"
            );
        }
        victim_paths
    }
}

struct PendingBatch {
    log: Vec<u8>,
    index: Vec<u8>,
    entries: Vec<(u64, u64)>,
    last_index_pos: Option<u64>,
    min_ts: i64,
    max_ts: i64,
    next: u64,
    count: u32,
}

impl Default for PendingBatch {
    fn default() -> Self {
        Self {
            log: Vec::new(),
            index: Vec::new(),
            entries: Vec::new(),
            last_index_pos: None,
            min_ts: i64::MAX,
            max_ts: i64::MIN,
            next: 0,
            count: 0,
        }
    }
}

/// Convert stored records to JSON DTOs. See [`Partition::read_records`].
pub fn records_to_dtos(partition: u32, records: Vec<Record>, base64: bool) -> Vec<RecordDto> {
    records
        .into_iter()
        .map(|r| RecordDto {
            partition,
            offset: r.offset,
            timestamp_ms: r.timestamp_ms,
            key: r.key.map(|k| bytes_to_text(k, base64)),
            value: bytes_to_text(r.value, base64),
        })
        .collect()
}

fn bytes_to_text(b: Vec<u8>, base64: bool) -> String {
    if base64 {
        return base64::engine::general_purpose::STANDARD.encode(b);
    }
    // Valid UTF-8 (the common case) is reused without a copy.
    match String::from_utf8(b) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_append_assigns_contiguous_offsets_and_rolls() {
        let dir = tempfile::tempdir().unwrap();
        let p = Partition::open(dir.path().to_path_buf(), 0, 512, 1).unwrap();
        let recs: Vec<AppendRecord> = (0..50)
            .map(|i| AppendRecord::new(None, format!("value-{i}").into_bytes()))
            .collect();
        let offs = p.append_batch(&recs, Durability::Policy).unwrap();
        assert_eq!(offs, (0..50).collect::<Vec<u64>>());
        assert!(p.segment_count() > 1, "512-byte segments must roll");
        let (got, next, hwm) = p.read_records_raw(0, 1000, 1 << 20).unwrap();
        assert_eq!(hwm, 50);
        assert!(!got.is_empty());
        assert_eq!(got[0].value, b"value-0");
        assert_eq!(next, got.last().unwrap().offset + 1);
        // Reading from the middle crosses into the right segment.
        let (got, _, _) = p.read_records_raw(37, 1, 1 << 20).unwrap();
        assert_eq!(got[0].offset, 37);
    }

    #[test]
    fn explicit_offsets_skip_what_is_already_applied() {
        let dir = tempfile::tempdir().unwrap();
        let p = Partition::open(dir.path().to_path_buf(), 0, 1 << 20, 1).unwrap();
        let mk = |o: u64| AppendRecord {
            key: None,
            value: format!("v{o}").into_bytes(),
            timestamp_ms: Some(7),
            offset: Some(o),
        };
        assert_eq!(
            p.append_batch(&[mk(0), mk(1)], Durability::Deferred)
                .unwrap(),
            vec![0, 1]
        );
        // Re-applying 1 is a no-op; 5 leaves a gap.
        assert_eq!(
            p.append_batch(&[mk(1), mk(5)], Durability::Deferred)
                .unwrap(),
            vec![1, 5]
        );
        assert_eq!(p.end_offset(), 6);
        let (got, _, _) = p.read_records_raw(0, 10, 1 << 20).unwrap();
        let offs: Vec<u64> = got.iter().map(|r| r.offset).collect();
        assert_eq!(offs, vec![0, 1, 5]);
        assert_eq!(got[0].timestamp_ms, 7, "leader-assigned timestamp kept");
    }

    /// With fsync on every append, no append returns before a sync that
    /// started after its write has finished.
    #[test]
    fn concurrent_appends_each_wait_for_a_covering_sync() {
        let dir = tempfile::tempdir().unwrap();
        let p = Partition::open(dir.path().to_path_buf(), 0, 1 << 20, 1).unwrap();
        let mut hs = Vec::new();
        for t in 0..8u8 {
            let p = p.clone();
            hs.push(std::thread::spawn(move || {
                for _ in 0..200 {
                    p.append_batch(&[AppendRecord::new(None, vec![t])], Durability::Policy)
                        .unwrap();
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        let synced = *p.synced.lock().unwrap();
        assert_eq!(
            synced,
            p.write_seq.load(Ordering::Acquire),
            "every write was synced"
        );
        assert_eq!(p.end_offset(), 1600);
    }

    /// The interleaving that lost durability: another writer zeroes the
    /// unsynced counter, then this append must still sync rather than read
    /// the zero as "already durable".
    #[test]
    fn a_zeroed_counter_does_not_skip_the_sync() {
        let dir = tempfile::tempdir().unwrap();
        let p = Partition::open(dir.path().to_path_buf(), 0, 1 << 20, 1).unwrap();
        p.append_batch(
            &[AppendRecord::new(None, b"a".to_vec())],
            Durability::Deferred,
        )
        .unwrap();
        // Simulate the other writer's sync having reset the counter but not
        // yet covered our write.
        p.unsynced.store(0, Ordering::Release);
        p.append_batch(
            &[AppendRecord::new(None, b"b".to_vec())],
            Durability::Policy,
        )
        .unwrap();
        assert_eq!(
            *p.synced.lock().unwrap(),
            p.write_seq.load(Ordering::Acquire)
        );
    }

    #[test]
    fn records_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let p = Partition::open(dir.path().to_path_buf(), 0, 300, 1).unwrap();
            let recs: Vec<AppendRecord> = (0..40)
                .map(|i| AppendRecord::new(Some(vec![i as u8]), vec![b'x'; 20]))
                .collect();
            p.append_batch(&recs, Durability::Policy).unwrap();
        }
        let p = Partition::open(dir.path().to_path_buf(), 0, 300, 1).unwrap();
        assert_eq!(p.end_offset(), 40);
        let offs = p
            .append_batch(
                &[AppendRecord::new(None, b"z".to_vec())],
                Durability::Policy,
            )
            .unwrap();
        assert_eq!(offs, vec![40]);
    }
}
