use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use super::index::{SparseIndex, INDEX_ENTRY_LEN, INDEX_INTERVAL_BYTES};
use super::record::RecordDecodeError;
use super::segment::{
    segment_index_name, segment_log_name, RecordCursor, Segment, SegmentAppender, READ_WINDOW_BYTES,
};

pub struct RecoveredPartition {
    pub segments: Vec<Arc<Segment>>,
    pub next_offset: u64,
    pub appender: SegmentAppender,
}

/// Name of the file a compaction writes before it starts replacing segments.
pub const COMPACTION_MARKER: &str = "compaction.marker";

/// What a compaction is about to do, written (durably) before the first rename
/// so a crash anywhere in the swap can be finished on the next boot instead of
/// leaving the compacted segment and the originals it replaced side by side.
#[derive(Debug, Serialize, Deserialize)]
pub struct CompactionMarker {
    /// The segment the compacted output replaces (and takes the name of).
    pub base: u64,
    /// The other sealed segments folded into it, deleted once it is in place.
    pub victims: Vec<u64>,
}

pub fn compaction_tmp_names(base: u64) -> (String, String) {
    (
        format!("{:020}.compact.tmp.log", base),
        format!("{:020}.compact.tmp.index", base),
    )
}

/// Scan a partition directory and bring it up to a consistent state:
///   * finish a compaction that was interrupted after it committed (marker)
///   * sweep leftover compaction-tmp files (interrupted before it committed)
///   * sealed segments: trust their index after a cheap consistency check,
///     scan fully only when the check fails
///   * the active (last) segment: always scanned; a torn tail is truncated
///   * a corrupt record inside a *sealed* segment makes the rest of that one
///     segment unreadable — it never deletes the segments after it
///   * if the directory has no segments at all, create one with `base_offset = 0`
pub fn recover_partition(dir: &Path) -> io::Result<RecoveredPartition> {
    crate::fsutil::create_dir_all_private(dir)?;
    finish_compaction(dir)?;
    sweep_compaction_tmp(dir)?;
    let mut base_offsets = collect_segment_base_offsets(dir)?;
    base_offsets.sort_unstable();

    if base_offsets.is_empty() {
        let appender = SegmentAppender::create(dir, 0)?;
        crate::fsutil::fsync_dir(dir)?;
        let seg = Arc::new(Segment::open_empty(dir, 0)?);
        return Ok(RecoveredPartition {
            segments: vec![seg],
            next_offset: 0,
            appender,
        });
    }

    let mut segments: Vec<Arc<Segment>> = Vec::with_capacity(base_offsets.len());
    let mut next_offset = base_offsets[0];
    let last = base_offsets.len() - 1;
    let mut active_index_len = 0u64;
    let mut active_last_index_pos = None;

    for (i, base_offset) in base_offsets.iter().copied().enumerate() {
        let log_path = dir.join(segment_log_name(base_offset));
        let index_path = dir.join(segment_index_name(base_offset));
        let is_active = i == last;

        let trusted = if is_active {
            None
        } else {
            scan_sealed_trusted(&log_path, &index_path, base_offset)
        };
        let scan = match trusted {
            Some(s) => s,
            None => scan_full(&log_path, base_offset)?,
        };

        if scan.damaged {
            if is_active {
                let log = fs::OpenOptions::new().write(true).open(&log_path)?;
                log.set_len(scan.valid_bytes)?;
                log.sync_all()?;
                warn!(
                    ?log_path,
                    truncated_at = scan.valid_bytes,
                    "truncated torn write tail during recovery"
                );
            } else {
                // Not a torn write: sealed segments were fsynced before the
                // next one was created. The file is left untouched as evidence;
                // only the readable prefix is served. Everything after it in
                // *this* segment is lost, and nothing else is.
                error!(
                    ?log_path,
                    readable_bytes = scan.valid_bytes,
                    "corrupt record inside a sealed segment: the rest of this segment is \
                     unreadable and will be skipped; newer segments are unaffected"
                );
            }
        }

        if !scan.index_trusted {
            let current = SparseIndex::load_from(&index_path).ok();
            if current.as_ref().map(|c| c.entries()) != Some(&scan.entries[..]) {
                SparseIndex::write_all_to(&index_path, &scan.entries)?;
            }
        }

        if is_active {
            active_index_len = (scan.entries.len() * INDEX_ENTRY_LEN) as u64;
            active_last_index_pos = scan.entries.last().map(|(_, p)| *p);
        }
        // A sealed segment whose tail is unreadable must not drag next_offset
        // backwards past segments that come after it.
        next_offset = next_offset.max(scan.next_offset);
        let seg = Arc::new(Segment::open(
            dir,
            base_offset,
            scan.valid_bytes,
            SparseIndex::from_entries(scan.entries),
            scan.min_ts,
            scan.max_ts,
        )?);
        segments.push(seg);
    }

    let active = segments.last().unwrap();
    let appender = SegmentAppender::open_existing(
        dir,
        active.base_offset,
        active.size_bytes.load(std::sync::atomic::Ordering::Acquire),
        active_index_len,
        active_last_index_pos,
    )?;

    info!(
        partition_dir = ?dir,
        next_offset,
        segments = segments.len(),
        "recovered partition"
    );

    Ok(RecoveredPartition {
        segments,
        next_offset,
        appender,
    })
}

/// Complete a compaction whose marker survived a crash.
///
/// The marker is only written once the compacted files are fsynced, so if the
/// temp files are still there they are whole; if they are gone, the rename
/// already happened. Either way the remaining steps are idempotent.
fn finish_compaction(dir: &Path) -> io::Result<()> {
    let marker_path = dir.join(COMPACTION_MARKER);
    let bytes = match fs::read(&marker_path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let marker: CompactionMarker = match serde_json::from_slice(&bytes) {
        Ok(m) => m,
        Err(e) => {
            // A marker that never finished being written belongs to a
            // compaction that never started its swap.
            warn!(?marker_path, error = %e, "discarding unreadable compaction marker");
            fs::remove_file(&marker_path)?;
            return crate::fsutil::fsync_dir(dir);
        }
    };
    let (tmp_log, tmp_idx) = compaction_tmp_names(marker.base);
    let tmp_log = dir.join(tmp_log);
    let tmp_idx = dir.join(tmp_idx);
    if tmp_log.exists() {
        fs::rename(&tmp_log, dir.join(segment_log_name(marker.base)))?;
    }
    if tmp_idx.exists() {
        fs::rename(&tmp_idx, dir.join(segment_index_name(marker.base)))?;
    }
    for v in &marker.victims {
        let _ = fs::remove_file(dir.join(segment_log_name(*v)));
        let _ = fs::remove_file(dir.join(segment_index_name(*v)));
    }
    crate::fsutil::fsync_dir(dir)?;
    fs::remove_file(&marker_path)?;
    crate::fsutil::fsync_dir(dir)?;
    warn!(partition_dir = ?dir, base = marker.base, "finished a compaction interrupted by a crash");
    Ok(())
}

fn sweep_compaction_tmp(dir: &Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        // `.compact.tmp.log` / `.compact.tmp.index` (any prefix).
        if name.contains(".compact.tmp.") {
            warn!(?path, "removing leftover compaction tmp file");
            let _ = fs::remove_file(&path);
        }
    }
    Ok(())
}

fn collect_segment_base_offsets(dir: &Path) -> io::Result<Vec<u64>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("log") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        // Defensive: skip any tmp leftovers that survived the sweep.
        if stem.contains('.') {
            continue;
        }
        if let Ok(n) = stem.parse::<u64>() {
            out.push(n);
        }
    }
    Ok(out)
}

struct SegmentScan {
    entries: Vec<(u64, u64)>,
    next_offset: u64,
    /// Bytes from the start of the file that hold whole, valid records.
    valid_bytes: u64,
    /// Whether anything past `valid_bytes` was found (torn tail or corruption).
    damaged: bool,
    /// Whether `entries` came from the on-disk index (no rewrite needed).
    index_trusted: bool,
    min_ts: i64,
    max_ts: i64,
}

/// Recover a sealed segment from its own index without reading every record.
///
/// Checks the index is well-formed and in bounds, then decodes the first
/// record and walks from the last index entry to end of file. Any surprise —
/// missing or torn index, a record that fails its CRC, bytes left over — returns
/// `None` and the caller falls back to a full scan.
///
/// Timestamps come from the first and last records only. Retention compares
/// the maximum against a cutoff, and appends stamp wall-clock time, so the
/// newest record's timestamp is the segment's maximum up to clock steps.
fn scan_sealed_trusted(log_path: &Path, index_path: &Path, base: u64) -> Option<SegmentScan> {
    let file = File::open(log_path).ok()?;
    let size = file.metadata().ok()?.len();
    let index = SparseIndex::load_from(index_path).ok()?;
    let entries = index.entries();
    if size == 0 {
        return entries.is_empty().then(|| SegmentScan {
            entries: Vec::new(),
            next_offset: base,
            valid_bytes: 0,
            damaged: false,
            index_trusted: true,
            min_ts: i64::MAX,
            max_ts: i64::MIN,
        });
    }
    let (first_rel, first_pos) = *entries.first()?;
    if first_pos != 0 {
        return None;
    }
    for w in entries.windows(2) {
        if w[1].0 <= w[0].0 || w[1].1 <= w[0].1 {
            return None;
        }
    }
    let (last_rel, last_pos) = *entries.last()?;
    if last_pos >= size {
        return None;
    }

    let mut c = RecordCursor::new(&file, 0, size, 4096);
    let first = c.next_record().ok()??;
    if first.offset.checked_sub(base)? != first_rel {
        return None;
    }

    let mut c = RecordCursor::new(&file, last_pos, size, READ_WINDOW_BYTES);
    let mut last = None;
    let mut first_in_tail = true;
    loop {
        match c.next_record() {
            Ok(Some(r)) => {
                if first_in_tail && r.offset.checked_sub(base)? != last_rel {
                    return None;
                }
                first_in_tail = false;
                last = Some(r);
            }
            Ok(None) => break,
            Err(_) => return None,
        }
    }
    let last = last?;
    if c.position() != size {
        return None;
    }
    Some(SegmentScan {
        // Indexes written before the index went sparse hold an entry per
        // record; thin them in memory so old segments stop costing 16 bytes
        // of RAM per record too. The file is left as it is.
        entries: thin_index(entries),
        next_offset: last.offset + 1,
        valid_bytes: size,
        damaged: false,
        index_trusted: true,
        min_ts: first.timestamp_ms.min(last.timestamp_ms),
        max_ts: first.timestamp_ms.max(last.timestamp_ms),
    })
}

fn thin_index(entries: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(entries.len().min(1024));
    for &(rel, pos) in entries {
        match out.last() {
            Some(&(_, p)) if pos < p + INDEX_INTERVAL_BYTES => {}
            _ => out.push((rel, pos)),
        }
    }
    out
}

fn scan_full(log_path: &PathBuf, base_offset: u64) -> io::Result<SegmentScan> {
    let file = match File::open(log_path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(SegmentScan {
                entries: Vec::new(),
                next_offset: base_offset,
                valid_bytes: 0,
                damaged: false,
                index_trusted: false,
                min_ts: i64::MAX,
                max_ts: i64::MIN,
            });
        }
        Err(e) => return Err(e),
    };
    let file_size = file.metadata()?.len();

    let mut entries = Vec::new();
    let mut next_offset = base_offset;
    let mut valid_bytes = 0u64;
    let mut damaged = false;
    let mut min_ts: i64 = i64::MAX;
    let mut max_ts: i64 = i64::MIN;
    let mut last_index_pos: Option<u64> = None;

    let mut c = RecordCursor::new(&file, 0, file_size, READ_WINDOW_BYTES);
    loop {
        let pos_before = c.position();
        match c.next_record() {
            Ok(Some(r)) => {
                let wants = match last_index_pos {
                    None => true,
                    Some(p) => pos_before >= p + INDEX_INTERVAL_BYTES,
                };
                if wants {
                    entries.push((r.offset.saturating_sub(base_offset), pos_before));
                    last_index_pos = Some(pos_before);
                }
                next_offset = r.offset + 1;
                valid_bytes = c.position();
                min_ts = min_ts.min(r.timestamp_ms);
                max_ts = max_ts.max(r.timestamp_ms);
            }
            Ok(None) => break,
            Err(RecordDecodeError::Io(e)) => return Err(e),
            Err(e) => {
                warn!(?log_path, error = %e, "torn or corrupt record during recovery");
                damaged = true;
                break;
            }
        }
    }

    Ok(SegmentScan {
        entries,
        next_offset,
        valid_bytes,
        damaged: damaged || valid_bytes != file_size,
        index_trusted: false,
        min_ts,
        max_ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::record::encode_record;

    fn write_segment(dir: &Path, base: u64, n: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        for i in 0..n {
            encode_record(&mut bytes, base + i, 1000 + i as i64, None, b"payload");
        }
        std::fs::write(dir.join(segment_log_name(base)), &bytes).unwrap();
        bytes
    }

    #[test]
    fn corruption_in_a_sealed_segment_keeps_newer_segments() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = write_segment(dir.path(), 0, 10);
        // Flip a byte in the middle of segment 0.
        let mid = first.len() / 2;
        first[mid] ^= 0xFF;
        std::fs::write(dir.path().join(segment_log_name(0)), &first).unwrap();
        write_segment(dir.path(), 10, 10);
        write_segment(dir.path(), 20, 5);

        let r = recover_partition(dir.path()).unwrap();
        assert_eq!(r.segments.len(), 3, "newer segments must survive");
        assert_eq!(r.next_offset, 25);
        assert!(dir.path().join(segment_log_name(10)).exists());
        assert!(dir.path().join(segment_log_name(20)).exists());
        // The damaged file is kept as evidence.
        assert_eq!(
            std::fs::metadata(dir.path().join(segment_log_name(0)))
                .unwrap()
                .len(),
            first.len() as u64
        );
    }

    #[test]
    fn sealed_segments_are_recovered_from_their_index_on_second_boot() {
        let dir = tempfile::tempdir().unwrap();
        write_segment(dir.path(), 0, 500);
        write_segment(dir.path(), 500, 3);
        // First boot builds the indexes.
        let r = recover_partition(dir.path()).unwrap();
        assert_eq!(r.next_offset, 503);
        drop(r);
        let idx = SparseIndex::load_from(&dir.path().join(segment_index_name(0))).unwrap();
        let scan = scan_sealed_trusted(
            &dir.path().join(segment_log_name(0)),
            &dir.path().join(segment_index_name(0)),
            0,
        )
        .expect("a clean sealed segment must be trusted");
        assert_eq!(scan.entries, idx.entries());
        assert_eq!(scan.next_offset, 500);
        assert!(idx.len() < 500, "index must be sparse, got {}", idx.len());
    }

    #[test]
    fn interrupted_compaction_is_finished_from_its_marker() {
        let dir = tempfile::tempdir().unwrap();
        write_segment(dir.path(), 0, 3);
        write_segment(dir.path(), 3, 3);
        write_segment(dir.path(), 6, 1);
        // Compacted output for [0, 6) is complete, marker written, crash
        // before the rename.
        let (tl, ti) = compaction_tmp_names(0);
        let mut bytes = Vec::new();
        encode_record(&mut bytes, 5, 0, None, b"kept");
        std::fs::write(dir.path().join(&tl), &bytes).unwrap();
        std::fs::write(dir.path().join(&ti), b"").unwrap();
        let marker = CompactionMarker {
            base: 0,
            victims: vec![3],
        };
        std::fs::write(
            dir.path().join(COMPACTION_MARKER),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();

        let r = recover_partition(dir.path()).unwrap();
        assert_eq!(r.segments.len(), 2);
        assert!(!dir.path().join(segment_log_name(3)).exists());
        assert!(!dir.path().join(COMPACTION_MARKER).exists());
        assert_eq!(r.next_offset, 7);
    }
}
