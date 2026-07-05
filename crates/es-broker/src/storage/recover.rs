use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::{info, warn};

use super::index::SparseIndex;
use super::record::{read_record, RecordDecodeError};
use super::segment::{Segment, SegmentAppender};

pub struct RecoveredPartition {
    pub segments: Vec<Arc<Segment>>,
    pub next_offset: u64,
    pub appender: SegmentAppender,
}

/// Scan a partition directory and bring it up to a consistent state:
///   * sweep leftover compaction-tmp files (interrupted compaction)
///   * parse all `<base>.log` files, sort by base offset
///   * fully scan each log; rebuild its `.index` from scratch
///   * on torn / corrupt records, truncate at the bad position and stop scanning
///     further segments — that segment becomes the active one
///   * if the directory has no segments at all, create one with `base_offset = 0`
///
/// Returns the recovered segment list, the next offset to assign on the next
/// append, and an open appender on the active (last) segment.
pub fn recover_partition(dir: &Path) -> io::Result<RecoveredPartition> {
    fs::create_dir_all(dir)?;
    sweep_compaction_tmp(dir)?;
    let mut base_offsets = collect_segment_base_offsets(dir)?;
    base_offsets.sort_unstable();

    if base_offsets.is_empty() {
        let appender = SegmentAppender::create(dir, 0)?;
        let seg = Arc::new(Segment::new(dir, 0));
        return Ok(RecoveredPartition {
            segments: vec![seg],
            next_offset: 0,
            appender,
        });
    }

    let mut segments: Vec<Arc<Segment>> = Vec::with_capacity(base_offsets.len());
    let mut next_offset = base_offsets[0];
    let mut active_idx = base_offsets.len() - 1;
    let mut active_truncate_log = u64::MAX;
    let mut active_truncate_index = u64::MAX;

    for (i, base_offset) in base_offsets.iter().copied().enumerate() {
        let log_path = dir.join(super::segment::segment_log_name(base_offset));
        let scan = scan_segment(&log_path, base_offset)?;

        let index_path = dir.join(super::segment::segment_index_name(base_offset));
        SparseIndex::write_all_to(&index_path, &scan.entries)?;

        let seg = Arc::new(Segment::with_state(
            dir,
            base_offset,
            scan.log_size_after_truncation,
            SparseIndex::from_entries(scan.entries.clone()),
            scan.min_ts,
            scan.max_ts,
        ));
        segments.push(seg);
        next_offset = scan.next_offset;

        if scan.truncated {
            let log = OpenOptions::new().write(true).open(&log_path)?;
            log.set_len(scan.log_size_after_truncation)?;
            warn!(
                ?log_path,
                truncated_at = scan.log_size_after_truncation,
                "truncated torn write tail during recovery"
            );
            active_idx = i;
            active_truncate_log = scan.log_size_after_truncation;
            active_truncate_index = (scan.entries.len() as u64) * 16;
            for newer in &base_offsets[i + 1..] {
                let p = dir.join(super::segment::segment_log_name(*newer));
                let _ = fs::remove_file(&p);
                let p = dir.join(super::segment::segment_index_name(*newer));
                let _ = fs::remove_file(&p);
            }
            segments.truncate(i + 1);
            break;
        }
    }

    let active_base = segments[active_idx].base_offset;
    let appender = if active_truncate_log == u64::MAX {
        SegmentAppender::open_existing(
            dir,
            active_base,
            segments[active_idx]
                .size_bytes
                .load(std::sync::atomic::Ordering::Acquire),
            (segments[active_idx]
                .index
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .len() as u64)
                * 16,
        )?
    } else {
        SegmentAppender::open_existing(
            dir,
            active_base,
            active_truncate_log,
            active_truncate_index,
        )?
    };

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
        if stem.contains(".") {
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
    log_size_after_truncation: u64,
    truncated: bool,
    min_ts: i64,
    max_ts: i64,
}

fn scan_segment(log_path: &PathBuf, base_offset: u64) -> io::Result<SegmentScan> {
    let mut file = match File::open(log_path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(SegmentScan {
                entries: Vec::new(),
                next_offset: base_offset,
                log_size_after_truncation: 0,
                truncated: false,
                min_ts: i64::MAX,
                max_ts: i64::MIN,
            });
        }
        Err(e) => return Err(e),
    };
    let file_size = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;

    let mut entries = Vec::new();
    let mut next_offset = base_offset;
    let mut last_good_pos = 0u64;
    let mut truncated = false;
    let mut min_ts: i64 = i64::MAX;
    let mut max_ts: i64 = i64::MIN;

    loop {
        let pos_before = file.stream_position()?;
        match read_record(&mut file) {
            Ok(r) => {
                let rel = r.offset.saturating_sub(base_offset);
                entries.push((rel, pos_before));
                next_offset = r.offset + 1;
                last_good_pos = file.stream_position()?;
                if r.timestamp_ms < min_ts {
                    min_ts = r.timestamp_ms;
                }
                if r.timestamp_ms > max_ts {
                    max_ts = r.timestamp_ms;
                }
            }
            Err(RecordDecodeError::Eof) => {
                if file_size > last_good_pos {
                    truncated = true;
                }
                break;
            }
            Err(RecordDecodeError::Truncated { at })
            | Err(RecordDecodeError::CrcMismatch { at, .. })
            | Err(RecordDecodeError::Invalid { at, .. }) => {
                warn!(?log_path, at, "torn or corrupt record during recovery");
                last_good_pos = at;
                truncated = true;
                break;
            }
            Err(RecordDecodeError::Io(e)) => return Err(e),
        }
    }

    Ok(SegmentScan {
        entries,
        next_offset,
        log_size_after_truncation: last_good_pos,
        truncated,
        min_ts,
        max_ts,
    })
}
