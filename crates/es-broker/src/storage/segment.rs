use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::RwLock;

use super::index::SparseIndex;
use super::record::{Record, RecordDecodeError, read_record};

pub fn segment_log_name(base_offset: u64) -> String {
    format!("{:020}.log", base_offset)
}

pub fn segment_index_name(base_offset: u64) -> String {
    format!("{:020}.index", base_offset)
}

/// One on-disk segment: a `.log` file and its sibling `.index` file.
///
/// Multiple readers can use the same `Segment` concurrently (each opens its own
/// `File`). Writes go through [`SegmentAppender`], which is held by the partition
/// under a mutex.
///
/// `min/max_timestamp_ms` are populated by [`crate::storage::recover::recover_partition`]
/// on startup and CAS-updated by `Partition::append` on each new record. Values
/// of `i64::MAX` / `i64::MIN` mean "no records yet".
pub struct Segment {
    pub base_offset: u64,
    pub log_path: PathBuf,
    pub index_path: PathBuf,
    pub size_bytes: AtomicU64,
    pub index: RwLock<SparseIndex>,
    pub min_timestamp_ms: AtomicI64,
    pub max_timestamp_ms: AtomicI64,
}

impl Segment {
    pub fn new(dir: &Path, base_offset: u64) -> Self {
        Self {
            base_offset,
            log_path: dir.join(segment_log_name(base_offset)),
            index_path: dir.join(segment_index_name(base_offset)),
            size_bytes: AtomicU64::new(0),
            index: RwLock::new(SparseIndex::new()),
            min_timestamp_ms: AtomicI64::new(i64::MAX),
            max_timestamp_ms: AtomicI64::new(i64::MIN),
        }
    }

    pub fn with_state(
        dir: &Path,
        base_offset: u64,
        size_bytes: u64,
        index: SparseIndex,
        min_timestamp_ms: i64,
        max_timestamp_ms: i64,
    ) -> Self {
        Self {
            base_offset,
            log_path: dir.join(segment_log_name(base_offset)),
            index_path: dir.join(segment_index_name(base_offset)),
            size_bytes: AtomicU64::new(size_bytes),
            index: RwLock::new(index),
            min_timestamp_ms: AtomicI64::new(min_timestamp_ms),
            max_timestamp_ms: AtomicI64::new(max_timestamp_ms),
        }
    }

    /// Update the timestamp range. Called from the appender for every new record.
    pub fn observe_timestamp(&self, ts: i64) {
        // Loose monotonicity: clocks can go backwards, but for retention purposes
        // we just want a rough min/max so we use Relaxed CAS loops.
        let mut cur_min = self.min_timestamp_ms.load(Ordering::Relaxed);
        while ts < cur_min {
            match self.min_timestamp_ms.compare_exchange_weak(
                cur_min, ts, Ordering::Relaxed, Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => cur_min = actual,
            }
        }
        let mut cur_max = self.max_timestamp_ms.load(Ordering::Relaxed);
        while ts > cur_max {
            match self.max_timestamp_ms.compare_exchange_weak(
                cur_max, ts, Ordering::Relaxed, Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => cur_max = actual,
            }
        }
    }

    pub fn delete_files(&self) -> io::Result<()> {
        let _ = std::fs::remove_file(&self.log_path);
        let _ = std::fs::remove_file(&self.index_path);
        Ok(())
    }

    /// Read records starting at the *first record whose offset >= target_offset*.
    /// Stops when either `max_records` records have been collected, the next record
    /// would push the byte total above `max_bytes`, or the segment is exhausted.
    ///
    /// `high_watermark` is the global next_offset for the partition; records with
    /// offset >= high_watermark are not returned.
    ///
    /// If the underlying file has been unlinked (the reaper finished its grace
    /// period and removed it), returns an empty vec so the caller can advance
    /// to the next segment without erroring.
    pub fn read_from(
        &self,
        target_offset: u64,
        max_records: usize,
        max_bytes: usize,
        high_watermark: u64,
    ) -> io::Result<Vec<Record>> {
        if max_records == 0 || target_offset >= high_watermark {
            return Ok(Vec::new());
        }

        let rel = target_offset.saturating_sub(self.base_offset);
        let start_pos = self
            .index
            .read()
            .unwrap()
            .floor(rel)
            .map(|(_, pos)| pos)
            .unwrap_or(0);

        let size = self.size_bytes.load(Ordering::Acquire);
        if start_pos >= size {
            return Ok(Vec::new());
        }

        let mut file = match File::open(&self.log_path) {
            Ok(f) => f,
            // The segment was deleted between snapshot capture and read. Caller
            // will advance to the next segment.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        file.seek(SeekFrom::Start(start_pos))?;

        let mut out = Vec::with_capacity(max_records.min(64));
        let mut bytes = 0usize;
        loop {
            // Don't read past the size known when we started — anything beyond may
            // be a partial write in progress.
            if file.stream_position()? >= size {
                break;
            }
            let r = match read_record(&mut file) {
                Ok(r) => r,
                Err(RecordDecodeError::Eof) => break,
                Err(RecordDecodeError::Truncated { .. }) => break,
                Err(RecordDecodeError::CrcMismatch { .. }) => break,
                Err(RecordDecodeError::Invalid { .. }) => break,
                Err(RecordDecodeError::Io(e)) => return Err(e),
            };
            if r.offset >= high_watermark {
                break;
            }
            if r.offset < target_offset {
                continue;
            }
            let approx_bytes = 4 + 8 + 8 + 4 + r.key.as_ref().map(|k| k.len()).unwrap_or(0)
                + 4
                + r.value.len()
                + 4;
            if !out.is_empty() && bytes + approx_bytes > max_bytes {
                break;
            }
            bytes += approx_bytes;
            out.push(r);
            if out.len() >= max_records {
                break;
            }
        }
        Ok(out)
    }
}

/// Owns the writer-side file handles for the currently active segment.
///
/// Only one of these exists per partition; it lives inside the partition's
/// appender mutex.
pub struct SegmentAppender {
    pub base_offset: u64,
    pub log: BufWriter<File>,
    pub index: BufWriter<File>,
    pub size_bytes: u64,
}

impl SegmentAppender {
    pub fn create(dir: &Path, base_offset: u64) -> io::Result<Self> {
        let log_path = dir.join(segment_log_name(base_offset));
        let index_path = dir.join(segment_index_name(base_offset));
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        let index = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&index_path)?;
        let size_bytes = log.metadata()?.len();
        Ok(Self {
            base_offset,
            log: BufWriter::new(log),
            index: BufWriter::new(index),
            size_bytes,
        })
    }

    /// Open the appender on an existing segment, optionally truncating both files
    /// to `truncate_log_to` / `truncate_index_to` bytes (used by recovery to drop
    /// a torn-write tail).
    pub fn open_existing(
        dir: &Path,
        base_offset: u64,
        truncate_log_to: u64,
        truncate_index_to: u64,
    ) -> io::Result<Self> {
        let log_path = dir.join(segment_log_name(base_offset));
        let index_path = dir.join(segment_index_name(base_offset));

        let log = OpenOptions::new().read(true).write(true).open(&log_path)?;
        log.set_len(truncate_log_to)?;
        let mut log = log;
        log.seek(SeekFrom::End(0))?;

        let index = OpenOptions::new().read(true).write(true).open(&index_path)?;
        index.set_len(truncate_index_to)?;
        let mut index = index;
        index.seek(SeekFrom::End(0))?;

        Ok(Self {
            base_offset,
            log: BufWriter::new(log),
            index: BufWriter::new(index),
            size_bytes: truncate_log_to,
        })
    }

    pub fn append_bytes(&mut self, record_bytes: &[u8]) -> io::Result<u64> {
        let file_pos = self.size_bytes;
        self.log.write_all(record_bytes)?;
        self.size_bytes += record_bytes.len() as u64;
        Ok(file_pos)
    }

    pub fn append_index_entry(&mut self, relative_offset: u64, file_pos: u64) -> io::Result<()> {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&relative_offset.to_be_bytes());
        buf[8..16].copy_from_slice(&file_pos.to_be_bytes());
        self.index.write_all(&buf)
    }

    /// Push the Rust BufWriter contents into the OS page cache. Visible to
    /// readers immediately; not durable until [`Self::sync`].
    pub fn flush_buffers(&mut self) -> io::Result<()> {
        self.log.flush()?;
        self.index.flush()?;
        Ok(())
    }

    /// Flush buffers + fsync both files. Records are crash-safe after this returns.
    pub fn sync(&mut self) -> io::Result<()> {
        self.flush_buffers()?;
        self.log.get_ref().sync_data()?;
        self.index.get_ref().sync_data()?;
        Ok(())
    }

    /// Back-compat alias — equivalent to `sync()`. Older callers expect this.
    pub fn flush(&mut self) -> io::Result<()> {
        self.sync()
    }
}
