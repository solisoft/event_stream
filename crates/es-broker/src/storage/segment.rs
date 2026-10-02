use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use super::index::{SparseIndex, INDEX_ENTRY_LEN, INDEX_INTERVAL_BYTES};
use super::record::{decode_record, peek_record_len, Record, RecordDecodeError};

pub fn segment_log_name(base_offset: u64) -> String {
    format!("{:020}.log", base_offset)
}

pub fn segment_index_name(base_offset: u64) -> String {
    format!("{:020}.index", base_offset)
}

/// Default read window for [`RecordCursor`]. One `pread` of this size covers
/// the gap between two sparse-index entries many times over.
pub const READ_WINDOW_BYTES: usize = 256 * 1024;

/// Positional read that tolerates a short read at end of file. Returns the
/// number of bytes read.
pub fn read_at(file: &File, buf: &mut [u8], pos: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        let mut done = 0usize;
        while done < buf.len() {
            match file.read_at(&mut buf[done..], pos + done as u64) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(done)
    }
    #[cfg(not(unix))]
    {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = file.try_clone()?;
        f.seek(SeekFrom::Start(pos))?;
        let mut done = 0usize;
        while done < buf.len() {
            match f.read(&mut buf[done..])? {
                0 => break,
                n => done += n,
            }
        }
        Ok(done)
    }
}

/// Sequential record reader over a byte range of a log file.
///
/// Reads in windows with `pread`, so walking a hundred records is one or two
/// syscalls rather than four per record, and no file cursor is shared between
/// readers. Records are decoded straight out of the window.
pub struct RecordCursor<'a> {
    file: &'a File,
    pos: u64,
    limit: u64,
    buf: Vec<u8>,
    buf_start: u64,
    window: usize,
}

impl<'a> RecordCursor<'a> {
    pub fn new(file: &'a File, start: u64, limit: u64, window: usize) -> Self {
        Self {
            file,
            pos: start,
            limit,
            buf: Vec::new(),
            buf_start: start,
            window: window.max(4096),
        }
    }

    /// File position of the next record.
    pub fn position(&self) -> u64 {
        self.pos
    }

    fn buffered(&self) -> &[u8] {
        let end = self.buf_start + self.buf.len() as u64;
        if self.pos < self.buf_start || self.pos >= end {
            return &[];
        }
        &self.buf[(self.pos - self.buf_start) as usize..]
    }

    fn refill(&mut self, at_least: usize) -> io::Result<()> {
        let remaining = self.limit.saturating_sub(self.pos) as usize;
        let want = at_least.max(self.window).min(remaining);
        self.buf.resize(want, 0);
        let n = read_at(self.file, &mut self.buf, self.pos)?;
        self.buf.truncate(n);
        self.buf_start = self.pos;
        Ok(())
    }

    /// The next record, or `None` once the cursor reaches its limit.
    ///
    /// A record that would extend past the limit is reported as `Truncated`:
    /// within a sealed segment that is corruption, at the tail of the active one
    /// it is a write in progress, and the caller knows which.
    pub fn next_record(&mut self) -> Result<Option<Record>, RecordDecodeError> {
        if self.pos >= self.limit {
            return Ok(None);
        }
        let mut refilled = false;
        loop {
            match decode_record(self.buffered(), self.pos) {
                Ok((rec, n)) => {
                    self.pos += n as u64;
                    return Ok(Some(rec));
                }
                Err(RecordDecodeError::Truncated { .. }) | Err(RecordDecodeError::Eof)
                    if !refilled =>
                {
                    let need = peek_record_len(self.buffered(), self.pos)?.unwrap_or(4);
                    if self.pos + need as u64 > self.limit {
                        return Err(RecordDecodeError::Truncated { at: self.pos });
                    }
                    self.refill(need)?;
                    refilled = true;
                }
                Err(RecordDecodeError::Eof) => {
                    return Err(RecordDecodeError::Truncated { at: self.pos })
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// One on-disk segment: a `.log` file and its sibling `.index` file.
///
/// A `Segment` holds its own read handle, opened when the segment is. Readers
/// use positional reads on it, so a segment that is renamed over or unlinked
/// (compaction, retention) keeps serving whoever still holds the old snapshot,
/// from the bytes that snapshot describes — never from a different file that
/// happens to have taken over the path.
///
/// `min/max_timestamp_ms` are populated by [`crate::storage::recover::recover_partition`]
/// on startup and CAS-updated by the partition on each new record. Values of
/// `i64::MAX` / `i64::MIN` mean "no records yet".
pub struct Segment {
    pub base_offset: u64,
    pub log_path: PathBuf,
    pub index_path: PathBuf,
    pub size_bytes: AtomicU64,
    pub index: RwLock<SparseIndex>,
    pub min_timestamp_ms: AtomicI64,
    pub max_timestamp_ms: AtomicI64,
    file: File,
}

impl Segment {
    /// Open the read side of an existing (possibly empty) segment.
    pub fn open(
        dir: &Path,
        base_offset: u64,
        size_bytes: u64,
        index: SparseIndex,
        min_timestamp_ms: i64,
        max_timestamp_ms: i64,
    ) -> io::Result<Self> {
        let log_path = dir.join(segment_log_name(base_offset));
        let file = File::open(&log_path)?;
        Ok(Self {
            base_offset,
            index_path: dir.join(segment_index_name(base_offset)),
            log_path,
            size_bytes: AtomicU64::new(size_bytes),
            index: RwLock::new(index),
            min_timestamp_ms: AtomicI64::new(min_timestamp_ms),
            max_timestamp_ms: AtomicI64::new(max_timestamp_ms),
            file,
        })
    }

    /// Open the read side of a segment that has no records yet.
    pub fn open_empty(dir: &Path, base_offset: u64) -> io::Result<Self> {
        Self::open(dir, base_offset, 0, SparseIndex::new(), i64::MAX, i64::MIN)
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    /// A cursor over this segment's records, from `start` to `limit` bytes.
    pub fn cursor(&self, start: u64, limit: u64, window: usize) -> RecordCursor<'_> {
        RecordCursor::new(&self.file, start, limit, window)
    }

    /// Update the timestamp range. Called from the appender for every new record.
    pub fn observe_timestamp(&self, ts: i64) {
        // Loose monotonicity: clocks can go backwards, but for retention purposes
        // we just want a rough min/max so we use Relaxed CAS loops.
        self.min_timestamp_ms.fetch_min(ts, Ordering::Relaxed);
        self.max_timestamp_ms.fetch_max(ts, Ordering::Relaxed);
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
            .unwrap_or_else(|e| e.into_inner())
            .floor(rel)
            .map(|(_, pos)| pos)
            .unwrap_or(0);

        // Don't read past the size known when we started — anything beyond may
        // be a partial write in progress.
        let size = self.size_bytes.load(Ordering::Acquire);
        if start_pos >= size {
            return Ok(Vec::new());
        }

        let window = max_bytes
            .saturating_add(INDEX_INTERVAL_BYTES as usize)
            .clamp(16 * 1024, READ_WINDOW_BYTES * 16);
        let mut cursor = self.cursor(start_pos, size, window);
        let mut out = Vec::with_capacity(max_records.min(256));
        let mut bytes = 0usize;
        loop {
            let r = match cursor.next_record() {
                Ok(Some(r)) => r,
                Ok(None) => break,
                Err(RecordDecodeError::Io(e)) => return Err(e),
                Err(e) => {
                    tracing::warn!(segment = ?self.log_path, error = %e, "unreadable record; stopping read");
                    break;
                }
            };
            if r.offset >= high_watermark {
                break;
            }
            if r.offset < target_offset {
                continue;
            }
            let approx_bytes =
                super::record::record_disk_size(r.key.as_ref().map(|k| k.len()), r.value.len());
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
/// appender mutex. The handles are `Arc`s so a group commit can `fsync` them
/// without holding that mutex.
pub struct SegmentAppender {
    pub base_offset: u64,
    pub log: Arc<File>,
    pub index: Arc<File>,
    pub size_bytes: u64,
    pub index_len: u64,
    /// File position of the newest index entry, `None` before the first.
    pub last_index_pos: Option<u64>,
}

impl SegmentAppender {
    pub fn create(dir: &Path, base_offset: u64) -> io::Result<Self> {
        let log_path = dir.join(segment_log_name(base_offset));
        let index_path = dir.join(segment_index_name(base_offset));
        let log = crate::fsutil::open_append_private(&log_path)?;
        let index = crate::fsutil::open_append_private(&index_path)?;
        let size_bytes = log.metadata()?.len();
        let index_len = index.metadata()?.len();
        Ok(Self {
            base_offset,
            log: Arc::new(log),
            index: Arc::new(index),
            size_bytes,
            index_len,
            last_index_pos: None,
        })
    }

    /// Open the appender on an existing segment, truncating both files to
    /// `truncate_log_to` / `truncate_index_to` bytes (used by recovery to drop
    /// a torn-write tail).
    pub fn open_existing(
        dir: &Path,
        base_offset: u64,
        truncate_log_to: u64,
        truncate_index_to: u64,
        last_index_pos: Option<u64>,
    ) -> io::Result<Self> {
        let log_path = dir.join(segment_log_name(base_offset));
        let index_path = dir.join(segment_index_name(base_offset));

        let log = crate::fsutil::open_append_private(&log_path)?;
        if log.metadata()?.len() != truncate_log_to {
            log.set_len(truncate_log_to)?;
        }
        let index = crate::fsutil::open_append_private(&index_path)?;
        if index.metadata()?.len() != truncate_index_to {
            index.set_len(truncate_index_to)?;
        }

        Ok(Self {
            base_offset,
            log: Arc::new(log),
            index: Arc::new(index),
            size_bytes: truncate_log_to,
            index_len: truncate_index_to,
            last_index_pos,
        })
    }

    /// Whether a record written at `file_pos` gets an index entry.
    pub fn wants_index_entry(&self, file_pos: u64) -> bool {
        match self.last_index_pos {
            None => true,
            Some(p) => file_pos >= p + INDEX_INTERVAL_BYTES,
        }
    }

    pub fn note_index_entry(&mut self, file_pos: u64) {
        self.last_index_pos = Some(file_pos);
    }

    /// Append a batch: log bytes, then the index entries describing them.
    ///
    /// On failure both files are cut back to where they were, so a short write
    /// (ENOSPC, EIO) never leaves torn bytes that later appends — the files are
    /// `O_APPEND` — would land after. Returns `Err((error, rolled_back))`;
    /// when `rolled_back` is false the files are in an unknown state and the
    /// partition must stop accepting writes.
    pub fn write_batch(
        &mut self,
        log_bytes: &[u8],
        index_bytes: &[u8],
    ) -> Result<(), (io::Error, bool)> {
        use std::io::Write;
        let (pre_log, pre_idx) = (self.size_bytes, self.index_len);
        let res = (&*self.log)
            .write_all(log_bytes)
            .and_then(|_| (&*self.index).write_all(index_bytes));
        if let Err(e) = res {
            let rolled = self.log.set_len(pre_log).is_ok() && self.index.set_len(pre_idx).is_ok();
            return Err((e, rolled));
        }
        self.size_bytes += log_bytes.len() as u64;
        self.index_len += index_bytes.len() as u64;
        Ok(())
    }

    /// fsync both files. Records are crash-safe after this returns.
    pub fn sync(&self) -> io::Result<()> {
        self.log.sync_data()?;
        self.index.sync_data()?;
        Ok(())
    }
}

/// Encode one index entry.
pub fn encode_index_entry(out: &mut Vec<u8>, relative_offset: u64, file_pos: u64) {
    out.reserve(INDEX_ENTRY_LEN);
    out.extend_from_slice(&relative_offset.to_be_bytes());
    out.extend_from_slice(&file_pos.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::record::encode_record;

    #[test]
    fn cursor_reads_across_windows_and_reports_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.log");
        let mut bytes = Vec::new();
        for i in 0..200u64 {
            encode_record(&mut bytes, i, 0, None, &[b'x'; 100]);
        }
        let good = bytes.len() as u64;
        bytes.extend_from_slice(&[0, 0, 0, 200, 1, 2]); // torn tail
        std::fs::write(&path, &bytes).unwrap();
        let f = File::open(&path).unwrap();
        // A window smaller than a record forces the refill path.
        let mut c = RecordCursor::new(&f, 0, bytes.len() as u64, 50);
        let mut n = 0u64;
        loop {
            match c.next_record() {
                Ok(Some(r)) => {
                    assert_eq!(r.offset, n);
                    n += 1;
                }
                Ok(None) => panic!("torn tail must not read as a clean end"),
                Err(RecordDecodeError::Truncated { at }) => {
                    assert_eq!(at, good);
                    break;
                }
                Err(e) => panic!("unexpected {e}"),
            }
        }
        assert_eq!(n, 200);
    }
}
