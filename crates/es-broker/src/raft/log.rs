//! Raft log + persistent store.
//!
//! Log entries are stored in a `Vec` indexed from 1 (Raft convention; index 0
//! is the implicit "before any entries" sentinel — `last_log_index = 0` means
//! the log is empty, `last_log_term = 0` in that case).
//!
//! # On disk ([`FileStore`])
//!
//! * `<path>` — hard state, `{"current_term", "voted_for"}`, replaced atomically
//!   (unique temp file, fsync, rename, fsync of the directory). Rewritten only
//!   when the term or vote changes.
//! * `<stem>.log` — the entries, append-only: `len u32 | crc32 u32 | term u64 |
//!   index u64 | payload`. An append is one `write` and one `fdatasync` for the
//!   whole batch; a conflict truncates with `set_len`; a snapshot rewrites only
//!   the (short) suffix that survives it.
//! * `<stem>.snapshot.json` — the latest snapshot's metadata.
//!
//! The previous store kept everything in one JSON file and rewrote it, with the
//! payloads base64-encoded, on every single append: O(log length) bytes and an
//! fsync per record. A store in that format is migrated on first load.

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

use super::messages::{LogEntry, LogIndex, NodeId, Term};

/// In-memory log with optional snapshot-compacted prefix.
///
/// `base_index` and `base_term` describe the last entry whose payload is no
/// longer in memory (it was folded into a snapshot). Entries in `entries` all
/// have `index > base_index`. With no snapshot, base = 0 and indexing matches
/// the textbook Raft "index 1 is first entry."
#[derive(Debug, Default, Clone)]
pub struct Log {
    pub entries: Vec<LogEntry>,
    pub base_index: LogIndex,
    pub base_term: Term,
}

impl Log {
    pub fn last_index(&self) -> LogIndex {
        self.entries
            .last()
            .map(|e| e.index)
            .unwrap_or(self.base_index)
    }

    pub fn last_term(&self) -> Term {
        self.entries
            .last()
            .map(|e| e.term)
            .unwrap_or(self.base_term)
    }

    /// Term at `index`. `Some(0)` for index 0 (Raft sentinel). `None` if the
    /// entry has been compacted away or is past the tail.
    pub fn term_at(&self, index: LogIndex) -> Option<Term> {
        if index == 0 {
            return Some(0);
        }
        if index == self.base_index {
            return Some(self.base_term);
        }
        if index < self.base_index {
            return None; // compacted
        }
        let e = self.get(index)?;
        Some(e.term)
    }

    pub fn get(&self, index: LogIndex) -> Option<&LogEntry> {
        let first_idx = self.entries.first()?.index;
        if index < first_idx {
            return None;
        }
        self.entries.get((index - first_idx) as usize)
    }

    /// Entries in `[start, end_exclusive)`. Returns an empty Vec if the range
    /// is empty, falls fully below `base_index`, or sits past the tail.
    /// When the start clips into the compacted region, the slice begins at the
    /// first in-memory entry.
    pub fn slice(&self, start: LogIndex, end_exclusive: LogIndex) -> Vec<LogEntry> {
        if start == 0 || end_exclusive <= start || self.entries.is_empty() {
            return Vec::new();
        }
        let first_idx = self.entries[0].index;
        let start = start.max(first_idx);
        let end = end_exclusive.min(self.last_index() + 1);
        if end <= start {
            return Vec::new();
        }
        let s = (start - first_idx) as usize;
        let e = (end - first_idx) as usize;
        self.entries[s..e].to_vec()
    }

    /// Entries from `start`, at most `max_entries` of them and — beyond the
    /// first — no more than `max_bytes` of payload.
    pub fn slice_bounded(
        &self,
        start: LogIndex,
        max_entries: usize,
        max_bytes: usize,
    ) -> Vec<LogEntry> {
        if start == 0 || self.entries.is_empty() {
            return Vec::new();
        }
        let first_idx = self.entries[0].index;
        let start = start.max(first_idx);
        if start > self.last_index() {
            return Vec::new();
        }
        let s = (start - first_idx) as usize;
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for e in &self.entries[s..] {
            if !out.is_empty() && (out.len() >= max_entries || bytes + e.payload.len() > max_bytes)
            {
                break;
            }
            bytes += e.payload.len();
            out.push(e.clone());
        }
        out
    }

    #[allow(clippy::explicit_counter_loop)]
    pub fn append_assign_indices(&mut self, mut entries: Vec<LogEntry>) {
        let mut next = self.last_index() + 1;
        for e in &mut entries {
            e.index = next;
            next += 1;
        }
        self.entries.extend(entries);
    }

    pub fn truncate_from(&mut self, cut_index: LogIndex) {
        if cut_index <= self.base_index {
            self.entries.clear();
            return;
        }
        if self.entries.is_empty() {
            return;
        }
        let first_idx = self.entries[0].index;
        if cut_index <= first_idx {
            self.entries.clear();
            return;
        }
        let keep = (cut_index - first_idx) as usize;
        self.entries.truncate(keep);
    }

    /// Append entries starting at `start_index`, truncating any conflicting
    /// suffix. `committed` is the highest index known to be committed; a
    /// conflict at or below it is refused (returns `Err(())` without mutating
    /// the log) so already-committed history can never be overwritten — a
    /// legitimate leader never conflicts below the commit point, so this only
    /// rejects forged/buggy appends.
    ///
    /// On success returns the first index whose entry changed, if any: the
    /// log from there on must be rewritten on disk.
    #[allow(clippy::explicit_counter_loop, clippy::result_unit_err)]
    pub fn append_at(
        &mut self,
        start_index: LogIndex,
        mut new_entries: Vec<LogEntry>,
        committed: LogIndex,
    ) -> Result<Option<LogIndex>, ()> {
        let mut idx = start_index;
        let mut skip = 0usize;
        while skip < new_entries.len() {
            // Entries folded into a snapshot are committed, hence identical.
            if idx <= self.base_index {
                skip += 1;
                idx += 1;
                continue;
            }
            match self.term_at(idx) {
                Some(t) if t == new_entries[skip].term => {
                    skip += 1;
                    idx += 1;
                }
                Some(_) => {
                    if idx <= committed {
                        // Refuse to truncate committed entries.
                        return Err(());
                    }
                    self.truncate_from(idx);
                    break;
                }
                None => break,
            }
        }
        if skip == new_entries.len() {
            return Ok(None);
        }
        let to_append = new_entries.split_off(skip);
        let first_changed = self.last_index() + 1;
        let mut next = first_changed;
        let mut out = Vec::with_capacity(to_append.len());
        for mut e in to_append {
            e.index = next;
            out.push(e);
            next += 1;
        }
        self.entries.extend(out);
        Ok(Some(first_changed))
    }

    /// Drop every entry with `index <= cut_index`. `cut_term` becomes the new
    /// `base_term`. Safe to call repeatedly; idempotent if `cut_index` is
    /// already ≤ `base_index`. For the node's *own* snapshot: everything up to
    /// `cut_index` is committed, so the suffix is kept unconditionally.
    pub fn compact_through(&mut self, cut_index: LogIndex, cut_term: Term) {
        if cut_index <= self.base_index {
            return;
        }
        let drop_count = if let Some(first) = self.entries.first() {
            (cut_index.saturating_add(1).saturating_sub(first.index) as usize)
                .min(self.entries.len())
        } else {
            0
        };
        self.entries.drain(..drop_count);
        self.base_index = cut_index;
        self.base_term = cut_term;
    }

    /// Install a snapshot received from a leader (§7): if this log has the
    /// snapshot's last entry with the same term, the entries after it are
    /// kept; otherwise the whole log is discarded, because what follows a
    /// mismatched entry may conflict with the leader's history.
    ///
    /// Returns whether the suffix was kept.
    pub fn install_snapshot(&mut self, last_index: LogIndex, last_term: Term) -> bool {
        let keep = self.term_at(last_index) == Some(last_term) && last_index >= self.base_index;
        if keep {
            self.compact_through(last_index, last_term);
        } else {
            self.entries.clear();
            self.base_index = last_index;
            self.base_term = last_term;
        }
        keep
    }
}

/// A durable change to the Raft state, recorded by the pure state machine and
/// applied by the store before any message that depends on it is sent.
#[derive(Debug, Clone)]
pub enum PersistOp {
    HardState {
        term: Term,
        voted_for: Option<NodeId>,
    },
    /// Contiguous entries, directly after the current last one.
    Append(Vec<LogEntry>),
    /// Drop entries with `index >= from` (all of them for `from <= 1`).
    TruncateFrom(LogIndex),
    /// Drop entries with `index <= through`.
    CompactThrough(LogIndex),
}

/// Persistent metadata + log. Every op must be durable when `persist` returns —
/// Raft's election safety depends on it.
///
/// `save_snapshot` and `load_snapshot` are independent of the log: the caller
/// saves a snapshot *before* persisting the compaction it allows.
pub trait RaftStore: Send + Sync {
    fn load(&self) -> Result<PersistedRaft>;
    fn persist(&self, ops: &[PersistOp]) -> Result<()>;
    fn load_snapshot(&self) -> Result<Option<PersistedSnapshot>>;
    fn save_snapshot(&self, snap: &PersistedSnapshot) -> Result<()>;

    /// Replace everything with `snap`.
    fn save_all(&self, snap: &PersistedRaft) -> Result<()> {
        self.persist(&[
            PersistOp::HardState {
                term: snap.current_term,
                voted_for: snap.voted_for,
            },
            PersistOp::TruncateFrom(0),
            PersistOp::Append(snap.log.clone()),
        ])
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedSnapshot {
    pub last_index: LogIndex,
    pub last_term: Term,
    /// State-machine-specific bytes. Opaque to Raft.
    pub data: Vec<u8>,
}

/// Everything a node needs to restart: hard state plus the log entries.
#[derive(Debug, Default, Clone)]
pub struct PersistedRaft {
    pub current_term: Term,
    pub voted_for: Option<NodeId>,
    pub log: Vec<LogEntry>,
}

impl PersistedRaft {
    pub fn from_runtime(current_term: Term, voted_for: Option<NodeId>, log: &Log) -> Self {
        Self {
            current_term,
            voted_for,
            log: log.entries.clone(),
        }
    }
    pub fn into_log(self) -> Result<Log> {
        Ok(Log {
            entries: self.log,
            base_index: 0,
            base_term: 0,
        })
    }
}

/// The hard-state file. `log` is only ever *read*: it is where the previous
/// single-file format kept the entries, and its presence triggers migration.
#[derive(Debug, Default, Serialize, Deserialize)]
struct HardStateFile {
    #[serde(default)]
    current_term: Term,
    #[serde(default)]
    voted_for: Option<NodeId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    log: Vec<LegacyEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LegacyEntry {
    term: Term,
    index: LogIndex,
    payload_b64: String,
}

const ENTRY_HEADER: usize = 4 + 4 + 8 + 8;
/// Refuse a log record claiming to be larger than this. A torn length must not
/// become a multi-gigabyte allocation on restart.
const MAX_ENTRY_BYTES: usize = 512 * 1024 * 1024;

fn encode_entry(out: &mut Vec<u8>, e: &LogEntry) {
    let body_len = 4 + 8 + 8 + e.payload.len();
    out.extend_from_slice(&(body_len as u32).to_be_bytes());
    let crc_at = out.len();
    out.extend_from_slice(&[0u8; 4]);
    let body_start = out.len();
    out.extend_from_slice(&e.term.to_be_bytes());
    out.extend_from_slice(&e.index.to_be_bytes());
    out.extend_from_slice(&e.payload);
    let crc = crc32fast::hash(&out[body_start..]);
    out[crc_at..crc_at + 4].copy_from_slice(&crc.to_be_bytes());
}

/// Parse a log file. Returns the entries with their file positions and the
/// length of the valid prefix (anything after is a torn tail).
fn decode_log(bytes: &[u8]) -> (Vec<(LogEntry, u64)>, u64) {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while bytes.len() - pos >= ENTRY_HEADER {
        let body_len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        if !(20..=MAX_ENTRY_BYTES).contains(&body_len) || pos + 4 + body_len > bytes.len() {
            break;
        }
        let crc = u32::from_be_bytes(bytes[pos + 4..pos + 8].try_into().unwrap());
        let body = &bytes[pos + 8..pos + 4 + body_len];
        if crc32fast::hash(body) != crc {
            break;
        }
        let term = u64::from_be_bytes(body[0..8].try_into().unwrap());
        let index = u64::from_be_bytes(body[8..16].try_into().unwrap());
        out.push((
            LogEntry {
                term,
                index,
                payload: body[16..].to_vec(),
            },
            pos as u64,
        ));
        pos += 4 + body_len;
    }
    (out, pos as u64)
}

struct FileLog {
    file: Option<File>,
    /// `(index, file position)` of every entry on disk, in order.
    positions: Vec<(LogIndex, u64)>,
    len: u64,
}

/// The durable store used by every Raft partition. See the module docs.
pub struct FileStore {
    meta_path: PathBuf,
    log_path: PathBuf,
    snapshot_path: PathBuf,
    inner: Mutex<FileLog>,
}

/// The name the store had when it was one JSON file. Kept so existing call
/// sites and on-disk paths stay valid.
pub type JsonStore = FileStore;

impl FileStore {
    pub fn new(path: PathBuf) -> Self {
        let stem = path.file_stem().unwrap_or_default().to_os_string();
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let mut log_name = stem.clone();
        log_name.push(".log");
        let mut snap_name = stem;
        snap_name.push(".snapshot.json");
        Self {
            log_path: parent.join(log_name),
            snapshot_path: parent.join(snap_name),
            meta_path: path,
            inner: Mutex::new(FileLog {
                file: None,
                positions: Vec::new(),
                len: 0,
            }),
        }
    }

    fn parent(&self) -> PathBuf {
        match self.meta_path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        }
    }

    fn write_hard_state(&self, term: Term, voted_for: Option<NodeId>) -> Result<()> {
        crate::fsutil::create_dir_all_private(&self.parent())?;
        let bytes = serde_json::to_vec(&HardStateFile {
            current_term: term,
            voted_for,
            log: Vec::new(),
        })?;
        crate::fsutil::write_atomic(&self.meta_path, &bytes)
            .with_context(|| format!("write raft hard state {:?}", self.meta_path))
    }

    fn open_log(&self, inner: &mut FileLog) -> Result<()> {
        if inner.file.is_none() {
            crate::fsutil::create_dir_all_private(&self.parent())?;
            let f = crate::fsutil::open_append_private(&self.log_path)
                .with_context(|| format!("open raft log {:?}", self.log_path))?;
            inner.len = f.metadata()?.len();
            inner.file = Some(f);
        }
        Ok(())
    }

    /// Rewrite the log file with exactly `entries`. Used by compaction, where
    /// the survivors are a short suffix.
    fn rewrite_log(&self, inner: &mut FileLog, entries: &[LogEntry]) -> Result<()> {
        let mut buf = Vec::new();
        let mut positions = Vec::with_capacity(entries.len());
        for e in entries {
            positions.push((e.index, buf.len() as u64));
            encode_entry(&mut buf, e);
        }
        crate::fsutil::write_atomic(&self.log_path, &buf)?;
        inner.file = None;
        inner.positions = positions;
        inner.len = buf.len() as u64;
        self.open_log(inner)
    }

    fn read_entries_after(&self, inner: &FileLog, through: LogIndex) -> Result<Vec<LogEntry>> {
        let first = inner.positions.partition_point(|(i, _)| *i <= through);
        let Some(&(_, start)) = inner.positions.get(first) else {
            return Ok(Vec::new());
        };
        let mut buf = vec![0u8; (inner.len - start) as usize];
        let f = inner
            .file
            .as_ref()
            .ok_or_else(|| anyhow!("raft log not open"))?;
        let n = crate::storage::segment::read_at(f, &mut buf, start)?;
        buf.truncate(n);
        Ok(decode_log(&buf).0.into_iter().map(|(e, _)| e).collect())
    }
}

impl RaftStore for FileStore {
    fn load(&self) -> Result<PersistedRaft> {
        let mut hard: HardStateFile = match std::fs::read(&self.meta_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parse raft store {:?}", self.meta_path))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HardStateFile::default(),
            Err(e) => return Err(e.into()),
        };
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Migrate the single-file format: move its entries into the log file
        // (durably) before the hard-state file stops carrying them.
        if !hard.log.is_empty() && !self.log_path.exists() {
            let entries = std::mem::take(&mut hard.log)
                .into_iter()
                .map(|l| {
                    Ok(LogEntry {
                        term: l.term,
                        index: l.index,
                        payload: base64::engine::general_purpose::STANDARD_NO_PAD
                            .decode(l.payload_b64.as_bytes())
                            .context("decode legacy raft log payload")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            self.rewrite_log(&mut inner, &entries)?;
            self.write_hard_state(hard.current_term, hard.voted_for)?;
            tracing::info!(store = ?self.meta_path, entries = entries.len(), "migrated raft store to the append-only log");
        }

        let bytes = match std::fs::read(&self.log_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        let (decoded, valid) = decode_log(&bytes);
        if valid < bytes.len() as u64 {
            tracing::warn!(log = ?self.log_path, valid, len = bytes.len(), "raft log has a torn tail; truncating");
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&self.log_path)?;
            f.set_len(valid)?;
            f.sync_all()?;
        }
        for w in decoded.windows(2) {
            if w[1].0.index != w[0].0.index + 1 {
                anyhow::bail!(
                    "raft log {:?} is not contiguous ({} then {})",
                    self.log_path,
                    w[0].0.index,
                    w[1].0.index
                );
            }
        }
        inner.file = None;
        inner.positions = decoded.iter().map(|(e, p)| (e.index, *p)).collect();
        inner.len = valid;
        if self.log_path.exists() {
            self.open_log(&mut inner)?;
        }
        Ok(PersistedRaft {
            current_term: hard.current_term,
            voted_for: hard.voted_for,
            log: decoded.into_iter().map(|(e, _)| e).collect(),
        })
    }

    fn persist(&self, ops: &[PersistOp]) -> Result<()> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut log_dirty = false;
        for op in ops {
            match op {
                PersistOp::HardState { term, voted_for } => {
                    self.write_hard_state(*term, *voted_for)?;
                }
                PersistOp::Append(entries) => {
                    if entries.is_empty() {
                        continue;
                    }
                    self.open_log(&mut inner)?;
                    let mut buf = Vec::new();
                    let base = inner.len;
                    let mut new_positions = Vec::with_capacity(entries.len());
                    for e in entries {
                        new_positions.push((e.index, base + buf.len() as u64));
                        encode_entry(&mut buf, e);
                    }
                    let f = inner.file.as_ref().unwrap();
                    if let Err(e) = (&*f).write_all(&buf) {
                        // Leave no torn bytes for the next append to land after.
                        let _ = f.set_len(base);
                        return Err(e).context("append to raft log");
                    }
                    inner.len += buf.len() as u64;
                    inner.positions.extend(new_positions);
                    log_dirty = true;
                }
                PersistOp::TruncateFrom(from) => {
                    let cut = inner.positions.partition_point(|(i, _)| *i < *from);
                    if cut == inner.positions.len() {
                        continue;
                    }
                    self.open_log(&mut inner)?;
                    let pos = inner.positions[cut].1;
                    inner.file.as_ref().unwrap().set_len(pos)?;
                    inner.positions.truncate(cut);
                    inner.len = pos;
                    log_dirty = true;
                }
                PersistOp::CompactThrough(through) => {
                    if inner
                        .positions
                        .first()
                        .map(|(i, _)| *i > *through)
                        .unwrap_or(true)
                    {
                        continue;
                    }
                    self.open_log(&mut inner)?;
                    if log_dirty {
                        inner.file.as_ref().unwrap().sync_data()?;
                        log_dirty = false;
                    }
                    let keep = self.read_entries_after(&inner, *through)?;
                    self.rewrite_log(&mut inner, &keep)?;
                }
            }
        }
        if log_dirty {
            inner
                .file
                .as_ref()
                .unwrap()
                .sync_data()
                .context("fsync raft log")?;
        }
        Ok(())
    }

    fn load_snapshot(&self) -> Result<Option<PersistedSnapshot>> {
        match std::fs::read(&self.snapshot_path) {
            Ok(bytes) => {
                Ok(Some(serde_json::from_slice(&bytes).with_context(|| {
                    format!("parse snapshot {:?}", self.snapshot_path)
                })?))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn save_snapshot(&self, snap: &PersistedSnapshot) -> Result<()> {
        crate::fsutil::create_dir_all_private(&self.parent())?;
        let bytes = serde_json::to_vec(snap)?;
        crate::fsutil::write_atomic(&self.snapshot_path, &bytes)?;
        Ok(())
    }
}

/// In-memory store for tests that want to bypass disk entirely.
pub struct MemStore {
    inner: Mutex<PersistedRaft>,
    snap: Mutex<Option<PersistedSnapshot>>,
}

impl MemStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(PersistedRaft::default()),
            snap: Mutex::new(None),
        }
    }
}

impl Default for MemStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RaftStore for MemStore {
    fn load(&self) -> Result<PersistedRaft> {
        Ok(self.inner.lock().unwrap().clone())
    }
    fn persist(&self, ops: &[PersistOp]) -> Result<()> {
        let mut s = self.inner.lock().unwrap();
        for op in ops {
            match op {
                PersistOp::HardState { term, voted_for } => {
                    s.current_term = *term;
                    s.voted_for = *voted_for;
                }
                PersistOp::Append(es) => s.log.extend(es.iter().cloned()),
                PersistOp::TruncateFrom(from) => s.log.retain(|e| e.index < *from),
                PersistOp::CompactThrough(t) => s.log.retain(|e| e.index > *t),
            }
        }
        Ok(())
    }
    fn load_snapshot(&self) -> Result<Option<PersistedSnapshot>> {
        Ok(self.snap.lock().unwrap().clone())
    }
    fn save_snapshot(&self, s: &PersistedSnapshot) -> Result<()> {
        *self.snap.lock().unwrap() = Some(s.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::messages::LogEntry;

    fn e(term: Term, payload: &[u8]) -> LogEntry {
        LogEntry {
            term,
            index: 0,
            payload: payload.to_vec(),
        }
    }

    fn ie(term: Term, index: LogIndex, payload: &[u8]) -> LogEntry {
        LogEntry {
            term,
            index,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn append_assigns_indices() {
        let mut log = Log::default();
        log.append_assign_indices(vec![e(1, b"a"), e(1, b"b"), e(2, b"c")]);
        assert_eq!(log.last_index(), 3);
        assert_eq!(log.last_term(), 2);
        assert_eq!(log.term_at(2), Some(1));
        assert_eq!(log.term_at(3), Some(2));
        assert_eq!(log.term_at(0), Some(0));
        assert_eq!(log.term_at(4), None);
    }

    #[test]
    fn append_at_truncates_conflicting_suffix() {
        let mut log = Log::default();
        log.append_assign_indices(vec![e(1, b"a"), e(1, b"b"), e(2, b"c")]);
        // Suppose leader sends a conflicting entry starting at index 3, term 3.
        assert_eq!(log.append_at(3, vec![e(3, b"C")], 0), Ok(Some(3)));
        assert_eq!(log.last_index(), 3);
        assert_eq!(log.term_at(3), Some(3));
    }

    #[test]
    fn append_at_refuses_to_truncate_committed() {
        let mut log = Log::default();
        log.append_assign_indices(vec![e(1, b"a"), e(1, b"b"), e(2, b"c")]);
        // Indices 1..=3 are committed. A conflicting entry at index 2 would
        // overwrite committed history — append_at must refuse and leave the log
        // untouched.
        assert!(log.append_at(2, vec![e(9, b"X")], 3).is_err());
        assert_eq!(log.last_index(), 3);
        assert_eq!(log.term_at(2), Some(1));
        assert_eq!(log.term_at(3), Some(2));
    }

    #[test]
    fn append_at_skips_matching_prefix() {
        let mut log = Log::default();
        log.append_assign_indices(vec![e(1, b"a"), e(1, b"b")]);
        // Leader sends [t1@2, t2@3]. We already have t1@2 — accept, then append t2@3.
        assert_eq!(
            log.append_at(2, vec![e(1, b"b-dup"), e(2, b"c")], 0),
            Ok(Some(3))
        );
        assert_eq!(log.last_index(), 3);
        assert_eq!(log.term_at(2), Some(1));
        assert_eq!(log.term_at(3), Some(2));
        // Re-delivery of what we already have changes nothing.
        assert_eq!(log.append_at(2, vec![e(1, b"b"), e(2, b"c")], 0), Ok(None));
    }

    #[test]
    fn install_snapshot_keeps_matching_suffix_only() {
        let mut log = Log::default();
        log.append_assign_indices(vec![e(1, b"a"), e(1, b"b"), e(2, b"c")]);
        assert!(log.install_snapshot(2, 1));
        assert_eq!(log.base_index, 2);
        assert_eq!(log.last_index(), 3);

        let mut log = Log::default();
        log.append_assign_indices(vec![e(1, b"a"), e(1, b"b"), e(2, b"c")]);
        // Leader's entry 2 has term 5: what we have after it may conflict.
        assert!(!log.install_snapshot(2, 5));
        assert_eq!(log.last_index(), 2);
        assert!(log.entries.is_empty());
    }

    #[test]
    fn file_store_appends_truncates_compacts_and_reloads() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("raft.json");
        let store = FileStore::new(path.clone());
        store.load().unwrap();
        store
            .persist(&[
                PersistOp::HardState {
                    term: 2,
                    voted_for: Some(7),
                },
                PersistOp::Append(vec![ie(1, 1, b"a"), ie(1, 2, b"b"), ie(2, 3, b"c")]),
            ])
            .unwrap();
        store
            .persist(&[
                PersistOp::TruncateFrom(3),
                PersistOp::Append(vec![ie(2, 3, b"C"), ie(2, 4, b"d")]),
            ])
            .unwrap();
        store.persist(&[PersistOp::CompactThrough(2)]).unwrap();

        let back = FileStore::new(path).load().unwrap();
        assert_eq!(back.current_term, 2);
        assert_eq!(back.voted_for, Some(7));
        let idx: Vec<_> = back
            .log
            .iter()
            .map(|e| (e.index, e.payload.clone()))
            .collect();
        assert_eq!(idx, vec![(3, b"C".to_vec()), (4, b"d".to_vec())]);
    }

    #[test]
    fn file_store_drops_a_torn_tail() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("raft.json");
        let store = FileStore::new(path.clone());
        store.load().unwrap();
        store
            .persist(&[PersistOp::Append(vec![ie(1, 1, b"a"), ie(1, 2, b"b")])])
            .unwrap();
        let log_path = tmp.path().join("raft.log");
        let mut bytes = std::fs::read(&log_path).unwrap();
        bytes.extend_from_slice(&[0, 0, 0, 99, 1, 2, 3]);
        std::fs::write(&log_path, bytes).unwrap();
        let back = FileStore::new(path).load().unwrap();
        assert_eq!(back.log.len(), 2);
    }

    #[test]
    fn legacy_single_file_store_is_migrated() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("raft.json");
        let legacy = serde_json::json!({
            "current_term": 4,
            "voted_for": 1,
            "log": [
                {"term": 4, "index": 1, "payload_b64": base64::engine::general_purpose::STANDARD_NO_PAD.encode(b"hello")}
            ]
        });
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let back = FileStore::new(path.clone()).load().unwrap();
        assert_eq!(back.current_term, 4);
        assert_eq!(back.log.len(), 1);
        assert_eq!(back.log[0].payload, b"hello");
        // Second load reads the migrated format.
        let again = FileStore::new(path).load().unwrap();
        assert_eq!(again.log.len(), 1);
    }
}
