//! Raft log + persistent metadata store.
//!
//! Log entries are stored in a `Vec` indexed from 1 (Raft convention; index 0
//! is the implicit "before any entries" sentinel — `last_log_index = 0` means
//! the log is empty, `last_log_term = 0` in that case).
//!
//! The persistent store keeps `(current_term, voted_for, entries)` in a single
//! JSON file written atomically (tmp + `fsync` + rename). For step 2 that's a
//! correctness-over-performance choice — rewriting the whole file per append
//! is O(N), fine for small logs and tests, and a future step can swap in a
//! proper append-only file without changing the surface API.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
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
        if self.entries.is_empty() {
            return None;
        }
        let first_idx = self.entries[0].index;
        if index < first_idx || index > self.last_index() {
            return None;
        }
        let pos = (index - first_idx) as usize;
        self.entries.get(pos).map(|e| e.term)
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

    #[allow(clippy::explicit_counter_loop)]
    pub fn append_at(&mut self, start_index: LogIndex, mut new_entries: Vec<LogEntry>) {
        let mut idx = start_index;
        let mut skip = 0usize;
        while skip < new_entries.len() {
            match self.term_at(idx) {
                Some(t) if t == new_entries[skip].term => {
                    skip += 1;
                    idx += 1;
                }
                Some(_) => {
                    self.truncate_from(idx);
                    break;
                }
                None => break,
            }
        }
        if skip == new_entries.len() {
            return;
        }
        let to_append = new_entries.split_off(skip);
        let mut next = self.last_index() + 1;
        let mut out = Vec::with_capacity(to_append.len());
        for mut e in to_append {
            e.index = next;
            out.push(e);
            next += 1;
        }
        self.entries.extend(out);
    }

    /// Drop every entry with `index <= cut_index`. `cut_term` becomes the new
    /// `base_term`. Safe to call repeatedly; idempotent if `cut_index` is
    /// already ≤ `base_index`.
    pub fn compact_through(&mut self, cut_index: LogIndex, cut_term: Term) {
        if cut_index <= self.base_index {
            return;
        }
        let drop_count = if let Some(first) = self.entries.first() {
            ((cut_index + 1).saturating_sub(first.index) as usize).min(self.entries.len())
        } else {
            0
        };
        self.entries.drain(..drop_count);
        self.base_index = cut_index;
        self.base_term = cut_term;
    }
}

/// Persistent metadata + log. All writes must be durable before the caller
/// responds to the RPC that requested them — Raft's election-safety property
/// depends on this.
///
/// `save_snapshot` and `load_snapshot` are independent of `save_all`/`load`:
/// the snapshot file lives next to the log so they can be written separately.
pub trait RaftStore: Send + Sync {
    fn load(&self) -> Result<PersistedRaft>;
    fn save_all(&self, snap: &PersistedRaft) -> Result<()>;
    fn load_snapshot(&self) -> Result<Option<PersistedSnapshot>>;
    fn save_snapshot(&self, snap: &PersistedSnapshot) -> Result<()>;
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedSnapshot {
    pub last_index: LogIndex,
    pub last_term: Term,
    /// State-machine-specific bytes. Opaque to Raft.
    pub data: Vec<u8>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PersistedRaft {
    #[serde(default)]
    pub current_term: Term,
    #[serde(default)]
    pub voted_for: Option<NodeId>,
    #[serde(default)]
    pub log: Vec<PersistedEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedEntry {
    pub term: Term,
    pub index: LogIndex,
    pub payload_b64: String,
}

impl PersistedEntry {
    fn from(e: &LogEntry) -> Self {
        Self {
            term: e.term,
            index: e.index,
            payload_b64: base64::engine::general_purpose::STANDARD_NO_PAD.encode(&e.payload),
        }
    }
    fn to(self) -> Result<LogEntry> {
        let payload = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(self.payload_b64.as_bytes())
            .context("decode log payload")?;
        Ok(LogEntry {
            term: self.term,
            index: self.index,
            payload,
        })
    }
}

impl PersistedRaft {
    pub fn from_runtime(current_term: Term, voted_for: Option<NodeId>, log: &Log) -> Self {
        Self {
            current_term,
            voted_for,
            log: log.entries.iter().map(PersistedEntry::from).collect(),
        }
    }
    pub fn into_log(self) -> Result<Log> {
        let entries = self
            .log
            .into_iter()
            .map(PersistedEntry::to)
            .collect::<Result<Vec<_>>>()?;
        Ok(Log {
            entries,
            base_index: 0,
            base_term: 0,
        })
    }
}

pub struct JsonStore {
    path: PathBuf,
    /// Serializes concurrent writers so the tmp+rename dance can't race
    /// between, e.g., the node loop's `save_all` and an application-driven
    /// `save_snapshot` / `save_all` from a different task.
    write_lock: std::sync::Mutex<()>,
}

impl JsonStore {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            write_lock: std::sync::Mutex::new(()),
        }
    }
}

impl JsonStore {
    fn snapshot_path(&self) -> PathBuf {
        let stem = self.path.file_stem().unwrap_or_default();
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let mut name = stem.to_os_string();
        name.push(".snapshot.json");
        parent.join(name)
    }
}

impl RaftStore for JsonStore {
    fn load(&self) -> Result<PersistedRaft> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)
                .with_context(|| format!("parse raft store {:?}", self.path))?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PersistedRaft::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn save_all(&self, snap: &PersistedRaft) -> Result<()> {
        let _guard = self.write_lock.lock().unwrap();
        let parent = self
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        std::fs::create_dir_all(&parent)?;
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(snap)?;
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    fn load_snapshot(&self) -> Result<Option<PersistedSnapshot>> {
        let path = self.snapshot_path();
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes)
                    .with_context(|| format!("parse snapshot {:?}", path))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn save_snapshot(&self, snap: &PersistedSnapshot) -> Result<()> {
        let _guard = self.write_lock.lock().unwrap();
        let path = self.snapshot_path();
        let parent = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        std::fs::create_dir_all(&parent)?;
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(snap)?;
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

/// In-memory store for tests that want to bypass disk entirely.
pub struct MemStore {
    inner: std::sync::Mutex<PersistedRaft>,
    snap: std::sync::Mutex<Option<PersistedSnapshot>>,
}

impl MemStore {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(PersistedRaft::default()),
            snap: std::sync::Mutex::new(None),
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
    fn save_all(&self, snap: &PersistedRaft) -> Result<()> {
        *self.inner.lock().unwrap() = snap.clone();
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
        log.append_at(3, vec![e(3, b"C")]);
        assert_eq!(log.last_index(), 3);
        assert_eq!(log.term_at(3), Some(3));
    }

    #[test]
    fn append_at_skips_matching_prefix() {
        let mut log = Log::default();
        log.append_assign_indices(vec![e(1, b"a"), e(1, b"b")]);
        // Leader sends [t1@2, t2@3]. We already have t1@2 — accept, then append t2@3.
        log.append_at(2, vec![e(1, b"b-dup"), e(2, b"c")]);
        assert_eq!(log.last_index(), 3);
        assert_eq!(log.term_at(2), Some(1));
        assert_eq!(log.term_at(3), Some(2));
    }

    #[test]
    fn json_store_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let store = JsonStore::new(tmp.path().join("raft.json"));
        let mut log = Log::default();
        log.append_assign_indices(vec![e(1, b"hello"), e(2, b"world")]);
        let snap = PersistedRaft::from_runtime(2, Some(7), &log);
        store.save_all(&snap).unwrap();
        let back = store.load().unwrap();
        assert_eq!(back.current_term, 2);
        assert_eq!(back.voted_for, Some(7));
        let log_back = back.into_log().unwrap();
        assert_eq!(log_back.entries.len(), 2);
        assert_eq!(log_back.entries[0].payload, b"hello");
        assert_eq!(log_back.entries[1].term, 2);
    }
}
