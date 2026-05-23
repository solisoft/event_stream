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

/// In-memory log. Index 1 is the first entry.
#[derive(Debug, Default, Clone)]
pub struct Log {
    pub entries: Vec<LogEntry>,
}

impl Log {
    pub fn last_index(&self) -> LogIndex {
        self.entries.last().map(|e| e.index).unwrap_or(0)
    }

    pub fn last_term(&self) -> Term {
        self.entries.last().map(|e| e.term).unwrap_or(0)
    }

    /// Term at `index` (1-based), or `None` if out of range.
    pub fn term_at(&self, index: LogIndex) -> Option<Term> {
        if index == 0 {
            return Some(0);
        }
        let pos = index.checked_sub(1)? as usize;
        self.entries.get(pos).map(|e| e.term)
    }

    /// Entries in `[start, end_exclusive)`. Bounds-tolerant.
    pub fn slice(&self, start: LogIndex, end_exclusive: LogIndex) -> Vec<LogEntry> {
        if start == 0 || end_exclusive <= start {
            return Vec::new();
        }
        let start = (start - 1) as usize;
        let end = (end_exclusive - 1) as usize;
        if start >= self.entries.len() {
            return Vec::new();
        }
        let end = end.min(self.entries.len());
        self.entries[start..end].to_vec()
    }

    /// Append entries that are guaranteed to follow the current tail.
    /// Caller is responsible for any conflict resolution (truncation) before
    /// calling this. Indices are reassigned to be contiguous on append; the
    /// `index` in the inbound entries is used only for cross-checking.
    pub fn append_assign_indices(&mut self, mut entries: Vec<LogEntry>) {
        let mut next = self.last_index() + 1;
        for e in &mut entries {
            e.index = next;
            next += 1;
        }
        self.entries.extend(entries);
    }

    /// Truncate the log so that no entry has `index >= cut_index`. Idempotent.
    pub fn truncate_from(&mut self, cut_index: LogIndex) {
        if cut_index == 0 {
            self.entries.clear();
            return;
        }
        let keep = (cut_index - 1) as usize;
        if keep < self.entries.len() {
            self.entries.truncate(keep);
        }
    }

    /// Append entries at a specific index, handling overlap correctly:
    /// any existing entry at the same index with a different term wins
    /// truncation, then matching prefix is skipped, then the tail is appended.
    pub fn append_at(&mut self, start_index: LogIndex, mut new_entries: Vec<LogEntry>) {
        // Walk the prefix that already matches.
        let mut idx = start_index;
        let mut skip = 0usize;
        while skip < new_entries.len() {
            let term_here = self.term_at(idx);
            match term_here {
                Some(t) if t == new_entries[skip].term => {
                    skip += 1;
                    idx += 1;
                }
                Some(_) => {
                    // Conflict: drop everything from `idx` onward.
                    self.truncate_from(idx);
                    break;
                }
                None => break,
            }
        }
        if skip == new_entries.len() {
            return;
        }
        // The remaining entries don't exist yet (after any truncate above).
        let to_append = new_entries.split_off(skip);
        // Force the index field so callers don't have to.
        let mut next = self.last_index() + 1;
        let mut out = Vec::with_capacity(to_append.len());
        for mut e in to_append {
            e.index = next;
            out.push(e);
            next += 1;
        }
        self.entries.extend(out);
    }
}

/// Persistent metadata + log. All writes must be durable before the caller
/// responds to the RPC that requested them — Raft's election-safety property
/// depends on this.
pub trait RaftStore: Send + Sync {
    fn load(&self) -> Result<PersistedRaft>;
    fn save_all(&self, snap: &PersistedRaft) -> Result<()>;
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
        Ok(Log { entries })
    }
}

pub struct JsonStore {
    path: PathBuf,
}

impl JsonStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
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
        // tmp + fsync + rename — same pattern used elsewhere in the codebase.
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
}

/// In-memory store for tests that want to bypass disk entirely.
pub struct MemStore {
    inner: std::sync::Mutex<PersistedRaft>,
}

impl MemStore {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(PersistedRaft::default()),
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
