//! Consumer-group committed offsets, and who a group belongs to.
//!
//! **Ownership.** A group belongs to the API key that first committed to it or
//! joined it. Only that key (or a global admin) can commit its offsets, read
//! them, consume through it, or join it. Without this, any key that could read
//! a topic could rewind or skip another tenant's consumer on it.
//!
//! **Durability.** A commit updates memory and marks the group dirty; dirty
//! groups are written out together every [`FLUSH_INTERVAL`] (and on shutdown).
//! Fsyncing a rewritten file on every commit, under the group's lock, on an
//! async worker, made commit-after-every-poll consumers pay a disk sync per
//! poll. A crash can lose the last interval of commits — the consumer then
//! re-reads those records, which at-least-once delivery already allows.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::auth::ApiKey;

pub type GroupOffsets = BTreeMap<String, BTreeMap<u32, u64>>;

/// Upper bound on the number of distinct consumer groups tracked. Bounds
/// memory/inode growth from an attacker committing offsets under many random
/// group names.
const MAX_GROUPS: usize = 100_000;
/// Distinct (topic, partition) entries one group may hold.
const MAX_ENTRIES_PER_GROUP: usize = 100_000;
/// How often dirty groups are written out.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Default, Clone)]
pub struct GroupEntry {
    /// `key_id` of the owner. Empty for a group persisted before ownership
    /// existed; the next key to use it claims it.
    pub owner: String,
    pub offsets: GroupOffsets,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupFile {
    owner: String,
    offsets: GroupOffsets,
}

/// Parse a group file: the current `{owner, offsets}` or the older bare
/// offsets map. (Not an untagged serde enum: those buffer the input and lose
/// the integer parsing of the partition keys.)
fn parse_group_file(bytes: &[u8]) -> Result<GroupEntry> {
    let v: serde_json::Value = serde_json::from_slice(bytes)?;
    let current = v.as_object().is_some_and(|o| {
        o.len() == 2
            && o.get("owner").is_some_and(|x| x.is_string())
            && o.get("offsets").is_some_and(|x| x.is_object())
    });
    if current {
        let f: GroupFile = serde_json::from_slice(bytes)?;
        Ok(GroupEntry {
            owner: f.owner,
            offsets: f.offsets,
        })
    } else {
        Ok(GroupEntry {
            owner: String::new(),
            offsets: serde_json::from_slice(bytes)?,
        })
    }
}

#[derive(Debug)]
pub enum GroupError {
    Invalid(String),
    Forbidden(String),
    Limit(String),
}

impl std::fmt::Display for GroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) | Self::Forbidden(m) | Self::Limit(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for GroupError {}

pub struct GroupStore {
    dir: PathBuf,
    entries: DashMap<String, Arc<Mutex<GroupEntry>>>,
    dirty: std::sync::Mutex<BTreeSet<String>>,
    flush_lock: Mutex<()>,
}

impl GroupStore {
    pub fn open(dir: PathBuf) -> Result<Self> {
        crate::fsutil::create_dir_all_private(&dir)
            .with_context(|| format!("create dir {:?}", dir))?;
        let entries = DashMap::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if crate::fsutil::is_atomic_tmp_leftover(&name) {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let group = match path.file_stem().and_then(|s| s.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            let bytes = std::fs::read(&path)?;
            let e = parse_group_file(&bytes)
                .with_context(|| format!("parse group offsets {:?}", path))?;
            entries.insert(group, Arc::new(Mutex::new(e)));
        }
        Ok(Self {
            dir,
            entries,
            dirty: std::sync::Mutex::new(BTreeSet::new()),
            flush_lock: Mutex::new(()),
        })
    }

    fn group_path(&self, group: &str) -> PathBuf {
        self.dir.join(format!("{}.json", group))
    }

    /// The group's entry if `key` may use it, claiming an unowned or new
    /// group for `key`. Only call this for operations that are allowed to
    /// create a group (commit, join).
    pub async fn authorize_or_claim(
        &self,
        group: &str,
        key: &ApiKey,
    ) -> Result<Arc<Mutex<GroupEntry>>, GroupError> {
        validate_group_name(group).map_err(|e| GroupError::Invalid(e.to_string()))?;
        let slot = match self.entries.get(group).map(|s| s.clone()) {
            Some(s) => s,
            None => {
                if self.entries.len() >= MAX_GROUPS {
                    return Err(GroupError::Limit(format!(
                        "consumer group limit reached ({})",
                        MAX_GROUPS
                    )));
                }
                self.entries
                    .entry(group.to_string())
                    .or_insert_with(|| Arc::new(Mutex::new(GroupEntry::default())))
                    .clone()
            }
        };
        {
            let mut g = slot.lock().await;
            if g.owner.is_empty() {
                g.owner = key.key_id.clone();
                self.mark_dirty(group);
            } else if g.owner != key.key_id && !key.is_admin() {
                return Err(GroupError::Forbidden(format!(
                    "consumer group '{}' belongs to another key",
                    group
                )));
            }
        }
        Ok(slot)
    }

    /// Whether `key` may use an *existing* group. Unknown groups are allowed
    /// (there is nothing in them to protect) and are not created.
    pub async fn check_access(&self, group: &str, key: &ApiKey) -> Result<(), GroupError> {
        let Some(slot) = self.entries.get(group).map(|s| s.clone()) else {
            return Ok(());
        };
        let g = slot.lock().await;
        if !g.owner.is_empty() && g.owner != key.key_id && !key.is_admin() {
            return Err(GroupError::Forbidden(format!(
                "consumer group '{}' belongs to another key",
                group
            )));
        }
        Ok(())
    }

    fn mark_dirty(&self, group: &str) {
        self.dirty
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(group.to_string());
    }

    /// Record a committed offset. The caller has checked that the topic and
    /// partition exist.
    pub async fn commit(
        &self,
        group: &str,
        key: &ApiKey,
        topic: &str,
        partition: u32,
        offset: u64,
    ) -> Result<(), GroupError> {
        let slot = self.authorize_or_claim(group, key).await?;
        let mut g = slot.lock().await;
        let present = g
            .offsets
            .get(topic)
            .map(|m| m.contains_key(&partition))
            .unwrap_or(false);
        if !present {
            let n: usize = g.offsets.values().map(|m| m.len()).sum();
            if n >= MAX_ENTRIES_PER_GROUP {
                return Err(GroupError::Limit(format!(
                    "consumer group '{}' already tracks {} partitions",
                    group, MAX_ENTRIES_PER_GROUP
                )));
            }
        }
        g.offsets
            .entry(topic.to_string())
            .or_default()
            .insert(partition, offset);
        drop(g);
        self.mark_dirty(group);
        Ok(())
    }

    /// Admin path: set an offset regardless of owner.
    pub async fn reset(&self, group: &str, topic: &str, partition: u32, offset: u64) {
        let Some(slot) = self.entries.get(group).map(|s| s.clone()) else {
            return;
        };
        slot.lock()
            .await
            .offsets
            .entry(topic.to_string())
            .or_default()
            .insert(partition, offset);
        self.mark_dirty(group);
    }

    pub async fn fetch(&self, group: &str, topic: &str, partition: u32) -> Option<u64> {
        // Read-only: never create a slot for an unknown group (that would let a
        // flood of random group names exhaust memory).
        let slot = self.entries.get(group).map(|s| s.clone())?;
        let guard = slot.lock().await;
        guard
            .offsets
            .get(topic)
            .and_then(|m| m.get(&partition))
            .copied()
    }

    pub async fn snapshot(&self, group: &str) -> GroupOffsets {
        let Some(slot) = self.entries.get(group).map(|s| s.clone()) else {
            return GroupOffsets::new();
        };
        let guard = slot.lock().await;
        guard.offsets.clone()
    }

    pub async fn owner(&self, group: &str) -> Option<String> {
        let slot = self.entries.get(group).map(|s| s.clone())?;
        let g = slot.lock().await;
        Some(g.owner.clone())
    }

    /// Snapshot the set of group names currently known to the broker. Used by
    /// the `/metrics` endpoint to iterate without holding the DashMap shard locks.
    pub fn iter_group_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.entries.iter().map(|kv| kv.key().clone()).collect();
        names.sort();
        names
    }

    /// Write every dirty group to disk.
    pub async fn flush(&self) -> Result<()> {
        let _guard = self.flush_lock.lock().await;
        let dirty: Vec<String> = {
            let mut d = self.dirty.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *d).into_iter().collect()
        };
        let mut writes = Vec::with_capacity(dirty.len());
        for group in &dirty {
            let Some(slot) = self.entries.get(group).map(|s| s.clone()) else {
                continue;
            };
            let g = slot.lock().await;
            let bytes = serde_json::to_vec(&GroupFile {
                owner: g.owner.clone(),
                offsets: g.offsets.clone(),
            })?;
            writes.push((self.group_path(group), bytes));
        }
        if writes.is_empty() {
            return Ok(());
        }
        let res = tokio::task::spawn_blocking(move || -> Result<()> {
            for (path, bytes) in writes {
                crate::fsutil::write_atomic(&path, &bytes)?;
            }
            Ok(())
        })
        .await
        .map_err(|e| anyhow::anyhow!("group flush task: {e}"))?;
        if res.is_err() {
            // Try again next time.
            self.dirty
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend(dirty);
        }
        res
    }
}

/// Periodically write dirty groups; once more on shutdown.
pub fn spawn_flusher(
    broker: &Arc<crate::broker::Broker>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    let weak = Arc::downgrade(broker);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(FLUSH_INTERVAL) => {}
            }
            let Some(b) = weak.upgrade() else { return };
            if let Err(e) = b.groups.flush().await {
                tracing::warn!(error = %e, "groups: flush failed");
            }
        }
        if let Some(b) = weak.upgrade() {
            if let Err(e) = b.groups.flush().await {
                tracing::warn!(error = %e, "groups: final flush failed");
            }
        }
    })
}

pub fn validate_group_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 200 {
        anyhow::bail!("group name length must be 1..=200");
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.');
    if !ok {
        anyhow::bail!("group name may only contain ASCII alphanumerics, '_', '-', '.'");
    }
    if name == "." || name == ".." {
        anyhow::bail!("group name '{}' is reserved", name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AclAction, AclRule};

    fn key(id: &str) -> ApiKey {
        ApiKey {
            key_id: id.into(),
            name: id.into(),
            acls: vec![AclRule {
                action: AclAction::Read,
                topic_prefix: "*".into(),
            }],
            produce_bytes_per_sec: None,
            consume_bytes_per_sec: None,
            created_at_ms: 0,
            disabled: false,
        }
    }

    #[tokio::test]
    async fn a_group_belongs_to_its_first_user() {
        let dir = tempfile::tempdir().unwrap();
        let s = GroupStore::open(dir.path().to_path_buf()).unwrap();
        s.commit("g", &key("a"), "t", 0, 5).await.unwrap();
        assert!(matches!(
            s.commit("g", &key("b"), "t", 0, 0).await,
            Err(GroupError::Forbidden(_))
        ));
        assert_eq!(s.fetch("g", "t", 0).await, Some(5));
    }

    #[tokio::test]
    async fn offsets_and_owner_survive_a_flush_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = GroupStore::open(dir.path().to_path_buf()).unwrap();
            s.commit("g", &key("a"), "t", 1, 9).await.unwrap();
            s.flush().await.unwrap();
        }
        let s = GroupStore::open(dir.path().to_path_buf()).unwrap();
        assert_eq!(s.fetch("g", "t", 1).await, Some(9));
        assert_eq!(s.owner("g").await.as_deref(), Some("a"));
    }

    #[tokio::test]
    async fn legacy_group_files_load_unowned() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("old.json"), br#"{"t":{"0":3}}"#).unwrap();
        let s = GroupStore::open(dir.path().to_path_buf()).unwrap();
        assert_eq!(s.fetch("old", "t", 0).await, Some(3));
        assert_eq!(s.owner("old").await.as_deref(), Some(""));
    }
}
