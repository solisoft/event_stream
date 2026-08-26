use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use dashmap::DashMap;
use tokio::sync::Mutex;

use crate::topic::write_json_atomic;

pub type GroupOffsets = BTreeMap<String, BTreeMap<u32, u64>>;

/// Upper bound on the number of distinct consumer groups tracked. Bounds
/// memory/inode growth from an attacker committing offsets under many random
/// group names.
const MAX_GROUPS: usize = 100_000;

pub struct GroupStore {
    dir: PathBuf,
    entries: DashMap<String, Arc<Mutex<GroupOffsets>>>,
}

impl GroupStore {
    pub fn open(dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&dir).with_context(|| format!("create dir {:?}", dir))?;
        let entries = DashMap::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let name = match path.file_stem().and_then(|s| s.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            let bytes = std::fs::read(&path)?;
            let offsets: GroupOffsets = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse group offsets {:?}", path))?;
            entries.insert(name, Arc::new(Mutex::new(offsets)));
        }
        Ok(Self { dir, entries })
    }

    fn group_path(&self, group: &str) -> PathBuf {
        self.dir.join(format!("{}.json", group))
    }

    pub fn slot(&self, group: &str) -> Arc<Mutex<GroupOffsets>> {
        if let Some(slot) = self.entries.get(group) {
            return slot.clone();
        }
        let new_slot: Arc<Mutex<GroupOffsets>> = Arc::new(Mutex::new(GroupOffsets::new()));
        self.entries
            .entry(group.to_string())
            .or_insert(new_slot)
            .clone()
    }

    pub async fn commit(
        &self,
        group: &str,
        topic: &str,
        partition: u32,
        offset: u64,
    ) -> Result<()> {
        validate_group_name(group)?;
        // Cap the number of tracked groups. `commit` is the only path that
        // creates a group slot, so enforcing here bounds total growth.
        if !self.entries.contains_key(group) && self.entries.len() >= MAX_GROUPS {
            anyhow::bail!("consumer group limit reached ({})", MAX_GROUPS);
        }
        let slot = self.slot(group);
        let mut guard = slot.lock().await;
        guard
            .entry(topic.to_string())
            .or_default()
            .insert(partition, offset);
        write_json_atomic(self.group_path(group), &*guard)?;
        Ok(())
    }

    pub async fn fetch(&self, group: &str, topic: &str, partition: u32) -> Option<u64> {
        // Read-only: never create a slot for an unknown group (that would let a
        // flood of random group names exhaust memory).
        let slot = self.entries.get(group).map(|s| s.clone())?;
        let guard = slot.lock().await;
        guard.get(topic).and_then(|m| m.get(&partition)).copied()
    }

    pub async fn snapshot(&self, group: &str) -> GroupOffsets {
        let Some(slot) = self.entries.get(group).map(|s| s.clone()) else {
            return GroupOffsets::new();
        };
        let guard = slot.lock().await;
        guard.clone()
    }

    /// Snapshot the set of group names currently known to the broker. Used by
    /// the `/metrics` endpoint to iterate without holding the DashMap shard locks.
    pub fn iter_group_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.entries.iter().map(|kv| kv.key().clone()).collect();
        names.sort();
        names
    }
}

fn validate_group_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 200 {
        anyhow::bail!("group name length must be 1..=200");
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.');
    if !ok {
        anyhow::bail!("group name may only contain ASCII alphanumerics, '_', '-', '.'");
    }
    Ok(())
}
