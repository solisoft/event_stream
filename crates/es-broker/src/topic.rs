use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::partition_handle::{PartitionHandle, RaftConfig};
use crate::raft::{group_key, RaftHub, Timing};
use es_protocol::{CleanupPolicyDto, TopicConfigDto, TopicConfigPatch};

/// Raft applies between snapshots when the operator has not set a value.
/// Snapshotting on every apply would rewrite the whole partition state per
/// record.
const DEFAULT_SNAPSHOT_AFTER_APPLIES: u32 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupPolicy {
    Delete,
    Compact,
    CompactDelete,
}

impl CleanupPolicy {
    pub fn includes_delete(self) -> bool {
        matches!(self, Self::Delete | Self::CompactDelete)
    }
    pub fn includes_compact(self) -> bool {
        matches!(self, Self::Compact | Self::CompactDelete)
    }

    fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "delete" => Some(Self::Delete),
            "compact" => Some(Self::Compact),
            "compact,delete" => Some(Self::CompactDelete),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "delete",
            Self::Compact => "compact",
            Self::CompactDelete => "compact,delete",
        }
    }

    pub fn to_dto(self) -> CleanupPolicyDto {
        match self {
            Self::Delete => CleanupPolicyDto::Delete,
            Self::Compact => CleanupPolicyDto::Compact,
            Self::CompactDelete => CleanupPolicyDto::CompactDelete,
        }
    }

    pub fn from_dto(d: CleanupPolicyDto) -> Self {
        match d {
            CleanupPolicyDto::Delete => Self::Delete,
            CleanupPolicyDto::Compact => Self::Compact,
            CleanupPolicyDto::CompactDelete => Self::CompactDelete,
        }
    }
}

/// Fully resolved runtime config. Lives behind an `ArcSwap` on `Topic`.
#[derive(Debug, Clone)]
pub struct TopicConfig {
    pub retention_ms: Option<u64>,
    pub retention_bytes: Option<u64>,
    pub cleanup_policy: CleanupPolicy,
    pub segment_bytes: u64,
    pub tombstone_retention_ms: u64,
}

impl TopicConfig {
    pub fn to_dto(&self) -> TopicConfigDto {
        TopicConfigDto {
            retention_ms: self.retention_ms,
            retention_bytes: self.retention_bytes,
            cleanup_policy: self.cleanup_policy.to_dto(),
            segment_bytes: self.segment_bytes,
            tombstone_retention_ms: self.tombstone_retention_ms,
        }
    }
}

/// On-disk representation. Every field is optional; absent fields fall back to
/// the broker defaults at load time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedTopicConfig {
    #[serde(default)]
    retention_ms: Option<u64>,
    #[serde(default)]
    retention_bytes: Option<u64>,
    #[serde(default)]
    cleanup_policy: Option<String>,
    #[serde(default)]
    segment_bytes: Option<u64>,
    #[serde(default)]
    tombstone_retention_ms: Option<u64>,
    #[serde(default)]
    raft: Option<PersistedRaftConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedRaftConfig {
    node_id: u32,
    #[serde(default)]
    peers: Vec<u32>,
    #[serde(default)]
    snapshot_after_applies: u32,
}

impl PersistedTopicConfig {
    fn from_patch(patch: &TopicConfigPatch) -> Self {
        Self {
            retention_ms: patch.retention_ms,
            retention_bytes: patch.retention_bytes,
            cleanup_policy: patch
                .cleanup_policy
                .map(|p| CleanupPolicy::from_dto(p).as_str().to_string()),
            segment_bytes: patch.segment_bytes,
            tombstone_retention_ms: patch.tombstone_retention_ms,
            raft: None,
        }
    }

    fn merge_patch(&mut self, patch: &TopicConfigPatch) {
        if let Some(v) = patch.retention_ms {
            self.retention_ms = Some(v);
        }
        if let Some(v) = patch.retention_bytes {
            self.retention_bytes = Some(v);
        }
        if let Some(p) = patch.cleanup_policy {
            self.cleanup_policy = Some(CleanupPolicy::from_dto(p).as_str().to_string());
        }
        if let Some(v) = patch.segment_bytes {
            self.segment_bytes = Some(v);
        }
        if let Some(v) = patch.tombstone_retention_ms {
            self.tombstone_retention_ms = Some(v);
        }
    }

    /// The Raft configuration for this topic's partitions, if any.
    ///
    /// Broker-level cluster membership wins over the persisted topic field, and
    /// deliberately so: which node this process is, and where the other members
    /// are, are properties of the *process*. A node id stored in topic metadata
    /// would claim the same id on every machine that metadata reached.
    ///
    /// The membership is `self` plus exactly the peers that have an address.
    /// There is no way to name a member without giving its address, which
    /// removes the failure where a member counts toward a quorum the node can
    /// never reach.
    fn resolve_raft(&self, broker: &Config, topic_name: &str) -> Option<RaftConfig> {
        // Each topic gets its own Raft state directory. Sharing one would put
        // two topics' partition 0 in the same state file and let each overwrite
        // the other's term and vote.
        let raft_store_dir = broker.data_dir.join("raft").join(topic_name);

        if let Some(node_id) = broker.raft_node_id {
            let snapshot_after_applies = self
                .raft
                .as_ref()
                .map(|rc| rc.snapshot_after_applies)
                .filter(|n| *n > 0)
                .unwrap_or(DEFAULT_SNAPSHOT_AFTER_APPLIES);
            return Some(RaftConfig {
                node_id,
                peers: broker.raft_peer_addrs.keys().copied().collect(),
                raft_store_dir,
                timing: Timing::default(),
                snapshot_after_applies,
                bind: broker.raft_bind,
                peer_addrs: broker.raft_peer_addrs.clone(),
                shared_secret: broker.raft_shared_secret.clone(),
            });
        }

        self.raft.as_ref().map(|rc| RaftConfig {
            node_id: rc.node_id,
            peers: rc.peers.clone(),
            raft_store_dir,
            timing: Timing::default(),
            snapshot_after_applies: rc.snapshot_after_applies.max(1),
            bind: None,
            peer_addrs: BTreeMap::new(),
            shared_secret: broker.raft_shared_secret.clone(),
        })
    }

    fn resolve(&self, broker: &Config) -> Result<TopicConfig> {
        let cleanup_policy = match self.cleanup_policy.as_deref() {
            None => broker.default_cleanup_policy,
            Some(s) => CleanupPolicy::from_str_opt(s)
                .ok_or_else(|| anyhow!("unknown cleanup_policy '{}'", s))?,
        };
        Ok(TopicConfig {
            retention_ms: self.retention_ms.or(broker.default_retention_ms),
            retention_bytes: self.retention_bytes.or(broker.default_retention_bytes),
            cleanup_policy,
            segment_bytes: self.segment_bytes.unwrap_or(broker.segment_bytes),
            tombstone_retention_ms: self
                .tombstone_retention_ms
                .unwrap_or(broker.default_tombstone_retention_ms),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TopicMeta {
    partitions: u32,
    #[serde(default)]
    config: PersistedTopicConfig,
}

pub struct Topic {
    pub name: String,
    pub partitions: Vec<PartitionHandle>,
    pub rr_counter: AtomicU64,
    pub config: ArcSwap<TopicConfig>,
    pub records_produced_total: AtomicU64,
    pub bytes_produced_total: AtomicU64,
    pub records_consumed_total: AtomicU64,
    pub bytes_consumed_total: AtomicU64,
    meta_path: PathBuf,
    persisted: std::sync::Mutex<PersistedTopicConfig>,
}

impl Topic {
    pub fn create(
        root: &Path,
        name: &str,
        partitions: u32,
        broker: &Config,
        patch: Option<&TopicConfigPatch>,
    ) -> Result<Arc<Self>> {
        if partitions == 0 {
            return Err(anyhow!("topic must have at least 1 partition"));
        }
        validate_topic_name(name)?;

        let topic_dir = root.join(name);
        std::fs::create_dir_all(&topic_dir)
            .with_context(|| format!("create dir {:?}", topic_dir))?;

        let meta_path = topic_dir.join("topic.json");
        if meta_path.exists() {
            return Err(anyhow!("topic '{}' already exists", name));
        }

        let persisted = patch
            .map(PersistedTopicConfig::from_patch)
            .unwrap_or_default();
        let resolved = persisted.resolve(broker)?;
        let raft_cfg = persisted.resolve_raft(broker, name);
        let meta = TopicMeta {
            partitions,
            config: persisted.clone(),
        };
        write_json_atomic(&meta_path, &meta)?;

        let mut parts = Vec::with_capacity(partitions as usize);
        for id in 0..partitions {
            let dir = topic_dir.join(id.to_string());
            std::fs::create_dir_all(&dir)?;
            parts.push(PartitionHandle::open(
                dir,
                id,
                resolved.segment_bytes,
                broker.flush_every_records,
                raft_cfg.as_ref(),
            )?);
        }
        Ok(Arc::new(Self {
            name: name.to_string(),
            partitions: parts,
            rr_counter: AtomicU64::new(0),
            config: ArcSwap::from_pointee(resolved),
            records_produced_total: AtomicU64::new(0),
            bytes_produced_total: AtomicU64::new(0),
            records_consumed_total: AtomicU64::new(0),
            bytes_consumed_total: AtomicU64::new(0),
            meta_path,
            persisted: std::sync::Mutex::new(persisted),
        }))
    }

    /// Route every Raft-backed partition of this topic over the broker's hub.
    ///
    /// Errors are returned, not logged: a partition that failed to attach
    /// accepts writes and replicates none of them, which is the one state an
    /// operator cannot tell apart from a healthy one.
    pub fn attach_raft(&self, hub: &Arc<RaftHub>) -> Result<()> {
        for (i, p) in self.partitions.iter().enumerate() {
            if !p.is_raft() {
                continue;
            }
            let group = group_key(&self.name, i as u32);
            p.attach_to_hub(hub, &group)
                .with_context(|| format!("attach {} partition {} to the raft hub", self.name, i))?;
        }
        Ok(())
    }

    /// Stop routing this topic's partitions. Called when a topic is deleted so
    /// a topic later recreated under the same name can register again.
    pub fn detach_raft(&self, hub: &Arc<RaftHub>) {
        for (i, p) in self.partitions.iter().enumerate() {
            if p.is_raft() {
                hub.unregister(&group_key(&self.name, i as u32));
            }
        }
    }

    /// Every partition of this topic, for callers that need the handle itself.
    pub fn raft_partitions(&self) -> impl Iterator<Item = &PartitionHandle> {
        self.partitions.iter().filter(|p| p.is_raft())
    }

    pub fn has_raft_partitions(&self) -> bool {
        self.partitions.iter().any(|p| p.is_raft())
    }

    pub fn open(root: &Path, name: &str, broker: &Config) -> Result<Arc<Self>> {
        let topic_dir = root.join(name);
        let meta_path = topic_dir.join("topic.json");
        let meta_bytes = std::fs::read(&meta_path)
            .with_context(|| format!("read topic meta {:?}", meta_path))?;
        let meta: TopicMeta = serde_json::from_slice(&meta_bytes)
            .with_context(|| format!("parse topic meta {:?}", meta_path))?;
        let resolved = meta.config.resolve(broker)?;
        let raft_cfg = meta.config.resolve_raft(broker, name);
        let mut parts = Vec::with_capacity(meta.partitions as usize);
        for id in 0..meta.partitions {
            let dir = topic_dir.join(id.to_string());
            parts.push(PartitionHandle::open(
                dir,
                id,
                resolved.segment_bytes,
                broker.flush_every_records,
                raft_cfg.as_ref(),
            )?);
        }
        Ok(Arc::new(Self {
            name: name.to_string(),
            partitions: parts,
            rr_counter: AtomicU64::new(0),
            config: ArcSwap::from_pointee(resolved),
            records_produced_total: AtomicU64::new(0),
            bytes_produced_total: AtomicU64::new(0),
            records_consumed_total: AtomicU64::new(0),
            bytes_consumed_total: AtomicU64::new(0),
            meta_path,
            persisted: std::sync::Mutex::new(meta.config),
        }))
    }

    pub fn resolved_config(&self) -> Arc<TopicConfig> {
        self.config.load_full()
    }

    pub fn update_config(
        &self,
        patch: &TopicConfigPatch,
        broker: &Config,
    ) -> Result<Arc<TopicConfig>> {
        let new_persisted = {
            let mut guard = self.persisted.lock().unwrap();
            guard.merge_patch(patch);
            guard.clone()
        };
        let resolved = new_persisted.resolve(broker)?;
        let meta = TopicMeta {
            partitions: self.partitions.len() as u32,
            config: new_persisted,
        };
        write_json_atomic(&self.meta_path, &meta)?;
        let resolved = Arc::new(resolved);
        self.config.store(resolved.clone());

        for p in &self.partitions {
            p.set_segment_bytes(resolved.segment_bytes);
        }

        Ok(resolved)
    }

    pub fn route(&self, key: Option<&[u8]>, hint: Option<u32>) -> Result<u32> {
        if let Some(h) = hint {
            if (h as usize) >= self.partitions.len() {
                return Err(anyhow!(
                    "partition {} out of range (topic has {} partitions)",
                    h,
                    self.partitions.len()
                ));
            }
            return Ok(h);
        }
        if let Some(k) = key {
            let h = fnv1a64(k);
            return Ok((h % self.partitions.len() as u64) as u32);
        }
        let n = self.rr_counter.fetch_add(1, Ordering::Relaxed);
        Ok((n % self.partitions.len() as u64) as u32)
    }
}

/// Validate a topic name. Rejects anything that isn't `[A-Za-z0-9_.-]{1,200}`
/// and the `.`/`..` path specials, so a topic name can never be used to escape
/// the data directory when it's joined into a filesystem path.
pub fn validate_topic_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 200 {
        return Err(anyhow!("topic name length must be 1..=200"));
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.');
    if !ok {
        return Err(anyhow!(
            "topic name may only contain ASCII alphanumerics, '_', '-', '.'"
        ));
    }
    if name == "." || name == ".." {
        return Err(anyhow!("topic name '{}' is reserved", name));
    }
    Ok(())
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub(crate) fn write_json_atomic<P: AsRef<Path>, T: Serialize>(path: P, value: &T) -> Result<()> {
    let path = path.as_ref();
    let tmp: PathBuf = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(value)?;
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
