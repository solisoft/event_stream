use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use crate::partition::Partition;
use crate::raft::{RaftHub, Timing};
use crate::raft_partition::{RaftPartition, RaftPartitionConfig, RaftTransportConfig};
use crate::storage::record::Record;
use crate::storage::segment::Segment;
use es_protocol::RecordDto;

#[derive(Debug, Clone)]
pub struct RaftConfig {
    pub node_id: crate::raft::NodeId,
    pub peers: Vec<crate::raft::NodeId>,
    pub raft_store_dir: PathBuf,
    pub timing: Timing,
    pub snapshot_after_applies: u32,
    pub bind: Option<SocketAddr>,
    pub peer_addrs: BTreeMap<crate::raft::NodeId, SocketAddr>,
    /// Pre-shared secret peers must present in the raft handshake.
    pub shared_secret: Option<String>,
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            node_id: 0,
            peers: Vec::new(),
            raft_store_dir: PathBuf::from("."),
            timing: Timing::default(),
            snapshot_after_applies: 1024,
            bind: None,
            peer_addrs: BTreeMap::new(),
            shared_secret: None,
        }
    }
}

pub enum PartitionHandle {
    Plain(Arc<Partition>),
    Raft(Arc<RaftPartition>),
}

impl PartitionHandle {
    pub fn id(&self) -> u32 {
        match self {
            Self::Plain(p) => p.id,
            Self::Raft(p) => p.partition().id,
        }
    }

    pub fn start_offset(&self) -> u64 {
        match self {
            Self::Plain(p) => p.start_offset(),
            Self::Raft(p) => p.partition().start_offset(),
        }
    }

    pub fn end_offset(&self) -> u64 {
        match self {
            Self::Plain(p) => p.end_offset(),
            Self::Raft(p) => p.partition().end_offset(),
        }
    }

    pub fn segment_count(&self) -> u32 {
        match self {
            Self::Plain(p) => p.segment_count(),
            Self::Raft(p) => p.partition().segment_count(),
        }
    }

    pub fn total_size_bytes(&self) -> u64 {
        match self {
            Self::Plain(p) => p.total_size_bytes(),
            Self::Raft(p) => p.partition().total_size_bytes(),
        }
    }

    pub fn segments_snapshot(&self) -> Arc<Vec<Arc<Segment>>> {
        match self {
            Self::Plain(p) => p.segments_snapshot(),
            Self::Raft(p) => p.partition().segments_snapshot(),
        }
    }

    pub async fn append(&self, key: Option<&[u8]>, value: &[u8]) -> Result<u64> {
        match self {
            Self::Plain(p) => p.append(key, value).await,
            Self::Raft(p) => p.append(key, value).await,
        }
    }

    pub fn read_records_raw(
        &self,
        target_offset: u64,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<(Vec<Record>, u64, u64)> {
        match self {
            Self::Plain(p) => p.read_records_raw(target_offset, max_records, max_bytes),
            Self::Raft(p) => p
                .partition()
                .read_records_raw(target_offset, max_records, max_bytes),
        }
    }

    pub fn read_records(
        &self,
        target_offset: u64,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<(Vec<RecordDto>, u64, u64)> {
        match self {
            Self::Plain(p) => p.read_records(target_offset, max_records, max_bytes),
            Self::Raft(p) => p
                .partition()
                .read_records(target_offset, max_records, max_bytes),
        }
    }

    pub async fn drop_sealed_segments(
        &self,
        victim_bases: &[u64],
        grace: Duration,
        cancel: &CancellationToken,
    ) -> Result<u64> {
        match self {
            Self::Plain(p) => p.drop_sealed_segments(victim_bases, grace, cancel).await,
            Self::Raft(p) => {
                p.partition()
                    .drop_sealed_segments(victim_bases, grace, cancel)
                    .await
            }
        }
    }

    pub fn retention_segments_deleted(&self) -> &AtomicU64 {
        match self {
            Self::Plain(p) => &p.retention_segments_deleted_total,
            Self::Raft(p) => &p.partition().retention_segments_deleted_total,
        }
    }

    pub fn retention_bytes_reclaimed(&self) -> &AtomicU64 {
        match self {
            Self::Plain(p) => &p.retention_bytes_reclaimed_total,
            Self::Raft(p) => &p.partition().retention_bytes_reclaimed_total,
        }
    }

    pub fn compaction_runs(&self) -> &AtomicU64 {
        match self {
            Self::Plain(p) => &p.compaction_runs_total,
            Self::Raft(p) => &p.partition().compaction_runs_total,
        }
    }

    pub fn compaction_records_dropped(&self) -> &AtomicU64 {
        match self {
            Self::Plain(p) => &p.compaction_records_dropped_total,
            Self::Raft(p) => &p.partition().compaction_records_dropped_total,
        }
    }

    pub fn set_segment_bytes(&self, bytes: u64) {
        match self {
            Self::Plain(p) => p.segment_bytes.store(bytes, Ordering::Release),
            Self::Raft(p) => p.partition().segment_bytes.store(bytes, Ordering::Release),
        }
    }

    pub fn inner(&self) -> &Arc<Partition> {
        match self {
            Self::Plain(p) => p,
            Self::Raft(p) => p.partition(),
        }
    }

    pub fn open(
        dir: PathBuf,
        id: u32,
        segment_bytes: u64,
        flush_every_records: u32,
        raft: Option<&RaftConfig>,
    ) -> Result<Self> {
        match raft {
            None => Partition::open(dir, id, segment_bytes, flush_every_records).map(Self::Plain),
            Some(cfg) => {
                let raft_cfg = RaftPartitionConfig {
                    node_id: cfg.node_id,
                    peers: cfg.peers.clone(),
                    raft_store_path: cfg.raft_store_dir.join(id.to_string()),
                    timing: cfg.timing,
                    snapshot_after_applies: cfg.snapshot_after_applies,
                };
                RaftPartition::open(dir, id, segment_bytes, flush_every_records, raft_cfg)
                    .map(Self::Raft)
            }
        }
    }

    pub async fn connect_transport(&self, tcfg: RaftTransportConfig) -> Result<()> {
        match self {
            Self::Plain(_) => Ok(()),
            Self::Raft(p) => p.connect_transport(tcfg).await,
        }
    }

    /// Route this partition over a broker-wide hub. A plain partition has no
    /// Raft traffic, so this is a no-op for it.
    pub fn attach_to_hub(&self, hub: &Arc<RaftHub>, group: &str) -> Result<()> {
        match self {
            Self::Plain(_) => Ok(()),
            Self::Raft(p) => p.attach_to_hub(hub, group),
        }
    }

    pub fn is_raft(&self) -> bool {
        matches!(self, Self::Raft(_))
    }

    pub async fn shutdown(&self) {
        if let Self::Raft(p) = self {
            p.shutdown().await;
        }
    }
}
