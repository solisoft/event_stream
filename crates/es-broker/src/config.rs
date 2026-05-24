use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::auth::AuthMode;
use crate::topic::CleanupPolicy;

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub bind: SocketAddr,

    pub segment_bytes: u64,
    pub retention_check_interval: Duration,
    pub compaction_check_interval: Duration,
    pub segment_delete_grace: Duration,
    pub default_tombstone_retention_ms: u64,
    pub default_retention_ms: Option<u64>,
    pub default_retention_bytes: Option<u64>,
    pub default_cleanup_policy: CleanupPolicy,
    pub auth_mode: AuthMode,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub producer_flush_interval: Duration,
    pub bind_binary: Option<SocketAddr>,
    pub flush_every_records: u32,
    pub coord_member_timeout: Duration,
    pub coord_expire_interval: Duration,
    pub max_request_body_bytes: usize,
    pub shutdown_timeout: Duration,

    /// Raft cluster configuration. When set, topics are created with Raft-backed
    /// partitions. `raft_bind` is the TCP address this broker listens on for
    /// Raft RPCs. `raft_peer_addrs` maps peer node IDs to their Raft addresses.
    pub raft_node_id: Option<u32>,
    pub raft_bind: Option<SocketAddr>,
    pub raft_peer_addrs: BTreeMap<u32, SocketAddr>,

    /// Cold-storage directory for tiered storage. When set, sealed segments are
    /// offloaded here instead of being deleted by retention.
    pub cold_storage_dir: Option<PathBuf>,
}

impl Config {
    pub fn new(data_dir: PathBuf, bind: SocketAddr, segment_bytes: u64) -> Self {
        Self {
            data_dir,
            bind,
            segment_bytes,
            retention_check_interval: Duration::from_secs(30),
            compaction_check_interval: Duration::from_secs(60),
            segment_delete_grace: Duration::from_secs(60),
            default_tombstone_retention_ms: 24 * 60 * 60 * 1000,
            default_retention_ms: None,
            default_retention_bytes: None,
            default_cleanup_policy: CleanupPolicy::Delete,
            auth_mode: AuthMode::Disabled,
            tls_cert_path: None,
            tls_key_path: None,
            producer_flush_interval: Duration::from_secs(2),
            bind_binary: None,
            flush_every_records: 1,
            coord_member_timeout: Duration::from_secs(15),
            coord_expire_interval: Duration::from_secs(2),
            max_request_body_bytes: 10 * 1024 * 1024,
            shutdown_timeout: Duration::from_secs(30),
            raft_node_id: None,
            raft_bind: None,
            raft_peer_addrs: BTreeMap::new(),
            cold_storage_dir: None,
        }
    }
}
