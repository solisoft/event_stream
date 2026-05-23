use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::auth::AuthMode;
use crate::topic::CleanupPolicy;

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub bind: SocketAddr,

    /// Broker-wide default segment size (overridable per-topic).
    pub segment_bytes: u64,

    /// How often the reaper inspects partitions for retention enforcement.
    pub retention_check_interval: Duration,

    /// How often the compactor inspects partitions for compaction work.
    pub compaction_check_interval: Duration,

    /// Grace period between dropping a segment from the in-memory snapshot and
    /// unlinking the underlying files. Lets in-flight readers finish.
    pub segment_delete_grace: Duration,

    /// Default tombstone retention for compacted topics that don't override it.
    pub default_tombstone_retention_ms: u64,

    /// Defaults applied to topics created without an explicit config.
    pub default_retention_ms: Option<u64>,
    pub default_retention_bytes: Option<u64>,
    pub default_cleanup_policy: CleanupPolicy,

    /// If `Required`, every non-public request must present a valid bearer token.
    /// If `Disabled`, the auth middleware passes through (back-compat default).
    pub auth_mode: AuthMode,

    /// TLS material. When both are set, the server listens with TLS.
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,

    /// How often the producer-state flusher persists registered sequences to disk.
    pub producer_flush_interval: Duration,

    /// Optional TCP listen address for the binary protocol. When unset, only
    /// the HTTP listener is started.
    pub bind_binary: Option<SocketAddr>,

    /// How many appended records to buffer before forcing an `fsync`. `1` is
    /// the safest setting (every record is durable before the producer is
    /// acked) but caps throughput at the disk's fsync rate. Higher values
    /// trade up to N un-acked records on a crash for proportionally higher
    /// throughput. Page-cache visibility (other readers in the same broker)
    /// is independent of this — that always happens on every append.
    pub flush_every_records: u32,

    /// A consumer-group member that hasn't sent a heartbeat within this window
    /// is evicted, triggering a rebalance for that group.
    pub coord_member_timeout: Duration,
    /// How often the coordinator sweeps for stale members.
    pub coord_expire_interval: Duration,
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
            default_tombstone_retention_ms: 24 * 60 * 60 * 1000, // 24h
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
        }
    }
}
