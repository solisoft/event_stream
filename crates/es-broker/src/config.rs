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

    /// Raft cluster configuration. When `raft_node_id` is set, every topic on
    /// this broker is created with Raft-backed partitions. `raft_bind` is the
    /// TCP address this broker listens on for Raft RPCs. `raft_peer_addrs` maps
    /// peer node IDs to their Raft addresses.
    ///
    /// The membership is this node plus exactly the peers listed here. There is
    /// deliberately no way to name a member without giving its address: a member
    /// that counts toward a quorum but has no address is a vote the node can
    /// never collect, and the cluster would stall with every process reporting
    /// healthy.
    pub raft_node_id: Option<u32>,
    pub raft_bind: Option<SocketAddr>,
    pub raft_peer_addrs: BTreeMap<u32, SocketAddr>,

    /// Pre-shared secret that peers must present in the Raft transport
    /// handshake. When `None`, the raft port performs no peer authentication
    /// (only safe on a fully trusted/loopback network).
    pub raft_shared_secret: Option<String>,

    /// Cold-storage directory for tiered storage. When set, sealed segments are
    /// offloaded here instead of being deleted by retention.
    pub cold_storage_dir: Option<PathBuf>,
}

impl Config {
    /// Reject Raft settings that cannot form a working cluster.
    ///
    /// Every one of these would otherwise produce a broker that starts, reports
    /// healthy, and replicates nothing — so they are refusals, not warnings.
    pub fn validate_raft(&self) -> anyhow::Result<()> {
        match (self.raft_node_id, self.raft_bind) {
            (Some(_), None) => anyhow::bail!(
                "--raft-node-id was given without --raft-bind: the node has an identity but no \
                 address to be reached at, so no peer could ever replicate to it"
            ),
            (None, Some(_)) => anyhow::bail!(
                "--raft-bind was given without --raft-node-id: a Raft member needs an id, and \
                 without one this broker would serve every topic from its own unreplicated copy"
            ),
            (None, None) => {
                if !self.raft_peer_addrs.is_empty() {
                    anyhow::bail!(
                        "--raft-peer was given without --raft-node-id: peers were named but this \
                         broker is not a cluster member, so nothing would be replicated"
                    );
                }
                return Ok(());
            }
            (Some(_), Some(_)) => {}
        }

        let node_id = self.raft_node_id.unwrap();
        if node_id == 0 {
            anyhow::bail!("--raft-node-id must not be 0: 0 is the 'no leader known' sentinel");
        }
        if self.raft_peer_addrs.contains_key(&node_id) {
            anyhow::bail!(
                "node {node_id} is listed in --raft-peer as one of its own peers: it would dial \
                 itself and count its own vote twice"
            );
        }

        let bind = self.raft_bind.unwrap();
        for (peer, addr) in &self.raft_peer_addrs {
            if *addr == bind {
                anyhow::bail!(
                    "peer {peer} has the same address as --raft-bind ({addr}): two members cannot \
                     share one address"
                );
            }
        }
        // Two peers sharing an address is the copy-paste mistake this catches:
        // the second entry silently shadows nothing, both dial the same process,
        // and a three-member cluster is really two.
        let mut seen: BTreeMap<SocketAddr, u32> = BTreeMap::new();
        for (peer, addr) in &self.raft_peer_addrs {
            if let Some(other) = seen.insert(*addr, *peer) {
                anyhow::bail!(
                    "peers {other} and {peer} share the address {addr}: the cluster has fewer \
                     members than it is configured for"
                );
            }
        }

        let members = self.raft_peer_addrs.len() + 1;
        if members.is_multiple_of(2) {
            tracing::warn!(
                members,
                "an even member count survives no more failures than {} would, and costs more",
                members - 1
            );
        }
        Ok(())
    }

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
            raft_shared_secret: None,
            cold_storage_dir: None,
        }
    }
}
