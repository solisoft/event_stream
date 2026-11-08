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

    /// Largest record (key + value bytes) accepted on either protocol. Records
    /// above it are refused at produce time — anything stored must also be
    /// readable, and fit in a Raft frame.
    pub max_record_bytes: usize,
    /// Upper bound on what one consume request may return, whatever it asks.
    pub max_fetch_bytes: usize,
    pub max_fetch_records: usize,
    /// With `flush_every_records > 1`, fsync partitions with unsynced records
    /// at least this often, so an idle partition does not keep acknowledged
    /// records only in the page cache.
    pub flush_interval: Duration,

    /// Origins allowed to call the HTTP API from a browser. Empty (the
    /// default) sends no CORS headers at all.
    pub cors_allowed_origins: Vec<String>,
    /// Host names (without port) the HTTP API answers to when auth is
    /// disabled, on top of the loopback names. Guards against DNS rebinding.
    pub allowed_hosts: Vec<String>,

    /// Allow `auth_mode = Disabled` on a non-loopback bind. Off by default:
    /// with auth disabled every caller is an admin.
    pub allow_remote_unauthenticated: bool,

    /// Binary protocol: connections allowed from one IP address.
    pub binary_max_connections_per_ip: usize,
    /// Binary protocol: an authenticated connection with no request for this
    /// long is closed.
    pub binary_idle_timeout: Duration,

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
    /// handshake. When `None`, the raft port performs no peer authentication,
    /// which the transport allows only on a loopback bind. The type refuses a
    /// secret shorter than [`crate::raft::secret::MIN_SECRET_BYTES`] and
    /// keeps it out of this struct's `Debug` output.
    pub raft_shared_secret: Option<crate::raft::SharedSecret>,

    /// Per-broker identity on the Raft port: this broker's certificate and key,
    /// and the CA that signs every member's. All three or none. See
    /// [`crate::raft::tls`] for the naming rule.
    pub raft_tls_cert: Option<PathBuf>,
    pub raft_tls_key: Option<PathBuf>,
    pub raft_tls_ca: Option<PathBuf>,

    /// Accept the 0.2 Raft handshake, and use it to reach 0.2 brokers. Only
    /// for a rolling upgrade from 0.2.1; deprecated, removed in 0.4.
    pub raft_legacy_handshake: bool,

    /// Cold-storage directory for tiered storage. When set, sealed segments are
    /// offloaded here instead of being deleted by retention.
    pub cold_storage_dir: Option<PathBuf>,
}

impl Config {
    /// Reject limits that contradict each other.
    pub fn validate_limits(&self) -> anyhow::Result<()> {
        // A record must fit in one Raft frame and one binary-protocol frame,
        // with room for headers.
        let cap = 32 * 1024 * 1024;
        if self.max_record_bytes == 0 || self.max_record_bytes > cap {
            anyhow::bail!("--max-record-bytes must be 1..={cap}");
        }
        if self.max_fetch_bytes == 0 || self.max_fetch_bytes > cap {
            anyhow::bail!("--max-fetch-bytes must be 1..={cap}");
        }
        Ok(())
    }

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
                let any_tls = self.raft_tls_cert.is_some()
                    || self.raft_tls_key.is_some()
                    || self.raft_tls_ca.is_some();
                if any_tls || self.raft_legacy_handshake {
                    anyhow::bail!(
                        "--raft-tls-* or --raft-legacy-handshake was given without \
                         --raft-node-id: they configure a Raft port this broker does not open"
                    );
                }
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

        // Two of three is the mistake this catches: a broker with a
        // certificate but no CA would trust nothing, and one with a CA but no
        // certificate could prove nothing — either way no peer connects.
        let tls_given = [
            self.raft_tls_cert.is_some(),
            self.raft_tls_key.is_some(),
            self.raft_tls_ca.is_some(),
        ];
        if tls_given.iter().any(|g| *g) && !tls_given.iter().all(|g| *g) {
            anyhow::bail!(
                "--raft-tls-cert, --raft-tls-key and --raft-tls-ca must be given together: mTLS \
                 needs this broker's identity and the CA that signs every member's"
            );
        }
        if self.raft_tls().is_some() && self.raft_legacy_handshake {
            anyhow::bail!(
                "--raft-legacy-handshake cannot be combined with --raft-tls-*: a 0.2 broker cannot \
                 speak TLS. Finish the upgrade, then enable mTLS on every member."
            );
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

    /// The mTLS files, when all three are set.
    pub fn raft_tls(&self) -> Option<(&PathBuf, &PathBuf, &PathBuf)> {
        match (&self.raft_tls_cert, &self.raft_tls_key, &self.raft_tls_ca) {
            (Some(c), Some(k), Some(ca)) => Some((c, k, ca)),
            _ => None,
        }
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
            max_record_bytes: 8 * 1024 * 1024,
            max_fetch_bytes: 8 * 1024 * 1024,
            max_fetch_records: 10_000,
            flush_interval: Duration::from_secs(1),
            cors_allowed_origins: Vec::new(),
            allowed_hosts: Vec::new(),
            allow_remote_unauthenticated: false,
            binary_max_connections_per_ip: 256,
            binary_idle_timeout: Duration::from_secs(600),
            raft_node_id: None,
            raft_bind: None,
            raft_peer_addrs: BTreeMap::new(),
            raft_shared_secret: None,
            raft_tls_cert: None,
            raft_tls_key: None,
            raft_tls_ca: None,
            raft_legacy_handshake: false,
            cold_storage_dir: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member() -> Config {
        let mut c = Config::new("/tmp".into(), "127.0.0.1:9000".parse().unwrap(), 1024);
        c.raft_node_id = Some(1);
        c.raft_bind = Some("127.0.0.1:6000".parse().unwrap());
        c
    }

    #[test]
    fn raft_tls_needs_all_three_files() {
        let mut c = member();
        c.raft_tls_cert = Some("node1.pem".into());
        c.raft_tls_key = Some("node1.key".into());
        let err = c.validate_raft().unwrap_err().to_string();
        assert!(err.contains("must be given together"), "{err}");
        c.raft_tls_ca = Some("ca.pem".into());
        c.validate_raft().unwrap();
    }

    #[test]
    fn raft_tls_and_the_legacy_handshake_exclude_each_other() {
        let mut c = member();
        c.raft_tls_cert = Some("node1.pem".into());
        c.raft_tls_key = Some("node1.key".into());
        c.raft_tls_ca = Some("ca.pem".into());
        c.raft_legacy_handshake = true;
        let err = c.validate_raft().unwrap_err().to_string();
        assert!(err.contains("cannot speak TLS"), "{err}");
    }

    #[test]
    fn raft_transport_flags_need_a_raft_node() {
        let mut c = Config::new("/tmp".into(), "127.0.0.1:9000".parse().unwrap(), 1024);
        c.raft_legacy_handshake = true;
        assert!(c.validate_raft().is_err());
    }
}
