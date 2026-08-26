use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use tokio::signal::unix::{signal, SignalKind};
use tracing_subscriber::EnvFilter;

use es_broker::auth::AuthMode;
use es_broker::{spawn, Config};

#[derive(Parser, Debug)]
#[command(name = "es-broker", about = "Basic event-streaming broker")]
struct Args {
    #[arg(long, default_value = "./data")]
    data_dir: PathBuf,

    #[arg(long, default_value = "127.0.0.1:9000")]
    bind: SocketAddr,

    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    segment_bytes: u64,

    #[arg(long, default_value = "30s", value_parser = parse_duration)]
    retention_check_interval: Duration,

    #[arg(long, default_value = "60s", value_parser = parse_duration)]
    compaction_check_interval: Duration,

    #[arg(long, default_value = "60s", value_parser = parse_duration)]
    segment_delete_grace: Duration,

    #[arg(long, default_value_t = 24 * 60 * 60 * 1000)]
    default_tombstone_retention_ms: u64,

    /// Authentication mode. `disabled` (default) allows every request through.
    /// `required` enforces `Authorization: Bearer <key>` and per-key ACLs.
    #[arg(long, value_enum, default_value_t = AuthFlag::Disabled)]
    auth: AuthFlag,

    /// PEM-encoded server certificate. Setting both `--tls-cert` and `--tls-key`
    /// makes the broker listen with TLS.
    #[arg(long)]
    tls_cert: Option<PathBuf>,

    #[arg(long)]
    tls_key: Option<PathBuf>,

    /// Optional second listener for the high-throughput binary protocol.
    /// When unset, only the HTTP API is available.
    #[arg(long)]
    bind_binary: Option<SocketAddr>,

    /// fsync the active segment every N appended records. 1 = every record
    /// (safest, slowest). Higher values trade up to N records of un-acked work
    /// on crash for proportionally higher throughput.
    #[arg(long, default_value_t = 1)]
    flush_every_records: u32,

    /// Maximum HTTP request body size in bytes (default 10 MiB).
    #[arg(long, default_value_t = 10 * 1024 * 1024)]
    max_request_body_bytes: usize,

    /// Maximum time to wait for graceful shutdown before forcing exit.
    #[arg(long, default_value = "30s", value_parser = parse_duration)]
    shutdown_timeout: Duration,

    /// Cold-storage directory for tiered storage. When set, sealed segments
    /// are offloaded here instead of being deleted by retention.
    #[arg(long)]
    cold_storage_dir: Option<PathBuf>,

    /// Pre-shared secret peers must present in the Raft transport handshake.
    /// Strongly recommended whenever Raft peers talk over an untrusted network —
    /// without it the raft port accepts messages from any client.
    #[arg(long, env = "ES_RAFT_SHARED_SECRET")]
    raft_shared_secret: Option<String>,

    /// This broker's Raft node id, unique in the cluster. Setting it makes every
    /// topic on this broker a replicated one; leaving it unset runs a
    /// single-node broker.
    #[arg(long)]
    raft_node_id: Option<u32>,

    /// Address this broker listens on for Raft RPCs from its peers. All groups
    /// share this one port — the group name travels in each frame.
    #[arg(long)]
    raft_bind: Option<SocketAddr>,

    /// A peer, as `<node-id>=<host:port>`. Repeat once per other member. The
    /// membership is this node plus exactly these peers, so a member with no
    /// address cannot be declared.
    #[arg(long = "raft-peer", value_parser = parse_raft_peer)]
    raft_peers: Vec<(u32, SocketAddr)>,
}

/// Parse `<node-id>=<host:port>`.
fn parse_raft_peer(s: &str) -> Result<(u32, SocketAddr), String> {
    let (id, addr) = s
        .split_once('=')
        .ok_or_else(|| format!("expected <node-id>=<host:port>, got '{s}'"))?;
    let id: u32 = id
        .trim()
        .parse()
        .map_err(|_| format!("'{id}' is not a node id"))?;
    if id == 0 {
        return Err("node id 0 is the 'no leader known' sentinel and cannot name a peer".into());
    }
    let addr: SocketAddr = addr
        .trim()
        .parse()
        .map_err(|_| format!("'{addr}' is not a host:port address"))?;
    Ok((id, addr))
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AuthFlag {
    Disabled,
    Required,
}

impl AuthFlag {
    fn into_mode(self) -> AuthMode {
        match self {
            Self::Disabled => AuthMode::Disabled,
            Self::Required => AuthMode::Required,
        }
    }
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    humantime::parse_duration(s).map_err(|e| format!("invalid duration '{}': {}", s, e))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Log panics with backtrace instead of letting them go to stderr silently.
    std::panic::set_hook(Box::new(|info| {
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic payload".to_string()
        };
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_default();
        tracing::error!(%payload, %location, "panic");
        // Also print to stderr so it is visible even if the subscriber is gone.
        eprintln!("panic at {location}: {payload}");
    }));

    // rustls needs a default crypto provider installed before use.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();
    let mut config = Config::new(args.data_dir, args.bind, args.segment_bytes);
    config.retention_check_interval = args.retention_check_interval;
    config.compaction_check_interval = args.compaction_check_interval;
    config.segment_delete_grace = args.segment_delete_grace;
    config.default_tombstone_retention_ms = args.default_tombstone_retention_ms;
    config.auth_mode = args.auth.into_mode();
    config.tls_cert_path = args.tls_cert;
    config.tls_key_path = args.tls_key;
    config.bind_binary = args.bind_binary;
    config.flush_every_records = args.flush_every_records;
    config.max_request_body_bytes = args.max_request_body_bytes;
    config.shutdown_timeout = args.shutdown_timeout;
    config.cold_storage_dir = args.cold_storage_dir;
    config.raft_shared_secret = args.raft_shared_secret;
    config.raft_node_id = args.raft_node_id;
    config.raft_bind = args.raft_bind;
    for (id, addr) in args.raft_peers {
        if let Some(prev) = config.raft_peer_addrs.insert(id, addr) {
            anyhow::bail!(
                "--raft-peer {id} was given twice ({prev} then {addr}); one address per peer"
            );
        }
    }
    // Refuse here rather than at the first append: a broker that got its
    // cluster settings wrong must not reach the point of accepting writes.
    config.validate_raft()?;

    if config.auth_mode == AuthMode::Disabled {
        tracing::warn!(
            "authentication is DISABLED (--auth disabled): every request is treated as an \
             admin with full access. Use `--auth required` on any non-trusted network."
        );
    }
    if config.bind_binary.is_some() && config.tls_cert_path.is_none() {
        tracing::warn!(
            "binary protocol listener is plaintext (no TLS): API tokens and record data are \
             sent unencrypted. Restrict it to a trusted network."
        );
    }

    let handle = spawn(config).await?;
    tracing::info!(addr = %handle.addr, scheme = handle.scheme, "broker listening");
    if let Some(bin_addr) = handle.binary_addr {
        tracing::info!(addr = %bin_addr, "broker binary protocol listening");
    }

    // Wait for SIGINT or SIGTERM.
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = sigint.recv() => {
            tracing::info!("SIGINT received, shutting down");
        }
        _ = sigterm.recv() => {
            tracing::info!("SIGTERM received, shutting down");
        }
    }

    handle.shutdown().await?;
    Ok(())
}
