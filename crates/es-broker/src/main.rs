use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches, Parser, ValueEnum};
use tokio::signal::unix::{signal, SignalKind};
use tracing_subscriber::EnvFilter;

use es_broker::auth::AuthMode;
use es_broker::raft::SharedSecret;
use es_broker::{spawn, Config};

#[derive(Parser, Debug)]
#[command(name = "es-broker", version, about = "Basic event-streaming broker")]
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

    /// Largest record (key + value bytes) accepted on either protocol.
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    max_record_bytes: usize,

    /// Most bytes one consume request returns, whatever it asks for.
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    max_fetch_bytes: usize,

    /// Most records one consume request returns.
    #[arg(long, default_value_t = 10_000)]
    max_fetch_records: usize,

    /// With --flush-every-records > 1: fsync unsynced records at least this
    /// often, so an idle partition does not hold acknowledged records only in
    /// memory.
    #[arg(long, default_value = "1s", value_parser = parse_duration)]
    flush_interval: Duration,

    /// Origin allowed to call the HTTP API from a browser (repeatable). None
    /// by default: no CORS headers are sent.
    #[arg(long = "cors-origin")]
    cors_origins: Vec<String>,

    /// Extra host name the HTTP API answers to while auth is disabled
    /// (repeatable). Loopback names are always accepted.
    #[arg(long = "allowed-host")]
    allowed_hosts: Vec<String>,

    /// Permit --auth disabled on a non-loopback address. Every caller is then
    /// an admin; only for networks where that is acceptable.
    #[arg(long)]
    allow_remote_unauthenticated: bool,

    /// Binary protocol: most connections from one IP address.
    #[arg(long, default_value_t = 256)]
    binary_max_connections_per_ip: usize,

    /// Binary protocol: close a connection idle for this long.
    #[arg(long, default_value = "10m", value_parser = parse_duration)]
    binary_idle_timeout: Duration,

    /// Maximum time to wait for graceful shutdown before forcing exit.
    #[arg(long, default_value = "30s", value_parser = parse_duration)]
    shutdown_timeout: Duration,

    /// Cold-storage directory for tiered storage. When set, sealed segments
    /// are offloaded here instead of being deleted by retention.
    #[arg(long)]
    cold_storage_dir: Option<PathBuf>,

    /// Pre-shared secret peers must present in the Raft transport handshake,
    /// at least 32 bytes (`openssl rand -hex 32`). Required unless --raft-bind
    /// is loopback. Prefer the environment variable or
    /// --raft-shared-secret-file: a value on the command line is visible to
    /// every local account in `ps`.
    #[arg(
        long,
        env = "ES_RAFT_SHARED_SECRET",
        hide_env_values = true,
        value_parser = secret_arg,
        conflicts_with = "raft_shared_secret_file"
    )]
    raft_shared_secret: Option<SecretArg>,

    /// File holding the Raft shared secret (a trailing newline is ignored).
    /// It must be readable by its owner only (chmod 600).
    #[arg(long, env = "ES_RAFT_SHARED_SECRET_FILE")]
    raft_shared_secret_file: Option<PathBuf>,

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

    /// A peer's client-facing HTTP API, as `<node-id>=<http(s)://host:port>`.
    /// Repeat once per peer. A produce sent to a follower is forwarded there
    /// when that peer leads the partition; without it, the produce fails with
    /// a retryable "not leader" error. Must be https when this broker serves
    /// TLS.
    #[arg(long = "raft-peer-api", value_parser = parse_raft_peer_api)]
    raft_peer_apis: Vec<(u32, String)>,

    /// PEM file of the certificate authorities trusted when forwarding to an
    /// https peer API. Without it, the public web roots are trusted.
    #[arg(long)]
    raft_peer_api_ca: Option<PathBuf>,

    /// This broker's Raft certificate (PEM, leaf first). It must name the broker
    /// as subjectAltName DNS:es-node-<id> and allow serverAuth and clientAuth.
    /// With --raft-tls-key and --raft-tls-ca, every Raft connection is mutual
    /// TLS and a member can no longer act as another.
    #[arg(long, requires_all = ["raft_tls_key", "raft_tls_ca"])]
    raft_tls_cert: Option<PathBuf>,

    /// Private key for --raft-tls-cert (PEM).
    #[arg(long, requires_all = ["raft_tls_cert", "raft_tls_ca"])]
    raft_tls_key: Option<PathBuf>,

    /// CA certificate(s) that sign every member's Raft certificate (PEM).
    #[arg(long, requires_all = ["raft_tls_cert", "raft_tls_key"])]
    raft_tls_ca: Option<PathBuf>,

    /// Accept the 0.2 Raft handshake, and use it to reach brokers still on 0.2.
    /// Only while upgrading a cluster from 0.2.1 one broker at a time; remove it
    /// once every member runs 0.3. Deprecated: removed in 0.4.
    #[arg(long)]
    raft_legacy_handshake: bool,

    /// Join a running cluster: start outside its membership, with --raft-peer
    /// naming the current members, and wait to be added with
    /// `POST /admin/raft/members` on the leaders. Without it a new broker counts
    /// itself a voter from the start, and campaigns.
    #[arg(long)]
    raft_join: bool,
}

/// A secret as clap received it. Kept opaque until it is checked, so neither
/// `Args`' `Debug` nor a clap parse error can print it: clap quotes the
/// rejected value in its errors, which is why the length check happens after
/// parsing, in [`SharedSecret::new`], whose refusal does not repeat it.
#[derive(Clone)]
struct SecretArg(String);

impl std::fmt::Debug for SecretArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

fn secret_arg(s: &str) -> Result<SecretArg, std::convert::Infallible> {
    Ok(SecretArg(s.to_string()))
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

/// Parse `<node-id>=<http(s)://host:port>`. The URL itself is checked by
/// `Config::validate_raft`, with the rest of the cluster settings.
fn parse_raft_peer_api(s: &str) -> Result<(u32, String), String> {
    let (id, url) = s
        .split_once('=')
        .ok_or_else(|| format!("expected <node-id>=<http(s)://host:port>, got '{s}'"))?;
    let id: u32 = id
        .trim()
        .parse()
        .map_err(|_| format!("'{id}' is not a node id"))?;
    Ok((id, url.trim().trim_end_matches('/').to_string()))
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

/// Raise the soft open-file limit to the hard one. Every segment holds a read
/// handle and every binary connection a socket; the common default soft limit
/// of 1024 is reached long before either budget is.
fn raise_fd_limit() {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain libc calls on a stack struct.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
            return;
        }
        if rl.rlim_cur < rl.rlim_max {
            let wanted = libc::rlimit {
                rlim_cur: rl.rlim_max,
                rlim_max: rl.rlim_max,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &wanted) == 0 {
                tracing::info!(
                    from = rl.rlim_cur,
                    to = rl.rlim_max,
                    "raised open-file limit"
                );
            }
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

    let matches = Args::command().get_matches();
    let secret_on_argv =
        matches.value_source("raft_shared_secret") == Some(ValueSource::CommandLine);
    let args = Args::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
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
    config.max_record_bytes = args.max_record_bytes;
    config.max_fetch_bytes = args.max_fetch_bytes;
    config.max_fetch_records = args.max_fetch_records.max(1);
    config.flush_interval = args.flush_interval;
    config.cors_allowed_origins = args.cors_origins;
    config.allowed_hosts = args.allowed_hosts;
    config.allow_remote_unauthenticated = args.allow_remote_unauthenticated;
    config.binary_max_connections_per_ip = args.binary_max_connections_per_ip;
    config.binary_idle_timeout = args.binary_idle_timeout;
    if secret_on_argv {
        tracing::warn!(
            "the raft shared secret was given with --raft-shared-secret: every local account can \
             read it from the process list. Use ES_RAFT_SHARED_SECRET or \
             --raft-shared-secret-file instead."
        );
    }
    config.raft_shared_secret = match (args.raft_shared_secret, args.raft_shared_secret_file) {
        (Some(arg), _) => Some(SharedSecret::new(arg.0)?),
        (None, Some(path)) => Some(SharedSecret::from_file(&path)?),
        (None, None) => None,
    };
    config.raft_node_id = args.raft_node_id;
    config.raft_bind = args.raft_bind;
    config.raft_tls_cert = args.raft_tls_cert;
    config.raft_tls_key = args.raft_tls_key;
    config.raft_tls_ca = args.raft_tls_ca;
    config.raft_legacy_handshake = args.raft_legacy_handshake;
    config.raft_join = args.raft_join;
    for (id, addr) in args.raft_peers {
        if let Some(prev) = config.raft_peer_addrs.insert(id, addr) {
            anyhow::bail!(
                "--raft-peer {id} was given twice ({prev} then {addr}); one address per peer"
            );
        }
    }
    for (id, url) in args.raft_peer_apis {
        if let Some(prev) = config.raft_peer_apis.insert(id, url.clone()) {
            anyhow::bail!(
                "--raft-peer-api {id} was given twice ({prev} then {url}); one address per peer"
            );
        }
    }
    config.raft_peer_api_ca = args.raft_peer_api_ca;
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
            "binary protocol listener is plaintext (no --tls-cert/--tls-key): API tokens and \
             record data are sent unencrypted. Restrict it to a trusted network."
        );
    }
    if config.raft_node_id.is_some() && config.raft_tls().is_none() {
        tracing::warn!(
            "raft replication traffic is authenticated but not encrypted, and members share one \
             identity: keep --raft-bind on a private network, or set --raft-tls-cert, \
             --raft-tls-key and --raft-tls-ca"
        );
    }
    raise_fd_limit();

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
