use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use tracing_subscriber::EnvFilter;

use es_broker::{Config, spawn};
use es_broker::auth::AuthMode;

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
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

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

    let handle = spawn(config).await?;
    tracing::info!(addr = %handle.addr, scheme = handle.scheme, "broker listening");
    if let Some(bin_addr) = handle.binary_addr {
        tracing::info!(addr = %bin_addr, "broker binary protocol listening");
    }

    tokio::signal::ctrl_c().await?;
    tracing::info!("ctrl-c received, shutting down");
    handle.shutdown().await?;
    Ok(())
}
