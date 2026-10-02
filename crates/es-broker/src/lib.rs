pub mod auth;
pub mod binary;
pub mod broker;
pub mod compaction;
pub mod config;
pub mod coord;
pub mod dataplane;
pub mod fsutil;
pub mod groups;
pub mod http;
pub mod partition;
pub mod partition_handle;
pub mod producers;
pub mod raft;
pub mod raft_partition;
pub mod retention;
pub mod schema;
pub mod storage;
pub mod tiered_storage;
pub mod topic;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub use broker::Broker;
pub use config::Config;

/// Handle to a running broker.
pub struct BrokerHandle {
    pub addr: SocketAddr,
    pub binary_addr: Option<SocketAddr>,
    pub broker: Arc<Broker>,
    pub scheme: &'static str,
    shutdown: Option<oneshot::Sender<()>>,
    shutdown_timeout: std::time::Duration,
    tls_handle: Option<axum_server::Handle>,
    join: Option<JoinHandle<Result<()>>>,
    binary_join: Option<JoinHandle<Result<()>>>,
}

impl BrokerHandle {
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn base_url(&self) -> String {
        format!("{}://{}", self.scheme, self.addr)
    }

    pub async fn shutdown(mut self) -> Result<()> {
        // Signal listeners to stop accepting new connections.
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        // Tell TLS server to drain (stop accepting, wait for in-flight).
        if let Some(h) = self.tls_handle.take() {
            h.graceful_shutdown(Some(std::time::Duration::from_secs(2)));
        }
        // The binary listener watches the broker's cancellation token.
        self.broker.shutdown.cancel();

        // Wait for HTTP and binary listeners with a timeout.
        let timeout = self.shutdown_timeout;
        let http_done = async {
            if let Some(join) = self.join.take() {
                let _ = join.await;
            }
        };
        let binary_done = async {
            if let Some(join) = self.binary_join.take() {
                let _ = join.await;
            }
        };
        let _ = tokio::time::timeout(timeout, async {
            tokio::join!(http_done, binary_done);
        })
        .await;

        self.broker.shutdown_background().await;
        Ok(())
    }
}

impl Drop for BrokerHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.tls_handle.take() {
            h.shutdown();
        }
        self.broker.shutdown.cancel();
    }
}

fn binary_tls_acceptor(
    cert: &std::path::Path,
    key: &std::path::Path,
) -> Result<tokio_rustls::TlsAcceptor> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("read tls cert {:?}", cert))?
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("parse tls cert {:?}", cert))?;
    let key =
        PrivateKeyDer::from_pem_file(key).with_context(|| format!("read tls key {:?}", key))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build binary listener TLS config")?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
}

/// Spawn a broker. Uses TLS when `config.tls_cert_path` and `config.tls_key_path`
/// are both set; otherwise plain HTTP. Optionally also spawns a binary protocol
/// listener when `config.bind_binary` is set.
pub async fn spawn(config: Config) -> Result<BrokerHandle> {
    config.validate_limits()?;
    if config.tls_cert_path.is_some() != config.tls_key_path.is_some() {
        anyhow::bail!(
            "--tls-cert and --tls-key must be given together: with only one of them the broker \
             would silently serve plaintext"
        );
    }
    if config.auth_mode == auth::AuthMode::Disabled
        && !config.allow_remote_unauthenticated
        && !(config.bind.ip().is_loopback()
            && config.bind_binary.is_none_or(|b| b.ip().is_loopback()))
    {
        anyhow::bail!(
            "refusing to serve without authentication on a non-loopback address: with --auth \
             disabled every caller is an admin. Use --auth required, bind to 127.0.0.1, or pass \
             --allow-remote-unauthenticated if this network is really trusted."
        );
    }
    let broker = Broker::open(config.clone())?;
    // Before the HTTP port opens: a cluster member that cannot reach its peers
    // must not get as far as accepting a write.
    broker.start_raft().await?;
    broker.start_background();
    let app = http::router(broker.clone());

    let tls_enabled = config.tls_cert_path.is_some() && config.tls_key_path.is_some();

    let (addr, tls_handle, join, shutdown_tx, scheme) = if tls_enabled {
        let cert_path = config
            .tls_cert_path
            .as_ref()
            .context("tls_cert_path is None but tls_enabled is true")?
            .clone();
        let key_path = config
            .tls_key_path
            .as_ref()
            .context("tls_key_path is None but tls_enabled is true")?
            .clone();
        let tls_config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                .await
                .with_context(|| format!("load tls cert={:?} key={:?}", cert_path, key_path))?;

        let listener = std::net::TcpListener::bind(config.bind)?;
        let addr = listener.local_addr()?;
        let tls_handle = axum_server::Handle::new();
        let handle_for_serve = tls_handle.clone();
        let (tx, _rx) = oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls_config)
                .handle(handle_for_serve)
                .serve(app.into_make_service())
                .await
                .map_err(anyhow::Error::from)
        });
        (addr, Some(tls_handle), join, tx, "https")
    } else {
        let listener = TcpListener::bind(config.bind).await?;
        let addr = listener.local_addr()?;
        let (tx, rx) = oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await
                .map_err(anyhow::Error::from)
        });
        (addr, None, join, tx, "http")
    };

    let (binary_addr, binary_join) = if let Some(bind_bin) = config.bind_binary {
        // The binary listener uses the same certificate as HTTP. It used to
        // ignore TLS entirely — tokens and records in cleartext on a broker
        // whose operator had configured TLS.
        let tls = match (&config.tls_cert_path, &config.tls_key_path) {
            (Some(c), Some(k)) => Some(binary_tls_acceptor(c, k)?),
            _ => None,
        };
        let listener = TcpListener::bind(bind_bin).await?;
        let bin_addr = listener.local_addr()?;
        let broker_for_binary = broker.clone();
        let cancel = broker.shutdown.clone();
        let join = tokio::spawn(async move {
            binary::serve_binary(broker_for_binary, listener, cancel, tls).await
        });
        (Some(bin_addr), Some(join))
    } else {
        (None, None)
    };

    Ok(BrokerHandle {
        addr,
        binary_addr,
        broker,
        scheme,
        shutdown: Some(shutdown_tx),
        shutdown_timeout: config.shutdown_timeout,
        tls_handle,
        join: Some(join),
        binary_join,
    })
}
