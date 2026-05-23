pub mod auth;
pub mod binary;
pub mod broker;
pub mod compaction;
pub mod config;
pub mod groups;
pub mod http;
pub mod partition;
pub mod producers;
pub mod retention;
pub mod storage;
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
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.tls_handle.take() {
            h.graceful_shutdown(Some(std::time::Duration::from_secs(2)));
        }
        // The binary listener watches the broker's cancellation token.
        self.broker.shutdown.cancel();
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
        if let Some(join) = self.binary_join.take() {
            let _ = join.await;
        }
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

/// Spawn a broker. Uses TLS when `config.tls_cert_path` and `config.tls_key_path`
/// are both set; otherwise plain HTTP. Optionally also spawns a binary protocol
/// listener when `config.bind_binary` is set.
pub async fn spawn(config: Config) -> Result<BrokerHandle> {
    let broker = Broker::open(config.clone())?;
    broker.start_background();
    let app = http::router(broker.clone());

    let tls_enabled =
        config.tls_cert_path.is_some() && config.tls_key_path.is_some();

    let (addr, tls_handle, join, shutdown_tx, scheme) = if tls_enabled {
        let cert_path = config.tls_cert_path.clone().unwrap();
        let key_path = config.tls_key_path.clone().unwrap();
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
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
        let listener = TcpListener::bind(bind_bin).await?;
        let bin_addr = listener.local_addr()?;
        let broker_for_binary = broker.clone();
        let cancel = broker.shutdown.clone();
        let join = tokio::spawn(async move {
            binary::serve_binary(broker_for_binary, listener, cancel).await
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
        tls_handle,
        join: Some(join),
        binary_join,
    })
}
