//! Mutual TLS for the Raft transport: one identity per broker.
//!
//! The shared secret proves a broker is a member, not *which* member: every
//! holder can compute every other member's proofs. A certificate per broker,
//! signed by a CA the members trust, closes that gap.
//!
//! # Naming rule
//!
//! A broker's certificate names its node id as a subjectAltName DNS entry,
//! `es-node-<id>` (node 7 is `DNS:es-node-7`). A DNS name rather than a URI or
//! the CN because it is the one form the standard WebPKI name check handles:
//! the dialer verifies the listener with exactly the check a browser makes,
//! and the listener reuses that same check against each member id. The
//! certificate must allow both serverAuth and clientAuth, because every broker
//! both listens and dials.
//!
//! # What each side checks
//!
//! * **Dialer.** The listener's chain ends at the CA, and its certificate
//!   names the node id the dialer meant to reach. A certificate for any other
//!   node fails the TLS handshake.
//! * **Listener.** The dialer presented a certificate, it chains to the CA, and
//!   it names exactly one current member. That member is the peer's id; the id
//!   the dialer announces in the Raft handshake must match it, so holding a
//!   valid certificate for node 2 does not let a broker speak as node 3.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::server::{ParsedCertificate, WebPkiClientVerifier};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::{client, server, TlsAcceptor, TlsConnector};

use super::messages::NodeId;

/// The subjectAltName DNS entry that names node `id`.
pub fn node_name(id: NodeId) -> String {
    format!("es-node-{id}")
}

/// What a broker needs to speak mTLS on the Raft port. Built once at startup.
pub struct RaftTls {
    me: NodeId,
    acceptor: TlsAcceptor,
    connector: TlsConnector,
}

impl fmt::Debug for RaftTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RaftTls").field("me", &self.me).finish()
    }
}

impl RaftTls {
    /// Load `--raft-tls-cert`, `--raft-tls-key` and `--raft-tls-ca`.
    pub fn from_pem_files(me: NodeId, cert: &Path, key: &Path, ca: &Path) -> Result<Self> {
        use rustls_pki_types::pem::PemObject;
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
            .with_context(|| format!("read --raft-tls-cert {}", cert.display()))?
            .collect::<Result<_, _>>()
            .with_context(|| format!("parse --raft-tls-cert {}", cert.display()))?;
        let key = PrivateKeyDer::from_pem_file(key)
            .with_context(|| format!("read --raft-tls-key {}", key.display()))?;
        let roots: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(ca)
            .with_context(|| format!("read --raft-tls-ca {}", ca.display()))?
            .collect::<Result<_, _>>()
            .with_context(|| format!("parse --raft-tls-ca {}", ca.display()))?;
        Self::new(me, certs, key, roots)
    }

    /// Build both sides from DER material: `certs` is this broker's chain,
    /// leaf first, and `roots` the CA certificates that sign members.
    pub fn new(
        me: NodeId,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        roots: Vec<CertificateDer<'static>>,
    ) -> Result<Self> {
        let leaf = certs
            .first()
            .ok_or_else(|| anyhow!("--raft-tls-cert holds no certificate"))?;
        // Refused here, not at the first connection: a certificate that does
        // not name this broker is refused by every peer, and the cluster would
        // look healthy on this node while nobody could replicate to it.
        if !names_node(leaf, me) {
            anyhow::bail!(
                "--raft-tls-cert does not name this broker: node {me} needs a certificate with \
                 subjectAltName DNS:{}",
                node_name(me)
            );
        }
        let mut store = RootCertStore::empty();
        for root in roots {
            store
                .add(root)
                .map_err(|e| anyhow!("--raft-tls-ca: unusable CA certificate: {e}"))?;
        }
        if store.is_empty() {
            anyhow::bail!("--raft-tls-ca holds no certificate");
        }
        let store = Arc::new(store);
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        // TLS 1.3 only: every member runs this same binary, so there is no
        // older peer to be compatible with.
        let verifier = WebPkiClientVerifier::builder_with_provider(store.clone(), provider.clone())
            .build()
            .map_err(|e| anyhow!("raft mTLS client verifier: {e}"))?;
        let server = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs.clone(), key.clone_key())
            .context("--raft-tls-cert / --raft-tls-key do not form a usable server identity")?;
        let client = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(store)
            .with_client_auth_cert(certs, key)
            .context("--raft-tls-cert / --raft-tls-key do not form a usable client identity")?;
        Ok(Self {
            me,
            acceptor: TlsAcceptor::from(Arc::new(server)),
            connector: TlsConnector::from(Arc::new(client)),
        })
    }

    /// Dial side: the handshake fails unless the listener's certificate names
    /// `peer`.
    pub(crate) async fn connect(
        &self,
        peer: NodeId,
        sock: TcpStream,
    ) -> std::io::Result<client::TlsStream<TcpStream>> {
        let name = ServerName::try_from(node_name(peer))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        self.connector.connect(name, sock).await
    }

    /// Listen side: the handshake fails unless the dialer presents a
    /// certificate the CA signed.
    pub(crate) async fn accept(
        &self,
        sock: TcpStream,
    ) -> std::io::Result<server::TlsStream<TcpStream>> {
        self.acceptor.accept(sock).await
    }
}

/// Whether `cert` names node `id`.
pub(crate) fn names_node(cert: &CertificateDer<'_>, id: NodeId) -> bool {
    let Ok(parsed) = ParsedCertificate::try_from(cert) else {
        return false;
    };
    let Ok(name) = ServerName::try_from(node_name(id)) else {
        return false;
    };
    rustls::client::verify_server_name(&parsed, &name).is_ok()
}

/// The one member among `candidates` that `cert` names.
///
/// WebPKI offers no way to list a certificate's names, only to test one, so
/// the listener tests each current member. A certificate naming none is not a
/// member's; one naming several is refused rather than guessed at, because
/// whichever id was picked, the other would be the one it could impersonate.
pub(crate) fn identify(
    cert: &CertificateDer<'_>,
    candidates: impl IntoIterator<Item = NodeId>,
) -> Result<NodeId, String> {
    let named: Vec<NodeId> = candidates
        .into_iter()
        .filter(|id| names_node(cert, *id))
        .collect();
    match named[..] {
        [id] => Ok(id),
        [] => Err("the peer's certificate names no member of this cluster".to_string()),
        _ => Err(format!(
            "the peer's certificate names several members ({named:?}); one certificate must \
             name one broker"
        )),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use rustls_pki_types::pem::PemObject;
    use std::path::PathBuf;

    pub fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/raft-tls")
            .join(name)
    }

    /// The fixture identity of node `n`, presented as node `me`.
    pub fn tls_as(me: NodeId, n: NodeId) -> Result<RaftTls> {
        let certs = CertificateDer::pem_file_iter(fixture(&format!("node{n}.pem")))?
            .collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_file(fixture(&format!("node{n}.key")))?;
        let roots =
            CertificateDer::pem_file_iter(fixture("ca.pem"))?.collect::<Result<Vec<_>, _>>()?;
        // Bypass the startup check so a test can hold a certificate that does
        // not name the id it claims.
        let mut tls = RaftTls::new(n, certs, key, roots)?;
        tls.me = me;
        Ok(tls)
    }

    pub fn tls(n: NodeId) -> Arc<RaftTls> {
        Arc::new(tls_as(n, n).unwrap())
    }

    pub fn leaf(n: NodeId) -> CertificateDer<'static> {
        CertificateDer::pem_file_iter(fixture(&format!("node{n}.pem")))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn a_certificate_names_exactly_its_node() {
        assert!(names_node(&leaf(2), 2));
        assert!(!names_node(&leaf(2), 3));
        assert!(!names_node(&leaf(2), 22), "es-node-22 is not es-node-2");
        assert_eq!(identify(&leaf(2), [1, 2, 3]), Ok(2));
        assert!(identify(&leaf(4), [1, 2, 3]).is_err(), "not a member");
    }

    #[test]
    fn startup_refuses_a_certificate_for_another_node() {
        let err = RaftTls::from_pem_files(
            1,
            &fixture("node2.pem"),
            &fixture("node2.key"),
            &fixture("ca.pem"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("DNS:es-node-1"), "{err}");
        RaftTls::from_pem_files(
            2,
            &fixture("node2.pem"),
            &fixture("node2.key"),
            &fixture("ca.pem"),
        )
        .expect("node 2's own certificate");
    }
}
