//! TCP transport for Raft RPCs.
//!
//! Per-peer persistent connection. Each node listens on `bind` and dials each
//! peer in its membership list. Connections carry length-prefixed
//! [`Message`](super::messages::Message) frames.
//!
//! Handshake (sender of the connection writes first):
//!
//! ```text
//!   magic: [u8; 4] = "RAFT"
//!   node_id: u32 BE
//! ```
//!
//! Once the handshake is exchanged, every subsequent frame is:
//!
//! ```text
//!   length: u32 BE   bytes of the encoded message body
//!   body: ...        Message::encode() output
//! ```
//!
//! Reconnect policy is simple: on disconnect or dial failure, sleep
//! `reconnect_backoff` and retry. No exponential backoff in step 1.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::messages::{Message, NodeId};
use super::node::Outbound;

const RAFT_MAGIC: [u8; 4] = *b"RAFT";
/// Max accepted length of the handshake shared-secret field.
const MAX_SECRET_LEN: usize = 1024;
/// How long a peer has to complete the handshake before we drop the socket.
/// Bounds slowloris-style holds on the raft listener.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether this address can only be reached from the machine itself.
///
/// The unspecified address (`0.0.0.0`, `::`) is deliberately **not** loopback:
/// it is the value that looks harmless in a config file and binds every
/// interface, including the public one. That is the exact case the old
/// "loopback setups" comment did not cover.
fn bind_is_loopback(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// Constant-time byte-slice equality, so a peer can't learn the shared secret
/// from handshake-rejection timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub struct Transport {
    pub join: JoinHandle<()>,
    pub cancel: CancellationToken,
}

/// Spawn a transport that connects `outbound_rx` and `inbound_tx` to a TCP mesh
/// of Raft peers. `peers` MUST not contain `node_id` itself.
pub async fn spawn_transport(
    node_id: NodeId,
    bind: SocketAddr,
    peers: BTreeMap<NodeId, SocketAddr>,
    inbound_tx: mpsc::UnboundedSender<Message>,
    mut outbound_rx: mpsc::UnboundedReceiver<Outbound>,
    reconnect_backoff: Duration,
    shared_secret: Option<String>,
) -> Result<Transport> {
    // Pre-shared secret both peers must present in the handshake. Without it the
    // raft port accepts any TCP client, letting an attacker inject arbitrary
    // AppendEntries/InstallSnapshot/config-change messages into replicated
    // state.
    //
    // No-auth is still allowed, but only where it was ever defensible: a bind
    // the kernel will not route from off-box. The old comment called it "the
    // (insecure) no-auth behavior for single-node/loopback setups" and then let
    // it apply to `0.0.0.0` too — which on any host with a public address is
    // remote control of the replicated state by anyone who can reach the port.
    //
    // Whether that is safe depends entirely on the bind address, so the code
    // now depends on the bind address rather than on the operator having read
    // a comment.
    let secret: Arc<Option<Vec<u8>>> = Arc::new(
        shared_secret
            .filter(|s| !s.is_empty())
            .map(|s| s.into_bytes()),
    );
    if secret.is_none() && !bind_is_loopback(&bind) {
        anyhow::bail!(
            "refusing to open an unauthenticated raft port on {bind}: no shared secret is \
             configured, and this address is reachable from off-box. Set the cluster shared \
             secret, or bind to 127.0.0.1 for a single-node setup."
        );
    }

    let listener = TcpListener::bind(bind).await?;
    let cancel = CancellationToken::new();

    // Each peer gets a per-peer mpsc; the dialer task drains it onto its socket.
    let peer_senders: Arc<DashMap<NodeId, mpsc::UnboundedSender<Vec<u8>>>> =
        Arc::new(DashMap::new());

    // --- listener: accept inbound peer connections ---
    {
        let inbound_tx = inbound_tx.clone();
        let cancel = cancel.clone();
        let secret = secret.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    res = listener.accept() => {
                        let (sock, _peer) = match res {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::warn!(error = %e, "raft accept failed");
                                continue;
                            }
                        };
                        let inbound_tx = inbound_tx.clone();
                        let cancel = cancel.clone();
                        let secret = secret.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_inbound(sock, inbound_tx, cancel, secret).await {
                                tracing::debug!(error = %e, "raft inbound closed");
                            }
                        });
                    }
                }
            }
        });
    }

    // --- one dialer task per peer ---
    for (peer_id, peer_addr) in peers {
        let (peer_tx, peer_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        peer_senders.insert(peer_id, peer_tx);
        let cancel = cancel.clone();
        let my_id = node_id;
        let secret = secret.clone();
        tokio::spawn(async move {
            dial_loop(
                my_id,
                peer_id,
                peer_addr,
                peer_rx,
                reconnect_backoff,
                cancel,
                secret,
            )
            .await;
        });
    }

    // --- dispatcher: pop Outbound, encode, ship to right peer mpsc ---
    let dispatch_cancel = cancel.clone();
    let dispatch_senders = peer_senders.clone();
    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = dispatch_cancel.cancelled() => break,
                msg = outbound_rx.recv() => {
                    let Some(out) = msg else { break; };
                    match out {
                        Outbound::SendTo(peer_id, msg) => {
                            if let Some(s) = dispatch_senders.get(&peer_id) {
                                let _ = s.send(frame(&msg));
                            }
                        }
                        Outbound::Broadcast(msg) => {
                            let bytes = frame(&msg);
                            for kv in dispatch_senders.iter() {
                                let _ = kv.value().send(bytes.clone());
                            }
                        }
                    }
                }
            }
        }
        tracing::debug!(node = node_id, "raft transport dispatcher exited");
    });
    Ok(Transport { join, cancel })
}

fn frame(msg: &Message) -> Vec<u8> {
    let body = msg.encode();
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

#[allow(clippy::too_many_arguments)]
async fn dial_loop(
    me: NodeId,
    peer_id: NodeId,
    peer_addr: SocketAddr,
    mut peer_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    reconnect_backoff: Duration,
    cancel: CancellationToken,
    secret: Arc<Option<Vec<u8>>>,
) {
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let sock = match TcpStream::connect(peer_addr).await {
            Ok(s) => s,
            Err(e) => {
                tracing::trace!(peer = peer_id, error = %e, "raft dial failed; retrying");
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(reconnect_backoff) => continue,
                }
            }
        };
        let _ = sock.set_nodelay(true);
        if let Err(e) = run_outbound(sock, me, &mut peer_rx, &cancel, &secret).await {
            tracing::debug!(peer = peer_id, error = %e, "raft connection dropped");
        }
        if cancel.is_cancelled() {
            return;
        }
        tokio::time::sleep(reconnect_backoff).await;
    }
}

async fn run_outbound(
    mut sock: TcpStream,
    me: NodeId,
    peer_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    cancel: &CancellationToken,
    secret: &Option<Vec<u8>>,
) -> std::io::Result<()> {
    // Handshake: send magic + our node id + the shared secret.
    sock.write_all(&RAFT_MAGIC).await?;
    sock.write_all(&me.to_be_bytes()).await?;
    let secret_bytes: &[u8] = secret.as_deref().unwrap_or(&[]);
    sock.write_all(&(secret_bytes.len() as u32).to_be_bytes())
        .await?;
    if !secret_bytes.is_empty() {
        sock.write_all(secret_bytes).await?;
    }

    // We don't read from this socket on the dialer side — inbound peer messages
    // arrive on that peer's own outbound-to-us connection (the peer dials us).
    // Just push frames as they come in.
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            msg = peer_rx.recv() => {
                let Some(frame) = msg else { return Ok(()); };
                sock.write_all(&frame).await?;
            }
        }
    }
}

async fn handle_inbound(
    mut sock: TcpStream,
    inbound_tx: mpsc::UnboundedSender<Message>,
    cancel: CancellationToken,
    secret: Arc<Option<Vec<u8>>>,
) -> std::io::Result<()> {
    let _ = sock.set_nodelay(true);
    // Handshake, under a timeout so a peer can't hold the socket open forever
    // by stalling mid-handshake.
    let handshake = async {
        let mut magic = [0u8; 4];
        sock.read_exact(&mut magic).await?;
        if magic != RAFT_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad raft magic",
            ));
        }
        let mut idbuf = [0u8; 4];
        sock.read_exact(&mut idbuf).await?;
        let _peer_id = u32::from_be_bytes(idbuf);

        // Authenticate the peer via the pre-shared secret before we accept any
        // Raft messages from this connection.
        let mut slen_buf = [0u8; 4];
        sock.read_exact(&mut slen_buf).await?;
        let slen = u32::from_be_bytes(slen_buf) as usize;
        if slen > MAX_SECRET_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "raft handshake secret too long",
            ));
        }
        let mut presented = vec![0u8; slen];
        if slen > 0 {
            sock.read_exact(&mut presented).await?;
        }
        let expected: &[u8] = secret.as_deref().unwrap_or(&[]);
        if !constant_time_eq(&presented, expected) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "raft handshake auth failed",
            ));
        }
        Ok(())
    };
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "raft handshake timed out",
            ))
        }
    }

    let mut len_buf = [0u8; 4];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            res = sock.read_exact(&mut len_buf) => {
                match res {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                    Err(e) => return Err(e),
                }
                let n = u32::from_be_bytes(len_buf) as usize;
                if n > 1 << 20 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "raft frame too large",
                    ));
                }
                let mut body = vec![0u8; n];
                sock.read_exact(&mut body).await?;
                let msg = Message::decode(&body).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("decode: {}", e))
                })?;
                if inbound_tx.send(msg).is_err() {
                    return Ok(()); // node loop exited
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::messages::{Message, RequestVote};

    fn sample_msg() -> Message {
        Message::RequestVote(RequestVote {
            term: 99,
            candidate_id: 7,
            last_log_index: 0,
            last_log_term: 0,
        })
    }

    async fn send_handshake(client: &mut TcpStream, node_id: u32, secret: &[u8]) {
        client.write_all(&RAFT_MAGIC).await.unwrap();
        client.write_all(&node_id.to_be_bytes()).await.unwrap();
        client
            .write_all(&(secret.len() as u32).to_be_bytes())
            .await
            .unwrap();
        if !secret.is_empty() {
            client.write_all(secret).await.unwrap();
        }
    }

    #[test]
    fn constant_time_eq_matches_std_eq() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreu"));
        assert!(!constant_time_eq(b"secret", b"secre"));
        assert!(constant_time_eq(b"", b""));
    }

    #[tokio::test]
    async fn rejects_peer_with_wrong_secret() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        let secret = Arc::new(Some(b"correct-secret".to_vec()));

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = handle_inbound(sock, inbound_tx, cancel, secret).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        send_handshake(&mut client, 7, b"wrong-secret").await;
        // Even if the attacker sends a well-formed frame, it must never be
        // delivered because the handshake auth failed.
        let _ = client.write_all(&frame(&sample_msg())).await;

        let got = tokio::time::timeout(Duration::from_millis(300), inbound_rx.recv()).await;
        assert!(
            matches!(got, Ok(None)) || got.is_err(),
            "no message may be delivered when the secret is wrong"
        );
        server.abort();
    }

    #[tokio::test]
    async fn accepts_peer_with_correct_secret() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        let secret = Arc::new(Some(b"correct-secret".to_vec()));

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = handle_inbound(sock, inbound_tx, cancel, secret).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        send_handshake(&mut client, 7, b"correct-secret").await;
        client.write_all(&frame(&sample_msg())).await.unwrap();

        let got = tokio::time::timeout(Duration::from_millis(500), inbound_rx.recv())
            .await
            .expect("message should be delivered within timeout");
        assert!(matches!(got, Some(Message::RequestVote(_))));
        server.abort();
    }
}

#[cfg(test)]
mod bind_guard_tests {
    use super::bind_is_loopback;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_may_run_without_a_secret() {
        // The case the exemption was written for, and the only one where it was
        // ever true: a port the kernel will not route from off-box.
        assert!(bind_is_loopback(&addr("127.0.0.1:9300")));
        assert!(bind_is_loopback(&addr("[::1]:9300")));
    }

    #[test]
    fn the_unspecified_address_is_not_loopback() {
        // The whole point. `0.0.0.0` looks harmless in a config file and binds
        // every interface including the public one — so an unauthenticated
        // raft port there is remote control of the replicated state.
        assert!(!bind_is_loopback(&addr("0.0.0.0:9300")));
        assert!(!bind_is_loopback(&addr("[::]:9300")));
    }

    #[test]
    fn a_routable_address_is_not_loopback() {
        assert!(!bind_is_loopback(&addr("203.0.113.7:9300")));
        assert!(!bind_is_loopback(&addr("10.0.0.7:9300")));
    }
}
