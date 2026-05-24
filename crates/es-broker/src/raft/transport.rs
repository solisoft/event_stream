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
) -> Result<Transport> {
    let listener = TcpListener::bind(bind).await?;
    let cancel = CancellationToken::new();

    // Each peer gets a per-peer mpsc; the dialer task drains it onto its socket.
    let peer_senders: Arc<DashMap<NodeId, mpsc::UnboundedSender<Vec<u8>>>> =
        Arc::new(DashMap::new());

    // --- listener: accept inbound peer connections ---
    {
        let inbound_tx = inbound_tx.clone();
        let cancel = cancel.clone();
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
                        tokio::spawn(async move {
                            if let Err(e) = handle_inbound(sock, inbound_tx, cancel).await {
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
        tokio::spawn(async move {
            dial_loop(
                my_id,
                peer_id,
                peer_addr,
                peer_rx,
                reconnect_backoff,
                cancel,
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

async fn dial_loop(
    me: NodeId,
    peer_id: NodeId,
    peer_addr: SocketAddr,
    mut peer_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    reconnect_backoff: Duration,
    cancel: CancellationToken,
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
        if let Err(e) = run_outbound(sock, me, &mut peer_rx, &cancel).await {
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
) -> std::io::Result<()> {
    // Handshake: send magic + our node id.
    sock.write_all(&RAFT_MAGIC).await?;
    sock.write_all(&me.to_be_bytes()).await?;

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
) -> std::io::Result<()> {
    let _ = sock.set_nodelay(true);
    // Handshake.
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
