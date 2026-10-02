//! TCP transport for Raft RPCs.
//!
//! One [`RaftHub`] per broker: a single listener, one persistent connection per
//! peer, and **many Raft groups multiplexed over them**. A group is one
//! replicated partition, named `"<topic>/<partition>"`, and each frame carries
//! that name so the receiver can route it.
//!
//! # Handshake (version 2)
//!
//! The dialer opens the connection; the shared secret never crosses the wire.
//!
//! ```text
//!   dialer   → listener : "RAF2" | dialer_id u32 | nonce_d [32]
//!   listener → dialer   : "RAF2" | listener_id u32 | nonce_l [32]
//!                         | HMAC(secret, "listener" | nonce_d | nonce_l | ids)
//!   dialer   → listener : HMAC(secret, "dialer" | nonce_d | nonce_l | ids)
//! ```
//!
//! Each side proves knowledge of the secret against a nonce the other chose,
//! so a recorded handshake cannot be replayed and an impostor listener learns
//! nothing it could reuse. The dialer checks the listener is the node it meant
//! to reach; the listener checks the dialer is a configured peer. Both ids are
//! bound into the session.
//!
//! # Frames
//!
//! ```text
//!   length: u32 BE      bytes of everything after this field
//!   group_len: u16 BE   bytes of the group name
//!   group: ...          UTF-8, e.g. "events/0"
//!   body: ...           Message::encode() output
//!   mac: [32]           HMAC(session_key, seq u64 BE | group_len..body)
//! ```
//!
//! `session_key` is derived from both nonces, and `seq` counts frames on the
//! connection: a frame cannot be injected, replayed from another session, or
//! reordered. Every message must name the authenticated dialer as its sender —
//! a peer cannot speak for another node.
//!
//! Without a shared secret (allowed only on a loopback bind) the same exchange
//! runs with an empty key: no authentication, but the same framing.
//!
//! A frame for a group this node has not registered is **dropped**, not an
//! error: during startup a peer may reach us before we have opened that topic,
//! and Raft retries. Dropping is the same outcome as a lost packet.
//!
//! Records travel in cleartext. Run the raft port on a private network.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::messages::{Message, NodeId};
use super::node::Outbound;

const RAFT_MAGIC: [u8; 4] = *b"RAF2";
const NONCE_LEN: usize = 32;
const MAC_LEN: usize = 32;
/// Max accepted length of a frame's group name. A topic name is already
/// validated well below this; the cap exists so a hostile peer cannot make us
/// allocate on its say-so before the frame is even parsed.
const MAX_GROUP_LEN: usize = 512;
/// Largest frame accepted. AppendEntries batches are capped well below this
/// (see `state::MAX_APPEND_BYTES`); the margin is for a single large record.
pub const MAX_RAFT_FRAME: usize = 64 * 1024 * 1024;
/// Frames queued per peer before new ones are dropped. Raft tolerates loss;
/// it does not tolerate a queue growing without bound behind a dead peer.
const PEER_QUEUE: usize = 4096;
/// A write that does not complete in this long means the peer is not reading:
/// drop the connection and redial instead of blocking behind it.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Concurrent inbound connections (handshaking or established).
const MAX_INBOUND_CONNECTIONS: usize = 256;
/// Group name used by [`spawn_transport`], the single-group convenience path.
pub const DEFAULT_GROUP: &str = "default";

/// The Raft group a frame belongs to: one replicated partition.
pub fn group_key(topic: &str, partition: u32) -> String {
    format!("{topic}/{partition}")
}
/// How long a peer has to complete the handshake before we drop the socket.
/// Bounds slowloris-style holds on the raft listener.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether this address can only be reached from the machine itself.
///
/// The unspecified address (`0.0.0.0`, `::`) is deliberately **not** loopback:
/// it is the value that looks harmless in a config file and binds every
/// interface, including the public one.
fn bind_is_loopback(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// Constant-time byte-slice equality.
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

/// HMAC-SHA256 (RFC 2104) over the concatenation of `parts`.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    for p in parts {
        inner.update(p);
    }
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(ih);
    outer.finalize().into()
}

/// The handshake transcript both proofs and the session key are bound to.
fn derive(
    secret: &[u8],
    label: &[u8],
    nd: &[u8],
    nl: &[u8],
    dialer: NodeId,
    listener: NodeId,
) -> [u8; 32] {
    hmac_sha256(
        secret,
        &[
            b"es-raft-v2/",
            label,
            nd,
            nl,
            &dialer.to_be_bytes(),
            &listener.to_be_bytes(),
        ],
    )
}

fn invalid(m: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string())
}

/// Seals frames for one direction of an authenticated session.
pub struct FrameSealer {
    key: [u8; 32],
    seq: u64,
}

impl FrameSealer {
    /// Frame an already-encoded `group_len | group | body` payload.
    fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
        let mac = hmac_sha256(&self.key, &[&self.seq.to_be_bytes(), payload]);
        self.seq += 1;
        let total = payload.len() + MAC_LEN;
        let mut out = Vec::with_capacity(4 + total);
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(&mac);
        out
    }

    /// Frame a message for `group`.
    pub fn frame(&mut self, group: &str, msg: &Message) -> Vec<u8> {
        self.seal(&encode_payload(group, msg))
    }
}

struct FrameOpener {
    key: [u8; 32],
    seq: u64,
}

impl FrameOpener {
    /// Verify a frame (everything after the length) and return its payload.
    fn open<'a>(&mut self, frame: &'a [u8]) -> std::io::Result<&'a [u8]> {
        if frame.len() < MAC_LEN {
            return Err(invalid("raft frame shorter than its MAC"));
        }
        let (payload, mac) = frame.split_at(frame.len() - MAC_LEN);
        let expected = hmac_sha256(&self.key, &[&self.seq.to_be_bytes(), payload]);
        if !constant_time_eq(mac, &expected) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "raft frame failed authentication",
            ));
        }
        self.seq += 1;
        Ok(payload)
    }
}

fn encode_payload(group: &str, msg: &Message) -> Vec<u8> {
    let body = msg.encode();
    let mut out = Vec::with_capacity(2 + group.len() + body.len());
    out.extend_from_slice(&(group.len() as u16).to_be_bytes());
    out.extend_from_slice(group.as_bytes());
    out.extend_from_slice(&body);
    out
}

/// Split a frame payload into its group name and message body.
fn split_frame(payload: &[u8]) -> std::io::Result<(&str, &[u8])> {
    if payload.len() < 2 {
        return Err(invalid("raft frame shorter than its group header"));
    }
    let glen = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if glen == 0 || glen > MAX_GROUP_LEN || payload.len() < 2 + glen {
        return Err(invalid("raft frame group name length out of range"));
    }
    let group = std::str::from_utf8(&payload[2..2 + glen])
        .map_err(|_| invalid("raft frame group name is not utf-8"))?;
    Ok((group, &payload[2 + glen..]))
}

/// Who this node is and whom it accepts.
struct HubAuth {
    me: NodeId,
    secret: Vec<u8>,
    peers: BTreeSet<NodeId>,
}

/// Run the dialer side of the handshake. Returns the sealer for frames sent on
/// this connection.
pub async fn dialer_handshake(
    sock: &mut TcpStream,
    me: NodeId,
    expected_peer: NodeId,
    secret: &[u8],
) -> std::io::Result<FrameSealer> {
    let mut nd = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nd);
    let fut = async {
        let mut hello = Vec::with_capacity(4 + 4 + NONCE_LEN);
        hello.extend_from_slice(&RAFT_MAGIC);
        hello.extend_from_slice(&me.to_be_bytes());
        hello.extend_from_slice(&nd);
        sock.write_all(&hello).await?;

        let mut reply = [0u8; 4 + 4 + NONCE_LEN + MAC_LEN];
        sock.read_exact(&mut reply).await?;
        if reply[0..4] != RAFT_MAGIC {
            return Err(invalid("bad raft magic from listener"));
        }
        let listener = u32::from_be_bytes(reply[4..8].try_into().unwrap());
        let nl = &reply[8..8 + NONCE_LEN];
        let proof_l = &reply[8 + NONCE_LEN..];
        if listener != expected_peer {
            return Err(invalid("raft listener is not the node we dialed"));
        }
        let expected = derive(secret, b"listener", &nd, nl, me, listener);
        if !constant_time_eq(proof_l, &expected) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "raft listener failed authentication",
            ));
        }
        let proof_d = derive(secret, b"dialer", &nd, nl, me, listener);
        sock.write_all(&proof_d).await?;
        Ok(FrameSealer {
            key: derive(secret, b"session", &nd, nl, me, listener),
            seq: 0,
        })
    };
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "raft handshake timed out",
        )),
    }
}

/// Run the listener side. Returns the authenticated dialer id and the opener
/// for its frames.
async fn listener_handshake(
    sock: &mut TcpStream,
    auth: &HubAuth,
) -> std::io::Result<(NodeId, FrameOpener)> {
    let fut = async {
        let mut hello = [0u8; 4 + 4 + NONCE_LEN];
        sock.read_exact(&mut hello).await?;
        if hello[0..4] != RAFT_MAGIC {
            return Err(invalid("bad raft magic"));
        }
        let dialer = u32::from_be_bytes(hello[4..8].try_into().unwrap());
        let nd = &hello[8..];
        if !auth.peers.contains(&dialer) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "raft dialer is not a configured peer",
            ));
        }
        let mut nl = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nl);
        let proof_l = derive(&auth.secret, b"listener", nd, &nl, dialer, auth.me);
        let mut reply = Vec::with_capacity(4 + 4 + NONCE_LEN + MAC_LEN);
        reply.extend_from_slice(&RAFT_MAGIC);
        reply.extend_from_slice(&auth.me.to_be_bytes());
        reply.extend_from_slice(&nl);
        reply.extend_from_slice(&proof_l);
        sock.write_all(&reply).await?;

        let mut proof_d = [0u8; MAC_LEN];
        sock.read_exact(&mut proof_d).await?;
        let expected = derive(&auth.secret, b"dialer", nd, &nl, dialer, auth.me);
        if !constant_time_eq(&proof_d, &expected) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "raft handshake auth failed",
            ));
        }
        Ok((
            dialer,
            FrameOpener {
                key: derive(&auth.secret, b"session", nd, &nl, dialer, auth.me),
                seq: 0,
            },
        ))
    };
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "raft handshake timed out",
        )),
    }
}

/// Inbound routing table: group name -> that group's node loop.
type Groups = Arc<DashMap<String, mpsc::UnboundedSender<Message>>>;
/// Outbound per-peer queues of encoded payloads (sealed by the connection).
type PeerSenders = Arc<DashMap<NodeId, mpsc::Sender<Arc<Vec<u8>>>>>;

/// One listener and one connection per peer, shared by every Raft group on this
/// broker. Groups come and go as topics are created; the connections do not.
pub struct RaftHub {
    node_id: NodeId,
    local_addr: SocketAddr,
    cancel: CancellationToken,
    peer_senders: PeerSenders,
    groups: Groups,
}

impl std::fmt::Debug for RaftHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RaftHub")
            .field("node_id", &self.node_id)
            .field("local_addr", &self.local_addr)
            .finish()
    }
}

/// A single-group transport. Kept for the one-partition case and for tests;
/// holds the hub alive for as long as the transport is held.
pub struct Transport {
    pub cancel: CancellationToken,
    pub join: JoinHandle<()>,
    _hub: Arc<RaftHub>,
}

impl RaftHub {
    /// Bind the listener and dial every peer. `peers` MUST not contain
    /// `node_id` itself.
    pub async fn bind(
        node_id: NodeId,
        bind: SocketAddr,
        peers: BTreeMap<NodeId, SocketAddr>,
        reconnect_backoff: Duration,
        shared_secret: Option<String>,
    ) -> Result<Arc<Self>> {
        // No-auth is allowed only where it was ever defensible: a bind the
        // kernel will not route from off-box.
        let secret: Vec<u8> = shared_secret
            .filter(|s| !s.is_empty())
            .map(|s| s.into_bytes())
            .unwrap_or_default();
        if secret.is_empty() && !bind_is_loopback(&bind) {
            anyhow::bail!(
                "refusing to open an unauthenticated raft port on {bind}: no shared secret is \
                 configured, and this address is reachable from off-box. Set the cluster shared \
                 secret, or bind to 127.0.0.1 for a single-node setup."
            );
        }
        if peers.contains_key(&node_id) {
            anyhow::bail!(
                "node {node_id} is listed as its own peer: a node that dials itself counts its \
                 own vote twice and a majority of two becomes one"
            );
        }
        let auth = Arc::new(HubAuth {
            me: node_id,
            secret,
            peers: peers.keys().copied().collect(),
        });

        let listener = TcpListener::bind(bind).await?;
        let local_addr = listener.local_addr()?;
        let cancel = CancellationToken::new();
        let groups: Groups = Arc::new(DashMap::new());
        let peer_senders: PeerSenders = Arc::new(DashMap::new());

        // --- listener: accept inbound peer connections ---
        {
            let groups = groups.clone();
            let cancel = cancel.clone();
            let auth = auth.clone();
            let slots = Arc::new(Semaphore::new(MAX_INBOUND_CONNECTIONS));
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        res = listener.accept() => {
                            let (sock, peer) = match res {
                                Ok(p) => p,
                                Err(e) => {
                                    tracing::warn!(error = %e, "raft accept failed");
                                    // EMFILE and friends: don't spin.
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                    continue;
                                }
                            };
                            let Ok(permit) = slots.clone().try_acquire_owned() else {
                                tracing::warn!(?peer, "raft: inbound connection limit reached");
                                continue;
                            };
                            let groups = groups.clone();
                            let cancel = cancel.clone();
                            let auth = auth.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                if let Err(e) = handle_inbound(sock, groups, cancel, auth).await {
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
            let (peer_tx, peer_rx) = mpsc::channel::<Arc<Vec<u8>>>(PEER_QUEUE);
            peer_senders.insert(peer_id, peer_tx);
            let cancel = cancel.clone();
            let auth = auth.clone();
            tokio::spawn(async move {
                dial_loop(peer_id, peer_addr, peer_rx, reconnect_backoff, cancel, auth).await;
            });
        }

        Ok(Arc::new(Self {
            node_id,
            local_addr,
            cancel,
            peer_senders,
            groups,
        }))
    }

    /// The address the listener actually bound. Differs from the requested one
    /// when port 0 was asked for.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Route this group's traffic over the hub's connections.
    ///
    /// Refuses a duplicate group rather than replacing the entry: two node loops
    /// answering for one partition would each see half the AppendEntries and
    /// both conclude the leader had gone quiet.
    /// Returns the handle of this group's dispatcher task, so a caller that
    /// tears the hub down can wait for it to actually stop.
    pub fn register(
        &self,
        group: impl Into<String>,
        inbound_tx: mpsc::UnboundedSender<Message>,
        mut outbound_rx: mpsc::UnboundedReceiver<Outbound>,
    ) -> Result<JoinHandle<()>> {
        let group = group.into();
        if group.is_empty() || group.len() > MAX_GROUP_LEN {
            anyhow::bail!(
                "raft group name must be 1..={MAX_GROUP_LEN} bytes, got {}",
                group.len()
            );
        }
        if self.groups.contains_key(&group) {
            anyhow::bail!("raft group '{group}' is already registered on this hub");
        }
        self.groups.insert(group.clone(), inbound_tx.clone());

        let cancel = self.cancel.clone();
        let senders = self.peer_senders.clone();
        let groups = self.groups.clone();
        let node_id = self.node_id;
        let join = tokio::spawn(async move {
            let enqueue = |peer: NodeId, payload: Arc<Vec<u8>>| {
                if let Some(s) = senders.get(&peer) {
                    if let Err(mpsc::error::TrySendError::Full(_)) = s.try_send(payload) {
                        tracing::trace!(peer, "raft: peer queue full; dropping a frame");
                    }
                }
            };
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    msg = outbound_rx.recv() => {
                        let Some(out) = msg else { break; };
                        match out {
                            Outbound::SendTo(peer_id, msg) => {
                                enqueue(peer_id, Arc::new(encode_payload(&group, &msg)));
                            }
                            Outbound::Broadcast(msg) => {
                                let payload = Arc::new(encode_payload(&group, &msg));
                                let peers: Vec<NodeId> = senders.iter().map(|kv| *kv.key()).collect();
                                for p in peers {
                                    enqueue(p, payload.clone());
                                }
                            }
                        }
                    }
                }
            }
            // The node loop for this group is gone; stop routing to it. Only
            // *our* registration: a topic deleted and recreated under the same
            // name has a new one, and removing by name took that away too.
            groups.remove_if(&group, |_, v| v.same_channel(&inbound_tx));
            tracing::debug!(node = node_id, group = %group, "raft group dispatcher exited");
        });
        Ok(join)
    }

    /// Stop routing a group. Its connections stay up for the other groups.
    pub fn unregister(&self, group: &str) {
        self.groups.remove(group);
    }

    pub fn registered_groups(&self) -> usize {
        self.groups.len()
    }

    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

/// Spawn a single-group transport. `peers` MUST not contain `node_id` itself.
pub async fn spawn_transport(
    node_id: NodeId,
    bind: SocketAddr,
    peers: BTreeMap<NodeId, SocketAddr>,
    inbound_tx: mpsc::UnboundedSender<Message>,
    outbound_rx: mpsc::UnboundedReceiver<Outbound>,
    reconnect_backoff: Duration,
    shared_secret: Option<String>,
) -> Result<Transport> {
    let hub = RaftHub::bind(node_id, bind, peers, reconnect_backoff, shared_secret).await?;
    let join = hub.register(DEFAULT_GROUP, inbound_tx, outbound_rx)?;
    Ok(Transport {
        cancel: hub.cancel.clone(),
        join,
        _hub: hub,
    })
}

async fn dial_loop(
    peer_id: NodeId,
    peer_addr: SocketAddr,
    mut peer_rx: mpsc::Receiver<Arc<Vec<u8>>>,
    reconnect_backoff: Duration,
    cancel: CancellationToken,
    auth: Arc<HubAuth>,
) {
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let connect = tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(peer_addr)).await;
        let sock = match connect {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::trace!(peer = peer_id, error = %e, "raft dial failed; retrying");
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(reconnect_backoff) => continue,
                }
            }
            Err(_) => {
                tracing::trace!(peer = peer_id, "raft dial timed out; retrying");
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        if let Err(e) = run_outbound(sock, peer_id, &mut peer_rx, &cancel, &auth).await {
            tracing::debug!(peer = peer_id, error = %e, "raft connection dropped");
        }
        if cancel.is_cancelled() {
            return;
        }
        // Frames queued for a dead connection are stale by now (heartbeats,
        // superseded AppendEntries); Raft resends what still matters.
        while peer_rx.try_recv().is_ok() {}
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(reconnect_backoff) => {}
        }
    }
}

async fn run_outbound(
    mut sock: TcpStream,
    peer_id: NodeId,
    peer_rx: &mut mpsc::Receiver<Arc<Vec<u8>>>,
    cancel: &CancellationToken,
    auth: &HubAuth,
) -> std::io::Result<()> {
    let mut sealer = dialer_handshake(&mut sock, auth.me, peer_id, &auth.secret).await?;
    // We don't read from this socket on the dialer side — inbound peer messages
    // arrive on that peer's own connection to us. Just push frames.
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            msg = peer_rx.recv() => {
                let Some(payload) = msg else { return Ok(()); };
                let frame = sealer.seal(&payload);
                match tokio::time::timeout(WRITE_TIMEOUT, sock.write_all(&frame)).await {
                    Ok(r) => r?,
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "raft write timed out; peer is not reading",
                        ))
                    }
                }
            }
        }
    }
}

async fn handle_inbound(
    mut sock: TcpStream,
    groups: Groups,
    cancel: CancellationToken,
    auth: Arc<HubAuth>,
) -> std::io::Result<()> {
    let _ = sock.set_nodelay(true);
    let (peer_id, mut opener) = listener_handshake(&mut sock, &auth).await?;

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
                if n > MAX_RAFT_FRAME {
                    return Err(invalid("raft frame too large"));
                }
                let mut frame = vec![0u8; n];
                sock.read_exact(&mut frame).await?;
                let payload = opener.open(&frame)?;
                let (group, body) = split_frame(payload)?;
                let msg = Message::decode(body)
                    .map_err(|e| invalid(&format!("decode: {}", e)))?;
                if msg.sender() != peer_id {
                    tracing::warn!(peer = peer_id, claimed = msg.sender(), "raft: message claims another sender; dropped");
                    continue;
                }
                // A group we do not host is dropped, not an error: a peer can
                // reach us before we have opened that topic, and Raft retries.
                // The DashMap guard is released before any remove: holding one
                // across a write to the same shard deadlocks.
                let node_loop_gone = match groups.get(group) {
                    Some(tx) => tx.send(msg).is_err(),
                    None => {
                        tracing::trace!(group = %group, "raft frame for an unregistered group");
                        false
                    }
                };
                if node_loop_gone {
                    // Keep the connection: the other groups still use it.
                    groups.remove_if(group, |_, v| v.is_closed());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::messages::{Message, RequestVote};

    fn sample_msg(from: NodeId) -> Message {
        Message::RequestVote(RequestVote {
            term: 99,
            candidate_id: from,
            last_log_index: 0,
            last_log_term: 0,
        })
    }

    /// A registry with `names` registered, plus the receivers to assert on.
    fn registry(names: &[&str]) -> (Groups, Vec<(String, mpsc::UnboundedReceiver<Message>)>) {
        let groups: Groups = Arc::new(DashMap::new());
        let mut rxs = Vec::new();
        for name in names {
            let (tx, rx) = mpsc::unbounded_channel();
            groups.insert((*name).to_string(), tx);
            rxs.push(((*name).to_string(), rx));
        }
        (groups, rxs)
    }

    fn auth(me: NodeId, secret: &[u8], peers: &[NodeId]) -> Arc<HubAuth> {
        Arc::new(HubAuth {
            me,
            secret: secret.to_vec(),
            peers: peers.iter().copied().collect(),
        })
    }

    async fn serve_one(groups: Groups, auth: Arc<HubAuth>) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = handle_inbound(sock, groups, CancellationToken::new(), auth).await;
        });
        (addr, h)
    }

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        let mac = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
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
        let (groups, mut rxs) = registry(&[DEFAULT_GROUP]);
        let (addr, server) = serve_one(groups, auth(1, b"correct-secret", &[7])).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        // The dialer itself notices: the listener's proof does not verify
        // under the wrong secret, so nothing is ever sent.
        let res = dialer_handshake(&mut client, 7, 1, b"wrong-secret").await;
        assert!(res.is_err(), "a wrong secret must fail the handshake");
        let (_, rx) = &mut rxs[0];
        let got = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(!matches!(got, Ok(Some(_))), "no message may be delivered");
        server.abort();
    }

    #[tokio::test]
    async fn accepts_peer_with_correct_secret() {
        let (groups, mut rxs) = registry(&[DEFAULT_GROUP]);
        let (addr, server) = serve_one(groups, auth(1, b"correct-secret", &[7])).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut sealer = dialer_handshake(&mut client, 7, 1, b"correct-secret")
            .await
            .unwrap();
        client
            .write_all(&sealer.frame(DEFAULT_GROUP, &sample_msg(7)))
            .await
            .unwrap();
        let (_, rx) = &mut rxs[0];
        let got = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("message should be delivered within timeout");
        assert!(matches!(got, Some(Message::RequestVote(_))));
        server.abort();
    }

    #[tokio::test]
    async fn a_peer_cannot_speak_for_another_node() {
        let (groups, mut rxs) = registry(&[DEFAULT_GROUP]);
        let (addr, server) = serve_one(groups, auth(1, b"s", &[7, 8])).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut sealer = dialer_handshake(&mut client, 7, 1, b"s").await.unwrap();
        // Authenticated as 7, claims to be 8.
        client
            .write_all(&sealer.frame(DEFAULT_GROUP, &sample_msg(8)))
            .await
            .unwrap();
        client
            .write_all(&sealer.frame(DEFAULT_GROUP, &sample_msg(7)))
            .await
            .unwrap();
        let (_, rx) = &mut rxs[0];
        let got = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.sender(), 7, "the impersonating frame must be dropped");
        server.abort();
    }

    #[tokio::test]
    async fn a_tampered_or_replayed_frame_closes_the_connection() {
        let (groups, mut rxs) = registry(&[DEFAULT_GROUP]);
        let (addr, server) = serve_one(groups, auth(1, b"s", &[7])).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut sealer = dialer_handshake(&mut client, 7, 1, b"s").await.unwrap();
        let first = sealer.frame(DEFAULT_GROUP, &sample_msg(7));
        client.write_all(&first).await.unwrap();
        // Replaying the same frame: its sequence number is already used.
        client.write_all(&first).await.unwrap();
        client
            .write_all(&sealer.frame(DEFAULT_GROUP, &sample_msg(7)))
            .await
            .ok();
        let (_, rx) = &mut rxs[0];
        assert!(rx.recv().await.is_some(), "the original frame arrives");
        let next = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(
            !matches!(next, Ok(Some(_))),
            "nothing after a replayed frame may be delivered"
        );
        server.abort();
    }

    #[tokio::test]
    async fn an_unconfigured_dialer_is_refused() {
        let (groups, _rxs) = registry(&[DEFAULT_GROUP]);
        let (addr, server) = serve_one(groups, auth(1, b"s", &[7])).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        assert!(dialer_handshake(&mut client, 9, 1, b"s").await.is_err());
        server.abort();
    }

    /// The point of the group key: two partitions sharing one connection must
    /// not see each other's traffic.
    #[tokio::test]
    async fn frames_route_to_their_own_group_only() {
        let (groups, mut rxs) = registry(&["events/0", "events/1"]);
        let (addr, server) = serve_one(groups, auth(1, b"", &[7])).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut sealer = dialer_handshake(&mut client, 7, 1, b"").await.unwrap();
        client
            .write_all(&sealer.frame("events/1", &sample_msg(7)))
            .await
            .unwrap();

        let (name_a, rx_a) = &mut rxs[0];
        assert_eq!(name_a, "events/0");
        assert!(
            tokio::time::timeout(Duration::from_millis(250), rx_a.recv())
                .await
                .is_err(),
            "partition 0 must not see partition 1's frame"
        );
        let (name_b, rx_b) = &mut rxs[1];
        assert_eq!(name_b, "events/1");
        let got = tokio::time::timeout(Duration::from_millis(500), rx_b.recv())
            .await
            .expect("partition 1 must receive its own frame");
        assert!(matches!(got, Some(Message::RequestVote(_))));
        server.abort();
    }

    /// A frame for a topic this node has not opened yet is dropped, and the
    /// connection survives.
    #[tokio::test]
    async fn an_unknown_group_is_dropped_without_closing_the_connection() {
        let (groups, mut rxs) = registry(&["events/0"]);
        let (addr, server) = serve_one(groups, auth(1, b"", &[7])).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut sealer = dialer_handshake(&mut client, 7, 1, b"").await.unwrap();
        client
            .write_all(&sealer.frame("not-open-here/0", &sample_msg(7)))
            .await
            .unwrap();
        client
            .write_all(&sealer.frame("events/0", &sample_msg(7)))
            .await
            .unwrap();
        let (_, rx) = &mut rxs[0];
        let got = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("the frame after an unknown group must still arrive");
        assert!(matches!(got, Some(Message::RequestVote(_))));
        server.abort();
    }

    #[test]
    fn split_frame_rejects_a_hostile_group_header() {
        let mut payload = 40u16.to_be_bytes().to_vec();
        payload.extend_from_slice(b"short");
        assert!(split_frame(&payload).is_err());
        assert!(split_frame(&0u16.to_be_bytes()).is_err());
        let mut bad = 2u16.to_be_bytes().to_vec();
        bad.extend_from_slice(&[0xff, 0xfe]);
        assert!(split_frame(&bad).is_err());
    }

    #[test]
    fn a_framed_message_round_trips_with_its_group() {
        let payload = encode_payload("events/3", &sample_msg(7));
        let mut sealer = FrameSealer {
            key: [7; 32],
            seq: 0,
        };
        let bytes = sealer.seal(&payload);
        let n = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        assert_eq!(n, bytes.len() - 4, "length prefix covers the whole payload");
        let mut opener = FrameOpener {
            key: [7; 32],
            seq: 0,
        };
        let opened = opener.open(&bytes[4..]).unwrap();
        let (group, body) = split_frame(opened).unwrap();
        assert_eq!(group, "events/3");
        assert!(matches!(
            Message::decode(body).unwrap(),
            Message::RequestVote(_)
        ));
    }

    #[tokio::test]
    async fn a_hub_refuses_to_register_one_group_twice() {
        let hub = RaftHub::bind(
            1,
            "127.0.0.1:0".parse().unwrap(),
            BTreeMap::new(),
            Duration::from_millis(50),
            None,
        )
        .await
        .unwrap();

        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (_otx1, orx1) = mpsc::unbounded_channel();
        hub.register("events/0", tx1, orx1).unwrap();

        let (tx2, _rx2) = mpsc::unbounded_channel();
        let (_otx2, orx2) = mpsc::unbounded_channel();
        let err = hub.register("events/0", tx2, orx2).unwrap_err();
        assert!(
            err.to_string().contains("already registered"),
            "unexpected: {err}"
        );
        hub.shutdown();
    }

    #[tokio::test]
    async fn a_hub_refuses_a_node_listed_as_its_own_peer() {
        let mut peers = BTreeMap::new();
        peers.insert(1u32, "127.0.0.1:1".parse().unwrap());
        let err = RaftHub::bind(
            1,
            "127.0.0.1:0".parse().unwrap(),
            peers,
            Duration::from_millis(50),
            None,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("its own peer"),
            "unexpected: {err}"
        );
    }

    /// A dispatcher that exits after its group was re-registered must not
    /// remove the new registration.
    #[tokio::test]
    async fn a_stale_dispatcher_does_not_unregister_its_successor() {
        let hub = RaftHub::bind(
            1,
            "127.0.0.1:0".parse().unwrap(),
            BTreeMap::new(),
            Duration::from_millis(50),
            None,
        )
        .await
        .unwrap();
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (otx1, orx1) = mpsc::unbounded_channel();
        let old = hub.register("t/0", tx1, orx1).unwrap();
        hub.unregister("t/0");
        let (tx2, _rx2) = mpsc::unbounded_channel();
        let (_otx2, orx2) = mpsc::unbounded_channel();
        hub.register("t/0", tx2, orx2).unwrap();
        drop(otx1);
        old.await.unwrap();
        assert_eq!(hub.registered_groups(), 1);
        hub.shutdown();
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
        assert!(bind_is_loopback(&addr("127.0.0.1:9300")));
        assert!(bind_is_loopback(&addr("[::1]:9300")));
    }

    #[test]
    fn the_unspecified_address_is_not_loopback() {
        assert!(!bind_is_loopback(&addr("0.0.0.0:9300")));
        assert!(!bind_is_loopback(&addr("[::]:9300")));
    }

    #[test]
    fn a_routable_address_is_not_loopback() {
        assert!(!bind_is_loopback(&addr("203.0.113.7:9300")));
        assert!(!bind_is_loopback(&addr("10.0.0.7:9300")));
    }
}
