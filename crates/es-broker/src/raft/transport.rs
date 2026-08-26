//! TCP transport for Raft RPCs.
//!
//! One [`RaftHub`] per broker: a single listener, one persistent connection per
//! peer, and **many Raft groups multiplexed over them**. A group is one
//! replicated partition, named `"<topic>/<partition>"`, and each frame carries
//! that name so the receiver can route it.
//!
//! Multiplexing is what makes a real cluster possible rather than a demo. A
//! port per group cannot be configured in advance, because topics are created
//! at runtime: the operator would have to predict every topic name and
//! partition count before starting the brokers. One port, a group key per
//! frame, and a registry that grows as topics are opened.
//!
//! Handshake (sender of the connection writes first):
//!
//! ```text
//!   magic: [u8; 4] = "RAFT"
//!   node_id: u32 BE
//!   secret_len: u32 BE
//!   secret: ...
//! ```
//!
//! Once the handshake is exchanged, every subsequent frame is:
//!
//! ```text
//!   length: u32 BE      bytes of everything after this field
//!   group_len: u16 BE   bytes of the group name
//!   group: ...          UTF-8, e.g. "events/0"
//!   body: ...           Message::encode() output
//! ```
//!
//! A frame for a group this node has not registered is **dropped**, not an
//! error: during startup a peer may reach us before we have opened that topic,
//! and Raft retries. Dropping is the same outcome as a lost packet, which the
//! protocol already handles.
//!
//! Reconnect policy is simple: on disconnect or dial failure, sleep
//! `reconnect_backoff` and retry.

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
/// Max accepted length of a frame's group name. A topic name is already
/// validated well below this; the cap exists so a hostile peer cannot make us
/// allocate on its say-so before the frame is even parsed.
const MAX_GROUP_LEN: usize = 512;
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

/// Inbound routing table: group name -> that group's node loop.
type Groups = Arc<DashMap<String, mpsc::UnboundedSender<Message>>>;

/// One listener and one connection per peer, shared by every Raft group on this
/// broker. Groups come and go as topics are created; the connections do not.
#[derive(Debug)]
pub struct RaftHub {
    node_id: NodeId,
    local_addr: SocketAddr,
    cancel: CancellationToken,
    peer_senders: Arc<DashMap<NodeId, mpsc::UnboundedSender<Vec<u8>>>>,
    groups: Groups,
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
        // Pre-shared secret both peers must present in the handshake. Without it
        // the raft port accepts any TCP client, letting an attacker inject
        // arbitrary AppendEntries/InstallSnapshot/config-change messages into
        // replicated state.
        //
        // No-auth is still allowed, but only where it was ever defensible: a
        // bind the kernel will not route from off-box. The old comment called it
        // "the (insecure) no-auth behavior for single-node/loopback setups" and
        // then let it apply to `0.0.0.0` too — which on any host with a public
        // address is remote control of the replicated state by anyone who can
        // reach the port.
        //
        // Whether that is safe depends entirely on the bind address, so the code
        // depends on the bind address rather than on the operator having read a
        // comment.
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
        if peers.contains_key(&node_id) {
            anyhow::bail!(
                "node {node_id} is listed as its own peer: a node that dials itself counts its \
                 own vote twice and a majority of two becomes one"
            );
        }

        let listener = TcpListener::bind(bind).await?;
        let local_addr = listener.local_addr()?;
        let cancel = CancellationToken::new();
        let groups: Groups = Arc::new(DashMap::new());

        // Each peer gets a per-peer mpsc; the dialer task drains it onto its socket.
        let peer_senders: Arc<DashMap<NodeId, mpsc::UnboundedSender<Vec<u8>>>> =
            Arc::new(DashMap::new());

        // --- listener: accept inbound peer connections ---
        {
            let groups = groups.clone();
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
                            let groups = groups.clone();
                            let cancel = cancel.clone();
                            let secret = secret.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_inbound(sock, groups, cancel, secret).await {
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
            let secret = secret.clone();
            tokio::spawn(async move {
                dial_loop(
                    node_id,
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
        self.groups.insert(group.clone(), inbound_tx);

        let cancel = self.cancel.clone();
        let senders = self.peer_senders.clone();
        let groups = self.groups.clone();
        let node_id = self.node_id;
        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    msg = outbound_rx.recv() => {
                        let Some(out) = msg else { break; };
                        match out {
                            Outbound::SendTo(peer_id, msg) => {
                                if let Some(s) = senders.get(&peer_id) {
                                    let _ = s.send(frame(&group, &msg));
                                }
                            }
                            Outbound::Broadcast(msg) => {
                                let bytes = frame(&group, &msg);
                                for kv in senders.iter() {
                                    let _ = kv.value().send(bytes.clone());
                                }
                            }
                        }
                    }
                }
            }
            // The node loop for this group is gone; stop routing to it so a
            // later topic of the same name can register.
            groups.remove(&group);
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

fn frame(group: &str, msg: &Message) -> Vec<u8> {
    let body = msg.encode();
    let payload_len = 2 + group.len() + body.len();
    let mut out = Vec::with_capacity(4 + payload_len);
    out.extend_from_slice(&(payload_len as u32).to_be_bytes());
    out.extend_from_slice(&(group.len() as u16).to_be_bytes());
    out.extend_from_slice(group.as_bytes());
    out.extend_from_slice(&body);
    out
}

/// Split a frame payload into its group name and message body.
fn split_frame(payload: &[u8]) -> std::io::Result<(&str, &[u8])> {
    let invalid = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
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
    groups: Groups,
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
                let mut payload = vec![0u8; n];
                sock.read_exact(&mut payload).await?;
                let (group, body) = split_frame(&payload)?;
                let msg = Message::decode(body).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("decode: {}", e))
                })?;
                // A group we do not host is dropped, not an error: a peer can
                // reach us before we have opened that topic, and Raft retries.
                // Closing the connection would take the other groups down with
                // it.
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
                    groups.remove(group);
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
        let (groups, mut rxs) = registry(&[DEFAULT_GROUP]);
        let cancel = CancellationToken::new();
        let secret = Arc::new(Some(b"correct-secret".to_vec()));

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = handle_inbound(sock, groups, cancel, secret).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        send_handshake(&mut client, 7, b"wrong-secret").await;
        // Even if the attacker sends a well-formed frame, it must never be
        // delivered because the handshake auth failed.
        let _ = client.write_all(&frame(DEFAULT_GROUP, &sample_msg())).await;

        let (_, rx) = &mut rxs[0];
        // Either outcome is correct — a timeout, or the channel closing because
        // the connection was dropped. What must never happen is a message
        // arriving.
        let got = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(
            !matches!(got, Ok(Some(_))),
            "no message may be delivered when the secret is wrong, got {got:?}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn accepts_peer_with_correct_secret() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (groups, mut rxs) = registry(&[DEFAULT_GROUP]);
        let cancel = CancellationToken::new();
        let secret = Arc::new(Some(b"correct-secret".to_vec()));

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = handle_inbound(sock, groups, cancel, secret).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        send_handshake(&mut client, 7, b"correct-secret").await;
        client
            .write_all(&frame(DEFAULT_GROUP, &sample_msg()))
            .await
            .unwrap();

        let (_, rx) = &mut rxs[0];
        let got = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("message should be delivered within timeout");
        assert!(matches!(got, Some(Message::RequestVote(_))));
        server.abort();
    }

    /// The point of the group key: two partitions sharing one connection must
    /// not see each other's traffic. Without routing, both node loops would
    /// receive every frame and each would count the other's votes.
    #[tokio::test]
    async fn frames_route_to_their_own_group_only() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (groups, mut rxs) = registry(&["events/0", "events/1"]);
        let cancel = CancellationToken::new();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = handle_inbound(sock, groups, cancel, Arc::new(None)).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        send_handshake(&mut client, 7, b"").await;
        client
            .write_all(&frame("events/1", &sample_msg()))
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
    /// connection survives — the frame that follows for a live group still
    /// arrives. Closing instead would let one unknown group stall every other.
    #[tokio::test]
    async fn an_unknown_group_is_dropped_without_closing_the_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (groups, mut rxs) = registry(&["events/0"]);
        let cancel = CancellationToken::new();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = handle_inbound(sock, groups, cancel, Arc::new(None)).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        send_handshake(&mut client, 7, b"").await;
        client
            .write_all(&frame("not-open-here/0", &sample_msg()))
            .await
            .unwrap();
        client
            .write_all(&frame("events/0", &sample_msg()))
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
        // Length beyond the payload: the cap must be checked before the slice.
        let mut payload = 40u16.to_be_bytes().to_vec();
        payload.extend_from_slice(b"short");
        assert!(split_frame(&payload).is_err());

        // Zero-length group name is not a group.
        assert!(split_frame(&0u16.to_be_bytes()).is_err());

        // Not UTF-8.
        let mut bad = 2u16.to_be_bytes().to_vec();
        bad.extend_from_slice(&[0xff, 0xfe]);
        assert!(split_frame(&bad).is_err());
    }

    #[test]
    fn a_framed_message_round_trips_with_its_group() {
        let bytes = frame("events/3", &sample_msg());
        let n = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        assert_eq!(n, bytes.len() - 4, "length prefix covers the whole payload");
        let (group, body) = split_frame(&bytes[4..]).unwrap();
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
