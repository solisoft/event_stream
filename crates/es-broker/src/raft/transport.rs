//! TCP transport for Raft RPCs.
//!
//! One [`RaftHub`] per broker: a single listener, one persistent connection per
//! peer, and **many Raft groups multiplexed over them**. A group is one
//! replicated partition, named `"<topic>/<partition>"`, and each frame carries
//! that name so the receiver can route it.
//!
//! # Handshake (version 3)
//!
//! The dialer opens the connection and **proves itself first**; the shared
//! secret never crosses the wire.
//!
//! ```text
//!   dialer   → listener : "RAF3" | dialer_id u32 | nonce_d [32]
//!   listener → dialer   : "RAF3" | listener_id u32 | nonce_l [32]
//!   dialer   → listener : HMAC(secret, "dialer" | nonce_d | nonce_l | ids)
//!   listener → dialer   : HMAC(secret, "listener" | nonce_d | nonce_l | ids)
//! ```
//!
//! Each side proves knowledge of the secret against a nonce the other chose,
//! so a recorded handshake cannot be replayed. The listener sends its proof
//! only once the dialer's has verified: a connection that has proved nothing
//! gets a nonce and nothing else, so no value derived from the secret is ever
//! handed to someone who cannot already compute it. The dialer checks the
//! listener is the node it meant to reach; the listener checks the dialer is a
//! current member. Both ids are bound into the session.
//!
//! Version 2 (0.2.x) had the listener prove first. A 0.3 listener refuses it
//! unless started with `--raft-legacy-handshake`, which exists for one release
//! so a cluster can be upgraded one broker at a time; with it, a dialer whose
//! version-3 hello is closed unanswered — what a 0.2 listener does with a magic
//! it does not know — retries in version 2. See [`HubOptions::legacy_handshake`].
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
//! `session_key` is derived from both nonces, one per direction, and `seq`
//! counts frames on the connection: a frame cannot be injected, replayed from
//! another session, or reordered. Every message must name the dialer's
//! handshake id as its sender.
//!
//! A frame whose payload is just `group_len = 0` is a **keepalive**. Raft
//! traffic flows dialer → listener only; keepalives flow both ways, every
//! [`HubOptions::keepalive_interval`] that nothing else was sent. Either side
//! closes a connection it has heard nothing on for
//! [`HubOptions::idle_timeout`], and the dialer redials. Without them a peer
//! that vanished without a FIN — a power cut, a dropped route — left a
//! connection that looked established for hours, and frames queued behind it.
//!
//! # Identity
//!
//! With a shared secret alone there is **one** secret for the whole cluster.
//! It keeps out everyone who does not hold it: an outsider can neither join,
//! nor forge, alter or replay a frame. It does **not** tell members apart: the
//! id a dialer announces is bound into the session but not itself proved —
//! every member can compute every other member's proofs — so a node holding
//! the secret can dial as any member id and vote, acknowledge or lead in its
//! name.
//!
//! With mTLS (`--raft-tls-cert`, `--raft-tls-key`, `--raft-tls-ca`) every
//! connection is a TLS 1.3 session, both sides present a certificate the CA
//! signed, and the certificate names the broker (see [`super::tls`]). The
//! listener takes the peer's id from the certificate and refuses a handshake
//! that claims another; the dialer refuses a listener whose certificate does
//! not name the node it dialed. Frames are then encrypted as well as
//! authenticated. The shared secret still works inside TLS when both are set.
//!
//! Without a secret or TLS (allowed only on a loopback bind) the same exchange
//! runs with an empty key: no authentication, but the same framing.
//!
//! # Inbound limits
//!
//! With authentication configured, a connection whose source address is not
//! one of the peers' addresses is closed at accept, before it costs a
//! handshake slot. Peers are given as IP addresses (`--raft-peer` takes no
//! host names), so the list is exact; a peer behind NAT, or one that dials from
//! a different address than the one it is listed with, is refused — the
//! warning names the address it came from. Handshakes are capped in total and
//! per source address and must finish within [`HANDSHAKE_TIMEOUT`]. An
//! established connection takes no slot: there is at most one per
//! authenticated peer id, and a newer one replaces it, so their number is
//! bounded by the membership.
//!
//! A frame for a group this node has not registered is **dropped**, not an
//! error: during startup a peer may reach us before we have opened that topic,
//! and Raft retries. Dropping is the same outcome as a lost packet.
//!
//! Without mTLS records travel in cleartext: run the raft port on a private
//! network.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::messages::{Message, NodeId};
use super::node::Outbound;
use super::secret::SharedSecret;
use super::tls::RaftTls;

/// The handshake this build speaks: version 3, dialer proves first.
pub const HANDSHAKE_VERSION: u8 = 3;
const MAGIC_V3: [u8; 4] = *b"RAF3";
/// The 0.2.x handshake, listener proves first. Accepted only with
/// `--raft-legacy-handshake`, for one release.
const MAGIC_V2: [u8; 4] = *b"RAF2";
const NONCE_LEN: usize = 32;
const MAC_LEN: usize = 32;
/// Hello and reply: magic, node id, nonce.
const HELLO_LEN: usize = 4 + 4 + NONCE_LEN;
/// A keepalive: a frame payload with an empty group name and no body. No
/// real frame has one — `split_frame` refuses a zero-length group — so it
/// cannot be mistaken for traffic.
const KEEPALIVE: [u8; 2] = [0, 0];
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
/// Inbound handshakes in progress at once, from all sources. Established
/// connections are not counted: there is one per peer at most.
const MAX_HANDSHAKES: usize = 64;
/// Inbound handshakes in progress at once from one source address. A real
/// peer has one dialer per hub, so one at a time plus a redial is the norm.
const MAX_HANDSHAKES_PER_IP: usize = 4;
/// Group name used by [`spawn_transport`], the single-group convenience path.
pub const DEFAULT_GROUP: &str = "default";
/// How often a connection with nothing else to send sends a keepalive.
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
/// How long a connection may stay silent before it is closed. Three
/// keepalives: one lost to a busy machine is normal, three are not.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// The Raft group a frame belongs to: one replicated partition.
pub fn group_key(topic: &str, partition: u32) -> String {
    format!("{topic}/{partition}")
}
/// How long a peer has to complete the handshake before we drop the socket.
/// Bounds slowloris-style holds on the raft listener; the handshake is two
/// round trips of under a hundred bytes (plus TLS, when configured).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a dial may take to connect before it is retried.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How a hub authenticates and keeps its connections.
#[derive(Debug, Clone)]
pub struct HubOptions {
    /// The cluster's shared secret. `None` without TLS is allowed only on a
    /// loopback bind.
    pub shared_secret: Option<SharedSecret>,
    /// Per-broker identity: mTLS on every connection.
    pub tls: Option<Arc<RaftTls>>,
    /// Accept version-2 handshakes from 0.2.x brokers, and fall back to
    /// version 2 when dialing one. For rolling upgrades from 0.2.1 only;
    /// deprecated, and removed in 0.4. A version-2 listener proves itself to
    /// anyone who connects, which is what version 3 exists to stop.
    pub legacy_handshake: bool,
    /// See [`DEFAULT_KEEPALIVE_INTERVAL`].
    pub keepalive_interval: Duration,
    /// See [`DEFAULT_IDLE_TIMEOUT`]. Must exceed `keepalive_interval`.
    pub idle_timeout: Duration,
}

impl Default for HubOptions {
    fn default() -> Self {
        Self {
            shared_secret: None,
            tls: None,
            legacy_handshake: false,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

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

/// A handshake version: what is on the wire, and the domain its keys are
/// derived in. The versions use different labels so no value computed in one
/// can be replayed in the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V2,
    V3,
}

impl Version {
    fn magic(self) -> [u8; 4] {
        match self {
            Self::V2 => MAGIC_V2,
            Self::V3 => MAGIC_V3,
        }
    }

    fn domain(self) -> &'static [u8] {
        match self {
            Self::V2 => b"es-raft-v2/",
            Self::V3 => b"es-raft-v3/",
        }
    }
}

/// The handshake transcript both proofs and the session keys are bound to.
fn derive(
    version: Version,
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
            version.domain(),
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

fn denied(m: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, m.into())
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

    /// Frame a keepalive.
    pub fn keepalive(&mut self) -> Vec<u8> {
        self.seal(&KEEPALIVE)
    }
}

/// Verifies frames for one direction of an authenticated session.
pub struct FrameOpener {
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
            return Err(denied("raft frame failed authentication"));
        }
        self.seq += 1;
        Ok(payload)
    }
}

/// Both directions of an established session, from one side's point of view.
pub struct Session {
    pub version: Version,
    /// Frames this side sends.
    pub sealer: FrameSealer,
    /// Frames this side receives.
    pub opener: FrameOpener,
}

impl Session {
    fn new(version: Version, secret: &[u8], nd: &[u8], nl: &[u8], d: NodeId, l: NodeId) -> Self {
        let d2l = derive(version, secret, b"session", nd, nl, d, l);
        // Version 2 had one key, dialer to listener, and nothing travelled
        // back. Version 3 adds the listener's direction for its keepalives.
        let l2d = derive(version, secret, b"session-l2d", nd, nl, d, l);
        Self {
            version,
            sealer: FrameSealer { key: d2l, seq: 0 },
            opener: FrameOpener { key: l2d, seq: 0 },
        }
    }

    /// The same session from the listener's side.
    fn reversed(self) -> Self {
        Self {
            version: self.version,
            sealer: FrameSealer {
                key: self.opener.key,
                seq: 0,
            },
            opener: FrameOpener {
                key: self.sealer.key,
                seq: 0,
            },
        }
    }

    /// Frame a message for `group`.
    pub fn frame(&mut self, group: &str, msg: &Message) -> Vec<u8> {
        self.sealer.frame(group, msg)
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

/// Who this node is, whom it accepts, and how its connections behave.
struct HubAuth {
    me: NodeId,
    secret: Vec<u8>,
    /// The ids a dialer may authenticate as. Behind a lock because the
    /// membership can change while the hub runs.
    peers: RwLock<BTreeSet<NodeId>>,
    tls: Option<Arc<RaftTls>>,
    legacy_handshake: bool,
    keepalive_interval: Duration,
    idle_timeout: Duration,
}

impl HubAuth {
    fn is_peer(&self, id: NodeId) -> bool {
        self.peers.read().unwrap().contains(&id)
    }

    fn peer_ids(&self) -> Vec<NodeId> {
        self.peers.read().unwrap().iter().copied().collect()
    }

    /// Whether a dialer announcing `dialer` may proceed. `certified` is the
    /// id its TLS certificate names, when TLS is on: the announcement must
    /// match it, which is what stops a member from speaking for another.
    fn admit_dialer(&self, dialer: NodeId, certified: Option<NodeId>) -> std::io::Result<()> {
        if let Some(cert_id) = certified {
            if cert_id != dialer {
                return Err(denied(format!(
                    "raft dialer claims to be node {dialer} but its certificate names node {cert_id}"
                )));
            }
        }
        if !self.is_peer(dialer) {
            return Err(denied("raft dialer is not a member"));
        }
        Ok(())
    }
}

async fn with_handshake_timeout<T>(
    fut: impl std::future::Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "raft handshake timed out",
        )),
    }
}

fn hello(version: Version, id: NodeId, nonce: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HELLO_LEN);
    out.extend_from_slice(&version.magic());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(nonce);
    out
}

/// Run the dialer side of the version-3 handshake: announce, prove, then
/// check the listener's proof.
///
/// A listener that closes the connection without answering the hello yields
/// `ConnectionRefused`: that is what a 0.2 broker does with a magic it does not
/// know, and the dial loop may retry in version 2.
pub async fn dialer_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    sock: &mut S,
    me: NodeId,
    expected_peer: NodeId,
    secret: &[u8],
) -> std::io::Result<Session> {
    let mut nd = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nd);
    with_handshake_timeout(async {
        sock.write_all(&hello(Version::V3, me, &nd)).await?;
        sock.flush().await?;

        let mut reply = [0u8; HELLO_LEN];
        if let Err(e) = sock.read_exact(&mut reply).await {
            return Err(if e.kind() == std::io::ErrorKind::UnexpectedEof {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "raft listener closed the connection without answering the hello",
                )
            } else {
                e
            });
        }
        if reply[0..4] != MAGIC_V3 {
            return Err(invalid("bad raft magic from listener"));
        }
        let listener = u32::from_be_bytes(reply[4..8].try_into().unwrap());
        let nl = &reply[8..];
        if listener != expected_peer {
            return Err(invalid("raft listener is not the node we dialed"));
        }
        let proof_d = derive(Version::V3, secret, b"dialer", &nd, nl, me, listener);
        sock.write_all(&proof_d).await?;
        sock.flush().await?;

        let mut proof_l = [0u8; MAC_LEN];
        sock.read_exact(&mut proof_l)
            .await
            .map_err(|_| denied("raft listener refused our proof"))?;
        let expected = derive(Version::V3, secret, b"listener", &nd, nl, me, listener);
        if !constant_time_eq(&proof_l, &expected) {
            return Err(denied("raft listener failed authentication"));
        }
        Ok(Session::new(Version::V3, secret, &nd, nl, me, listener))
    })
    .await
}

/// Run the dialer side of the 0.2 handshake, in which the listener proves
/// first. Only for reaching a 0.2 broker during a rolling upgrade.
pub async fn dialer_handshake_v2<S: AsyncRead + AsyncWrite + Unpin>(
    sock: &mut S,
    me: NodeId,
    expected_peer: NodeId,
    secret: &[u8],
) -> std::io::Result<Session> {
    let mut nd = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nd);
    with_handshake_timeout(async {
        sock.write_all(&hello(Version::V2, me, &nd)).await?;
        sock.flush().await?;

        let mut reply = [0u8; HELLO_LEN + MAC_LEN];
        sock.read_exact(&mut reply).await?;
        if reply[0..4] != MAGIC_V2 {
            return Err(invalid("bad raft magic from listener"));
        }
        let listener = u32::from_be_bytes(reply[4..8].try_into().unwrap());
        let nl = &reply[8..HELLO_LEN];
        let proof_l = &reply[HELLO_LEN..];
        if listener != expected_peer {
            return Err(invalid("raft listener is not the node we dialed"));
        }
        let expected = derive(Version::V2, secret, b"listener", &nd, nl, me, listener);
        if !constant_time_eq(proof_l, &expected) {
            return Err(denied("raft listener failed authentication"));
        }
        let proof_d = derive(Version::V2, secret, b"dialer", &nd, nl, me, listener);
        sock.write_all(&proof_d).await?;
        sock.flush().await?;
        Ok(Session::new(Version::V2, secret, &nd, nl, me, listener))
    })
    .await
}

/// Run the listener side. Returns the authenticated dialer id and the session
/// as the listener sees it. `certified` is the id the dialer's certificate
/// names, when TLS is on.
async fn listener_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    sock: &mut S,
    auth: &HubAuth,
    certified: Option<NodeId>,
) -> std::io::Result<(NodeId, Session)> {
    with_handshake_timeout(async {
        let mut hello_buf = [0u8; HELLO_LEN];
        sock.read_exact(&mut hello_buf).await?;
        let version = match hello_buf[0..4].try_into().unwrap() {
            MAGIC_V3 => Version::V3,
            MAGIC_V2 if auth.legacy_handshake => Version::V2,
            MAGIC_V2 => {
                return Err(denied(
                    "a 0.2 broker dialed with the version-2 raft handshake, which this broker \
                     refuses; finish the upgrade, or start the upgraded brokers with \
                     --raft-legacy-handshake until every member runs 0.3",
                ))
            }
            _ => return Err(invalid("bad raft magic")),
        };
        let dialer = u32::from_be_bytes(hello_buf[4..8].try_into().unwrap());
        let nd = &hello_buf[8..];
        auth.admit_dialer(dialer, certified)?;
        let mut nl = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nl);
        let proof_l = derive(version, &auth.secret, b"listener", nd, &nl, dialer, auth.me);

        let mut reply = hello(version, auth.me, &nl);
        if version == Version::V2 {
            // The deprecated order: the listener proves before the dialer has.
            tracing::warn!(
                peer = dialer,
                "raft: accepted a deprecated version-2 handshake (--raft-legacy-handshake); \
                 upgrade every member to 0.3 and drop the flag"
            );
            reply.extend_from_slice(&proof_l);
        }
        sock.write_all(&reply).await?;
        sock.flush().await?;

        let mut proof_d = [0u8; MAC_LEN];
        sock.read_exact(&mut proof_d).await?;
        let expected = derive(version, &auth.secret, b"dialer", nd, &nl, dialer, auth.me);
        if !constant_time_eq(&proof_d, &expected) {
            return Err(denied("raft handshake auth failed"));
        }
        if version == Version::V3 {
            sock.write_all(&proof_l).await?;
            sock.flush().await?;
        }
        let session = Session::new(version, &auth.secret, nd, &nl, dialer, auth.me).reversed();
        Ok((dialer, session))
    })
    .await
}

/// Anything a connection can run over: plain TCP, or TLS on either side.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type BoxIo = Box<dyn Io>;

/// Write one frame, giving up on a peer that is not reading.
async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &[u8]) -> std::io::Result<()> {
    let fut = async {
        w.write_all(frame).await?;
        // TLS buffers records; without the flush a keepalive could sit in
        // the session until the next real frame pushed it out.
        w.flush().await
    };
    match tokio::time::timeout(WRITE_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "raft write timed out; peer is not reading",
        )),
    }
}

/// Read one frame (everything after its length). `None` at a clean end of
/// stream. With `idle`, waiting longer than that for the frame to *start* is
/// an error: the peer missed its keepalives.
async fn read_frame<R: AsyncRead + Unpin>(
    rd: &mut R,
    idle: Option<Duration>,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    let res = match idle {
        Some(idle) => match tokio::time::timeout(idle, rd.read_exact(&mut len_buf)).await {
            Ok(r) => r,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "raft peer sent nothing, not even a keepalive, within the idle timeout",
                ))
            }
        },
        None => rd.read_exact(&mut len_buf).await,
    };
    match res {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len_buf) as usize;
    if n > MAX_RAFT_FRAME {
        return Err(invalid("raft frame too large"));
    }
    let mut frame = vec![0u8; n];
    rd.read_exact(&mut frame).await?;
    Ok(Some(frame))
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
    /// Bind the listener and dial every peer, authenticating with the shared
    /// secret alone. `peers` MUST not contain `node_id` itself.
    pub async fn bind(
        node_id: NodeId,
        bind: SocketAddr,
        peers: BTreeMap<NodeId, SocketAddr>,
        reconnect_backoff: Duration,
        shared_secret: Option<SharedSecret>,
    ) -> Result<Arc<Self>> {
        let options = HubOptions {
            shared_secret,
            ..HubOptions::default()
        };
        Self::bind_with_options(node_id, bind, peers, reconnect_backoff, options).await
    }

    /// Bind the listener and dial every peer. `peers` MUST not contain
    /// `node_id` itself.
    pub async fn bind_with_options(
        node_id: NodeId,
        bind: SocketAddr,
        peers: BTreeMap<NodeId, SocketAddr>,
        reconnect_backoff: Duration,
        options: HubOptions,
    ) -> Result<Arc<Self>> {
        // No-auth is allowed only where it was ever defensible: a bind the
        // kernel will not route from off-box. A secret that is present is at
        // least `MIN_SECRET_BYTES` long: `SharedSecret` cannot hold less.
        let secret: Vec<u8> = options
            .shared_secret
            .map(|s| s.expose().to_vec())
            .unwrap_or_default();
        let authenticated = !secret.is_empty() || options.tls.is_some();
        if !authenticated && !bind_is_loopback(&bind) {
            anyhow::bail!(
                "refusing to open an unauthenticated raft port on {bind}: neither a shared \
                 secret nor mTLS is configured, and this address is reachable from off-box. Set \
                 the cluster shared secret or --raft-tls-*, or bind to 127.0.0.1 for a \
                 single-node setup."
            );
        }
        if options.tls.is_some() && options.legacy_handshake {
            anyhow::bail!(
                "--raft-legacy-handshake cannot be combined with mTLS: a 0.2 broker cannot speak \
                 TLS, so there is nothing for it to stay compatible with. Finish the upgrade \
                 first, then enable --raft-tls-* on every member."
            );
        }
        if options.idle_timeout <= options.keepalive_interval {
            anyhow::bail!(
                "the raft idle timeout ({:?}) must exceed the keepalive interval ({:?}), or \
                 healthy connections are closed between two keepalives",
                options.idle_timeout,
                options.keepalive_interval
            );
        }
        if peers.contains_key(&node_id) {
            anyhow::bail!(
                "node {node_id} is listed as its own peer: a node that dials itself counts its \
                 own vote twice and a majority of two becomes one"
            );
        }
        if options.legacy_handshake {
            tracing::warn!(
                "--raft-legacy-handshake is set: this broker accepts the deprecated 0.2 raft \
                 handshake, in which it proves itself to anyone who connects. Remove the flag \
                 once every member runs 0.3; it goes away in 0.4."
            );
        }
        // Only with authentication: without it the bind is loopback, and the
        // filter would add nothing but a way to misconfigure `::1` against
        // `127.0.0.1`.
        let allowed_ips = if authenticated {
            peer_source_filter(&peers)
        } else {
            None
        };
        let auth = Arc::new(HubAuth {
            me: node_id,
            secret,
            peers: RwLock::new(peers.keys().copied().collect()),
            tls: options.tls,
            legacy_handshake: options.legacy_handshake,
            keepalive_interval: options.keepalive_interval,
            idle_timeout: options.idle_timeout,
        });

        let listener = TcpListener::bind(bind).await?;
        let local_addr = listener.local_addr()?;
        let cancel = CancellationToken::new();
        let groups: Groups = Arc::new(DashMap::new());
        let peer_senders: PeerSenders = Arc::new(DashMap::new());

        // --- listener: accept inbound peer connections ---
        let inbound = Inbound::new(groups.clone(), cancel.clone(), auth.clone(), allowed_ips);
        tokio::spawn(inbound.accept_loop(listener));

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
    shared_secret: Option<SharedSecret>,
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
    // Version 2 is tried only after a version-3 hello went unanswered, and
    // only for one connection: once that peer is upgraded, the next dial
    // finds it speaking version 3.
    let mut try_v2 = false;
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let connect = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(peer_addr)).await;
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
        let version = if try_v2 { Version::V2 } else { Version::V3 };
        try_v2 = false;
        match run_outbound(sock, peer_id, version, &mut peer_rx, &cancel, &auth).await {
            Err(e)
                if version == Version::V3
                    && auth.legacy_handshake
                    && e.kind() == std::io::ErrorKind::ConnectionRefused =>
            {
                tracing::info!(
                    peer = peer_id,
                    "raft: peer did not answer the version-3 handshake; retrying in version 2 \
                     (--raft-legacy-handshake)"
                );
                try_v2 = true;
                continue;
            }
            Err(e) => tracing::debug!(peer = peer_id, error = %e, "raft connection dropped"),
            Ok(()) => {}
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

/// Aborts a task when dropped, so a connection's reader never outlives it.
struct AbortOnDrop(JoinHandle<std::io::Result<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn run_outbound(
    sock: TcpStream,
    peer_id: NodeId,
    version: Version,
    peer_rx: &mut mpsc::Receiver<Arc<Vec<u8>>>,
    cancel: &CancellationToken,
    auth: &HubAuth,
) -> std::io::Result<()> {
    let mut io: BoxIo = match &auth.tls {
        Some(tls) => Box::new(with_handshake_timeout(tls.connect(peer_id, sock)).await?),
        None => Box::new(sock),
    };
    let session = match version {
        Version::V3 => dialer_handshake(&mut io, auth.me, peer_id, &auth.secret).await?,
        Version::V2 => dialer_handshake_v2(&mut io, auth.me, peer_id, &auth.secret).await?,
    };
    let Session {
        mut sealer, opener, ..
    } = session;
    let (rd, mut wr) = tokio::io::split(io);

    // Inbound peer messages arrive on that peer's own connection to us; what
    // comes back on this one is the listener's keepalives, read on their own
    // task so a frame half-read is never abandoned by the select below. A
    // 0.2 listener sends nothing back and expects no keepalives.
    let keepalives = version == Version::V3;
    let mut reader = AbortOnDrop(tokio::spawn(read_keepalives(
        rd,
        opener,
        keepalives.then_some(auth.idle_timeout),
    )));
    let mut tick = tokio::time::interval(auth.keepalive_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    let mut sent_since_tick = false;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            res = &mut reader.0 => {
                return match res {
                    Ok(r) => r,
                    Err(e) => Err(std::io::Error::other(e)),
                };
            }
            msg = peer_rx.recv() => {
                let Some(payload) = msg else { return Ok(()); };
                write_frame(&mut wr, &sealer.seal(&payload)).await?;
                sent_since_tick = true;
            }
            _ = tick.tick(), if keepalives => {
                if !sent_since_tick {
                    write_frame(&mut wr, &sealer.keepalive()).await?;
                }
                sent_since_tick = false;
            }
        }
    }
}

/// The dialer's read side: only keepalives come back. Ends cleanly when the
/// listener closes the connection, which sends the dial loop to redial.
async fn read_keepalives<R: AsyncRead + Unpin>(
    mut rd: R,
    mut opener: FrameOpener,
    idle: Option<Duration>,
) -> std::io::Result<()> {
    loop {
        let Some(frame) = read_frame(&mut rd, idle).await? else {
            return Ok(());
        };
        if opener.open(&frame)? != KEEPALIVE {
            return Err(invalid(
                "raft listener sent something other than a keepalive",
            ));
        }
    }
}

/// The source addresses inbound connections may come from: the peers' IPs.
/// `None` means no filter — no peers, or one listed at an unspecified address,
/// which names no source to compare against.
fn peer_source_filter(peers: &BTreeMap<NodeId, SocketAddr>) -> Option<HashSet<IpAddr>> {
    if peers.is_empty() || peers.values().any(|a| a.ip().is_unspecified()) {
        return None;
    }
    Some(peers.values().map(|a| a.ip().to_canonical()).collect())
}

/// The listener side of a hub: who may connect, how many may be handshaking,
/// and which connection currently speaks for each peer.
struct Inbound {
    groups: Groups,
    cancel: CancellationToken,
    auth: Arc<HubAuth>,
    /// Source addresses accepted at all; `None` accepts any.
    allowed_ips: Option<HashSet<IpAddr>>,
    handshakes: Arc<Semaphore>,
    handshakes_per_ip: Mutex<HashMap<IpAddr, usize>>,
    /// The live inbound connection of each authenticated peer: its id and the
    /// token that closes it.
    established: Mutex<HashMap<NodeId, (u64, CancellationToken)>>,
    next_conn: AtomicU64,
}

/// A handshake slot, global and per source address. Released on drop, which
/// is when the handshake ends one way or the other.
struct HandshakeSlot {
    inbound: Arc<Inbound>,
    ip: IpAddr,
    _permit: OwnedSemaphorePermit,
}

impl Drop for HandshakeSlot {
    fn drop(&mut self) {
        let mut per_ip = self.inbound.handshakes_per_ip.lock().unwrap();
        if let Some(n) = per_ip.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                per_ip.remove(&self.ip);
            }
        }
    }
}

impl Inbound {
    fn new(
        groups: Groups,
        cancel: CancellationToken,
        auth: Arc<HubAuth>,
        allowed_ips: Option<HashSet<IpAddr>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            groups,
            cancel,
            auth,
            allowed_ips,
            handshakes: Arc::new(Semaphore::new(MAX_HANDSHAKES)),
            handshakes_per_ip: Mutex::new(HashMap::new()),
            established: Mutex::new(HashMap::new()),
            next_conn: AtomicU64::new(0),
        })
    }

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                res = listener.accept() => {
                    let (sock, from) = match res {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(error = %e, "raft accept failed");
                            // EMFILE and friends: don't spin.
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    let Some(slot) = self.admit(from.ip()) else {
                        continue;
                    };
                    let me = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = me.serve(sock, slot).await {
                            tracing::debug!(%from, error = %e, "raft inbound closed");
                        }
                    });
                }
            }
        }
    }

    /// Decide at accept whether a connection from `ip` may handshake, and
    /// take its slot if so. Dropping the socket is the refusal.
    fn admit(self: &Arc<Self>, ip: IpAddr) -> Option<HandshakeSlot> {
        let ip = ip.to_canonical();
        if let Some(allowed) = &self.allowed_ips {
            if !allowed.contains(&ip) {
                tracing::warn!(%ip, "raft: connection from an address that is no configured peer's; closed");
                return None;
            }
        }
        let Ok(permit) = self.handshakes.clone().try_acquire_owned() else {
            tracing::warn!(%ip, "raft: too many handshakes in progress; connection closed");
            return None;
        };
        let mut per_ip = self.handshakes_per_ip.lock().unwrap();
        let n = per_ip.entry(ip).or_insert(0);
        if *n >= MAX_HANDSHAKES_PER_IP {
            tracing::warn!(%ip, "raft: too many handshakes in progress from one address; connection closed");
            return None;
        }
        *n += 1;
        Some(HandshakeSlot {
            inbound: self.clone(),
            ip,
            _permit: permit,
        })
    }

    /// Make this connection the one that speaks for `peer`, closing the one
    /// it replaces. A peer redials when its connection breaks, so the newest
    /// is the live one; keeping the old would let a dead socket, or a holder
    /// of the secret, pile up connections under one id.
    fn claim(&self, peer: NodeId) -> (u64, CancellationToken) {
        let id = self.next_conn.fetch_add(1, Ordering::Relaxed);
        let token = self.cancel.child_token();
        let old = self
            .established
            .lock()
            .unwrap()
            .insert(peer, (id, token.clone()));
        if let Some((_, old)) = old {
            tracing::debug!(
                peer,
                "raft: a new connection from this peer replaces the old one"
            );
            old.cancel();
        }
        (id, token)
    }

    fn release(&self, peer: NodeId, id: u64) {
        let mut est = self.established.lock().unwrap();
        if est.get(&peer).is_some_and(|(cur, _)| *cur == id) {
            est.remove(&peer);
        }
    }

    async fn serve(&self, sock: TcpStream, slot: HandshakeSlot) -> std::io::Result<()> {
        let _ = sock.set_nodelay(true);
        let (mut io, certified): (BoxIo, Option<NodeId>) = match &self.auth.tls {
            Some(tls) => {
                let stream = with_handshake_timeout(tls.accept(sock)).await?;
                let cert = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|chain| chain.first())
                    .ok_or_else(|| denied("raft dialer presented no certificate"))?;
                let id = super::tls::identify(cert, self.auth.peer_ids()).map_err(denied)?;
                (Box::new(stream), Some(id))
            }
            None => (Box::new(sock), None),
        };
        let (peer_id, session) = listener_handshake(&mut io, &self.auth, certified).await?;
        drop(slot);
        let (conn, closed) = self.claim(peer_id);
        let res = self.run_session(io, peer_id, session, &closed).await;
        self.release(peer_id, conn);
        res
    }

    async fn run_session(
        &self,
        io: BoxIo,
        peer_id: NodeId,
        session: Session,
        closed: &CancellationToken,
    ) -> std::io::Result<()> {
        let Session {
            version,
            sealer,
            opener,
        } = session;
        if version == Version::V2 {
            // A 0.2 dialer sends nothing when it has nothing to say and reads
            // nothing back: no keepalives, and so no idle timeout either.
            return read_frames(io, peer_id, opener, &self.groups, closed, None).await;
        }
        let (rd, wr) = tokio::io::split(io);
        let reading = read_frames(
            rd,
            peer_id,
            opener,
            &self.groups,
            closed,
            Some(self.auth.idle_timeout),
        );
        tokio::select! {
            r = reading => r,
            r = send_keepalives(wr, sealer, self.auth.keepalive_interval) => r,
        }
    }
}

/// The listener's write side: nothing but keepalives, until a write fails.
async fn send_keepalives<W: AsyncWrite + Unpin>(
    mut wr: W,
    mut sealer: FrameSealer,
    interval: Duration,
) -> std::io::Result<()> {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tick.tick().await;
        write_frame(&mut wr, &sealer.keepalive()).await?;
    }
}

/// Read, verify and route frames from an authenticated peer until the
/// connection ends, `closed` fires, or — with `idle` — the peer goes silent.
async fn read_frames<R: AsyncRead + Unpin>(
    mut sock: R,
    peer_id: NodeId,
    mut opener: FrameOpener,
    groups: &Groups,
    closed: &CancellationToken,
    idle: Option<Duration>,
) -> std::io::Result<()> {
    loop {
        let frame = tokio::select! {
            _ = closed.cancelled() => return Ok(()),
            res = read_frame(&mut sock, idle) => match res? {
                Some(frame) => frame,
                None => return Ok(()),
            },
        };
        let payload = opener.open(&frame)?;
        if payload == KEEPALIVE {
            continue;
        }
        let (group, body) = split_frame(payload)?;
        let msg = Message::decode(body).map_err(|e| invalid(&format!("decode: {}", e)))?;
        if msg.sender() != peer_id {
            tracing::warn!(
                peer = peer_id,
                claimed = msg.sender(),
                "raft: message claims another sender; dropped"
            );
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::messages::{Message, RequestVote};

    pub(super) fn sample_msg(from: NodeId) -> Message {
        Message::RequestVote(RequestVote {
            term: 99,
            candidate_id: from,
            last_log_index: 0,
            last_log_term: 0,
        })
    }

    /// A registry with `names` registered, plus the receivers to assert on.
    pub(super) fn registry(
        names: &[&str],
    ) -> (Groups, Vec<(String, mpsc::UnboundedReceiver<Message>)>) {
        let groups: Groups = Arc::new(DashMap::new());
        let mut rxs = Vec::new();
        for name in names {
            let (tx, rx) = mpsc::unbounded_channel();
            groups.insert((*name).to_string(), tx);
            rxs.push(((*name).to_string(), rx));
        }
        (groups, rxs)
    }

    pub(super) fn base_auth(me: NodeId, secret: &[u8], peers: &[NodeId]) -> HubAuth {
        HubAuth {
            me,
            secret: secret.to_vec(),
            peers: RwLock::new(peers.iter().copied().collect()),
            tls: None,
            legacy_handshake: false,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }

    pub(super) fn auth(me: NodeId, secret: &[u8], peers: &[NodeId]) -> Arc<HubAuth> {
        Arc::new(base_auth(me, secret, peers))
    }

    /// A cluster secret long enough for `SharedSecret`.
    pub(super) const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
    const WRONG: &[u8] = b"fedcba9876543210fedcba9876543210";

    pub(super) async fn serve_one(
        groups: Groups,
        auth: Arc<HubAuth>,
    ) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let inbound = Inbound::new(groups, CancellationToken::new(), auth, None);
        (addr, tokio::spawn(inbound.accept_loop(listener)))
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
        let (addr, server) = serve_one(groups, auth(1, SECRET, &[7])).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        // The dialer itself notices: the listener's proof does not verify
        // under the wrong secret, so nothing is ever sent.
        let res = dialer_handshake(&mut client, 7, 1, WRONG).await;
        assert!(res.is_err(), "a wrong secret must fail the handshake");
        let (_, rx) = &mut rxs[0];
        let got = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(!matches!(got, Ok(Some(_))), "no message may be delivered");
        server.abort();
    }

    #[tokio::test]
    async fn accepts_peer_with_correct_secret() {
        let (groups, mut rxs) = registry(&[DEFAULT_GROUP]);
        let (addr, server) = serve_one(groups, auth(1, SECRET, &[7])).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut sealer = dialer_handshake(&mut client, 7, 1, SECRET).await.unwrap();
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
        let (addr, server) = serve_one(groups, auth(1, SECRET, &[7, 8])).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut sealer = dialer_handshake(&mut client, 7, 1, SECRET).await.unwrap();
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

    /// The limit of a cluster-wide secret, pinned so the docs stay honest: a
    /// holder of the secret can authenticate as any member id it likes.
    #[tokio::test]
    async fn a_secret_holder_can_dial_as_any_member() {
        let (groups, mut rxs) = registry(&[DEFAULT_GROUP]);
        let (addr, server) = serve_one(groups, auth(1, SECRET, &[7, 8])).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut sealer = dialer_handshake(&mut client, 8, 1, SECRET).await.unwrap();
        client
            .write_all(&sealer.frame(DEFAULT_GROUP, &sample_msg(8)))
            .await
            .unwrap();
        let (_, rx) = &mut rxs[0];
        let got = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.sender(), 8);
        server.abort();
    }

    /// A second connection from the same peer replaces the first: one
    /// established inbound connection per peer id.
    #[tokio::test]
    async fn a_new_connection_from_a_peer_replaces_its_old_one() {
        let (groups, mut rxs) = registry(&[DEFAULT_GROUP]);
        let (addr, server) = serve_one(groups, auth(1, SECRET, &[7])).await;
        let (_, rx) = &mut rxs[0];
        let mut first = TcpStream::connect(addr).await.unwrap();
        let mut first_sealer = dialer_handshake(&mut first, 7, 1, SECRET).await.unwrap();
        // Wait until the listener has taken the first connection as peer 7's.
        first
            .write_all(&first_sealer.frame(DEFAULT_GROUP, &sample_msg(7)))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("the first connection carries traffic");
        let mut second = TcpStream::connect(addr).await.unwrap();
        let mut sealer = dialer_handshake(&mut second, 7, 1, SECRET).await.unwrap();

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), first.read(&mut buf))
            .await
            .expect("the replaced connection must be closed")
            .unwrap_or(0);
        assert_eq!(n, 0, "the replaced connection reads end-of-stream");

        second
            .write_all(&sealer.frame(DEFAULT_GROUP, &sample_msg(7)))
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("the replacing connection carries traffic");
        assert!(matches!(got, Some(Message::RequestVote(_))));
        server.abort();
    }

    #[test]
    fn only_configured_peer_addresses_may_connect() {
        let mut peers = BTreeMap::new();
        peers.insert(2u32, "10.0.0.2:6000".parse().unwrap());
        peers.insert(3u32, "10.0.0.3:6000".parse().unwrap());
        let allowed = peer_source_filter(&peers);
        let (groups, _rxs) = registry(&[]);
        let inbound = Inbound::new(
            groups,
            CancellationToken::new(),
            auth(1, SECRET, &[2, 3]),
            allowed,
        );
        assert!(inbound.admit("203.0.113.9".parse().unwrap()).is_none());
        assert!(inbound.admit("10.0.0.2".parse().unwrap()).is_some());
        // A dual-stack listener sees IPv4 peers as mapped IPv6 addresses.
        assert!(inbound.admit("::ffff:10.0.0.3".parse().unwrap()).is_some());

        peers.insert(4u32, "0.0.0.0:6000".parse().unwrap());
        assert!(
            peer_source_filter(&peers).is_none(),
            "an unspecified peer address names no source"
        );
        assert!(peer_source_filter(&BTreeMap::new()).is_none());
    }

    #[test]
    fn handshakes_are_capped_per_source_address() {
        let (groups, _rxs) = registry(&[]);
        let inbound = Inbound::new(
            groups,
            CancellationToken::new(),
            auth(1, SECRET, &[7]),
            None,
        );
        let a: IpAddr = "10.0.0.7".parse().unwrap();
        let mut held: Vec<_> = (0..MAX_HANDSHAKES_PER_IP)
            .map(|_| inbound.admit(a).expect("under the cap"))
            .collect();
        assert!(inbound.admit(a).is_none(), "one address cannot hold more");
        assert!(
            inbound.admit("10.0.0.8".parse().unwrap()).is_some(),
            "others are unaffected"
        );
        held.pop();
        assert!(
            inbound.admit(a).is_some(),
            "a finished handshake frees its slot"
        );
    }

    #[tokio::test]
    async fn a_tampered_or_replayed_frame_closes_the_connection() {
        let (groups, mut rxs) = registry(&[DEFAULT_GROUP]);
        let (addr, server) = serve_one(groups, auth(1, SECRET, &[7])).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut sealer = dialer_handshake(&mut client, 7, 1, SECRET).await.unwrap();
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
        let (addr, server) = serve_one(groups, auth(1, SECRET, &[7])).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        assert!(dialer_handshake(&mut client, 9, 1, SECRET).await.is_err());
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

/// Bonfire #724: the version-3 handshake, keepalives, and mTLS identity.
#[cfg(test)]
mod identity_tests {
    use super::tests::{auth, base_auth, registry, sample_msg, serve_one, SECRET};
    use super::*;
    use crate::raft::tls::test_support::{tls, tls_as};

    /// A port nothing listens on yet, for a hub whose peers must know it.
    fn free_addr() -> SocketAddr {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    }

    /// Read until the peer closes; the bytes read, or `None` if it stayed
    /// open past `within`.
    async fn read_to_close<R: AsyncRead + Unpin>(r: &mut R, within: Duration) -> Option<usize> {
        let mut total = 0;
        let mut buf = [0u8; 256];
        let res = tokio::time::timeout(within, async {
            loop {
                match r.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => total += n,
                }
            }
        })
        .await;
        res.ok().map(|_| total)
    }

    #[tokio::test]
    async fn the_listener_never_proves_itself_before_the_dialer() {
        let (groups, _rxs) = registry(&[DEFAULT_GROUP]);
        let (addr, server) = serve_one(groups, auth(1, SECRET, &[7])).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(&hello(Version::V3, 7, &[9u8; NONCE_LEN]))
            .await
            .unwrap();
        let mut reply = [0u8; HELLO_LEN];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[0..4], b"RAF3");
        assert_eq!(u32::from_be_bytes(reply[4..8].try_into().unwrap()), 1);

        // The reply is a nonce and nothing else: no proof until ours arrives.
        let mut extra = [0u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), c.read(&mut extra))
                .await
                .is_err(),
            "the listener sent more than its nonce before the dialer proved anything"
        );
        // A wrong proof: the connection closes, and the listener's proof
        // never comes.
        c.write_all(&[0u8; MAC_LEN]).await.unwrap();
        assert_eq!(
            read_to_close(&mut c, Duration::from_secs(2)).await,
            Some(0),
            "no byte may follow a failed dialer proof"
        );
        server.abort();
    }

    #[tokio::test]
    async fn a_version_2_dialer_is_refused_unless_legacy_is_enabled() {
        let (groups, _rxs) = registry(&[DEFAULT_GROUP]);
        let (addr, server) = serve_one(groups, auth(1, SECRET, &[7])).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        assert!(
            dialer_handshake_v2(&mut c, 7, 1, SECRET).await.is_err(),
            "version 2 hands out the listener's proof first; refused by default"
        );
        server.abort();

        let (groups, mut rxs) = registry(&[DEFAULT_GROUP]);
        let mut legacy = base_auth(1, SECRET, &[7]);
        legacy.legacy_handshake = true;
        let (addr, server) = serve_one(groups, Arc::new(legacy)).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        let mut s = dialer_handshake_v2(&mut c, 7, 1, SECRET).await.unwrap();
        assert_eq!(s.version, Version::V2);
        c.write_all(&s.frame(DEFAULT_GROUP, &sample_msg(7)))
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_millis(500), rxs[0].1.recv())
            .await
            .expect("a 0.2 dialer's frame is delivered under --raft-legacy-handshake");
        assert!(matches!(got, Some(Message::RequestVote(_))));
        server.abort();
    }

    /// A 0.2.1 listener, as it behaved: version 2 only, closing on any other
    /// magic. Reports every message it authenticates.
    async fn old_listener(me: NodeId) -> (SocketAddr, mpsc::UnboundedReceiver<Message>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut h = [0u8; HELLO_LEN];
                    s.read_exact(&mut h).await?;
                    if h[0..4] != MAGIC_V2 {
                        return Ok::<(), std::io::Error>(());
                    }
                    let d = u32::from_be_bytes(h[4..8].try_into().unwrap());
                    let nl = [5u8; NONCE_LEN];
                    let mut reply = hello(Version::V2, me, &nl);
                    reply.extend_from_slice(&derive(
                        Version::V2,
                        SECRET,
                        b"listener",
                        &h[8..],
                        &nl,
                        d,
                        me,
                    ));
                    s.write_all(&reply).await?;
                    let mut proof = [0u8; MAC_LEN];
                    s.read_exact(&mut proof).await?;
                    let mut opener = Session::new(Version::V2, SECRET, &h[8..], &nl, d, me)
                        .reversed()
                        .opener;
                    while let Some(frame) = read_frame(&mut s, None).await? {
                        let (_, body) = split_frame(opener.open(&frame)?)?;
                        let _ = tx.send(Message::decode(body)?);
                    }
                    Ok(())
                });
            }
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn a_dialer_falls_back_to_version_2_for_a_0_2_broker() {
        let (addr, mut got) = old_listener(1).await;
        let options = HubOptions {
            shared_secret: Some(SharedSecret::new(SECRET).unwrap()),
            legacy_handshake: true,
            ..HubOptions::default()
        };
        let hub = RaftHub::bind_with_options(
            7,
            "127.0.0.1:0".parse().unwrap(),
            BTreeMap::from([(1, addr)]),
            Duration::from_millis(20),
            options,
        )
        .await
        .unwrap();
        let (in_tx, _in_rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        hub.register(DEFAULT_GROUP, in_tx, out_rx).unwrap();
        out_tx.send(Outbound::SendTo(1, sample_msg(7))).unwrap();
        let msg = tokio::time::timeout(Duration::from_secs(3), got.recv())
            .await
            .expect("the 0.2 broker is reached in version 2");
        assert_eq!(msg.unwrap().sender(), 7);
        hub.shutdown();
    }

    #[tokio::test]
    async fn an_idle_connection_is_closed() {
        let (groups, _rxs) = registry(&[DEFAULT_GROUP]);
        let mut a = base_auth(1, SECRET, &[7]);
        a.keepalive_interval = Duration::from_millis(50);
        a.idle_timeout = Duration::from_millis(250);
        let (addr, server) = serve_one(groups, Arc::new(a)).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        dialer_handshake(&mut c, 7, 1, SECRET).await.unwrap();
        // The listener keeps sending its keepalives, but hears none: it must
        // close the connection rather than hold it forever.
        let read = read_to_close(&mut c, Duration::from_secs(3)).await;
        assert!(read.is_some(), "a silent dialer must be disconnected");
        server.abort();
    }

    #[tokio::test]
    async fn keepalives_hold_a_quiet_connection_open() {
        let (groups, mut rxs) = registry(&[DEFAULT_GROUP]);
        let mut a = base_auth(1, SECRET, &[7]);
        a.keepalive_interval = Duration::from_millis(50);
        a.idle_timeout = Duration::from_millis(250);
        let (addr, server) = serve_one(groups, Arc::new(a)).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        let mut s = dialer_handshake(&mut c, 7, 1, SECRET).await.unwrap();
        for _ in 0..12 {
            c.write_all(&s.sealer.keepalive()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        c.write_all(&s.frame(DEFAULT_GROUP, &sample_msg(7)))
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_millis(500), rxs[0].1.recv())
            .await
            .expect("a connection kept alive past the idle timeout still carries traffic");
        assert!(matches!(got, Some(Message::RequestVote(_))));
        // And what came back were authenticated keepalives.
        let mut n = 0;
        while let Ok(Ok(Some(frame))) =
            tokio::time::timeout(Duration::from_millis(100), read_frame(&mut c, None)).await
        {
            assert_eq!(s.opener.open(&frame).unwrap(), KEEPALIVE);
            n += 1;
        }
        assert!(n > 0, "the listener sends keepalives too");
        server.abort();
    }

    #[tokio::test]
    async fn a_dialer_redials_when_its_listener_goes_silent() {
        // A listener that completes the handshake, then never sends a
        // keepalive: the dialer must give up on it and dial again.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicU64::new(0));
        let counter = accepted.clone();
        let la = auth(1, SECRET, &[7]);
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let la = la.clone();
                tokio::spawn(async move {
                    if listener_handshake(&mut s, &la, None).await.is_ok() {
                        let mut sink = [0u8; 1024];
                        while matches!(s.read(&mut sink).await, Ok(n) if n > 0) {}
                    }
                });
            }
        });
        let options = HubOptions {
            shared_secret: Some(SharedSecret::new(SECRET).unwrap()),
            keepalive_interval: Duration::from_millis(50),
            idle_timeout: Duration::from_millis(250),
            ..HubOptions::default()
        };
        let hub = RaftHub::bind_with_options(
            7,
            "127.0.0.1:0".parse().unwrap(),
            BTreeMap::from([(1, addr)]),
            Duration::from_millis(20),
            options,
        )
        .await
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while accepted.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            accepted.load(Ordering::SeqCst) >= 2,
            "a missed keepalive must close the connection and the dialer redial"
        );
        hub.shutdown();
    }

    #[tokio::test]
    async fn the_hub_refuses_an_idle_timeout_shorter_than_its_keepalives() {
        let options = HubOptions {
            keepalive_interval: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(5),
            ..HubOptions::default()
        };
        let err = RaftHub::bind_with_options(
            1,
            "127.0.0.1:0".parse().unwrap(),
            BTreeMap::new(),
            Duration::from_millis(50),
            options,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("must exceed"), "{err}");
    }

    fn mtls_auth(me: NodeId, presented: NodeId, peers: &[NodeId]) -> Arc<HubAuth> {
        let mut a = base_auth(me, b"", peers);
        a.tls = Some(Arc::new(tls_as(me, presented).unwrap()));
        Arc::new(a)
    }

    #[tokio::test]
    async fn under_mtls_a_broker_cannot_claim_another_node_id() {
        let (groups, mut rxs) = registry(&[DEFAULT_GROUP]);
        let (addr, server) = serve_one(groups, mtls_auth(1, 1, &[2, 3])).await;

        // Node 2's valid certificate, announcing itself as node 3.
        let sock = TcpStream::connect(addr).await.unwrap();
        let mut s = tls(2).connect(1, sock).await.unwrap();
        let res = dialer_handshake(&mut s, 3, 1, b"").await;
        assert!(res.is_err(), "the certificate names node 2, not node 3");
        let got = tokio::time::timeout(Duration::from_millis(300), rxs[0].1.recv()).await;
        assert!(!matches!(got, Ok(Some(_))), "nothing may be delivered");

        // The same certificate, announcing the node it names, is accepted.
        let sock = TcpStream::connect(addr).await.unwrap();
        let mut s = tls(2).connect(1, sock).await.unwrap();
        let mut session = dialer_handshake(&mut s, 2, 1, b"").await.unwrap();
        s.write_all(&session.frame(DEFAULT_GROUP, &sample_msg(2)))
            .await
            .unwrap();
        s.flush().await.unwrap();
        let got = tokio::time::timeout(Duration::from_millis(500), rxs[0].1.recv())
            .await
            .expect("node 2 speaks as node 2");
        assert_eq!(got.unwrap().sender(), 2);
        server.abort();
    }

    #[tokio::test]
    async fn under_mtls_the_dialer_refuses_a_certificate_for_another_node() {
        let (groups, _rxs) = registry(&[DEFAULT_GROUP]);
        // Listening as node 1 with node 3's certificate.
        let (addr, server) = serve_one(groups, mtls_auth(1, 3, &[2])).await;
        let sock = TcpStream::connect(addr).await.unwrap();
        assert!(
            tls(2).connect(1, sock).await.is_err(),
            "node 2 dialed node 1 and must not accept a certificate naming node 3"
        );
        server.abort();
    }

    #[tokio::test]
    async fn under_mtls_a_dialer_without_a_certificate_is_refused() {
        let (groups, _rxs) = registry(&[DEFAULT_GROUP]);
        let (addr, server) = serve_one(groups, mtls_auth(1, 1, &[2])).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        assert!(dialer_handshake(&mut c, 2, 1, b"").await.is_err());
        server.abort();
    }

    #[tokio::test]
    async fn two_hubs_replicate_over_mtls() {
        let (a1, a2) = (free_addr(), free_addr());
        let opts = |n| HubOptions {
            tls: Some(tls(n)),
            ..HubOptions::default()
        };
        let h1 = RaftHub::bind_with_options(
            1,
            a1,
            BTreeMap::from([(2, a2)]),
            Duration::from_millis(20),
            opts(1),
        )
        .await
        .unwrap();
        let h2 = RaftHub::bind_with_options(
            2,
            a2,
            BTreeMap::from([(1, a1)]),
            Duration::from_millis(20),
            opts(2),
        )
        .await
        .unwrap();
        let (in1, _r1) = mpsc::unbounded_channel();
        let (out1, orx1) = mpsc::unbounded_channel();
        h1.register(DEFAULT_GROUP, in1, orx1).unwrap();
        let (in2, mut r2) = mpsc::unbounded_channel();
        let (_out2, orx2) = mpsc::unbounded_channel();
        h2.register(DEFAULT_GROUP, in2, orx2).unwrap();
        out1.send(Outbound::SendTo(2, sample_msg(1))).unwrap();
        let got = tokio::time::timeout(Duration::from_secs(3), r2.recv())
            .await
            .expect("a frame crosses an mTLS connection");
        assert_eq!(got.unwrap().sender(), 1);
        h1.shutdown();
        h2.shutdown();
    }

    #[tokio::test]
    async fn mtls_allows_a_routable_bind_without_a_secret_but_not_legacy() {
        let ok = RaftHub::bind_with_options(
            1,
            "0.0.0.0:0".parse().unwrap(),
            BTreeMap::new(),
            Duration::from_millis(50),
            HubOptions {
                tls: Some(tls(1)),
                ..HubOptions::default()
            },
        )
        .await;
        ok.expect("mTLS authenticates the port").shutdown();
        let err = RaftHub::bind_with_options(
            1,
            "127.0.0.1:0".parse().unwrap(),
            BTreeMap::new(),
            Duration::from_millis(50),
            HubOptions {
                tls: Some(tls(1)),
                legacy_handshake: true,
                ..HubOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("cannot speak TLS"), "{err}");
    }
}
