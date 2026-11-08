use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout_at, Instant};
use tokio_util::sync::CancellationToken;

use es_protocol::wire::{
    decode_consume_request, decode_produce_request, encode_produce_response, HandshakeStatus,
    Opcode, WireConsumeRequest, WireProduceResult, FEATURE_GZIP, WIRE_MAGIC,
};

use crate::auth::{AclAction, ApiKey, AuthMode, ANONYMOUS_ADMIN};
use crate::broker::Broker;
use crate::config::Config;
use crate::dataplane::{self, IncomingRecord, Origin, MAX_RECORDS_PER_REQUEST};

use super::codec::{self, IoStream};

/// Ceiling on concurrent connections, before the file-descriptor budget.
const MAX_CONNECTIONS_CAP: usize = 4096;
/// Time budget for a client to complete the TLS and protocol handshakes,
/// together: one deadline, not one per stage. Bounds pre-auth slowloris holds.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Once a frame's length prefix has arrived, its header must follow within
/// this window; its body may fall this far behind [`MIN_BODY_RATE`].
const BODY_GRACE: Duration = Duration::from_secs(3);
/// Slowest rate, in bytes per second, at which a frame body may arrive once
/// memory is reserved for it. A body that only trickles in would otherwise
/// keep its whole reservation for [`FRAME_BODY_TIMEOUT`].
const MIN_BODY_RATE: u64 = 1 << 20;
/// Longest any frame body may take, however large.
const FRAME_BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// Bodies are read, and their progress checked, this much at a time.
const BODY_CHUNK: usize = 64 * 1024;
/// A response the client does not read within this long ends the connection,
/// instead of parking its task and buffers forever.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Requests one connection may have in progress at once.
const MAX_INFLIGHT_PER_CONN: usize = 32;
/// Bytes (in KiB) of requests and responses held in memory across all
/// connections. Every frame draws from it, together with room to decompress
/// it, before its body is read; every consume draws its response before
/// fetching; both are returned only once the response is written. Memory is
/// bounded by this rather than by connections × frame size.
const INFLIGHT_BUDGET_KIB: u32 = 1024 * 1024;
/// Share of the budget that frames from one source — an IPv4 address or an
/// IPv6 /64 — may hold while their bodies are still arriving. Length prefixes
/// cost nothing to send; without this, a few dozen of them from one host
/// reserved the whole budget.
const SOURCE_TRANSIT_KIB: u32 = INFLIGHT_BUDGET_KIB / 8;
/// Deflate cannot expand its input by more than this (258-byte matches coded
/// in about two bits), so a small gzip frame needs only a small reservation.
const MAX_INFLATE_RATIO: usize = 1032;
/// Bytes a consume response spends per record on partition, offset,
/// timestamp and the two lengths.
const CONSUME_RECORD_OVERHEAD: usize = 28;
/// Produce-order chains a connection keeps before pruning finished ones.
const MAX_CHAINS: usize = MAX_INFLIGHT_PER_CONN * 2;

fn kib(bytes: usize) -> u32 {
    (bytes.div_ceil(1024)).clamp(1, INFLIGHT_BUDGET_KIB as usize) as u32
}

/// How many connections this process can afford: half of the soft
/// `RLIMIT_NOFILE`, leaving the rest for segment files and HTTP. A cap above
/// the descriptor limit meant `accept` started failing first — and so did
/// every `open` the broker needed for its own data.
pub fn connection_budget() -> usize {
    #[cfg(unix)]
    {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit only writes the struct we pass.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 {
            let soft = rl.rlim_cur as usize;
            return (soft / 2).clamp(16, MAX_CONNECTIONS_CAP);
        }
    }
    MAX_CONNECTIONS_CAP
}

/// Largest request frame accepted (and largest decompressed payload).
fn max_request_bytes(broker: &Broker) -> usize {
    (broker.config.max_record_bytes + (1 << 20)).max(16 << 20)
}

/// Most bytes a gzip body of `compressed` bytes can inflate to, and so the
/// cap it is decompressed under.
fn inflate_bound(compressed: usize, max_request: usize) -> usize {
    compressed
        .saturating_mul(MAX_INFLATE_RATIO)
        .saturating_add(1024)
        .min(max_request)
}

/// Largest response a consume can build, counted twice: the fetched records
/// and their encoding coexist while the body is built, then the body and its
/// gzip copy. A fetch returns its first record whatever `max_bytes` says.
fn consume_reservation(cfg: &Config, req: &WireConsumeRequest) -> usize {
    let max_bytes = (req.max_bytes as usize).clamp(1, cfg.max_fetch_bytes.max(1));
    let max_records = (req.max_records as usize).clamp(1, cfg.max_fetch_records.max(1));
    let body = 20 + max_bytes.max(cfg.max_record_bytes) + max_records * CONSUME_RECORD_OVERHEAD;
    2 * body
}

/// The address connection limits count against. An IPv6 host is handed a
/// whole /64, so counting exact addresses let one host open the per-address
/// cap once per address it chose; IPv4-mapped addresses count as the IPv4
/// address they carry.
fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

/// What the accept loop tracks for one source.
struct Source {
    conns: usize,
    /// Connections that have not completed the handshake yet.
    unauthenticated: usize,
    /// This source's share of the budget for frames still arriving.
    transit: Arc<Semaphore>,
}

type Sources = Arc<DashMap<IpAddr, Source>>;

/// Releases a source's connection slot when the connection ends.
struct SourceSlot {
    map: Sources,
    key: IpAddr,
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let empty = match self.map.get_mut(&self.key) {
            Some(mut s) => {
                s.conns = s.conns.saturating_sub(1);
                s.conns == 0
            }
            None => false,
        };
        if empty {
            self.map.remove_if(&self.key, |_, s| s.conns == 0);
        }
    }
}

/// Releases a source's pre-auth slot once the handshake is over, however it
/// ended.
struct PreAuthSlot {
    map: Sources,
    key: IpAddr,
}

impl Drop for PreAuthSlot {
    fn drop(&mut self) {
        if let Some(mut s) = self.map.get_mut(&self.key) {
            s.unauthenticated = s.unauthenticated.saturating_sub(1);
        }
    }
}

/// The memory a connection's frames and responses draw from.
#[derive(Clone)]
struct Budgets {
    global: Arc<Semaphore>,
    global_kib: u32,
    /// The connection's source's share, for frames still arriving.
    source: Arc<Semaphore>,
    source_kib: u32,
}

/// Run the binary protocol accept loop on `listener` until `cancel` fires.
pub async fn serve_binary(
    broker: Arc<Broker>,
    listener: TcpListener,
    cancel: CancellationToken,
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> Result<()> {
    let addr = listener.local_addr()?;
    let max_connections = connection_budget();
    tracing::info!(
        ?addr,
        tls = tls.is_some(),
        max_connections,
        "binary: listening"
    );
    let conn_limit = Arc::new(Semaphore::new(max_connections));
    let budget = Arc::new(Semaphore::new(INFLIGHT_BUDGET_KIB as usize));
    let sources: Sources = Arc::new(DashMap::new());
    let max_per_ip = broker.config.binary_max_connections_per_ip.max(1);
    // Holding a connection open before authenticating costs a client
    // nothing; a quarter of the per-source cap is plenty for clients that
    // open a pool at once.
    let max_unauthenticated = max_per_ip.div_ceil(4);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!(?addr, "binary: accept loop stopping");
                return Ok(());
            }
            res = listener.accept() => {
                let (sock, peer) = match res {
                    Ok(s) => s,
                    Err(e) => {
                        // EMFILE/ENFILE persist until something closes; a hot
                        // retry loop only burns CPU and floods the log.
                        tracing::warn!(error = %e, "binary: accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let permit = match conn_limit.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!(peer = ?peer, "binary: connection limit reached, dropping");
                        continue;
                    }
                };
                let key = source_key(peer.ip());
                let transit = {
                    // A fresh entry has no connections, so neither check
                    // below can leave an empty one behind.
                    let mut s = sources.entry(key).or_insert_with(|| Source {
                        conns: 0,
                        unauthenticated: 0,
                        transit: Arc::new(Semaphore::new(SOURCE_TRANSIT_KIB as usize)),
                    });
                    if s.conns >= max_per_ip {
                        tracing::warn!(peer = ?peer, "binary: per-address connection limit reached, dropping");
                        continue;
                    }
                    if s.unauthenticated >= max_unauthenticated {
                        tracing::warn!(peer = ?peer, "binary: per-address handshake limit reached, dropping");
                        continue;
                    }
                    s.conns += 1;
                    s.unauthenticated += 1;
                    s.transit.clone()
                };
                let slot = SourceSlot { map: sources.clone(), key };
                let pre_auth = PreAuthSlot { map: sources.clone(), key };
                let budgets = Budgets {
                    global: budget.clone(),
                    global_kib: INFLIGHT_BUDGET_KIB,
                    source: transit,
                    source_kib: SOURCE_TRANSIT_KIB,
                };
                let broker = broker.clone();
                let cancel = cancel.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _slot = slot;
                    if let Err(e) = handle_connection(broker, sock, peer, cancel, tls, budgets, pre_auth).await {
                        tracing::debug!(peer = ?peer, error = %e, "binary: connection ended");
                    }
                });
            }
        }
    }
}

async fn handle_connection(
    broker: Arc<Broker>,
    sock: TcpStream,
    peer: SocketAddr,
    cancel: CancellationToken,
    tls: Option<tokio_rustls::TlsAcceptor>,
    budgets: Budgets,
    pre_auth: PreAuthSlot,
) -> Result<()> {
    sock.set_nodelay(true).ok();
    // One deadline for both handshakes: a separate window for each let a
    // client hold a connection unauthenticated for twice as long.
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let stream: Box<dyn IoStream> = match tls {
        None => Box::new(sock),
        Some(acceptor) => match timeout_at(deadline, acceptor.accept(sock)).await {
            Ok(Ok(s)) => Box::new(s),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Ok(()),
        },
    };
    serve(broker, stream, peer, cancel, budgets, deadline, pre_auth).await
}

/// Client handshake: `magic(4) | features(u32) | auth_token_len(u32) | auth_token`.
async fn read_handshake<S: AsyncRead + Unpin>(
    sock: &mut S,
) -> std::io::Result<([u8; 4], u32, Vec<u8>, bool)> {
    let mut head = [0u8; 12];
    sock.read_exact(&mut head).await?;
    let magic: [u8; 4] = head[0..4].try_into().unwrap();
    let client_features = u32::from_be_bytes(head[4..8].try_into().unwrap());
    let token_len = u32::from_be_bytes(head[8..12].try_into().unwrap());
    if token_len > 1024 {
        return Ok((magic, client_features, Vec::new(), true));
    }
    let mut token = vec![0u8; token_len as usize];
    sock.read_exact(&mut token).await?;
    Ok((magic, client_features, token, false))
}

async fn write_handshake<S: AsyncWrite + Unpin>(
    sock: &mut S,
    status: HandshakeStatus,
    features: u32,
    msg: &str,
) -> std::io::Result<()> {
    // Server reply: magic(4) | status(u8) | features(u32) | msg_len(u32) | msg
    let mut out = Vec::with_capacity(13 + msg.len());
    out.extend_from_slice(&WIRE_MAGIC);
    out.push(status as u8);
    out.extend_from_slice(&features.to_be_bytes());
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg.as_bytes());
    sock.write_all(&out).await?;
    sock.flush().await
}

/// Run the protocol handshake. `None` when the client was turned away.
async fn handshake(
    broker: &Broker,
    stream: &mut Box<dyn IoStream>,
) -> Result<Option<(Arc<ApiKey>, Option<Arc<str>>, bool)>> {
    let (magic, client_features, token_bytes, token_too_long) = read_handshake(stream).await?;
    if magic != WIRE_MAGIC {
        write_handshake(stream, HandshakeStatus::BadMagic, 0, "bad magic").await?;
        return Ok(None);
    }
    if token_too_long {
        write_handshake(
            stream,
            HandshakeStatus::AuthFailed,
            0,
            "auth token too long",
        )
        .await?;
        return Ok(None);
    }
    let token = String::from_utf8(token_bytes).unwrap_or_default();

    let (key, credential): (Arc<ApiKey>, Option<Arc<str>>) = if broker.config.auth_mode
        != AuthMode::Required
    {
        (ANONYMOUS_ADMIN.clone(), None)
    } else {
        if token.is_empty() {
            write_handshake(
                stream,
                HandshakeStatus::AuthRequired,
                0,
                "auth token required",
            )
            .await?;
            return Ok(None);
        }
        match broker.keys.authenticate(&token) {
            // The token is kept: a produce forwarded to a partition's leader
            // presents it there, and the leader authenticates the caller again.
            Some(k) => (k, Some(Arc::from(token))),
            None => {
                write_handshake(stream, HandshakeStatus::AuthFailed, 0, "invalid token").await?;
                return Ok(None);
            }
        }
    };

    // We support only the gzip feature bit. The negotiated set is the
    // intersection of what the client requested and what we know about.
    let negotiated = client_features & FEATURE_GZIP;
    write_handshake(stream, HandshakeStatus::Ok, negotiated, "").await?;
    Ok(Some((key, credential, negotiated & FEATURE_GZIP != 0)))
}

/// A frame on its way to the writer, with the memory reservation it is
/// charged to. The reservation is released once the frame is written, so
/// responses a client does not read count against the budget — they used
/// to be bounded only by the channel's frame count.
struct Outbound {
    frame: Vec<u8>,
    _mem: Option<OwnedSemaphorePermit>,
}

impl Outbound {
    fn new(frame: Vec<u8>, mem: Option<OwnedSemaphorePermit>) -> Self {
        Self { frame, _mem: mem }
    }
}

/// Give back whatever `permit` holds beyond `keep` KiB.
fn shrink(permit: &mut OwnedSemaphorePermit, keep: u32) {
    let held = permit.num_permits();
    let keep = keep as usize;
    if held > keep {
        drop(permit.split(held - keep));
    }
}

/// Reserve `need` KiB for a frame whose body has not arrived: first from the
/// source's share, then from the global budget. Taken in one piece each,
/// before anything else is waited on — a frame that held part of its memory
/// while waiting for the rest could deadlock every connection doing the same.
/// `None` if the connection is cancelled meanwhile.
async fn reserve_frame(
    b: &Budgets,
    need: u32,
    cancel: &CancellationToken,
) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
    let source = tokio::select! {
        _ = cancel.cancelled() => return None,
        p = b.source.clone().acquire_many_owned(need.min(b.source_kib)) => p.ok()?,
    };
    let global = tokio::select! {
        _ = cancel.cancelled() => return None,
        p = b.global.clone().acquire_many_owned(need.min(b.global_kib)) => p.ok()?,
    };
    Some((global, source))
}

/// Read a frame body, which must keep up with [`MIN_BODY_RATE`] give or take
/// [`BODY_GRACE`], and finish within [`FRAME_BODY_TIMEOUT`].
async fn read_body<R: AsyncRead + Unpin>(rd: &mut R, buf: &mut [u8]) -> Result<()> {
    let start = Instant::now();
    let hard = start + FRAME_BODY_TIMEOUT;
    let mut done = 0;
    while done < buf.len() {
        let end = (done + BODY_CHUNK).min(buf.len());
        let due = start + BODY_GRACE + Duration::from_millis(end as u64 * 1000 / MIN_BODY_RATE);
        match timeout_at(due.min(hard), rd.read_exact(&mut buf[done..end])).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(anyhow::anyhow!("frame body arrived too slowly")),
        }
        done = end;
    }
    Ok(())
}

/// Forget produce chains whose produce has finished. Only produces still in
/// progress — at most one per in-flight permit — need to be waited on; the
/// map used to keep one entry per topic name ever sent, existing or not.
fn prune_chains(chains: &mut HashMap<String, oneshot::Receiver<()>>) {
    chains.retain(|_, rx| matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
}

async fn serve(
    broker: Arc<Broker>,
    mut stream: Box<dyn IoStream>,
    peer: SocketAddr,
    cancel: CancellationToken,
    budgets: Budgets,
    deadline: Instant,
    pre_auth: PreAuthSlot,
) -> Result<()> {
    let (mut key, credential, gzip) =
        match timeout_at(deadline, handshake(&broker, &mut stream)).await {
            Ok(Ok(Some(v))) => v,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()), // handshake timed out; drop the connection
        };
    drop(pre_auth);
    let auth_required = broker.config.auth_mode == AuthMode::Required;
    let mut epoch = broker.keys.revocation_epoch();
    tracing::debug!(?peer, principal = %key.name, gzip, "binary: handshake complete");

    let (mut rd, wr) = tokio::io::split(stream);
    let conn_cancel = cancel.child_token();
    let (out_tx, out_rx) = mpsc::channel::<Outbound>(MAX_INFLIGHT_PER_CONN * 2);
    let writer = tokio::spawn(writer_loop(wr, out_rx, conn_cancel.clone()));
    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT_PER_CONN));
    let max_request = max_request_bytes(&broker);
    let idle = broker.config.binary_idle_timeout;
    // Produces to one topic start in the order they arrived: each waits for
    // the previous one's completion signal. Requests to different topics, and
    // all consumes, run concurrently.
    let mut chains: HashMap<String, oneshot::Receiver<()>> = HashMap::new();

    let result: Result<()> = async {
        loop {
            let mut len_buf = [0u8; 4];
            let read = tokio::select! {
                _ = conn_cancel.cancelled() => return Ok(()),
                r = tokio::time::timeout(idle, rd.read_exact(&mut len_buf)) => r,
            };
            match read {
                Ok(Ok(_)) => {}
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {
                    tracing::debug!(?peer, "binary: idle connection closed");
                    return Ok(());
                }
            }
            let total = u32::from_be_bytes(len_buf) as usize;
            if !(5..=max_request).contains(&total) {
                return Err(anyhow::anyhow!("frame size {} out of bounds", total));
            }
            let mut head = [0u8; 5];
            match timeout_at(Instant::now() + BODY_GRACE, rd.read_exact(&mut head)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => return Err(anyhow::anyhow!("frame header read timed out")),
            }
            let request_id = u32::from_be_bytes(head[0..4].try_into().unwrap());
            let Some(opcode) = Opcode::from_u8(head[4]) else {
                return Err(anyhow::anyhow!("unknown opcode {:#x}", head[4]));
            };

            // The key was captured at handshake; a revocation must reach
            // connections that are already open, not only new ones.
            if auth_required {
                let now = broker.keys.revocation_epoch();
                if now != epoch {
                    epoch = now;
                    match broker.keys.get_enabled(&key.key_id) {
                        Some(k) => key = k,
                        None => {
                            let frame = error_frame(request_id, "key revoked", gzip);
                            let _ = out_tx.send(Outbound::new(frame, None)).await;
                            return Ok(());
                        }
                    }
                }
            }

            let permit = tokio::select! {
                _ = conn_cancel.cancelled() => return Ok(()),
                p = inflight.clone().acquire_owned() => p?,
            };
            // Memory first, bytes second: the frame and, for gzip, all it
            // may inflate to, in one reservation.
            let body_len = total - 5;
            let inflate_cap = (gzip && matches!(opcode, Opcode::Produce | Opcode::Consume))
                .then(|| inflate_bound(body_len, max_request));
            let need = kib(total).saturating_add(inflate_cap.map_or(0, kib));
            let Some((mem, transit)) = reserve_frame(&budgets, need, &conn_cancel).await else {
                return Ok(());
            };
            let mut payload = vec![0u8; body_len];
            read_body(&mut rd, &mut payload).await?;
            drop(transit);

            match opcode {
                Opcode::Ping => {
                    let frame = respond(request_id, Opcode::PingOk, Vec::new(), gzip).await;
                    if out_tx.send(Outbound::new(frame, Some(mem))).await.is_err() {
                        return Ok(());
                    }
                }
                Opcode::Produce | Opcode::Consume => {
                    // Authorize on the topic named at the head of the payload
                    // before decompressing or decoding the rest of it.
                    let topic = match codec::peek_topic(&payload, gzip) {
                        Ok(t) => t,
                        Err(e) => {
                            let frame = error_frame(request_id, &format!("decode: {}", e), gzip);
                            let _ = out_tx.send(Outbound::new(frame, Some(mem))).await;
                            continue;
                        }
                    };
                    let action = if opcode == Opcode::Produce {
                        AclAction::Write
                    } else {
                        AclAction::Read
                    };
                    if !key.can(action, &topic) {
                        let msg = format!(
                            "forbidden: key '{}' has no {} access to '{}'",
                            key.key_id,
                            if action == AclAction::Write {
                                "write"
                            } else {
                                "read"
                            },
                            topic
                        );
                        let frame = error_frame(request_id, &msg, gzip);
                        let _ = out_tx.send(Outbound::new(frame, Some(mem))).await;
                        continue;
                    }
                    let (done_tx, done_rx) = oneshot::channel::<()>();
                    let prev = if opcode == Opcode::Produce {
                        if chains.len() >= MAX_CHAINS {
                            prune_chains(&mut chains);
                        }
                        chains.insert(topic, done_rx)
                    } else {
                        None
                    };
                    let broker = broker.clone();
                    let key = key.clone();
                    let credential = credential.clone();
                    let out_tx = out_tx.clone();
                    let global = budgets.global.clone();
                    let global_kib = budgets.global_kib;
                    let cancel = conn_cancel.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let mut mem = Some(mem);
                        if let Some(prev) = prev {
                            tokio::select! {
                                _ = cancel.cancelled() => return,
                                _ = prev => {}
                            }
                        }
                        let req = Request {
                            opcode,
                            payload,
                            inflate_cap,
                            credential,
                        };
                        let (op, body) =
                            process(&broker, &key, req, &mut mem, (&global, global_kib), &cancel)
                                .await;
                        drop(done_tx);
                        let frame = respond(request_id, op, body, gzip).await;
                        if let Some(m) = mem.as_mut() {
                            shrink(m, kib(frame.len()));
                        }
                        let _ = out_tx.send(Outbound::new(frame, mem)).await;
                    });
                }
                other => {
                    let msg = format!("unexpected opcode in request: {:?}", other);
                    let frame = error_frame(request_id, &msg, gzip);
                    let _ = out_tx.send(Outbound::new(frame, Some(mem))).await;
                }
            }
        }
    }
    .await;

    // Let requests already in progress finish and their responses go out;
    // the writer stops once every sender is gone.
    drop(out_tx);
    if result.is_err() {
        conn_cancel.cancel();
    }
    let _ = tokio::time::timeout(WRITE_TIMEOUT, writer).await;
    // Whatever is still waiting — on the budget, or behind another produce —
    // has nobody left to answer.
    conn_cancel.cancel();
    result
}

async fn writer_loop(
    mut wr: tokio::io::WriteHalf<Box<dyn IoStream>>,
    mut rx: mpsc::Receiver<Outbound>,
    cancel: CancellationToken,
) {
    loop {
        let out = tokio::select! {
            _ = cancel.cancelled() => break,
            f = rx.recv() => match f {
                Some(f) => f,
                None => break,
            },
        };
        let write = async {
            wr.write_all(&out.frame).await?;
            if rx.is_empty() {
                wr.flush().await?;
            }
            Ok::<_, std::io::Error>(())
        };
        match tokio::time::timeout(WRITE_TIMEOUT, write).await {
            Ok(Ok(())) => {}
            _ => {
                cancel.cancel();
                break;
            }
        }
        // Written: its reservation goes back to the budget.
        drop(out);
    }
    let _ = wr.flush().await;
}

fn error_frame(request_id: u32, msg: &str, gzip: bool) -> Vec<u8> {
    let body = if gzip {
        codec::compress(msg.as_bytes()).unwrap_or_default()
    } else {
        msg.as_bytes().to_vec()
    };
    codec::encode_frame(request_id, Opcode::Error, &body).unwrap_or_default()
}

/// Frame a response, compressing on a blocking thread when it is large.
async fn respond(request_id: u32, opcode: Opcode, body: Vec<u8>, gzip: bool) -> Vec<u8> {
    let body = if !gzip {
        body
    } else if body.len() < 64 * 1024 {
        match codec::compress(&body) {
            Ok(b) => b,
            Err(e) => return error_frame(request_id, &format!("compress: {}", e), gzip),
        }
    } else {
        match tokio::task::spawn_blocking(move || codec::compress(&body)).await {
            Ok(Ok(b)) => b,
            _ => return error_frame(request_id, "compress failed", gzip),
        }
    };
    match codec::encode_frame(request_id, opcode, &body) {
        Ok(f) => f,
        Err(e) => error_frame(request_id, &e.to_string(), gzip),
    }
}

/// A produce or consume as read off the wire.
struct Request {
    opcode: Opcode,
    payload: Vec<u8>,
    /// Decompression cap when the payload is gzip.
    inflate_cap: Option<usize>,
    /// The token the connection authenticated with, for a produce forwarded
    /// to a partition's leader.
    credential: Option<Arc<str>>,
}

/// Run one produce or consume. Returns the response opcode and the
/// (uncompressed) body. `mem` is the request's reservation on entry and the
/// response's on return.
async fn process(
    broker: &Arc<Broker>,
    key: &ApiKey,
    req: Request,
    mem: &mut Option<OwnedSemaphorePermit>,
    (budget, budget_kib): (&Arc<Semaphore>, u32),
    cancel: &CancellationToken,
) -> (Opcode, Vec<u8>) {
    let err = |m: String| (Opcode::Error, m.into_bytes());
    let Request {
        opcode,
        payload,
        inflate_cap,
        credential,
    } = req;
    let payload = match inflate_cap {
        // Room to inflate into was reserved with the frame.
        Some(cap) => {
            match tokio::task::spawn_blocking(move || codec::decompress(&payload, cap)).await {
                Ok(Ok(p)) => {
                    // Give back the inflate room the payload did not use.
                    if let Some(m) = mem.as_mut() {
                        let held = m.num_permits() as u32;
                        shrink(m, held - kib(cap).min(held) + kib(p.len()));
                    }
                    p
                }
                Ok(Err(e)) => return err(format!("decode: {}", e)),
                Err(_) => return err("decode task failed".into()),
            }
        }
        None => payload,
    };
    match opcode {
        Opcode::Produce => {
            let req = match decode_produce_request(&payload, MAX_RECORDS_PER_REQUEST) {
                Ok(r) => r,
                Err(e) => return err(format!("decode: {}", e)),
            };
            drop(payload);
            let records = req
                .records
                .into_iter()
                .map(|r| IncomingRecord {
                    key: r.key,
                    value: r.value,
                    partition: r.partition,
                    sequence: r.sequence,
                })
                .collect();
            // Forwarded over HTTP when the leader is another broker; the
            // per-topic chain holds the next produce until this one is
            // answered, so a pipelined client keeps its order through the hop.
            let origin = Origin {
                credential: credential.as_deref(),
                forwarded: false,
            };
            match dataplane::produce(
                broker,
                key,
                &req.topic,
                records,
                req.producer_id.as_deref(),
                origin,
            )
            .await
            {
                Ok(produced) => {
                    let results: Vec<WireProduceResult> = produced
                        .into_iter()
                        .map(|p| WireProduceResult {
                            partition: p.partition,
                            offset: p.offset,
                            duplicate: p.duplicate,
                        })
                        .collect();
                    match encode_produce_response(&results) {
                        Ok(b) => (Opcode::ProduceOk, b),
                        Err(e) => err(e.to_string()),
                    }
                }
                Err(e) => err(e.to_string()),
            }
        }
        Opcode::Consume => {
            let req = match decode_consume_request(&payload) {
                Ok(r) => r,
                Err(e) => return err(format!("decode: {}", e)),
            };
            drop(payload);
            // A 30-byte request can fetch megabytes. Swap the request's
            // reservation for one sized to the largest response it can
            // build — released first, so nothing is held while waiting.
            *mem = None;
            let need = kib(consume_reservation(&broker.config, &req)).min(budget_kib);
            let reserved = tokio::select! {
                _ = cancel.cancelled() => return err("connection closed".into()),
                p = budget.clone().acquire_many_owned(need) => match p {
                    Ok(p) => p,
                    Err(_) => return err("server shutting down".into()),
                },
            };
            *mem = Some(reserved);
            match dataplane::consume(
                broker,
                key,
                &req.topic,
                req.partition,
                req.offset,
                req.max_records as usize,
                req.max_bytes as usize,
            )
            .await
            {
                Ok(f) => match encode_consume_from_records(
                    req.partition,
                    f.next_offset,
                    f.high_watermark,
                    &f.records,
                ) {
                    Ok(b) => (Opcode::ConsumeOk, b),
                    Err(e) => err(e.to_string()),
                },
                Err(e) => err(e.to_string()),
            }
        }
        other => err(format!("unexpected opcode in request: {:?}", other)),
    }
}

/// Encode a consume response directly from storage records, avoiding the
/// intermediate WireRecord allocation and key/value clones.
fn encode_consume_from_records(
    partition: u32,
    next_offset: u64,
    high_watermark: u64,
    records: &[crate::storage::record::Record],
) -> std::io::Result<Vec<u8>> {
    let size: usize = records
        .iter()
        .map(|r| 4 + 8 + 8 + 4 + r.key.as_ref().map_or(0, |k| k.len()) + 4 + r.value.len())
        .sum();
    let mut b = es_protocol::wire::WireBuf {
        bytes: Vec::with_capacity(20 + size),
    };
    b.put_u64(next_offset);
    b.put_u64(high_watermark);
    b.put_count(records.len())?;
    for r in records {
        b.put_u32(partition);
        b.put_u64(r.offset);
        b.put_i64(r.timestamp_ms);
        b.put_opt_bytes_i32(r.key.as_deref())?;
        b.put_value(&r.value)?;
    }
    Ok(b.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use es_protocol::wire::{
        decode_produce_response, encode_consume_request, encode_produce_request, WireProduceRecord,
        WireProduceRequest,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::io::DuplexStream;

    #[test]
    fn ipv6_sources_are_keyed_by_their_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(source_key(a), source_key(b));
        assert_eq!(source_key(a), "2001:db8:1:2::".parse::<IpAddr>().unwrap());
        assert_ne!(source_key(a), source_key(other));
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        assert_eq!(source_key(v4), v4);
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped());
        assert_eq!(source_key(mapped), v4);
        assert_eq!(
            source_key(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            "::".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn finished_chains_are_pruned() {
        let mut chains = HashMap::new();
        let mut live = Vec::new();
        for i in 0..1000 {
            let (tx, rx) = oneshot::channel::<()>();
            chains.insert(format!("topic-{i}"), rx);
            if i % 100 == 0 {
                live.push(tx);
            }
        }
        prune_chains(&mut chains);
        assert_eq!(chains.len(), live.len());
        drop(live);
        prune_chains(&mut chains);
        assert!(chains.is_empty());
    }

    #[test]
    fn small_gzip_frames_reserve_little() {
        assert_eq!(inflate_bound(100, 16 << 20), 100 * MAX_INFLATE_RATIO + 1024);
        assert_eq!(inflate_bound(1 << 20, 16 << 20), 16 << 20);
    }

    struct Fixture {
        _tmp: tempfile::TempDir,
        broker: Arc<Broker>,
        global: Arc<Semaphore>,
        global_kib: u32,
    }

    impl Fixture {
        fn new(global_kib: u32) -> Self {
            let tmp = tempfile::TempDir::new().unwrap();
            let cfg = Config::new(
                tmp.path().to_path_buf(),
                "127.0.0.1:0".parse().unwrap(),
                1 << 20,
            );
            let broker = Broker::open(cfg).unwrap();
            broker.create_topic("t", 1, None).unwrap();
            broker.create_topic("u", 1, None).unwrap();
            Self {
                _tmp: tmp,
                broker,
                global: Arc::new(Semaphore::new(global_kib as usize)),
                global_kib,
            }
        }

        /// A connection served over an in-memory pipe, past the handshake.
        async fn connect(&self, gzip: bool, pipe: usize) -> DuplexStream {
            let (mut client, server) = tokio::io::duplex(pipe);
            let sources: Sources = Arc::new(DashMap::new());
            let key: IpAddr = Ipv4Addr::LOCALHOST.into();
            let budgets = Budgets {
                global: self.global.clone(),
                global_kib: self.global_kib,
                source: Arc::new(Semaphore::new(self.global_kib as usize)),
                source_kib: self.global_kib,
            };
            let broker = self.broker.clone();
            tokio::spawn(async move {
                let _ = serve(
                    broker,
                    Box::new(server),
                    "127.0.0.1:1".parse().unwrap(),
                    CancellationToken::new(),
                    budgets,
                    Instant::now() + HANDSHAKE_TIMEOUT,
                    PreAuthSlot { map: sources, key },
                )
                .await;
            });
            let mut hello = WIRE_MAGIC.to_vec();
            hello.extend_from_slice(&(if gzip { FEATURE_GZIP } else { 0 }).to_be_bytes());
            hello.extend_from_slice(&0u32.to_be_bytes());
            client.write_all(&hello).await.unwrap();
            let mut reply = [0u8; 13];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[4], HandshakeStatus::Ok as u8);
            client
        }
    }

    fn produce_payload(topic: &str, value_len: usize) -> Vec<u8> {
        encode_produce_request(&WireProduceRequest {
            topic: topic.into(),
            producer_id: None,
            records: vec![WireProduceRecord {
                key: None,
                value: vec![b'x'; value_len],
                partition: Some(0),
                sequence: None,
            }],
        })
        .unwrap()
    }

    async fn send(c: &mut DuplexStream, id: u32, op: Opcode, payload: &[u8], gzip: bool) {
        let body = if gzip {
            codec::compress(payload).unwrap()
        } else {
            payload.to_vec()
        };
        c.write_all(&codec::encode_frame(id, op, &body).unwrap())
            .await
            .unwrap();
    }

    async fn recv(c: &mut DuplexStream, gzip: bool) -> (u32, Opcode, Vec<u8>) {
        let (id, op, body) = codec::read_frame(c).await.unwrap();
        let body = if gzip {
            codec::decompress(&body, 64 << 20).unwrap()
        } else {
            body
        };
        (id, op, body)
    }

    /// Two gzip frames used to each hold their frame and wait for 16 MiB more
    /// from the same budget; with a budget too small for both, every acquire
    /// stopped for good. One reservation per frame lets them take turns.
    #[tokio::test]
    async fn concurrent_gzip_frames_cannot_deadlock_the_budget() {
        let payload = produce_payload("t", 300 * 1024);
        let compressed = codec::compress(&payload).unwrap().len();
        // Room for exactly one frame's reservation at a time.
        let one = kib(compressed + 5) + kib(inflate_bound(compressed, 16 << 20));
        let fx = Fixture::new(one);
        let mut a = fx.connect(true, 1 << 20).await;
        let mut b = fx.connect(true, 1 << 20).await;
        let done = async {
            send(&mut a, 1, Opcode::Produce, &payload, true).await;
            send(
                &mut b,
                1,
                Opcode::Produce,
                &produce_payload("u", 300 * 1024),
                true,
            )
            .await;
            let (_, op_a, body_a) = recv(&mut a, true).await;
            let (_, op_b, _) = recv(&mut b, true).await;
            (op_a, op_b, body_a)
        };
        let (op_a, op_b, body_a) = tokio::time::timeout(Duration::from_secs(10), done)
            .await
            .expect("both frames complete");
        assert_eq!(
            op_a,
            Opcode::ProduceOk,
            "{}",
            String::from_utf8_lossy(&body_a)
        );
        assert_eq!(op_b, Opcode::ProduceOk);
        assert_eq!(decode_produce_response(&body_a).unwrap().len(), 1);
        // Everything went back to the budget once written.
        for _ in 0..100 {
            if fx.global.available_permits() == one as usize {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(fx.global.available_permits(), one as usize);
    }

    /// A consume's response stays charged to the budget until it is written:
    /// a client that does not read cannot pile responses up outside it.
    #[tokio::test]
    async fn unread_consume_responses_are_charged_to_the_budget() {
        let budget_kib = 64 * 1024;
        let fx = Fixture::new(budget_kib);
        // A pipe much smaller than the response, so the writer blocks.
        let mut c = fx.connect(false, 4096).await;
        send(
            &mut c,
            1,
            Opcode::Produce,
            &produce_payload("t", 256 * 1024),
            false,
        )
        .await;
        assert_eq!(recv(&mut c, false).await.1, Opcode::ProduceOk);
        let consume = encode_consume_request(&WireConsumeRequest {
            topic: "t".into(),
            partition: 0,
            offset: 0,
            max_records: 10,
            max_bytes: 1 << 20,
        })
        .unwrap();
        send(&mut c, 2, Opcode::Consume, &consume, false).await;
        // While the response sits unread, at least its size is reserved.
        let mut held = 0;
        for _ in 0..200 {
            held = budget_kib as usize - fx.global.available_permits();
            if held >= 256 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            held >= 256,
            "only {held} KiB reserved for a 256 KiB response"
        );
        let (id, op, body) = recv(&mut c, false).await;
        assert_eq!((id, op), (2, Opcode::ConsumeOk));
        assert!(body.len() > 256 * 1024);
        for _ in 0..100 {
            if fx.global.available_permits() == budget_kib as usize {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(fx.global.available_permits(), budget_kib as usize);
    }

    #[tokio::test]
    async fn a_body_that_stalls_is_cut_off() {
        let fx = Fixture::new(64 * 1024);
        let mut c = fx.connect(false, 1 << 20).await;
        // A length prefix and header for 8 MiB, then nothing.
        c.write_all(&((8u32 << 20) + 5).to_be_bytes())
            .await
            .unwrap();
        c.write_all(&[0, 0, 0, 1, Opcode::Produce as u8])
            .await
            .unwrap();
        // The connection is closed after the grace period, not held for
        // FRAME_BODY_TIMEOUT.
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(BODY_GRACE + Duration::from_secs(1), c.read(&mut buf))
            .await
            .expect("closed within the grace period")
            .unwrap();
        assert_eq!(n, 0);
    }
}
