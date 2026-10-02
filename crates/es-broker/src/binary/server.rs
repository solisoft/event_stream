use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio_util::sync::CancellationToken;

use es_protocol::wire::{
    decode_consume_request, decode_produce_request, encode_produce_response, HandshakeStatus,
    Opcode, WireProduceResult, FEATURE_GZIP, WIRE_MAGIC,
};

use crate::auth::{AclAction, ApiKey, AuthMode, ANONYMOUS_ADMIN};
use crate::broker::Broker;
use crate::dataplane::{self, IncomingRecord};

use super::codec::{self, IoStream};

/// Ceiling on concurrent connections, before the file-descriptor budget.
const MAX_CONNECTIONS_CAP: usize = 4096;
/// Time budget for a client to complete the (TLS and protocol) handshake.
/// Bounds pre-auth slowloris holds.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Once a frame's length prefix has arrived, its body must follow within this
/// window.
const FRAME_BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// A response the client does not read within this long ends the connection,
/// instead of parking its task and buffers forever.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Requests one connection may have in progress at once.
const MAX_INFLIGHT_PER_CONN: usize = 32;
/// Bytes of request frames (in KiB) held in memory across all connections.
/// Every frame — and every decompression — draws from it before it is read,
/// so memory is bounded by this rather than by connections × frame size.
const INFLIGHT_BUDGET_KIB: u32 = 1024 * 1024;

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

/// Releases a per-IP connection slot when the connection ends.
struct IpSlot {
    map: Arc<DashMap<IpAddr, usize>>,
    ip: IpAddr,
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let empty = match self.map.get_mut(&self.ip) {
            Some(mut c) => {
                *c = c.saturating_sub(1);
                *c == 0
            }
            None => false,
        };
        if empty {
            self.map.remove_if(&self.ip, |_, c| *c == 0);
        }
    }
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
    let per_ip: Arc<DashMap<IpAddr, usize>> = Arc::new(DashMap::new());
    let max_per_ip = broker.config.binary_max_connections_per_ip.max(1);
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
                let ip = peer.ip();
                {
                    let mut c = per_ip.entry(ip).or_insert(0);
                    if *c >= max_per_ip {
                        tracing::warn!(peer = ?peer, "binary: per-address connection limit reached, dropping");
                        continue;
                    }
                    *c += 1;
                }
                let slot = IpSlot { map: per_ip.clone(), ip };
                let broker = broker.clone();
                let cancel = cancel.clone();
                let tls = tls.clone();
                let budget = budget.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _slot = slot;
                    if let Err(e) = handle_connection(broker, sock, peer, cancel, tls, budget).await {
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
    budget: Arc<Semaphore>,
) -> Result<()> {
    sock.set_nodelay(true).ok();
    let stream: Box<dyn IoStream> = match tls {
        None => Box::new(sock),
        Some(acceptor) => {
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(sock)).await {
                Ok(Ok(s)) => Box::new(s),
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => return Ok(()),
            }
        }
    };
    serve(broker, stream, peer, cancel, budget).await
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

async fn serve(
    broker: Arc<Broker>,
    mut stream: Box<dyn IoStream>,
    peer: SocketAddr,
    cancel: CancellationToken,
    budget: Arc<Semaphore>,
) -> Result<()> {
    let (magic, client_features, token_bytes, token_too_long) =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_handshake(&mut stream)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Ok(()), // handshake timed out; drop the connection
        };
    if magic != WIRE_MAGIC {
        write_handshake(&mut stream, HandshakeStatus::BadMagic, 0, "bad magic").await?;
        return Ok(());
    }
    if token_too_long {
        write_handshake(
            &mut stream,
            HandshakeStatus::AuthFailed,
            0,
            "auth token too long",
        )
        .await?;
        return Ok(());
    }
    let token = String::from_utf8(token_bytes).unwrap_or_default();

    let auth_required = broker.config.auth_mode == AuthMode::Required;
    let mut key: Arc<ApiKey> = if !auth_required {
        ANONYMOUS_ADMIN.clone()
    } else {
        if token.is_empty() {
            write_handshake(
                &mut stream,
                HandshakeStatus::AuthRequired,
                0,
                "auth token required",
            )
            .await?;
            return Ok(());
        }
        match broker.keys.authenticate(&token) {
            Some(k) => k,
            None => {
                write_handshake(&mut stream, HandshakeStatus::AuthFailed, 0, "invalid token")
                    .await?;
                return Ok(());
            }
        }
    };
    let mut epoch = broker.keys.revocation_epoch();

    // We support only the gzip feature bit. The negotiated set is the
    // intersection of what the client requested and what we know about.
    let negotiated = client_features & FEATURE_GZIP;
    write_handshake(&mut stream, HandshakeStatus::Ok, negotiated, "").await?;
    let gzip = negotiated & FEATURE_GZIP != 0;
    tracing::debug!(?peer, principal = %key.name, gzip, "binary: handshake complete");

    let (mut rd, wr) = tokio::io::split(stream);
    let conn_cancel = cancel.child_token();
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(MAX_INFLIGHT_PER_CONN * 2);
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
            // Memory first, bytes second.
            let mem = budget.clone().acquire_many_owned(kib(total)).await?;
            let mut head = [0u8; 5];
            let mut payload = vec![0u8; total - 5];
            let body = async {
                rd.read_exact(&mut head).await?;
                rd.read_exact(&mut payload).await
            };
            match tokio::time::timeout(FRAME_BODY_TIMEOUT, body).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => return Err(anyhow::anyhow!("frame body read timed out")),
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
                            let _ = out_tx.send(frame).await;
                            return Ok(());
                        }
                    }
                }
            }

            let permit = inflight.clone().acquire_owned().await?;
            match opcode {
                Opcode::Ping => {
                    let frame = respond(request_id, Opcode::PingOk, Vec::new(), gzip).await;
                    if out_tx.send(frame).await.is_err() {
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
                            let _ = out_tx.send(frame).await;
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
                        let _ = out_tx.send(error_frame(request_id, &msg, gzip)).await;
                        continue;
                    }
                    let (done_tx, done_rx) = oneshot::channel::<()>();
                    let prev = if opcode == Opcode::Produce {
                        chains.insert(topic, done_rx)
                    } else {
                        None
                    };
                    let broker = broker.clone();
                    let key = key.clone();
                    let out_tx = out_tx.clone();
                    let budget = budget.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _mem = mem;
                        if let Some(prev) = prev {
                            let _ = prev.await;
                        }
                        let (op, body) =
                            process(&broker, &key, opcode, payload, gzip, max_request, &budget)
                                .await;
                        drop(done_tx);
                        let frame = respond(request_id, op, body, gzip).await;
                        let _ = out_tx.send(frame).await;
                    });
                }
                other => {
                    let msg = format!("unexpected opcode in request: {:?}", other);
                    let _ = out_tx.send(error_frame(request_id, &msg, gzip)).await;
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
    result
}

async fn writer_loop(
    mut wr: tokio::io::WriteHalf<Box<dyn IoStream>>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    cancel: CancellationToken,
) {
    loop {
        let frame = tokio::select! {
            _ = cancel.cancelled() => break,
            f = rx.recv() => match f {
                Some(f) => f,
                None => break,
            },
        };
        let write = async {
            wr.write_all(&frame).await?;
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

/// Run one produce or consume. Returns the response opcode and the
/// (uncompressed) body.
async fn process(
    broker: &Arc<Broker>,
    key: &ApiKey,
    opcode: Opcode,
    payload: Vec<u8>,
    gzip: bool,
    max_request: usize,
    budget: &Arc<Semaphore>,
) -> (Opcode, Vec<u8>) {
    let err = |m: String| (Opcode::Error, m.into_bytes());
    let (payload, _inflated_mem) = if gzip {
        // Reserve the decompressed bytes in the global budget before inflating.
        let reserve = match budget.clone().acquire_many_owned(kib(max_request)).await {
            Ok(p) => p,
            Err(_) => return err("server shutting down".into()),
        };
        match tokio::task::spawn_blocking(move || codec::decompress(&payload, max_request)).await {
            Ok(Ok(p)) => (p, Some(reserve)),
            Ok(Err(e)) => return err(format!("decode: {}", e)),
            Err(_) => return err("decode task failed".into()),
        }
    } else {
        (payload, None)
    };
    match opcode {
        Opcode::Produce => {
            let req = match decode_produce_request(&payload) {
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
            match dataplane::produce(broker, key, &req.topic, records, req.producer_id.as_deref())
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
                    (Opcode::ProduceOk, encode_produce_response(&results))
                }
                Err(e) => err(e.to_string()),
            }
        }
        Opcode::Consume => {
            let req = match decode_consume_request(&payload) {
                Ok(r) => r,
                Err(e) => return err(format!("decode: {}", e)),
            };
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
                Ok(f) => (
                    Opcode::ConsumeOk,
                    encode_consume_from_records(
                        req.partition,
                        f.next_offset,
                        f.high_watermark,
                        &f.records,
                    ),
                ),
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
) -> Vec<u8> {
    let size: usize = records
        .iter()
        .map(|r| 4 + 8 + 8 + 4 + r.key.as_ref().map_or(0, |k| k.len()) + 4 + r.value.len())
        .sum();
    let mut b = es_protocol::wire::WireBuf {
        bytes: Vec::with_capacity(20 + size),
    };
    b.put_u64(next_offset);
    b.put_u64(high_watermark);
    b.put_u32(records.len() as u32);
    for r in records {
        b.put_u32(partition);
        b.put_u64(r.offset);
        b.put_i64(r.timestamp_ms);
        b.put_opt_bytes_i32(r.key.as_deref());
        b.put_value(&r.value);
    }
    b.bytes
}
