use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use es_protocol::wire::{
    decode_consume_request, decode_produce_request, encode_produce_response, HandshakeStatus,
    Opcode, WireProduceResult, FEATURE_GZIP, WIRE_MAGIC,
};

use crate::auth::{AclAction, ApiKey, AuthMode};
use crate::broker::Broker;
use crate::producers::DedupeOutcome;

/// Maximum allowed frame body size. Caps memory per connection.
const MAX_FRAME_BYTES: u32 = 64 * 1024 * 1024;
/// Maximum decompressed payload size. Bounds a gzip decompression bomb: the
/// 64 MiB frame cap only limits the *compressed* bytes, which can inflate to
/// many GB. Set above the frame cap so legitimate compressible frames still fit.
const MAX_DECOMPRESSED_BYTES: usize = 256 * 1024 * 1024;
/// Max concurrent binary connections. Bounds socket/task/memory exhaustion.
const MAX_CONNECTIONS: usize = 4096;
/// Time budget for a client to complete the handshake before we drop the
/// socket. Bounds pre-auth slowloris holds.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Once a frame's length prefix has arrived, its body must follow within this
/// window. (There is deliberately no timeout on the *idle* wait for the next
/// frame — consumers may hold a connection open between requests.)
const FRAME_BODY_TIMEOUT: Duration = Duration::from_secs(30);

/// Run the binary protocol accept loop on `listener` until `cancel` fires.
pub async fn serve_binary(
    broker: Arc<Broker>,
    listener: TcpListener,
    cancel: CancellationToken,
) -> Result<()> {
    let addr = listener.local_addr()?;
    tracing::info!(?addr, "binary: listening");
    let conn_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
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
                        tracing::warn!(error = %e, "binary: accept failed");
                        continue;
                    }
                };
                // Bound concurrent connections. If we're at the cap, drop the
                // new connection rather than spawning an unbounded task.
                let permit = match conn_limit.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!(peer = ?peer, "binary: connection limit reached, dropping");
                        continue;
                    }
                };
                let broker = broker.clone();
                let cancel = cancel.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_connection(broker, sock, peer, cancel).await {
                        tracing::debug!(peer = ?peer, error = %e, "binary: connection ended");
                    }
                });
            }
        }
    }
}

async fn handle_connection(
    broker: Arc<Broker>,
    mut sock: TcpStream,
    peer: SocketAddr,
    cancel: CancellationToken,
) -> Result<()> {
    // TCP_NODELAY off keeps frame writes small. We coalesce header + payload
    // in `write_frame` so a single write_all is one packet; NODELAY just makes
    // sure the kernel doesn't add latency waiting for more bytes.
    sock.set_nodelay(true).ok();
    // ---- Handshake ----
    // Client: magic(4) | features(u32) | auth_token_len(u32) | auth_token
    // Read the fixed header + token under a timeout so a peer can't hold the
    // connection open indefinitely by stalling mid-handshake (pre-auth
    // slowloris).
    let handshake_read = async {
        let mut magic = [0u8; 4];
        sock.read_exact(&mut magic).await?;
        let mut buf4 = [0u8; 4];
        sock.read_exact(&mut buf4).await?;
        let client_features = u32::from_be_bytes(buf4);
        sock.read_exact(&mut buf4).await?;
        let token_len = u32::from_be_bytes(buf4);
        if token_len > 1024 {
            return Ok::<_, std::io::Error>((magic, client_features, Vec::new(), true));
        }
        let mut token_bytes = vec![0u8; token_len as usize];
        if !token_bytes.is_empty() {
            sock.read_exact(&mut token_bytes).await?;
        }
        Ok((magic, client_features, token_bytes, false))
    };
    let (magic, client_features, token_bytes, token_too_long) =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake_read).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Ok(()), // handshake timed out; drop the connection
        };
    if magic != WIRE_MAGIC {
        write_handshake_status(&mut sock, HandshakeStatus::BadMagic, "bad magic").await?;
        return Ok(());
    }
    if token_too_long {
        write_handshake_status(
            &mut sock,
            HandshakeStatus::AuthFailed,
            "auth token too long",
        )
        .await?;
        return Ok(());
    }
    let token = String::from_utf8(token_bytes).unwrap_or_default();

    // Authenticate the connection up-front. The principal is captured for every
    // request issued on this stream.
    let key = match broker.config.auth_mode {
        AuthMode::Disabled => Arc::new(crate::auth::ApiKey {
            key_id: "anonymous".to_string(),
            name: "anonymous".to_string(),
            acls: vec![crate::auth::AclRule {
                action: crate::auth::AclAction::Admin,
                topic_prefix: "*".to_string(),
            }],
            produce_bytes_per_sec: None,
            consume_bytes_per_sec: None,
            created_at_ms: 0,
            disabled: false,
        }),
        AuthMode::Required => {
            if token.is_empty() {
                write_handshake_status(
                    &mut sock,
                    HandshakeStatus::AuthRequired,
                    "auth token required",
                )
                .await?;
                return Ok(());
            }
            match broker.keys.authenticate(&token) {
                Some(k) => k,
                None => {
                    write_handshake_status(&mut sock, HandshakeStatus::AuthFailed, "invalid token")
                        .await?;
                    return Ok(());
                }
            }
        }
    };

    // We support only the gzip feature bit. The negotiated set is the
    // intersection of what the client requested and what we know about.
    let supported: u32 = FEATURE_GZIP;
    let negotiated = client_features & supported;
    write_handshake_ok(&mut sock, negotiated).await?;
    let gzip = (negotiated & FEATURE_GZIP) != 0;
    tracing::debug!(?peer, principal = %key.name, gzip, "binary: handshake complete");

    // ---- Frame loop ----
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            res = read_frame(&mut sock, gzip) => {
                let (request_id, opcode, payload) = match res {
                    Ok(Some(v)) => v,
                    Ok(None) => return Ok(()), // peer closed
                    Err(e) => return Err(e.into()),
                };
                let response_payload = dispatch(&broker, &key, opcode, &payload).await;
                match response_payload {
                    Ok((resp_op, body)) => {
                        write_frame(&mut sock, request_id, resp_op, &body, gzip).await?;
                    }
                    Err(msg) => {
                        write_frame(&mut sock, request_id, Opcode::Error, msg.as_bytes(), gzip).await?;
                    }
                }
            }
        }
    }
}

async fn write_handshake_ok(sock: &mut TcpStream, features: u32) -> std::io::Result<()> {
    sock.write_all(&WIRE_MAGIC).await?;
    sock.write_all(&[HandshakeStatus::Ok as u8]).await?;
    sock.write_all(&features.to_be_bytes()).await?;
    sock.write_all(&0u32.to_be_bytes()).await?; // empty msg
    Ok(())
}

async fn write_handshake_status(
    sock: &mut TcpStream,
    status: HandshakeStatus,
    msg: &str,
) -> std::io::Result<()> {
    // Server reply: magic(4) | status(u8) | features(u32) | msg_len(u32) | msg
    sock.write_all(&WIRE_MAGIC).await?;
    sock.write_all(&[status as u8]).await?;
    sock.write_all(&0u32.to_be_bytes()).await?; // no features yet
    let msg_bytes = msg.as_bytes();
    sock.write_all(&(msg_bytes.len() as u32).to_be_bytes())
        .await?;
    sock.write_all(msg_bytes).await?;
    Ok(())
}

async fn read_frame(
    sock: &mut TcpStream,
    gzip: bool,
) -> std::io::Result<Option<(u32, Opcode, Vec<u8>)>> {
    let mut len_buf = [0u8; 4];
    match sock.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let total = u32::from_be_bytes(len_buf);
    if !(5..=MAX_FRAME_BYTES).contains(&total) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame size {} out of bounds", total),
        ));
    }
    let mut frame = vec![0u8; total as usize];
    // The length is committed; require the body to arrive promptly so a client
    // can't declare a large frame and then trickle the bytes (slowloris).
    match tokio::time::timeout(FRAME_BODY_TIMEOUT, sock.read_exact(&mut frame)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "frame body read timed out",
            ))
        }
    }
    let request_id = u32::from_be_bytes(frame[0..4].try_into().unwrap());
    let opcode_byte = frame[4];
    let opcode = Opcode::from_u8(opcode_byte).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown opcode {:#x}", opcode_byte),
        )
    })?;
    let raw_payload = &frame[5..];
    let payload = if gzip {
        decompress(raw_payload)?
    } else {
        raw_payload.to_vec()
    };
    Ok(Some((request_id, opcode, payload)))
}

async fn write_frame(
    sock: &mut TcpStream,
    request_id: u32,
    opcode: Opcode,
    payload: &[u8],
    gzip: bool,
) -> std::io::Result<()> {
    let body: std::borrow::Cow<[u8]> = if gzip {
        std::borrow::Cow::Owned(compress(payload)?)
    } else {
        std::borrow::Cow::Borrowed(payload)
    };
    let total = (4 + 1 + body.len()) as u32;
    let mut frame = Vec::with_capacity(4 + 4 + 1 + body.len());
    frame.extend_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(&request_id.to_be_bytes());
    frame.push(opcode as u8);
    frame.extend_from_slice(&body);
    sock.write_all(&frame).await?;
    Ok(())
}

fn compress(input: &[u8]) -> std::io::Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut enc = GzEncoder::new(
        Vec::with_capacity(input.len() / 2 + 32),
        Compression::default(),
    );
    enc.write_all(input)?;
    enc.finish()
}

/// Encode a consume response directly from storage records, avoiding the
/// intermediate WireRecord allocation and key/value clones.
fn encode_consume_from_records(
    partition: u32,
    next_offset: u64,
    high_watermark: u64,
    records: &[crate::storage::record::Record],
) -> Vec<u8> {
    let mut b = es_protocol::wire::WireBuf::new();
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

fn decompress(input: &[u8]) -> std::io::Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let dec = GzDecoder::new(input);
    // Bound the decompressed size: read at most MAX_DECOMPRESSED_BYTES + 1 and
    // reject if the stream is longer, so a compression bomb can't exhaust memory.
    let mut limited = dec.take(MAX_DECOMPRESSED_BYTES as u64 + 1);
    let mut out = Vec::with_capacity((input.len() * 2).min(MAX_DECOMPRESSED_BYTES));
    limited.read_to_end(&mut out)?;
    if out.len() > MAX_DECOMPRESSED_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "decompressed frame exceeds maximum size",
        ));
    }
    Ok(out)
}

async fn dispatch(
    broker: &Arc<Broker>,
    key: &Arc<ApiKey>,
    opcode: Opcode,
    payload: &[u8],
) -> std::result::Result<(Opcode, Vec<u8>), String> {
    match opcode {
        Opcode::Ping => Ok((Opcode::PingOk, Vec::new())),
        Opcode::Produce => {
            let req = decode_produce_request(payload).map_err(|e| format!("decode: {}", e))?;
            if !key.can(AclAction::Write, &req.topic) {
                return Err(format!(
                    "forbidden: key '{}' has no write access to '{}'",
                    key.key_id, req.topic
                ));
            }
            let topic = broker
                .topic(&req.topic)
                .ok_or_else(|| format!("topic '{}' not found", req.topic))?;

            let request_bytes: u64 = req
                .records
                .iter()
                .map(|r| r.key.as_ref().map(|k| k.len() as u64).unwrap_or(0) + r.value.len() as u64)
                .sum();
            if let Err(retry_after) = broker.keys.check_produce(&key.key_id, request_bytes as u32) {
                return Err(format!("rate_limited: retry in {:.1}s", retry_after));
            }

            // Idempotent path mirrors the HTTP handler.
            if let Some(pid) = &req.producer_id {
                broker
                    .producers
                    .check_admission(pid)
                    .map_err(|e| format!("{}", e))?;
                for (i, r) in req.records.iter().enumerate() {
                    match r.sequence {
                        None => {
                            return Err(format!(
                                "record {} missing sequence (required when producer_id is set)",
                                i
                            ));
                        }
                        Some(s) if s < 0 => {
                            return Err(format!("record {} has negative sequence {}", i, s));
                        }
                        Some(_) => {}
                    }
                }
            }

            let mut results: Vec<WireProduceResult> = Vec::with_capacity(req.records.len());
            let mut total_appended: u64 = 0;
            let mut records_appended: u64 = 0;
            for r in &req.records {
                let partition_id = topic
                    .route(r.key.as_deref(), r.partition)
                    .map_err(|e| format!("route: {}", e))?;

                if let Some(pid) = &req.producer_id {
                    let seq = r
                        .sequence
                        .expect("sequence must be present when producer_id is set");
                    match broker
                        .producers
                        .check_and_advance(pid, &req.topic, partition_id, seq)
                        .await
                    {
                        DedupeOutcome::Duplicate { prev_offset } => {
                            results.push(WireProduceResult {
                                partition: partition_id,
                                offset: prev_offset,
                                duplicate: true,
                            });
                            continue;
                        }
                        DedupeOutcome::Accept => {}
                        DedupeOutcome::SequenceTooLow { last_seen } => {
                            return Err(format!(
                                "sequence_too_low: producer={} partition={} seq={} last_seen={}",
                                pid, partition_id, seq, last_seen
                            ));
                        }
                        DedupeOutcome::Gap { expected, got } => {
                            return Err(format!(
                                "sequence_gap: producer={} partition={} expected={} got={}",
                                pid, partition_id, expected, got
                            ));
                        }
                        DedupeOutcome::NeedsInit => {
                            return Err(format!("producer {} state missing", pid));
                        }
                    }
                }

                let partition = &topic.partitions[partition_id as usize];
                let offset = partition
                    .append(r.key.as_deref(), &r.value)
                    .await
                    .map_err(|e| format!("append: {}", e))?;
                if let Some(pid) = &req.producer_id {
                    broker
                        .producers
                        .record_offset(
                            pid,
                            &req.topic,
                            partition_id,
                            r.sequence
                                .expect("sequence must be present when producer_id is set"),
                            offset,
                        )
                        .await;
                }
                total_appended +=
                    r.key.as_ref().map(|k| k.len() as u64).unwrap_or(0) + r.value.len() as u64;
                records_appended += 1;
                results.push(WireProduceResult {
                    partition: partition_id,
                    offset,
                    duplicate: false,
                });
            }

            topic
                .records_produced_total
                .fetch_add(records_appended, Ordering::Relaxed);
            topic
                .bytes_produced_total
                .fetch_add(total_appended, Ordering::Relaxed);

            let body = encode_produce_response(&results);
            Ok((Opcode::ProduceOk, body))
        }
        Opcode::Consume => {
            let req = decode_consume_request(payload).map_err(|e| format!("decode: {}", e))?;
            if !key.can(AclAction::Read, &req.topic) {
                return Err(format!(
                    "forbidden: key '{}' has no read access to '{}'",
                    key.key_id, req.topic
                ));
            }
            let topic = broker
                .topic(&req.topic)
                .ok_or_else(|| format!("topic '{}' not found", req.topic))?;
            let partition = topic
                .partitions
                .get(req.partition as usize)
                .ok_or_else(|| format!("partition {} out of range", req.partition))?;

            let (records, next_offset, high_watermark) = partition
                .read_records_raw(req.offset, req.max_records as usize, req.max_bytes as usize)
                .map_err(|e| format!("read: {}", e))?;

            let consumed_bytes: u64 = records
                .iter()
                .map(|r| r.key.as_ref().map(|k| k.len() as u64).unwrap_or(0) + r.value.len() as u64)
                .sum();
            let _ = broker
                .keys
                .check_consume(&key.key_id, consumed_bytes as u32);

            topic
                .records_consumed_total
                .fetch_add(records.len() as u64, Ordering::Relaxed);
            topic
                .bytes_consumed_total
                .fetch_add(consumed_bytes, Ordering::Relaxed);

            let body =
                encode_consume_from_records(req.partition, next_offset, high_watermark, &records);
            Ok((Opcode::ConsumeOk, body))
        }
        // Server response codes should never arrive on the request side.
        _ => Err(format!("unexpected opcode in request: {:?}", opcode)),
    }
}
