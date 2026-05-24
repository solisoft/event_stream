//! Pipelined binary protocol client.
//!
//! Differences from [`super::client::BinaryClient`]:
//!   * Many in-flight requests on a single TCP connection.
//!   * Cloneable handle — one connection, many concurrent callers.
//!   * Reader runs in a background task; each caller gets its response via a
//!     per-request `oneshot` channel.
//!
//! Same wire format, same handshake, same auth. The broker side already
//! supports pipelining — its per-connection frame loop processes requests in
//! the order they arrive and emits responses with matching `request_id`s.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Result, anyhow};
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use es_protocol::wire::{
    FEATURE_GZIP, HandshakeStatus, Opcode, WireConsumeRequest, WireConsumeResponse,
    WireProduceRecord, WireProduceRequest, WireProduceResult, WIRE_MAGIC, decode_consume_response,
    decode_produce_response, encode_consume_request, encode_produce_request,
};

use super::client::ClientOptions;

#[derive(Clone)]
pub struct PipelinedClient {
    inner: Arc<Inner>,
}

struct Inner {
    write: Mutex<OwnedWriteHalf>,
    pending: DashMap<u32, oneshot::Sender<FrameOutcome>>,
    next_id: AtomicU32,
    gzip: bool,
    cancel: CancellationToken,
    reader: Mutex<Option<JoinHandle<()>>>,
}

type FrameOutcome = Result<(Opcode, Vec<u8>), String>;

impl PipelinedClient {
    pub async fn connect(addr: SocketAddr, token: &str) -> Result<Self> {
        Self::connect_with(addr, token, ClientOptions::default()).await
    }

    pub async fn connect_with(
        addr: SocketAddr,
        token: &str,
        opts: ClientOptions,
    ) -> Result<Self> {
        let mut sock = TcpStream::connect(addr).await?;
        sock.set_nodelay(true).ok();

        // ----- handshake (same shape as the single-flight client) -----
        let mut requested: u32 = 0;
        if opts.gzip {
            requested |= FEATURE_GZIP;
        }
        sock.write_all(&WIRE_MAGIC).await?;
        sock.write_all(&requested.to_be_bytes()).await?;
        let token_bytes = token.as_bytes();
        sock.write_all(&(token_bytes.len() as u32).to_be_bytes())
            .await?;
        sock.write_all(token_bytes).await?;

        let mut magic = [0u8; 4];
        sock.read_exact(&mut magic).await?;
        if magic != WIRE_MAGIC {
            return Err(anyhow!("bad server magic"));
        }
        let mut byte = [0u8; 1];
        sock.read_exact(&mut byte).await?;
        let status = HandshakeStatus::from_u8(byte[0])
            .ok_or_else(|| anyhow!("unknown handshake status {}", byte[0]))?;
        let mut buf4 = [0u8; 4];
        sock.read_exact(&mut buf4).await?;
        let features = u32::from_be_bytes(buf4);
        sock.read_exact(&mut buf4).await?;
        let msg_len = u32::from_be_bytes(buf4) as usize;
        let mut msg = vec![0u8; msg_len];
        if msg_len > 0 {
            sock.read_exact(&mut msg).await?;
        }
        if status != HandshakeStatus::Ok {
            let msg = String::from_utf8_lossy(&msg);
            return Err(anyhow!("handshake failed: {:?} ({})", status, msg));
        }
        let gzip = opts.gzip && (features & FEATURE_GZIP) != 0;

        let (read_half, write_half) = sock.into_split();

        let pending: DashMap<u32, oneshot::Sender<FrameOutcome>> = DashMap::new();
        let cancel = CancellationToken::new();

        let inner = Arc::new(Inner {
            write: Mutex::new(write_half),
            pending,
            next_id: AtomicU32::new(1),
            gzip,
            cancel: cancel.clone(),
            reader: Mutex::new(None),
        });

        let inner_for_reader = inner.clone();
        let join = tokio::spawn(async move {
            reader_loop(read_half, inner_for_reader).await;
        });
        *inner.reader.lock().await = Some(join);

        Ok(Self { inner })
    }

    pub fn gzip_enabled(&self) -> bool {
        self.inner.gzip
    }

    fn next_id(&self) -> u32 {
        self.inner.next_id.fetch_add(1, Ordering::Relaxed)
    }

    async fn round_trip(&self, opcode: Opcode, payload: Vec<u8>) -> Result<(Opcode, Vec<u8>)> {
        let id = self.next_id();
        let (tx, rx) = oneshot::channel();
        self.inner.pending.insert(id, tx);

        let body: std::borrow::Cow<[u8]> = if self.inner.gzip {
            std::borrow::Cow::Owned(compress(&payload)?)
        } else {
            std::borrow::Cow::Owned(payload)
        };
        let total = (4 + 1 + body.len()) as u32;
        let mut frame = Vec::with_capacity(4 + 4 + 1 + body.len());
        frame.extend_from_slice(&total.to_be_bytes());
        frame.extend_from_slice(&id.to_be_bytes());
        frame.push(opcode as u8);
        frame.extend_from_slice(&body);

        {
            let mut w = self.inner.write.lock().await;
            if let Err(e) = w.write_all(&frame).await {
                self.inner.pending.remove(&id);
                return Err(e.into());
            }
        }

        match rx.await {
            Ok(Ok(pair)) => Ok(pair),
            Ok(Err(msg)) => Err(anyhow!("server error: {}", msg)),
            Err(_) => Err(anyhow!("connection closed before response")),
        }
    }

    pub async fn produce(
        &self,
        topic: &str,
        producer_id: Option<&str>,
        records: Vec<WireProduceRecord>,
    ) -> Result<Vec<WireProduceResult>> {
        let req = WireProduceRequest {
            topic: topic.to_string(),
            producer_id: producer_id.map(|s| s.to_string()),
            records,
        };
        let payload = encode_produce_request(&req);
        let (opcode, body) = self.round_trip(Opcode::Produce, payload).await?;
        match opcode {
            Opcode::ProduceOk => Ok(decode_produce_response(&body)?),
            other => Err(anyhow!("unexpected response opcode {:?}", other)),
        }
    }

    pub async fn consume(
        &self,
        topic: &str,
        partition: u32,
        offset: u64,
        max_records: u32,
        max_bytes: u32,
    ) -> Result<WireConsumeResponse> {
        let req = WireConsumeRequest {
            topic: topic.to_string(),
            partition,
            offset,
            max_records,
            max_bytes,
        };
        let payload = encode_consume_request(&req);
        let (opcode, body) = self.round_trip(Opcode::Consume, payload).await?;
        match opcode {
            Opcode::ConsumeOk => Ok(decode_consume_response(&body)?),
            other => Err(anyhow!("unexpected response opcode {:?}", other)),
        }
    }

    /// Cancel the reader, wake all pending waiters with an error, and join
    /// the background task. Idempotent.
    pub async fn shutdown(&self) {
        self.inner.cancel.cancel();
        let join = self.inner.reader.lock().await.take();
        if let Some(j) = join {
            let _ = j.await;
        }
        // Fail any callers still waiting.
        let ids: Vec<u32> = self.inner.pending.iter().map(|kv| *kv.key()).collect();
        for id in ids {
            if let Some((_, tx)) = self.inner.pending.remove(&id) {
                let _ = tx.send(Err("client shutdown".to_string()));
            }
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn reader_loop(mut read: OwnedReadHalf, inner: Arc<Inner>) {
    loop {
        let frame_res = tokio::select! {
            _ = inner.cancel.cancelled() => break,
            res = read_frame(&mut read, inner.gzip) => res,
        };
        match frame_res {
            Ok(None) => break, // peer closed
            Ok(Some((id, opcode, body))) => {
                if let Some((_, tx)) = inner.pending.remove(&id) {
                    if opcode == Opcode::Error {
                        let _ = tx.send(Err(String::from_utf8_lossy(&body).into_owned()));
                    } else {
                        let _ = tx.send(Ok((opcode, body)));
                    }
                }
                // If the id isn't pending, the caller cancelled — drop the response.
            }
            Err(e) => {
                tracing::debug!(error = %e, "pipelined: reader error, closing");
                break;
            }
        }
    }
    // Wake everyone who's still waiting.
    let ids: Vec<u32> = inner.pending.iter().map(|kv| *kv.key()).collect();
    for id in ids {
        if let Some((_, tx)) = inner.pending.remove(&id) {
            let _ = tx.send(Err("connection closed".to_string()));
        }
    }
}

async fn read_frame(
    read: &mut OwnedReadHalf,
    gzip: bool,
) -> Result<Option<(u32, Opcode, Vec<u8>)>> {
    let mut len_buf = [0u8; 4];
    match read.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let total = u32::from_be_bytes(len_buf);
    if !(5..=64 * 1024 * 1024).contains(&total) {
        return Err(anyhow!("invalid frame size {}", total));
    }
    let mut frame = vec![0u8; total as usize];
    read.read_exact(&mut frame).await?;
    let request_id = u32::from_be_bytes(frame[0..4].try_into().unwrap());
    let opcode = Opcode::from_u8(frame[4])
        .ok_or_else(|| anyhow!("unknown opcode {:#x}", frame[4]))?;
    let payload = if gzip {
        decompress(&frame[5..])?
    } else {
        frame[5..].to_vec()
    };
    Ok(Some((request_id, opcode, payload)))
}

fn compress(input: &[u8]) -> std::io::Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::with_capacity(input.len() / 2 + 32), Compression::default());
    enc.write_all(input)?;
    enc.finish()
}

fn decompress(input: &[u8]) -> std::io::Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut dec = GzDecoder::new(input);
    let mut out = Vec::with_capacity(input.len() * 2);
    dec.read_to_end(&mut out)?;
    Ok(out)
}
