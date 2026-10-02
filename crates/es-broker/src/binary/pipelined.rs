//! Pipelined binary protocol client.
//!
//! Differences from [`super::client::BinaryClient`]:
//!   * Many in-flight requests on a single connection.
//!   * Cloneable handle — one connection, many concurrent callers.
//!   * Reader runs in a background task; each caller gets its response via a
//!     per-request `oneshot` channel.
//!
//! Same wire format, same handshake, same auth. The broker processes requests
//! from one connection concurrently, keeping produces to the same topic in
//! arrival order, and answers each with its `request_id`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use es_protocol::wire::{
    decode_consume_response, decode_produce_response, encode_consume_request,
    encode_produce_request, Opcode, WireConsumeRequest, WireConsumeResponse, WireProduceRecord,
    WireProduceRequest, WireProduceResult,
};

use super::client::ClientOptions;
use super::codec::{self, IoStream, MAX_FRAME_BYTES};

#[derive(Clone)]
pub struct PipelinedClient {
    inner: Arc<Inner>,
}

struct Inner {
    write: Mutex<WriteHalf<Box<dyn IoStream>>>,
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

    pub async fn connect_with(addr: SocketAddr, token: &str, opts: ClientOptions) -> Result<Self> {
        let (stream, gzip) = codec::connect(addr, token, opts.gzip, opts.tls.as_ref()).await?;
        let (read_half, write_half) = tokio::io::split(stream);
        let cancel = CancellationToken::new();
        let inner = Arc::new(Inner {
            write: Mutex::new(write_half),
            pending: DashMap::new(),
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

        let body = if self.inner.gzip {
            codec::compress(&payload)?
        } else {
            payload
        };
        let frame = match codec::encode_frame(id, opcode, &body) {
            Ok(f) => f,
            Err(e) => {
                self.inner.pending.remove(&id);
                return Err(e);
            }
        };
        {
            let mut w = self.inner.write.lock().await;
            let res = async {
                w.write_all(&frame).await?;
                w.flush().await
            }
            .await;
            if let Err(e) = res {
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
        fail_all(&self.inner, "client shutdown");
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn fail_all(inner: &Inner, why: &str) {
    let ids: Vec<u32> = inner.pending.iter().map(|kv| *kv.key()).collect();
    for id in ids {
        if let Some((_, tx)) = inner.pending.remove(&id) {
            let _ = tx.send(Err(why.to_string()));
        }
    }
}

async fn reader_loop(mut read: ReadHalf<Box<dyn IoStream>>, inner: Arc<Inner>) {
    loop {
        let frame_res = tokio::select! {
            _ = inner.cancel.cancelled() => break,
            res = codec::read_frame(&mut read) => res,
        };
        match frame_res {
            Ok((id, opcode, body)) => {
                let body = if inner.gzip {
                    // Capped: a malicious server — or anyone in the path of a
                    // plaintext connection — could otherwise inflate a 64 MiB
                    // frame into many gigabytes here.
                    match codec::decompress(&body, MAX_FRAME_BYTES) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::debug!(error = %e, "pipelined: bad compressed frame, closing");
                            break;
                        }
                    }
                } else {
                    body
                };
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
    fail_all(&inner, "connection closed");
}
