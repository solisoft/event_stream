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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use es_protocol::wire::{
    decode_consume_response, decode_produce_response, encode_consume_request_with_flags,
    encode_produce_request, Opcode, WireConsumeRequest, WireConsumeResponse, WireProduceRecord,
    WireProduceRequest, WireProduceResult, CONSUME_FLAG_LINEARIZABLE, FEATURE_CONSUME_FLAGS,
    FEATURE_GZIP,
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
    /// Set by the reader as it exits. A request registered after that would
    /// otherwise wait forever for a response nobody is left to deliver.
    closed: AtomicBool,
    gzip: bool,
    /// Whether the server understands consume flags.
    consume_flags: bool,
    cancel: CancellationToken,
    reader: Mutex<Option<JoinHandle<()>>>,
}

type FrameOutcome = Result<(Opcode, Vec<u8>), String>;

impl PipelinedClient {
    pub async fn connect(addr: SocketAddr, token: &str) -> Result<Self> {
        Self::connect_with(addr, token, ClientOptions::default()).await
    }

    pub async fn connect_with(addr: SocketAddr, token: &str, opts: ClientOptions) -> Result<Self> {
        let (stream, features) =
            codec::connect_with_features(addr, token, opts.gzip, opts.tls.as_ref()).await?;
        let (read_half, write_half) = tokio::io::split(stream);
        let cancel = CancellationToken::new();
        let inner = Arc::new(Inner {
            write: Mutex::new(write_half),
            pending: DashMap::new(),
            next_id: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            gzip: features & FEATURE_GZIP != 0,
            consume_flags: features & FEATURE_CONSUME_FLAGS != 0,
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

    /// Register a waiter under a fresh request id. An id that wrapped around
    /// to one still pending is skipped: replacing its sender would hand that
    /// caller's response to this one.
    fn register(&self) -> Result<Pending<'_>> {
        let (tx, rx) = oneshot::channel();
        let mut tx = Some(tx);
        let id = loop {
            let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
            if let dashmap::mapref::entry::Entry::Vacant(v) = self.inner.pending.entry(id) {
                v.insert(tx.take().expect("sender is inserted once"));
                break id;
            }
        };
        let pending = Pending {
            inner: &self.inner,
            id,
            rx: Some(rx),
        };
        // Checked after the insert: the reader sets `closed` before failing
        // what is pending, so either it sees this entry or we see the flag.
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(anyhow!("connection closed"));
        }
        Ok(pending)
    }

    async fn round_trip(&self, opcode: Opcode, payload: Vec<u8>) -> Result<(Opcode, Vec<u8>)> {
        let mut pending = self.register()?;
        let id = pending.id;

        let body = if self.inner.gzip {
            codec::compress(&payload)?
        } else {
            payload
        };
        let frame = codec::encode_frame(id, opcode, &body)?;
        {
            let mut w = self.inner.write.lock().await;
            w.write_all(&frame).await?;
            w.flush().await?;
        }

        let rx = pending.rx.as_mut().expect("receiver is taken only on drop");
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
        let payload = encode_produce_request(&req)?;
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
        self.consume_with_flags(topic, partition, offset, max_records, max_bytes, 0)
            .await
    }

    /// See [`super::client::BinaryClient::consume_linearizable`].
    pub async fn consume_linearizable(
        &self,
        topic: &str,
        partition: u32,
        offset: u64,
        max_records: u32,
        max_bytes: u32,
    ) -> Result<WireConsumeResponse> {
        if !self.inner.consume_flags {
            return Err(anyhow!(
                "the broker does not support linearizable reads (no consume flags at handshake)"
            ));
        }
        self.consume_with_flags(
            topic,
            partition,
            offset,
            max_records,
            max_bytes,
            CONSUME_FLAG_LINEARIZABLE,
        )
        .await
    }

    async fn consume_with_flags(
        &self,
        topic: &str,
        partition: u32,
        offset: u64,
        max_records: u32,
        max_bytes: u32,
        flags: u8,
    ) -> Result<WireConsumeResponse> {
        let req = WireConsumeRequest {
            topic: topic.to_string(),
            partition,
            offset,
            max_records,
            max_bytes,
        };
        let payload = encode_consume_request_with_flags(&req, flags)?;
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

/// A registered request. Dropping it — on any error, or when the caller's
/// future is cancelled mid-flight — removes its `pending` entry, which used
/// to stay behind until the connection closed.
struct Pending<'a> {
    inner: &'a Inner,
    id: u32,
    rx: Option<oneshot::Receiver<FrameOutcome>>,
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        // Our receiver goes first, so our sender — if it is still there —
        // reports closed; an entry under the same id with a live receiver
        // belongs to someone else and is left alone.
        drop(self.rx.take());
        self.inner
            .pending
            .remove_if(&self.id, |_, tx| tx.is_closed());
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
    inner.closed.store(true, Ordering::SeqCst);
    fail_all(&inner, "connection closed");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client whose server end is the returned duplex half, already past
    /// the handshake.
    fn client() -> (PipelinedClient, tokio::io::DuplexStream) {
        let (ours, theirs) = tokio::io::duplex(1 << 16);
        let stream: Box<dyn IoStream> = Box::new(ours);
        let (read_half, write_half) = tokio::io::split(stream);
        let inner = Arc::new(Inner {
            write: Mutex::new(write_half),
            pending: DashMap::new(),
            next_id: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            gzip: false,
            consume_flags: true,
            cancel: CancellationToken::new(),
            reader: Mutex::new(None),
        });
        let for_reader = inner.clone();
        tokio::spawn(async move { reader_loop(read_half, for_reader).await });
        (PipelinedClient { inner }, theirs)
    }

    #[tokio::test]
    async fn a_request_after_the_reader_exits_fails_instead_of_hanging() {
        let (c, server) = client();
        drop(server);
        // Wait for the reader to notice the close.
        for _ in 0..100 {
            if c.inner.closed.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(c.inner.closed.load(Ordering::SeqCst));
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            c.round_trip(Opcode::Ping, Vec::new()),
        )
        .await
        .expect("round_trip must not hang on a closed connection");
        assert!(res.is_err());
        assert!(c.inner.pending.is_empty());
    }

    #[tokio::test]
    async fn a_cancelled_request_leaves_no_pending_entry() {
        let (c, _server) = client();
        // The server never answers; the caller gives up.
        let res = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            c.round_trip(Opcode::Ping, Vec::new()),
        )
        .await;
        assert!(res.is_err());
        assert!(c.inner.pending.is_empty());
    }

    #[tokio::test]
    async fn a_wrapped_id_skips_one_still_pending() {
        let (c, _server) = client();
        let (live_tx, _live_rx) = oneshot::channel();
        c.inner.pending.insert(u32::MAX, live_tx);
        c.inner.next_id.store(u32::MAX, Ordering::Relaxed);
        let p = c.register().unwrap();
        assert_eq!(p.id, 0, "wrapped past the pending id");
        // The older waiter's sender is still the one under its id.
        assert!(!c.inner.pending.get(&u32::MAX).unwrap().is_closed());
        drop(p);
        assert!(c.inner.pending.get(&0).is_none());
        assert!(c.inner.pending.get(&u32::MAX).is_some());
    }
}
