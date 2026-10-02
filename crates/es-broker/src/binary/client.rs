//! Tokio-based binary protocol client.

use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use tokio::io::AsyncWriteExt;

use es_protocol::wire::{
    decode_consume_response, decode_produce_response, encode_consume_request,
    encode_produce_request, Opcode, WireConsumeRequest, WireConsumeResponse, WireProduceRecord,
    WireProduceRequest, WireProduceResult,
};

use super::codec::{self, ClientTls, IoStream, MAX_FRAME_BYTES};

#[derive(Clone, Default)]
pub struct ClientOptions {
    /// Request gzip compression on the connection. The server may decline,
    /// in which case the client falls back to uncompressed frames.
    pub gzip: bool,
    /// Connect over TLS. Required when the broker's binary listener has TLS.
    pub tls: Option<ClientTls>,
}

pub struct BinaryClient {
    sock: Box<dyn IoStream>,
    next_request_id: u32,
    gzip: bool,
}

impl BinaryClient {
    pub async fn connect(addr: SocketAddr, token: &str) -> Result<Self> {
        Self::connect_with(addr, token, ClientOptions::default()).await
    }

    /// Open a connection and run the handshake with the given options.
    /// `token` may be empty when the broker has auth disabled.
    pub async fn connect_with(addr: SocketAddr, token: &str, opts: ClientOptions) -> Result<Self> {
        let (sock, gzip) = codec::connect(addr, token, opts.gzip, opts.tls.as_ref()).await?;
        Ok(Self {
            sock,
            next_request_id: 1,
            gzip,
        })
    }

    pub fn gzip_enabled(&self) -> bool {
        self.gzip
    }

    fn next_id(&mut self) -> u32 {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        id
    }

    async fn write_frame(&mut self, request_id: u32, opcode: Opcode, payload: &[u8]) -> Result<()> {
        let body: std::borrow::Cow<[u8]> = if self.gzip {
            std::borrow::Cow::Owned(codec::compress(payload)?)
        } else {
            std::borrow::Cow::Borrowed(payload)
        };
        // One buffer, one write: with TCP_NODELAY on, separate writes become
        // separate packets and dominate latency at small frame sizes.
        let frame = codec::encode_frame(request_id, opcode, &body)?;
        self.sock.write_all(&frame).await?;
        self.sock.flush().await?;
        Ok(())
    }

    async fn read_frame(&mut self) -> Result<(u32, Opcode, Vec<u8>)> {
        let (id, op, payload) = codec::read_frame(&mut self.sock).await?;
        let payload = if self.gzip {
            codec::decompress(&payload, MAX_FRAME_BYTES)?
        } else {
            payload
        };
        Ok((id, op, payload))
    }

    async fn round_trip(&mut self, opcode: Opcode, payload: &[u8]) -> Result<(Opcode, Vec<u8>)> {
        let id = self.next_id();
        self.write_frame(id, opcode, payload).await?;
        let (resp_id, op, body) = self.read_frame().await?;
        if resp_id != id {
            return Err(anyhow!("response id {} != request id {}", resp_id, id));
        }
        Ok((op, body))
    }

    pub async fn ping(&mut self) -> Result<()> {
        match self.round_trip(Opcode::Ping, &[]).await?.0 {
            Opcode::PingOk => Ok(()),
            other => Err(anyhow!("ping returned opcode {:?}", other)),
        }
    }

    pub async fn produce(
        &mut self,
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
        match self.round_trip(Opcode::Produce, &payload).await? {
            (Opcode::ProduceOk, body) => Ok(decode_produce_response(&body)?),
            (Opcode::Error, body) => {
                Err(anyhow!("server error: {}", String::from_utf8_lossy(&body)))
            }
            (other, _) => Err(anyhow!("unexpected opcode {:?}", other)),
        }
    }

    pub async fn consume(
        &mut self,
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
        match self.round_trip(Opcode::Consume, &payload).await? {
            (Opcode::ConsumeOk, body) => Ok(decode_consume_response(&body)?),
            (Opcode::Error, body) => {
                Err(anyhow!("server error: {}", String::from_utf8_lossy(&body)))
            }
            (other, _) => Err(anyhow!("unexpected opcode {:?}", other)),
        }
    }
}
