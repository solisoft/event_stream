//! Tokio-based binary protocol client.

use std::net::SocketAddr;

use anyhow::{Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use es_protocol::wire::{
    FEATURE_GZIP, HandshakeStatus, Opcode, WireConsumeRequest, WireConsumeResponse,
    WireProduceRecord, WireProduceRequest, WireProduceResult, WIRE_MAGIC, decode_consume_response,
    decode_produce_response, encode_consume_request, encode_produce_request,
};

#[derive(Debug, Clone, Copy)]
pub struct ClientOptions {
    /// Request gzip compression on the connection. The server may decline,
    /// in which case the client falls back to uncompressed frames.
    pub gzip: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self { gzip: false }
    }
}

pub struct BinaryClient {
    sock: TcpStream,
    next_request_id: u32,
    gzip: bool,
}

impl BinaryClient {
    pub async fn connect(addr: SocketAddr, token: &str) -> Result<Self> {
        Self::connect_with(addr, token, ClientOptions::default()).await
    }

    /// Open a TCP connection and run the handshake with the given options.
    /// `token` may be empty when the broker has auth disabled.
    pub async fn connect_with(
        addr: SocketAddr,
        token: &str,
        opts: ClientOptions,
    ) -> Result<Self> {
        let mut sock = TcpStream::connect(addr).await?;
        sock.set_nodelay(true).ok();

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
            std::borrow::Cow::Owned(compress(payload)?)
        } else {
            std::borrow::Cow::Borrowed(payload)
        };
        let total = (4 + 1 + body.len()) as u32;
        // Coalesce header + payload into one buffer so it ships as a single
        // write — with TCP_NODELAY on, separate write_all calls turn into
        // separate packets and dominate latency at small frame sizes.
        let mut frame = Vec::with_capacity(4 + 4 + 1 + body.len());
        frame.extend_from_slice(&total.to_be_bytes());
        frame.extend_from_slice(&request_id.to_be_bytes());
        frame.push(opcode as u8);
        frame.extend_from_slice(&body);
        self.sock.write_all(&frame).await?;
        Ok(())
    }

    async fn read_frame(&mut self) -> Result<(u32, Opcode, Vec<u8>)> {
        let mut len_buf = [0u8; 4];
        self.sock.read_exact(&mut len_buf).await?;
        let total = u32::from_be_bytes(len_buf) as usize;
        if total < 5 {
            return Err(anyhow!("server sent undersized frame {}", total));
        }
        let mut frame = vec![0u8; total];
        self.sock.read_exact(&mut frame).await?;
        let request_id = u32::from_be_bytes(frame[0..4].try_into().unwrap());
        let opcode = Opcode::from_u8(frame[4])
            .ok_or_else(|| anyhow!("unknown opcode {:#x}", frame[4]))?;
        let payload = if self.gzip {
            decompress(&frame[5..])?
        } else {
            frame[5..].to_vec()
        };
        Ok((request_id, opcode, payload))
    }

    pub async fn ping(&mut self) -> Result<()> {
        let id = self.next_id();
        self.write_frame(id, Opcode::Ping, &[]).await?;
        let (resp_id, opcode, _payload) = self.read_frame().await?;
        if resp_id != id {
            return Err(anyhow!("response id {} != request id {}", resp_id, id));
        }
        if opcode == Opcode::PingOk {
            Ok(())
        } else {
            Err(anyhow!("ping returned opcode {:?}", opcode))
        }
    }

    pub async fn produce(
        &mut self,
        topic: &str,
        producer_id: Option<&str>,
        records: Vec<WireProduceRecord>,
    ) -> Result<Vec<WireProduceResult>> {
        let id = self.next_id();
        let req = WireProduceRequest {
            topic: topic.to_string(),
            producer_id: producer_id.map(|s| s.to_string()),
            records,
        };
        let payload = encode_produce_request(&req);
        self.write_frame(id, Opcode::Produce, &payload).await?;
        let (resp_id, opcode, body) = self.read_frame().await?;
        if resp_id != id {
            return Err(anyhow!("response id mismatch"));
        }
        match opcode {
            Opcode::ProduceOk => Ok(decode_produce_response(&body)?),
            Opcode::Error => Err(anyhow!("server error: {}", String::from_utf8_lossy(&body))),
            other => Err(anyhow!("unexpected opcode {:?}", other)),
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
        let id = self.next_id();
        let req = WireConsumeRequest {
            topic: topic.to_string(),
            partition,
            offset,
            max_records,
            max_bytes,
        };
        let payload = encode_consume_request(&req);
        self.write_frame(id, Opcode::Consume, &payload).await?;
        let (resp_id, opcode, body) = self.read_frame().await?;
        if resp_id != id {
            return Err(anyhow!("response id mismatch"));
        }
        match opcode {
            Opcode::ConsumeOk => Ok(decode_consume_response(&body)?),
            Opcode::Error => Err(anyhow!("server error: {}", String::from_utf8_lossy(&body))),
            other => Err(anyhow!("unexpected opcode {:?}", other)),
        }
    }
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
