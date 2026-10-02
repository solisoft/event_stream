//! Pieces of the binary protocol shared by the server and both clients.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use es_protocol::wire::{HandshakeStatus, Opcode, FEATURE_GZIP, WIRE_MAGIC};

/// Any byte stream the protocol can run over: plain TCP or TLS.
pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}

/// Largest frame either side accepts. Requests are bounded far below this by
/// the broker's record and fetch limits.
pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
/// Largest handshake message accepted from a server. The client used to
/// allocate whatever length the server sent — up to 4 GiB.
const MAX_HANDSHAKE_MSG: usize = 4096;
/// Connect + handshake budget for clients.
pub const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Payloads smaller than this are not worth compressing: deflate's state
/// costs more than the bytes it would save on a 13-byte produce ack. The frame
/// still goes through gzip (both sides negotiated it), at the cheapest level.
const SMALL_PAYLOAD: usize = 512;

/// Gzip `input`. Fast level: the protocol favours throughput.
pub fn compress(input: &[u8]) -> std::io::Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let level = if input.len() < SMALL_PAYLOAD {
        Compression::none()
    } else {
        Compression::fast()
    };
    let mut enc = GzEncoder::new(Vec::with_capacity(input.len() / 2 + 32), level);
    enc.write_all(input)?;
    enc.finish()
}

/// Gunzip `input`, refusing to produce more than `cap` bytes.
pub fn decompress(input: &[u8], cap: usize) -> std::io::Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    let dec = GzDecoder::new(input);
    let mut limited = dec.take(cap as u64 + 1);
    let mut out = Vec::with_capacity((input.len() * 2).min(cap));
    limited.read_to_end(&mut out)?;
    if out.len() > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "decompressed frame exceeds maximum size",
        ));
    }
    Ok(out)
}

/// The topic a produce or consume payload addresses. Both start with it as a
/// `u16`-length string, so for a gzip frame only the first few bytes are
/// inflated — enough to authorize the request before paying for the rest.
pub fn peek_topic(payload: &[u8], gzip: bool) -> std::io::Result<String> {
    let invalid = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
    let read_str = |r: &mut dyn Read| -> std::io::Result<String> {
        let mut len = [0u8; 2];
        r.read_exact(&mut len)?;
        let n = u16::from_be_bytes(len) as usize;
        let mut buf = vec![0u8; n];
        r.read_exact(&mut buf)?;
        String::from_utf8(buf).map_err(|_| invalid("topic is not utf-8"))
    };
    if gzip {
        read_str(&mut flate2::read::GzDecoder::new(payload))
    } else {
        read_str(&mut &payload[..])
    }
}

/// Build one frame: `len | request_id | opcode | payload`.
pub fn encode_frame(request_id: u32, opcode: Opcode, payload: &[u8]) -> Result<Vec<u8>> {
    let total = u32::try_from(4 + 1 + payload.len())
        .ok()
        .filter(|t| (*t as usize) <= MAX_FRAME_BYTES)
        .ok_or_else(|| {
            anyhow!(
                "frame of {} bytes exceeds the protocol limit",
                payload.len()
            )
        })?;
    let mut frame = Vec::with_capacity(4 + 4 + 1 + payload.len());
    frame.extend_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(&request_id.to_be_bytes());
    frame.push(opcode as u8);
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Read one frame from a server. Returns `(request_id, opcode, payload)`,
/// payload still compressed if gzip was negotiated.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<(u32, Opcode, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let total = u32::from_be_bytes(len_buf) as usize;
    if !(5..=MAX_FRAME_BYTES).contains(&total) {
        return Err(anyhow!("server sent out-of-bounds frame size {}", total));
    }
    let mut head = [0u8; 5];
    r.read_exact(&mut head).await?;
    let request_id = u32::from_be_bytes(head[0..4].try_into().unwrap());
    let opcode =
        Opcode::from_u8(head[4]).ok_or_else(|| anyhow!("unknown opcode {:#x}", head[4]))?;
    let mut payload = vec![0u8; total - 5];
    r.read_exact(&mut payload).await?;
    Ok((request_id, opcode, payload))
}

/// TLS settings for a client.
#[derive(Clone)]
pub struct ClientTls {
    pub config: Arc<rustls::ClientConfig>,
    /// Name the server's certificate must carry.
    pub server_name: String,
}

/// Connect (optionally over TLS) and run the client handshake. Returns the
/// stream and whether gzip was negotiated.
pub async fn connect(
    addr: std::net::SocketAddr,
    token: &str,
    want_gzip: bool,
    tls: Option<&ClientTls>,
) -> Result<(Box<dyn IoStream>, bool)> {
    let fut = async {
        let sock = tokio::net::TcpStream::connect(addr).await?;
        sock.set_nodelay(true).ok();
        let mut stream: Box<dyn IoStream> = match tls {
            None => Box::new(sock),
            Some(t) => {
                let name = rustls::pki_types::ServerName::try_from(t.server_name.clone())
                    .map_err(|e| anyhow!("invalid TLS server name: {e}"))?;
                let connector = tokio_rustls::TlsConnector::from(t.config.clone());
                Box::new(connector.connect(name, sock).await?)
            }
        };
        let gzip = handshake(&mut stream, token, want_gzip).await?;
        Ok::<_, anyhow::Error>((stream, gzip))
    };
    tokio::time::timeout(CLIENT_HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| anyhow!("connect/handshake timed out"))?
}

async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    sock: &mut S,
    token: &str,
    want_gzip: bool,
) -> Result<bool> {
    let requested: u32 = if want_gzip { FEATURE_GZIP } else { 0 };
    let token_bytes = token.as_bytes();
    let mut hello = Vec::with_capacity(12 + token_bytes.len());
    hello.extend_from_slice(&WIRE_MAGIC);
    hello.extend_from_slice(&requested.to_be_bytes());
    hello.extend_from_slice(&(token_bytes.len() as u32).to_be_bytes());
    hello.extend_from_slice(token_bytes);
    sock.write_all(&hello).await?;
    sock.flush().await?;

    let mut head = [0u8; 4 + 1 + 4 + 4];
    sock.read_exact(&mut head).await?;
    if head[0..4] != WIRE_MAGIC {
        return Err(anyhow!("bad server magic"));
    }
    let status = HandshakeStatus::from_u8(head[4])
        .ok_or_else(|| anyhow!("unknown handshake status {}", head[4]))?;
    let features = u32::from_be_bytes(head[5..9].try_into().unwrap());
    let msg_len = u32::from_be_bytes(head[9..13].try_into().unwrap()) as usize;
    if msg_len > MAX_HANDSHAKE_MSG {
        return Err(anyhow!(
            "server handshake message too long ({msg_len} bytes)"
        ));
    }
    let mut msg = vec![0u8; msg_len];
    sock.read_exact(&mut msg).await?;
    if status != HandshakeStatus::Ok {
        let msg = String::from_utf8_lossy(&msg);
        return Err(anyhow!("handshake failed: {:?} ({})", status, msg));
    }
    Ok(want_gzip && (features & FEATURE_GZIP) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_is_read_from_the_head_of_a_gzip_stream() {
        let mut b = es_protocol::wire::WireBuf::new();
        b.put_str("orders");
        b.put_bytes(&vec![0u8; 1 << 20]);
        let z = compress(&b.bytes).unwrap();
        assert_eq!(peek_topic(&z, true).unwrap(), "orders");
        assert_eq!(peek_topic(&b.bytes, false).unwrap(), "orders");
    }

    #[test]
    fn decompression_is_capped() {
        let z = compress(&vec![0u8; 1 << 20]).unwrap();
        assert!(decompress(&z, 1024).is_err());
        assert_eq!(decompress(&z, 1 << 20).unwrap().len(), 1 << 20);
    }
}
