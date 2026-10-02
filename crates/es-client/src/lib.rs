//! A blocking client for the es binary protocol.
//!
//! The broker's own client (`es_broker::binary::BinaryClient`) runs on tokio
//! and lives inside the broker crate, so using it means depending on the whole
//! broker. This one is plain `std::net`: one connection, one request at a time,
//! for a caller that already has its own threads — an interpreter worker, a
//! script, a CLI.
//!
//! The protocol is `es_protocol::wire`; the handshake and framing below are the
//! client half of `es-broker/src/binary/codec.rs`, and `tests/against_broker.rs`
//! runs them against a real broker so the two cannot drift apart silently.
//!
//! The binary protocol carries produce, consume and ping. Topics, consumer
//! groups, commits and administration are HTTP only.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use es_protocol::wire::{
    decode_consume_response, decode_produce_response, encode_consume_request,
    encode_produce_request, HandshakeStatus, Opcode, WireProduceRequest, FEATURE_GZIP, WIRE_MAGIC,
};
pub use es_protocol::wire::{
    WireConsumeRequest, WireConsumeResponse, WireProduceRecord, WireProduceResult, WireRecord,
};

/// Largest frame either side accepts (`es-broker`'s `MAX_FRAME_BYTES`).
pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
/// Largest handshake message accepted from a server.
const MAX_HANDSHAKE_MSG: usize = 4096;
/// Payloads below this go through gzip uncompressed, as the broker does:
/// deflate's state costs more than it saves on a small frame.
const SMALL_PAYLOAD: usize = 512;

/// What went wrong, sorted by what it means for the connection.
#[derive(Debug)]
pub enum Error {
    /// The socket failed or closed. The connection is unusable.
    Io(io::Error),
    /// The server spoke something this client does not understand. The
    /// connection is unusable.
    Protocol(String),
    /// The server refused the handshake — a wrong token, most often.
    Handshake {
        status: Option<HandshakeStatus>,
        message: String,
    },
    /// The server answered the request with an error (unknown topic, a
    /// sequence gap, a missing grant…). The connection is still good.
    Server(String),
}

impl Error {
    /// Whether the connection can carry another request after this error.
    pub fn connection_usable(&self) -> bool {
        matches!(self, Error::Server(_))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Protocol(m) => write!(f, "protocol error: {m}"),
            Error::Handshake {
                status: Some(HandshakeStatus::AuthFailed),
                message,
            } => write!(f, "authentication failed: {message}"),
            Error::Handshake {
                status: Some(HandshakeStatus::AuthRequired),
                message,
            } => write!(f, "the broker requires a token: {message}"),
            Error::Handshake { status, message } => {
                write!(f, "handshake refused ({status:?}): {message}")
            }
            Error::Server(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// TLS settings: the broker's binary listener uses TLS whenever its HTTP
/// listener does (`--tls-cert` / `--tls-key`).
#[cfg(feature = "tls")]
#[derive(Clone)]
pub struct Tls {
    pub config: std::sync::Arc<rustls::ClientConfig>,
    /// Name the server's certificate must carry.
    pub server_name: String,
}

#[cfg(feature = "tls")]
impl Tls {
    /// Trust the certificates in `roots`.
    pub fn with_roots(
        roots: rustls::RootCertStore,
        server_name: impl Into<String>,
    ) -> Result<Self> {
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Protocol(format!("TLS setup: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            config: std::sync::Arc::new(config),
            server_name: server_name.into(),
        })
    }

    /// Trust the CA certificates in the PEM file at `path` — for a broker
    /// whose certificate is not signed by a public authority.
    pub fn from_ca_file(path: &std::path::Path, server_name: impl Into<String>) -> Result<Self> {
        use rustls_pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        let certs = rustls_pki_types::CertificateDer::pem_file_iter(path)
            .map_err(|e| Error::Protocol(format!("read {}: {e}", path.display())))?;
        for cert in certs {
            let cert =
                cert.map_err(|e| Error::Protocol(format!("parse {}: {e}", path.display())))?;
            roots
                .add(cert)
                .map_err(|e| Error::Protocol(format!("{}: {e}", path.display())))?;
        }
        Self::with_roots(roots, server_name)
    }
}

/// How to connect.
#[derive(Clone)]
pub struct Options {
    /// Bearer token; empty when the broker runs with `--auth disabled`.
    pub token: String,
    /// Ask for gzip-compressed frames. The broker may decline.
    pub gzip: bool,
    #[cfg(feature = "tls")]
    pub tls: Option<Tls>,
    pub connect_timeout: Duration,
    /// Read and write timeout on every request. `None` waits for ever.
    pub io_timeout: Option<Duration>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            token: String::new(),
            gzip: false,
            #[cfg(feature = "tls")]
            tls: None,
            connect_timeout: Duration::from_secs(5),
            io_timeout: Some(Duration::from_secs(30)),
        }
    }
}

enum Stream {
    Plain(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Stream {
    fn tcp(&self) -> &TcpStream {
        match self {
            Stream::Plain(s) => s,
            #[cfg(feature = "tls")]
            Stream::Tls(s) => &s.sock,
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.flush(),
        }
    }
}

/// One connection to a broker's binary listener.
pub struct Client {
    stream: Stream,
    next_request_id: u32,
    gzip: bool,
}

impl Client {
    /// Connect to `addr` (`host:port`) and run the handshake.
    pub fn connect(addr: impl ToSocketAddrs, options: &Options) -> Result<Self> {
        let addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();
        let mut last = None;
        for a in &addrs {
            match TcpStream::connect_timeout(a, options.connect_timeout) {
                Ok(sock) => return Self::handshake_on(sock, options),
                Err(e) => last = Some(e),
            }
        }
        Err(Error::Io(last.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "the address resolved to nothing")
        })))
    }

    fn handshake_on(sock: TcpStream, options: &Options) -> Result<Self> {
        sock.set_nodelay(true).ok();
        // The handshake gets the connect budget; requests get the I/O one.
        sock.set_read_timeout(Some(options.connect_timeout))?;
        sock.set_write_timeout(Some(options.connect_timeout))?;
        #[cfg(feature = "tls")]
        let mut stream = match &options.tls {
            None => Stream::Plain(sock),
            Some(tls) => {
                let name = rustls_pki_types::ServerName::try_from(tls.server_name.clone())
                    .map_err(|e| Error::Protocol(format!("invalid TLS server name: {e}")))?;
                let conn = rustls::ClientConnection::new(tls.config.clone(), name)
                    .map_err(|e| Error::Protocol(format!("TLS setup: {e}")))?;
                Stream::Tls(Box::new(rustls::StreamOwned::new(conn, sock)))
            }
        };
        #[cfg(not(feature = "tls"))]
        let mut stream = Stream::Plain(sock);

        let gzip = handshake(&mut stream, &options.token, options.gzip)?;
        stream.tcp().set_read_timeout(options.io_timeout)?;
        stream.tcp().set_write_timeout(options.io_timeout)?;
        Ok(Self {
            stream,
            next_request_id: 1,
            gzip,
        })
    }

    /// Whether gzip was negotiated.
    pub fn gzip_enabled(&self) -> bool {
        self.gzip
    }

    /// Whether an idle connection has been closed by the broker.
    ///
    /// The protocol only speaks when asked, so anything waiting to be read on
    /// an idle connection — end of stream, a TLS alert — means it is over. The
    /// broker closes idle connections (`--binary-idle-timeout`, 10 minutes by
    /// default); a pool calls this before reusing one rather than sending a
    /// produce into a dead socket and not knowing whether it landed.
    pub fn is_closed(&mut self) -> bool {
        if self.stream.tcp().set_nonblocking(true).is_err() {
            return true;
        }
        let closed = match &mut self.stream {
            Stream::Plain(tcp) => {
                let mut probe = [0u8; 1];
                match tcp.peek(&mut probe) {
                    Ok(_) => true,
                    Err(e) => e.kind() != io::ErrorKind::WouldBlock,
                }
            }
            // TLS 1.3 servers send session tickets after the handshake, so
            // bytes on an idle TLS socket are not by themselves a close: hand
            // them to rustls and look at what they were.
            #[cfg(feature = "tls")]
            Stream::Tls(s) => {
                let (conn, sock) = (&mut s.conn, &mut s.sock);
                loop {
                    match conn.read_tls(sock) {
                        Ok(0) => break true,
                        Ok(_) => match conn.process_new_packets() {
                            Err(_) => break true,
                            Ok(state) if state.peer_has_closed() => break true,
                            Ok(state) if state.plaintext_bytes_to_read() > 0 => break true,
                            Ok(_) => continue,
                        },
                        Err(e) => break e.kind() != io::ErrorKind::WouldBlock,
                    }
                }
            }
        };
        self.stream.tcp().set_nonblocking(false).is_err() || closed
    }

    pub fn ping(&mut self) -> Result<()> {
        match self.round_trip(Opcode::Ping, &[])? {
            (Opcode::PingOk, _) => Ok(()),
            (other, body) => unexpected(other, &body),
        }
    }

    /// Append `records` to `topic`. One result per record, in order.
    ///
    /// With a `producer_id`, every record needs a `sequence`, and the broker
    /// answers a retry of an acknowledged record with its original offset and
    /// `duplicate: true`.
    pub fn produce(
        &mut self,
        topic: &str,
        producer_id: Option<&str>,
        records: Vec<WireProduceRecord>,
    ) -> Result<Vec<WireProduceResult>> {
        let payload = encode_produce_request(&WireProduceRequest {
            topic: topic.to_string(),
            producer_id: producer_id.map(str::to_string),
            records,
        });
        match self.round_trip(Opcode::Produce, &payload)? {
            (Opcode::ProduceOk, body) => {
                decode_produce_response(&body).map_err(|e| Error::Protocol(e.to_string()))
            }
            (other, body) => unexpected(other, &body),
        }
    }

    /// Read from `request.partition` of `request.topic`, starting at
    /// `request.offset`.
    pub fn consume(&mut self, request: &WireConsumeRequest) -> Result<WireConsumeResponse> {
        let payload = encode_consume_request(request);
        match self.round_trip(Opcode::Consume, &payload)? {
            (Opcode::ConsumeOk, body) => {
                decode_consume_response(&body).map_err(|e| Error::Protocol(e.to_string()))
            }
            (other, body) => unexpected(other, &body),
        }
    }

    fn round_trip(&mut self, opcode: Opcode, payload: &[u8]) -> Result<(Opcode, Vec<u8>)> {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        let compressed;
        let body = if self.gzip {
            compressed = compress(payload)?;
            &compressed[..]
        } else {
            payload
        };
        // One buffer, one write: with TCP_NODELAY, separate writes become
        // separate packets.
        let frame = encode_frame(id, opcode, body)?;
        self.stream.write_all(&frame)?;
        self.stream.flush()?;

        let (resp_id, op, body) = read_frame(&mut self.stream)?;
        if resp_id != id {
            return Err(Error::Protocol(format!(
                "response id {resp_id} answers no request (sent {id})"
            )));
        }
        let body = if self.gzip {
            decompress(&body, MAX_FRAME_BYTES)?
        } else {
            body
        };
        Ok((op, body))
    }
}

fn unexpected<T>(op: Opcode, body: &[u8]) -> Result<T> {
    match op {
        Opcode::Error => Err(Error::Server(String::from_utf8_lossy(body).into_owned())),
        other => Err(Error::Protocol(format!("unexpected opcode {other:?}"))),
    }
}

fn handshake(stream: &mut Stream, token: &str, want_gzip: bool) -> Result<bool> {
    let requested: u32 = if want_gzip { FEATURE_GZIP } else { 0 };
    let token = token.as_bytes();
    let token_len =
        u32::try_from(token.len()).map_err(|_| Error::Protocol("token too long".to_string()))?;
    let mut hello = Vec::with_capacity(12 + token.len());
    hello.extend_from_slice(&WIRE_MAGIC);
    hello.extend_from_slice(&requested.to_be_bytes());
    hello.extend_from_slice(&token_len.to_be_bytes());
    hello.extend_from_slice(token);
    stream.write_all(&hello)?;
    stream.flush()?;

    let mut head = [0u8; 4 + 1 + 4 + 4];
    stream.read_exact(&mut head)?;
    if head[0..4] != WIRE_MAGIC {
        return Err(Error::Protocol(
            "not an es binary listener (bad magic) — is this the HTTP port?".to_string(),
        ));
    }
    let status = HandshakeStatus::from_u8(head[4]);
    let features = u32::from_be_bytes([head[5], head[6], head[7], head[8]]);
    let msg_len = u32::from_be_bytes([head[9], head[10], head[11], head[12]]) as usize;
    if msg_len > MAX_HANDSHAKE_MSG {
        return Err(Error::Protocol(format!(
            "handshake message too long ({msg_len} bytes)"
        )));
    }
    let mut msg = vec![0u8; msg_len];
    stream.read_exact(&mut msg)?;
    if status != Some(HandshakeStatus::Ok) {
        return Err(Error::Handshake {
            status,
            message: String::from_utf8_lossy(&msg).into_owned(),
        });
    }
    Ok(want_gzip && features & FEATURE_GZIP != 0)
}

/// `len | request_id | opcode | payload`.
fn encode_frame(request_id: u32, opcode: Opcode, payload: &[u8]) -> Result<Vec<u8>> {
    let total = u32::try_from(4 + 1 + payload.len())
        .ok()
        .filter(|t| (*t as usize) <= MAX_FRAME_BYTES)
        .ok_or_else(|| {
            Error::Protocol(format!(
                "a frame of {} bytes exceeds the protocol limit of {MAX_FRAME_BYTES}",
                payload.len()
            ))
        })?;
    let mut frame = Vec::with_capacity(4 + 4 + 1 + payload.len());
    frame.extend_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(&request_id.to_be_bytes());
    frame.push(opcode as u8);
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn read_frame(r: &mut impl Read) -> Result<(u32, Opcode, Vec<u8>)> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let total = u32::from_be_bytes(len) as usize;
    if !(5..=MAX_FRAME_BYTES).contains(&total) {
        return Err(Error::Protocol(format!(
            "server sent an out-of-bounds frame size {total}"
        )));
    }
    let mut head = [0u8; 5];
    r.read_exact(&mut head)?;
    let request_id = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let opcode = Opcode::from_u8(head[4])
        .ok_or_else(|| Error::Protocol(format!("unknown opcode {:#x}", head[4])))?;
    let mut payload = vec![0u8; total - 5];
    r.read_exact(&mut payload)?;
    Ok((request_id, opcode, payload))
}

fn compress(input: &[u8]) -> io::Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let level = if input.len() < SMALL_PAYLOAD {
        Compression::none()
    } else {
        Compression::fast()
    };
    let mut enc = GzEncoder::new(Vec::with_capacity(input.len() / 2 + 32), level);
    enc.write_all(input)?;
    enc.finish()
}

fn decompress(input: &[u8], cap: usize) -> io::Result<Vec<u8>> {
    let mut limited = flate2::read::GzDecoder::new(input).take(cap as u64 + 1);
    let mut out = Vec::with_capacity((input.len() * 2).min(cap));
    limited.read_to_end(&mut out)?;
    if out.len() > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decompressed frame exceeds the maximum size",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_reads_back_as_it_was_written() {
        let frame = encode_frame(7, Opcode::Ping, b"abc").unwrap();
        let (id, op, body) = read_frame(&mut &frame[..]).unwrap();
        assert_eq!((id, op, body.as_slice()), (7, Opcode::Ping, &b"abc"[..]));
    }

    #[test]
    fn a_frame_size_out_of_bounds_is_refused() {
        let mut bogus = Vec::new();
        bogus.extend_from_slice(&(u32::MAX).to_be_bytes());
        assert!(matches!(
            read_frame(&mut &bogus[..]),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn gzip_round_trips_and_is_capped() {
        let big = vec![b'x'; 10_000];
        assert_eq!(decompress(&compress(&big).unwrap(), 10_000).unwrap(), big);
        assert!(decompress(&compress(&big).unwrap(), 100).is_err());
    }

    #[test]
    fn only_a_server_error_leaves_the_connection_usable() {
        assert!(Error::Server("x".into()).connection_usable());
        assert!(!Error::Protocol("x".into()).connection_usable());
        assert!(!Error::Io(io::Error::other("x")).connection_usable());
    }
}
