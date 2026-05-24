//! Binary wire protocol for the high-throughput hot path.
//!
//! Framing (after handshake):
//!   `length: u32 BE` — bytes of everything below.
//!   `request_id: u32 BE`
//!   `opcode: u8`
//!   `payload: opcode-specific`
//!
//! Numbers are big-endian. Strings are length-prefixed bytes (UTF-8 by
//! convention but the broker doesn't enforce it on the binary path).
//!
//! See `wire::Opcode` for the opcode table. Server responses set the high bit
//! (`0x80`) so a request/response pair can be distinguished without context.
//!
//! Carrying native `Vec<u8>` for keys + values is the main reason to prefer
//! this over the JSON path — it skips both JSON parsing and the lossy UTF-8
//! conversion that the HTTP path performs.

use std::io;

/// Connection-prefix bytes. Both sides MUST send this exactly during handshake.
pub const WIRE_MAGIC: [u8; 4] = *b"ES01";

/// Feature bit: gzip compression of frame payloads (everything after
/// `request_id` + `opcode`). The header bytes themselves stay uncompressed
/// so the server can frame-parse without paying the decompress.
pub const FEATURE_GZIP: u32 = 1 << 0;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStatus {
    Ok = 0,
    BadMagic = 1,
    AuthFailed = 2,
    AuthRequired = 3,
    FeatureUnsupported = 4,
    Internal = 5,
}

impl HandshakeStatus {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Ok),
            1 => Some(Self::BadMagic),
            2 => Some(Self::AuthFailed),
            3 => Some(Self::AuthRequired),
            4 => Some(Self::FeatureUnsupported),
            5 => Some(Self::Internal),
            _ => None,
        }
    }
}

/// Request opcode (low 7 bits). Server response uses the high bit set.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Produce = 0x01,
    Consume = 0x02,
    Ping = 0x03,

    ProduceOk = 0x81,
    ConsumeOk = 0x82,
    PingOk = 0x83,

    Error = 0xFF,
}

impl Opcode {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Produce),
            0x02 => Some(Self::Consume),
            0x03 => Some(Self::Ping),
            0x81 => Some(Self::ProduceOk),
            0x82 => Some(Self::ConsumeOk),
            0x83 => Some(Self::PingOk),
            0xFF => Some(Self::Error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WireProduceRecord {
    pub key: Option<Vec<u8>>,
    pub value: Vec<u8>,
    pub partition: Option<u32>,
    pub sequence: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct WireProduceRequest {
    pub topic: String,
    pub producer_id: Option<String>,
    pub records: Vec<WireProduceRecord>,
}

#[derive(Debug, Clone)]
pub struct WireProduceResult {
    pub partition: u32,
    pub offset: u64,
    pub duplicate: bool,
}

#[derive(Debug, Clone)]
pub struct WireConsumeRequest {
    pub topic: String,
    pub partition: u32,
    pub offset: u64,
    pub max_records: u32,
    pub max_bytes: u32,
}

#[derive(Debug, Clone)]
pub struct WireRecord {
    pub partition: u32,
    pub offset: u64,
    pub timestamp_ms: i64,
    pub key: Option<Vec<u8>>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct WireConsumeResponse {
    pub records: Vec<WireRecord>,
    pub next_offset: u64,
    pub high_watermark: u64,
}

// ----- encode/decode -----

/// Compact builder reused by both client and server.
#[derive(Default)]
pub struct WireBuf {
    pub bytes: Vec<u8>,
}

impl WireBuf {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn put_u8(&mut self, v: u8) {
        self.bytes.push(v);
    }
    pub fn put_u16(&mut self, v: u16) {
        self.bytes.extend_from_slice(&v.to_be_bytes());
    }
    pub fn put_u32(&mut self, v: u32) {
        self.bytes.extend_from_slice(&v.to_be_bytes());
    }
    pub fn put_i32(&mut self, v: i32) {
        self.bytes.extend_from_slice(&v.to_be_bytes());
    }
    pub fn put_u64(&mut self, v: u64) {
        self.bytes.extend_from_slice(&v.to_be_bytes());
    }
    pub fn put_i64(&mut self, v: i64) {
        self.bytes.extend_from_slice(&v.to_be_bytes());
    }
    pub fn put_bytes(&mut self, v: &[u8]) {
        self.bytes.extend_from_slice(v);
    }
    pub fn put_str(&mut self, s: &str) {
        let b = s.as_bytes();
        self.put_u16(b.len() as u16);
        self.put_bytes(b);
    }
    pub fn put_opt_bytes_i32(&mut self, v: Option<&[u8]>) {
        match v {
            None => self.put_i32(-1),
            Some(b) => {
                self.put_i32(b.len() as i32);
                self.put_bytes(b);
            }
        }
    }
    pub fn put_value(&mut self, v: &[u8]) {
        self.put_u32(v.len() as u32);
        self.put_bytes(v);
    }
    pub fn put_opt_string_i32(&mut self, v: Option<&str>) {
        match v {
            None => self.put_i32(-1),
            Some(s) => {
                let b = s.as_bytes();
                self.put_i32(b.len() as i32);
                self.put_bytes(b);
            }
        }
    }
    pub fn put_opt_u32_neg(&mut self, v: Option<u32>) {
        match v {
            None => self.put_i32(-1),
            Some(n) => self.put_i32(n as i32),
        }
    }
    pub fn put_opt_i64_min(&mut self, v: Option<i64>) {
        match v {
            None => self.put_i64(i64::MIN),
            Some(n) => self.put_i64(n),
        }
    }
}

pub struct WireReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
    fn ensure(&self, n: usize) -> io::Result<()> {
        if self.remaining() < n {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short read in wire decode",
            ))
        } else {
            Ok(())
        }
    }
    pub fn get_u8(&mut self) -> io::Result<u8> {
        self.ensure(1)?;
        let v = self.bytes[self.pos];
        self.pos += 1;
        Ok(v)
    }
    pub fn get_u16(&mut self) -> io::Result<u16> {
        self.ensure(2)?;
        let v = u16::from_be_bytes(self.bytes[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Ok(v)
    }
    pub fn get_u32(&mut self) -> io::Result<u32> {
        self.ensure(4)?;
        let v = u32::from_be_bytes(self.bytes[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }
    pub fn get_i32(&mut self) -> io::Result<i32> {
        Ok(self.get_u32()? as i32)
    }
    pub fn get_u64(&mut self) -> io::Result<u64> {
        self.ensure(8)?;
        let v = u64::from_be_bytes(self.bytes[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }
    pub fn get_i64(&mut self) -> io::Result<i64> {
        Ok(self.get_u64()? as i64)
    }
    pub fn get_bytes(&mut self, n: usize) -> io::Result<Vec<u8>> {
        self.ensure(n)?;
        let v = self.bytes[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }
    pub fn get_str(&mut self) -> io::Result<String> {
        let n = self.get_u16()? as usize;
        let raw = self.get_bytes(n)?;
        String::from_utf8(raw).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("non-utf8 string: {}", e),
            )
        })
    }
    pub fn get_opt_bytes_i32(&mut self) -> io::Result<Option<Vec<u8>>> {
        let len = self.get_i32()?;
        if len < 0 {
            Ok(None)
        } else {
            Ok(Some(self.get_bytes(len as usize)?))
        }
    }
    pub fn get_value(&mut self) -> io::Result<Vec<u8>> {
        let n = self.get_u32()? as usize;
        self.get_bytes(n)
    }
    pub fn get_opt_string_i32(&mut self) -> io::Result<Option<String>> {
        let len = self.get_i32()?;
        if len < 0 {
            return Ok(None);
        }
        let raw = self.get_bytes(len as usize)?;
        Ok(Some(String::from_utf8(raw).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("non-utf8: {}", e))
        })?))
    }
    pub fn get_opt_u32_neg(&mut self) -> io::Result<Option<u32>> {
        let v = self.get_i32()?;
        if v < 0 {
            Ok(None)
        } else {
            Ok(Some(v as u32))
        }
    }
    pub fn get_opt_i64_min(&mut self) -> io::Result<Option<i64>> {
        let v = self.get_i64()?;
        if v == i64::MIN {
            Ok(None)
        } else {
            Ok(Some(v))
        }
    }
}

// -- typed encoders/decoders --

pub fn encode_produce_request(req: &WireProduceRequest) -> Vec<u8> {
    let mut b = WireBuf::new();
    b.put_str(&req.topic);
    b.put_opt_string_i32(req.producer_id.as_deref());
    b.put_u32(req.records.len() as u32);
    for r in &req.records {
        b.put_opt_bytes_i32(r.key.as_deref());
        b.put_value(&r.value);
        b.put_opt_u32_neg(r.partition);
        b.put_opt_i64_min(r.sequence);
    }
    b.bytes
}

pub fn decode_produce_request(bytes: &[u8]) -> io::Result<WireProduceRequest> {
    let mut r = WireReader::new(bytes);
    let topic = r.get_str()?;
    let producer_id = r.get_opt_string_i32()?;
    let n = r.get_u32()? as usize;
    let mut records = Vec::with_capacity(n);
    for _ in 0..n {
        let key = r.get_opt_bytes_i32()?;
        let value = r.get_value()?;
        let partition = r.get_opt_u32_neg()?;
        let sequence = r.get_opt_i64_min()?;
        records.push(WireProduceRecord {
            key,
            value,
            partition,
            sequence,
        });
    }
    Ok(WireProduceRequest {
        topic,
        producer_id,
        records,
    })
}

pub fn encode_produce_response(results: &[WireProduceResult]) -> Vec<u8> {
    let mut b = WireBuf::new();
    b.put_u32(results.len() as u32);
    for r in results {
        b.put_u32(r.partition);
        b.put_u64(r.offset);
        b.put_u8(if r.duplicate { 1 } else { 0 });
    }
    b.bytes
}

pub fn decode_produce_response(bytes: &[u8]) -> io::Result<Vec<WireProduceResult>> {
    let mut r = WireReader::new(bytes);
    let n = r.get_u32()? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(WireProduceResult {
            partition: r.get_u32()?,
            offset: r.get_u64()?,
            duplicate: r.get_u8()? != 0,
        });
    }
    Ok(out)
}

pub fn encode_consume_request(req: &WireConsumeRequest) -> Vec<u8> {
    let mut b = WireBuf::new();
    b.put_str(&req.topic);
    b.put_u32(req.partition);
    b.put_u64(req.offset);
    b.put_u32(req.max_records);
    b.put_u32(req.max_bytes);
    b.bytes
}

pub fn decode_consume_request(bytes: &[u8]) -> io::Result<WireConsumeRequest> {
    let mut r = WireReader::new(bytes);
    Ok(WireConsumeRequest {
        topic: r.get_str()?,
        partition: r.get_u32()?,
        offset: r.get_u64()?,
        max_records: r.get_u32()?,
        max_bytes: r.get_u32()?,
    })
}

pub fn encode_consume_response(resp: &WireConsumeResponse) -> Vec<u8> {
    let mut b = WireBuf::new();
    b.put_u64(resp.next_offset);
    b.put_u64(resp.high_watermark);
    b.put_u32(resp.records.len() as u32);
    for r in &resp.records {
        b.put_u32(r.partition);
        b.put_u64(r.offset);
        b.put_i64(r.timestamp_ms);
        b.put_opt_bytes_i32(r.key.as_deref());
        b.put_value(&r.value);
    }
    b.bytes
}

pub fn decode_consume_response(bytes: &[u8]) -> io::Result<WireConsumeResponse> {
    let mut r = WireReader::new(bytes);
    let next_offset = r.get_u64()?;
    let high_watermark = r.get_u64()?;
    let n = r.get_u32()? as usize;
    let mut records = Vec::with_capacity(n);
    for _ in 0..n {
        records.push(WireRecord {
            partition: r.get_u32()?,
            offset: r.get_u64()?,
            timestamp_ms: r.get_i64()?,
            key: r.get_opt_bytes_i32()?,
            value: r.get_value()?,
        });
    }
    Ok(WireConsumeResponse {
        records,
        next_offset,
        high_watermark,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produce_request_roundtrip() {
        let req = WireProduceRequest {
            topic: "orders".to_string(),
            producer_id: Some("pid-1".to_string()),
            records: vec![
                WireProduceRecord {
                    key: Some(b"k1".to_vec()),
                    value: b"\x00\x01\x02non-utf8\xff".to_vec(),
                    partition: Some(2),
                    sequence: Some(42),
                },
                WireProduceRecord {
                    key: None,
                    value: b"v2".to_vec(),
                    partition: None,
                    sequence: None,
                },
            ],
        };
        let bytes = encode_produce_request(&req);
        let back = decode_produce_request(&bytes).unwrap();
        assert_eq!(back.topic, req.topic);
        assert_eq!(back.producer_id, req.producer_id);
        assert_eq!(back.records.len(), 2);
        assert_eq!(back.records[0].key, req.records[0].key);
        assert_eq!(back.records[0].value, req.records[0].value);
        assert_eq!(back.records[0].partition, Some(2));
        assert_eq!(back.records[0].sequence, Some(42));
        assert_eq!(back.records[1].key, None);
        assert_eq!(back.records[1].partition, None);
        assert_eq!(back.records[1].sequence, None);
    }

    #[test]
    fn consume_response_roundtrip() {
        let resp = WireConsumeResponse {
            records: vec![WireRecord {
                partition: 1,
                offset: 100,
                timestamp_ms: 1700000000000,
                key: Some(vec![0, 0xFF, 0xC3]),
                value: vec![0x00, 0x01],
            }],
            next_offset: 101,
            high_watermark: 200,
        };
        let bytes = encode_consume_response(&resp);
        let back = decode_consume_response(&bytes).unwrap();
        assert_eq!(back.records.len(), 1);
        assert_eq!(back.records[0].key, resp.records[0].key);
        assert_eq!(back.records[0].value, resp.records[0].value);
        assert_eq!(back.next_offset, 101);
        assert_eq!(back.high_watermark, 200);
    }
}
