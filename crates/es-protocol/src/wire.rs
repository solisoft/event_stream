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

/// Feature bit: the server understands consume flags
/// ([`CONSUME_FLAG_LINEARIZABLE`]). A client must see it in the server's
/// handshake reply before sending a flagged consume: a server without it
/// ignores the trailing flags byte and would serve a plain read.
pub const FEATURE_CONSUME_FLAGS: u32 = 1 << 1;

/// Consume flag: a linearizable read (see the docs' cluster page). Carried
/// in an optional `flags: u8` after `max_bytes`; a request without it is a
/// plain read, byte for byte the format of earlier versions.
pub const CONSUME_FLAG_LINEARIZABLE: u8 = 1 << 0;
/// Every consume flag this version knows. A server refuses a request with
/// any other bit set, rather than serve it without what the bit asked for.
pub const CONSUME_FLAGS_KNOWN: u8 = CONSUME_FLAG_LINEARIZABLE;

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
    /// A `u16`-length string. Fails, rather than truncating the length,
    /// when the string does not fit: a wrapped length would let the bytes
    /// past it be read as the following fields.
    pub fn put_str(&mut self, s: &str) -> io::Result<()> {
        let b = s.as_bytes();
        let n = u16::try_from(b.len()).map_err(|_| too_long("string", b.len()))?;
        self.put_u16(n);
        self.put_bytes(b);
        Ok(())
    }
    pub fn put_opt_bytes_i32(&mut self, v: Option<&[u8]>) -> io::Result<()> {
        match v {
            None => self.put_i32(-1),
            Some(b) => {
                let n = i32::try_from(b.len()).map_err(|_| too_long("bytes", b.len()))?;
                self.put_i32(n);
                self.put_bytes(b);
            }
        }
        Ok(())
    }
    pub fn put_value(&mut self, v: &[u8]) -> io::Result<()> {
        self.put_count(v.len())?;
        self.put_bytes(v);
        Ok(())
    }
    pub fn put_opt_string_i32(&mut self, v: Option<&str>) -> io::Result<()> {
        self.put_opt_bytes_i32(v.map(str::as_bytes))
    }
    /// A `u32` length or element count.
    pub fn put_count(&mut self, n: usize) -> io::Result<()> {
        let n32 = u32::try_from(n).map_err(|_| too_long("count", n))?;
        self.put_u32(n32);
        Ok(())
    }
    /// `None` is `-1`, so a partition above `i32::MAX` would read back as
    /// "no partition" — refused instead.
    pub fn put_opt_u32_neg(&mut self, v: Option<u32>) -> io::Result<()> {
        match v {
            None => self.put_i32(-1),
            Some(n) => {
                let n = i32::try_from(n).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{} does not fit in the wire's i32", n),
                    )
                })?;
                self.put_i32(n);
            }
        }
        Ok(())
    }
    pub fn put_opt_i64_min(&mut self, v: Option<i64>) {
        match v {
            None => self.put_i64(i64::MIN),
            Some(n) => self.put_i64(n),
        }
    }
}

fn too_long(what: &str, len: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "{} of {} bytes is too long for its wire length field",
            what, len
        ),
    )
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
    /// Bounded capacity hint for a length-prefixed collection. Never trust a
    /// wire count to size an allocation directly — cap it to the number of
    /// items that could possibly still fit in the unread bytes. `min_item_bytes`
    /// is the smallest encoded size of one item.
    pub fn cap_hint(&self, count: usize, min_item_bytes: usize) -> usize {
        count.min(self.remaining() / min_item_bytes.max(1))
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

pub fn encode_produce_request(req: &WireProduceRequest) -> io::Result<Vec<u8>> {
    let mut b = WireBuf::new();
    b.put_str(&req.topic)?;
    b.put_opt_string_i32(req.producer_id.as_deref())?;
    b.put_count(req.records.len())?;
    for r in &req.records {
        b.put_opt_bytes_i32(r.key.as_deref())?;
        b.put_value(&r.value)?;
        b.put_opt_u32_neg(r.partition)?;
        b.put_opt_i64_min(r.sequence);
    }
    Ok(b.bytes)
}

/// Decode a produce request, refusing one that claims more than
/// `max_records` records before decoding any of them.
pub fn decode_produce_request(bytes: &[u8], max_records: usize) -> io::Result<WireProduceRequest> {
    let mut r = WireReader::new(bytes);
    let topic = r.get_str()?;
    let producer_id = r.get_opt_string_i32()?;
    let n = r.get_u32()? as usize;
    // A small frame of empty records still decodes to hundreds of thousands
    // of allocations; the limit applies before the loop, not after it.
    if n > max_records {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} records in one request; the limit is {}", n, max_records),
        ));
    }
    // Min per-record wire size: key(i32=4) + value_len(u32=4) + partition(i32=4)
    // + sequence(i64=8) = 20 bytes. Cap the pre-allocation to the frame size.
    let mut records = Vec::with_capacity(r.cap_hint(n, 20));
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

pub fn encode_produce_response(results: &[WireProduceResult]) -> io::Result<Vec<u8>> {
    let mut b = WireBuf::new();
    b.put_count(results.len())?;
    for r in results {
        b.put_u32(r.partition);
        b.put_u64(r.offset);
        b.put_u8(if r.duplicate { 1 } else { 0 });
    }
    Ok(b.bytes)
}

pub fn decode_produce_response(bytes: &[u8]) -> io::Result<Vec<WireProduceResult>> {
    let mut r = WireReader::new(bytes);
    let n = r.get_u32()? as usize;
    // Min per-result wire size: partition(u32=4) + offset(u64=8) + duplicate(u8=1).
    let mut out = Vec::with_capacity(r.cap_hint(n, 13));
    for _ in 0..n {
        out.push(WireProduceResult {
            partition: r.get_u32()?,
            offset: r.get_u64()?,
            duplicate: r.get_u8()? != 0,
        });
    }
    Ok(out)
}

pub fn encode_consume_request(req: &WireConsumeRequest) -> io::Result<Vec<u8>> {
    encode_consume_request_with_flags(req, 0)
}

/// A consume request with `flags` (`CONSUME_FLAG_*`). With no flag set the
/// trailing byte is left out, so a plain request is what every earlier
/// version sent and understands.
pub fn encode_consume_request_with_flags(
    req: &WireConsumeRequest,
    flags: u8,
) -> io::Result<Vec<u8>> {
    let mut b = WireBuf::new();
    b.put_str(&req.topic)?;
    b.put_u32(req.partition);
    b.put_u64(req.offset);
    b.put_u32(req.max_records);
    b.put_u32(req.max_bytes);
    if flags != 0 {
        b.put_u8(flags);
    }
    Ok(b.bytes)
}

/// Decode a consume request, ignoring any flags. See
/// [`decode_consume_request_with_flags`].
pub fn decode_consume_request(bytes: &[u8]) -> io::Result<WireConsumeRequest> {
    decode_consume_request_with_flags(bytes).map(|(req, _)| req)
}

/// Decode a consume request and its flags byte, zero when absent (a client
/// that predates flags).
pub fn decode_consume_request_with_flags(bytes: &[u8]) -> io::Result<(WireConsumeRequest, u8)> {
    let mut r = WireReader::new(bytes);
    let req = WireConsumeRequest {
        topic: r.get_str()?,
        partition: r.get_u32()?,
        offset: r.get_u64()?,
        max_records: r.get_u32()?,
        max_bytes: r.get_u32()?,
    };
    let flags = if r.remaining() > 0 { r.get_u8()? } else { 0 };
    Ok((req, flags))
}

pub fn encode_consume_response(resp: &WireConsumeResponse) -> io::Result<Vec<u8>> {
    let mut b = WireBuf::new();
    b.put_u64(resp.next_offset);
    b.put_u64(resp.high_watermark);
    b.put_count(resp.records.len())?;
    for r in &resp.records {
        b.put_u32(r.partition);
        b.put_u64(r.offset);
        b.put_i64(r.timestamp_ms);
        b.put_opt_bytes_i32(r.key.as_deref())?;
        b.put_value(&r.value)?;
    }
    Ok(b.bytes)
}

pub fn decode_consume_response(bytes: &[u8]) -> io::Result<WireConsumeResponse> {
    let mut r = WireReader::new(bytes);
    let next_offset = r.get_u64()?;
    let high_watermark = r.get_u64()?;
    let n = r.get_u32()? as usize;
    // Min per-record wire size: partition(4) + offset(8) + timestamp(8) +
    // key(i32=4) + value_len(u32=4) = 28 bytes.
    let mut records = Vec::with_capacity(r.cap_hint(n, 28));
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
        let bytes = encode_produce_request(&req).unwrap();
        let back = decode_produce_request(&bytes, 100).unwrap();
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

    /// The consume request as every client before consume flags encoded it,
    /// written out by hand so a change to the encoder cannot hide a change
    /// to the format.
    fn old_format_consume(topic: &str, partition: u32, offset: u64) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        v.extend_from_slice(topic.as_bytes());
        v.extend_from_slice(&partition.to_be_bytes());
        v.extend_from_slice(&offset.to_be_bytes());
        v.extend_from_slice(&100u32.to_be_bytes());
        v.extend_from_slice(&65536u32.to_be_bytes());
        v
    }

    #[test]
    fn an_old_format_consume_request_still_decodes() {
        let old = old_format_consume("orders", 3, 42);
        let (req, flags) = decode_consume_request_with_flags(&old).unwrap();
        assert_eq!(flags, 0, "no flags byte: a plain read");
        assert_eq!(req.topic, "orders");
        assert_eq!((req.partition, req.offset), (3, 42));
        assert_eq!((req.max_records, req.max_bytes), (100, 65536));
        // And a plain request encodes to exactly that format.
        let req = WireConsumeRequest {
            topic: "orders".into(),
            partition: 3,
            offset: 42,
            max_records: 100,
            max_bytes: 65536,
        };
        assert_eq!(encode_consume_request(&req).unwrap(), old);
    }

    #[test]
    fn consume_flags_roundtrip_as_a_trailing_byte() {
        let req = WireConsumeRequest {
            topic: "t".into(),
            partition: 1,
            offset: 2,
            max_records: 3,
            max_bytes: 4,
        };
        let bytes = encode_consume_request_with_flags(&req, CONSUME_FLAG_LINEARIZABLE).unwrap();
        assert_eq!(bytes.len(), encode_consume_request(&req).unwrap().len() + 1);
        let (back, flags) = decode_consume_request_with_flags(&bytes).unwrap();
        assert_eq!(flags, CONSUME_FLAG_LINEARIZABLE);
        assert_eq!((back.partition, back.offset), (1, 2));
        // The flag-blind decoder still reads the request itself.
        assert_eq!(decode_consume_request(&bytes).unwrap().max_bytes, 4);
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
        let bytes = encode_consume_response(&resp).unwrap();
        let back = decode_consume_response(&bytes).unwrap();
        assert_eq!(back.records.len(), 1);
        assert_eq!(back.records[0].key, resp.records[0].key);
        assert_eq!(back.records[0].value, resp.records[0].value);
        assert_eq!(back.next_offset, 101);
        assert_eq!(back.high_watermark, 200);
    }

    #[test]
    fn decode_produce_request_rejects_bogus_record_count_without_oom() {
        // Craft a tiny frame that lies about its record count (u32::MAX) but
        // carries no record bytes. The decoder must not pre-allocate ~4 billion
        // records — cap_hint bounds capacity to the (near-zero) remaining bytes,
        // and the first record read fails cleanly.
        let mut b = WireBuf::new();
        b.put_str("").unwrap(); // topic
        b.put_opt_string_i32(None).unwrap(); // producer_id
        b.put_u32(u32::MAX); // record_count — hostile
        let err = decode_produce_request(&b.bytes, usize::MAX).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn cap_hint_bounds_capacity_to_remaining_bytes() {
        let buf = [0u8; 40];
        let r = WireReader::new(&buf);
        // A hostile count is clamped to what could actually fit.
        assert_eq!(r.cap_hint(usize::MAX, 20), 2);
        assert_eq!(r.cap_hint(1, 20), 1);
    }

    #[test]
    fn decode_produce_request_refuses_a_count_above_the_limit_before_decoding() {
        // 838k empty records fit in a 16 MiB frame; the count is checked
        // first, so none of them is built.
        let mut b = WireBuf::new();
        b.put_str("t").unwrap();
        b.put_opt_string_i32(None).unwrap();
        b.put_u32(101);
        for _ in 0..101 {
            b.put_opt_bytes_i32(None).unwrap();
            b.put_value(b"").unwrap();
            b.put_opt_u32_neg(None).unwrap();
            b.put_opt_i64_min(None);
        }
        let err = decode_produce_request(&b.bytes, 100).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("limit is 100"));
        assert_eq!(
            decode_produce_request(&b.bytes, 101).unwrap().records.len(),
            101
        );
    }

    #[test]
    fn an_over_long_topic_is_refused_not_truncated() {
        // A 65 537-byte topic used to be written with length 1, and the
        // remaining bytes were then read as the request's other fields.
        let mut topic = "a".repeat(u16::MAX as usize + 1);
        topic.push('b');
        let req = WireConsumeRequest {
            topic: topic.clone(),
            partition: 0,
            offset: 0,
            max_records: 1,
            max_bytes: 1,
        };
        let err = encode_consume_request(&req).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let preq = WireProduceRequest {
            topic,
            producer_id: None,
            records: Vec::new(),
        };
        assert!(encode_produce_request(&preq).is_err());

        // The longest topic that fits still round-trips.
        let ok = WireConsumeRequest {
            topic: "a".repeat(u16::MAX as usize),
            ..req
        };
        let back = decode_consume_request(&encode_consume_request(&ok).unwrap()).unwrap();
        assert_eq!(back.topic.len(), u16::MAX as usize);
    }

    #[test]
    fn a_partition_above_i32_max_is_refused_not_read_back_as_none() {
        let req = WireProduceRequest {
            topic: "t".into(),
            producer_id: None,
            records: vec![WireProduceRecord {
                key: None,
                value: Vec::new(),
                partition: Some(u32::MAX),
                sequence: None,
            }],
        };
        assert!(encode_produce_request(&req).is_err());
    }
}
