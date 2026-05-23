use std::io::{self, Read, Seek, SeekFrom};

use thiserror::Error;

/// One event record as it lives on disk.
///
/// Wire format (big-endian):
///   record_len   u32   bytes of everything below (excluding itself and the CRC trailer)
///   offset       u64
///   timestamp_ms i64
///   key_len      i32   -1 means null
///   key          bytes (key_len bytes; absent if key_len == -1)
///   value_len    u32
///   value        bytes (value_len bytes)
///   crc32        u32   CRC32 of bytes from `offset` through end of `value`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub offset: u64,
    pub timestamp_ms: i64,
    pub key: Option<Vec<u8>>,
    pub value: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum RecordDecodeError {
    #[error("eof")]
    Eof,
    #[error("truncated record at byte {at}")]
    Truncated { at: u64 },
    #[error("crc mismatch at byte {at}: stored={stored:#010x} computed={computed:#010x}")]
    CrcMismatch { at: u64, stored: u32, computed: u32 },
    #[error("invalid record header at byte {at}: {reason}")]
    Invalid { at: u64, reason: &'static str },
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

const HEADER_LEN: usize = 8 + 8 + 4; // offset + ts + key_len
const VALUE_LEN_FIELD: usize = 4;
const CRC_LEN: usize = 4;
const RECORD_LEN_FIELD: usize = 4;

/// Encode a record into `buf`. Returns the total number of bytes written, including
/// the leading `record_len` and trailing CRC.
pub fn encode_record(
    buf: &mut Vec<u8>,
    offset: u64,
    timestamp_ms: i64,
    key: Option<&[u8]>,
    value: &[u8],
) -> usize {
    let key_len_field: i32 = match key {
        Some(k) => k.len() as i32,
        None => -1,
    };
    let key_bytes_len = key.map(|k| k.len()).unwrap_or(0);
    let body_len = HEADER_LEN + key_bytes_len + VALUE_LEN_FIELD + value.len() + CRC_LEN;

    let start = buf.len();
    buf.reserve(RECORD_LEN_FIELD + body_len);
    buf.extend_from_slice(&(body_len as u32).to_be_bytes());

    let crc_start = buf.len();
    buf.extend_from_slice(&offset.to_be_bytes());
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    buf.extend_from_slice(&key_len_field.to_be_bytes());
    if let Some(k) = key {
        buf.extend_from_slice(k);
    }
    buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buf.extend_from_slice(value);

    let crc = crc32fast::hash(&buf[crc_start..buf.len()]);
    buf.extend_from_slice(&crc.to_be_bytes());

    buf.len() - start
}

/// Read one record from `reader`, starting at the current file position.
///
/// On a clean EOF (no record_len bytes available at all), returns [`RecordDecodeError::Eof`].
/// On a torn / corrupted record, returns [`RecordDecodeError::Truncated`] or
/// [`RecordDecodeError::CrcMismatch`] with `at` set to the file position where the
/// bad record started — callers should truncate the file at `at` to recover.
pub fn read_record<R: Read + Seek>(reader: &mut R) -> Result<Record, RecordDecodeError> {
    let at = reader.stream_position()?;

    let mut len_buf = [0u8; RECORD_LEN_FIELD];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(RecordDecodeError::Eof);
        }
        Err(e) => return Err(e.into()),
    }
    let body_len = u32::from_be_bytes(len_buf) as usize;

    if body_len < HEADER_LEN + VALUE_LEN_FIELD + CRC_LEN {
        return Err(RecordDecodeError::Invalid {
            at,
            reason: "body_len below minimum",
        });
    }

    let mut body = vec![0u8; body_len];
    if let Err(e) = reader.read_exact(&mut body) {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            // Don't leave the cursor mid-record; the caller will truncate at `at`.
            reader.seek(SeekFrom::Start(at))?;
            return Err(RecordDecodeError::Truncated { at });
        }
        return Err(e.into());
    }

    let mut p = 0usize;
    let offset = u64::from_be_bytes(body[p..p + 8].try_into().unwrap());
    p += 8;
    let timestamp_ms = i64::from_be_bytes(body[p..p + 8].try_into().unwrap());
    p += 8;
    let key_len = i32::from_be_bytes(body[p..p + 4].try_into().unwrap());
    p += 4;

    let key = if key_len < 0 {
        if key_len != -1 {
            return Err(RecordDecodeError::Invalid {
                at,
                reason: "key_len negative != -1",
            });
        }
        None
    } else {
        let kl = key_len as usize;
        if p + kl > body.len() {
            return Err(RecordDecodeError::Truncated { at });
        }
        let k = body[p..p + kl].to_vec();
        p += kl;
        Some(k)
    };

    if p + VALUE_LEN_FIELD > body.len() {
        return Err(RecordDecodeError::Truncated { at });
    }
    let value_len = u32::from_be_bytes(body[p..p + 4].try_into().unwrap()) as usize;
    p += 4;
    if p + value_len + CRC_LEN != body.len() {
        return Err(RecordDecodeError::Invalid {
            at,
            reason: "value_len does not match remaining body",
        });
    }
    let value = body[p..p + value_len].to_vec();
    p += value_len;

    let stored_crc = u32::from_be_bytes(body[p..p + 4].try_into().unwrap());
    let computed_crc = crc32fast::hash(&body[..p]);
    if stored_crc != computed_crc {
        return Err(RecordDecodeError::CrcMismatch {
            at,
            stored: stored_crc,
            computed: computed_crc,
        });
    }

    Ok(Record {
        offset,
        timestamp_ms,
        key,
        value,
    })
}

/// Total on-disk size of a record with the given key/value lengths (including
/// record_len prefix and CRC trailer).
pub fn record_disk_size(key_len: Option<usize>, value_len: usize) -> usize {
    let body =
        HEADER_LEN + key_len.unwrap_or(0) + VALUE_LEN_FIELD + value_len + CRC_LEN;
    RECORD_LEN_FIELD + body
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_with_key() {
        let mut buf = Vec::new();
        let n = encode_record(&mut buf, 42, 1_700_000_000_000, Some(b"hello"), b"world");
        assert_eq!(n, buf.len());

        let mut cur = Cursor::new(buf);
        let r = read_record(&mut cur).unwrap();
        assert_eq!(r.offset, 42);
        assert_eq!(r.timestamp_ms, 1_700_000_000_000);
        assert_eq!(r.key.as_deref(), Some(&b"hello"[..]));
        assert_eq!(r.value, b"world");
    }

    #[test]
    fn roundtrip_without_key() {
        let mut buf = Vec::new();
        encode_record(&mut buf, 7, 0, None, b"v");
        let mut cur = Cursor::new(buf);
        let r = read_record(&mut cur).unwrap();
        assert_eq!(r.key, None);
        assert_eq!(r.value, b"v");
    }

    #[test]
    fn detects_corruption() {
        let mut buf = Vec::new();
        encode_record(&mut buf, 1, 0, None, b"abc");
        let last = buf.len() - 5;
        buf[last] ^= 0xFF;
        let mut cur = Cursor::new(buf);
        let err = read_record(&mut cur).unwrap_err();
        assert!(matches!(err, RecordDecodeError::CrcMismatch { .. }));
    }

    #[test]
    fn detects_truncation() {
        let mut buf = Vec::new();
        encode_record(&mut buf, 1, 0, None, b"abc");
        buf.truncate(buf.len() - 3);
        let mut cur = Cursor::new(buf);
        let err = read_record(&mut cur).unwrap_err();
        assert!(matches!(err, RecordDecodeError::Truncated { .. }));
    }

    #[test]
    fn clean_eof_at_boundary() {
        let buf: Vec<u8> = Vec::new();
        let mut cur = Cursor::new(buf);
        let err = read_record(&mut cur).unwrap_err();
        assert!(matches!(err, RecordDecodeError::Eof));
    }
}
