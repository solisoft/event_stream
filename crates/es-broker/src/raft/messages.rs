//! Raft RPC message types. Implements the **leader-election** subset for
//! session 1 — log replication carries `entries` and `leader_commit` but the
//! current node only ever sends empty heartbeats.
//!
//! Wire format (big-endian, length-prefixed at the framing layer):
//!
//! ```text
//!   tag: u8           message kind
//!   body: ...         kind-specific
//! ```
//!
//! Tags are kept simple integers rather than an enum-with-discriminant so the
//! wire is stable independent of Rust enum layout.

use std::io;

pub const TAG_REQUEST_VOTE: u8 = 0x01;
pub const TAG_REQUEST_VOTE_RESP: u8 = 0x02;
pub const TAG_APPEND_ENTRIES: u8 = 0x03;
pub const TAG_APPEND_ENTRIES_RESP: u8 = 0x04;
pub const TAG_INSTALL_SNAPSHOT: u8 = 0x05;
pub const TAG_INSTALL_SNAPSHOT_RESP: u8 = 0x06;

/// Node identifier. Hand-assigned via CLI in step 1; later a discovery service.
pub type NodeId = u32;

/// Raft term. Monotonically increasing.
pub type Term = u64;

/// Index into the replicated log. Step 1 only carries log_index = 0 in
/// AppendEntries heartbeats, but the field is here so step 2 doesn't need a
/// wire change.
pub type LogIndex = u64;

#[derive(Debug, Clone)]
pub struct RequestVote {
    pub term: Term,
    pub candidate_id: NodeId,
    pub last_log_index: LogIndex,
    pub last_log_term: Term,
}

#[derive(Debug, Clone)]
pub struct RequestVoteResp {
    pub term: Term,
    pub vote_granted: bool,
    pub voter_id: NodeId,
}

#[derive(Debug, Clone)]
pub struct AppendEntries {
    pub term: Term,
    pub leader_id: NodeId,
    pub prev_log_index: LogIndex,
    pub prev_log_term: Term,
    /// In step 1 this is always empty. Carries log entries in step 2.
    pub entries: Vec<LogEntry>,
    pub leader_commit: LogIndex,
}

#[derive(Debug, Clone)]
pub struct AppendEntriesResp {
    pub term: Term,
    pub success: bool,
    pub responder_id: NodeId,
    /// For step 2: the highest log_index the follower has after this RPC.
    pub match_index: LogIndex,
}

#[derive(Debug, Clone)]
pub struct InstallSnapshot {
    pub term: Term,
    pub leader_id: NodeId,
    pub last_index: LogIndex,
    pub last_term: Term,
    pub offset: u64,
    pub done: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct InstallSnapshotResp {
    pub term: Term,
    pub success: bool,
    pub responder_id: NodeId,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub term: Term,
    pub index: LogIndex,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum Message {
    RequestVote(RequestVote),
    RequestVoteResp(RequestVoteResp),
    AppendEntries(AppendEntries),
    AppendEntriesResp(AppendEntriesResp),
    InstallSnapshot(InstallSnapshot),
    InstallSnapshotResp(InstallSnapshotResp),
}

impl Message {
    pub fn term(&self) -> Term {
        match self {
            Self::RequestVote(m) => m.term,
            Self::RequestVoteResp(m) => m.term,
            Self::AppendEntries(m) => m.term,
            Self::AppendEntriesResp(m) => m.term,
            Self::InstallSnapshot(m) => m.term,
            Self::InstallSnapshotResp(m) => m.term,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        match self {
            Self::RequestVote(m) => {
                buf.push(TAG_REQUEST_VOTE);
                buf.extend_from_slice(&m.term.to_be_bytes());
                buf.extend_from_slice(&m.candidate_id.to_be_bytes());
                buf.extend_from_slice(&m.last_log_index.to_be_bytes());
                buf.extend_from_slice(&m.last_log_term.to_be_bytes());
            }
            Self::RequestVoteResp(m) => {
                buf.push(TAG_REQUEST_VOTE_RESP);
                buf.extend_from_slice(&m.term.to_be_bytes());
                buf.push(if m.vote_granted { 1 } else { 0 });
                buf.extend_from_slice(&m.voter_id.to_be_bytes());
            }
            Self::AppendEntries(m) => {
                buf.push(TAG_APPEND_ENTRIES);
                buf.extend_from_slice(&m.term.to_be_bytes());
                buf.extend_from_slice(&m.leader_id.to_be_bytes());
                buf.extend_from_slice(&m.prev_log_index.to_be_bytes());
                buf.extend_from_slice(&m.prev_log_term.to_be_bytes());
                buf.extend_from_slice(&(m.entries.len() as u32).to_be_bytes());
                for e in &m.entries {
                    buf.extend_from_slice(&e.term.to_be_bytes());
                    buf.extend_from_slice(&e.index.to_be_bytes());
                    buf.extend_from_slice(&(e.payload.len() as u32).to_be_bytes());
                    buf.extend_from_slice(&e.payload);
                }
                buf.extend_from_slice(&m.leader_commit.to_be_bytes());
            }
            Self::AppendEntriesResp(m) => {
                buf.push(TAG_APPEND_ENTRIES_RESP);
                buf.extend_from_slice(&m.term.to_be_bytes());
                buf.push(if m.success { 1 } else { 0 });
                buf.extend_from_slice(&m.responder_id.to_be_bytes());
                buf.extend_from_slice(&m.match_index.to_be_bytes());
            }
            Self::InstallSnapshot(m) => {
                buf.push(TAG_INSTALL_SNAPSHOT);
                buf.extend_from_slice(&m.term.to_be_bytes());
                buf.extend_from_slice(&m.leader_id.to_be_bytes());
                buf.extend_from_slice(&m.last_index.to_be_bytes());
                buf.extend_from_slice(&m.last_term.to_be_bytes());
                buf.extend_from_slice(&m.offset.to_be_bytes());
                buf.push(if m.done { 1 } else { 0 });
                buf.extend_from_slice(&(m.data.len() as u32).to_be_bytes());
                buf.extend_from_slice(&m.data);
            }
            Self::InstallSnapshotResp(m) => {
                buf.push(TAG_INSTALL_SNAPSHOT_RESP);
                buf.extend_from_slice(&m.term.to_be_bytes());
                buf.push(if m.success { 1 } else { 0 });
                buf.extend_from_slice(&m.responder_id.to_be_bytes());
            }
        }
        buf
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty"));
        }
        let mut r = Reader::new(bytes);
        let tag = r.u8()?;
        match tag {
            TAG_REQUEST_VOTE => Ok(Self::RequestVote(RequestVote {
                term: r.u64()?,
                candidate_id: r.u32()?,
                last_log_index: r.u64()?,
                last_log_term: r.u64()?,
            })),
            TAG_REQUEST_VOTE_RESP => Ok(Self::RequestVoteResp(RequestVoteResp {
                term: r.u64()?,
                vote_granted: r.u8()? != 0,
                voter_id: r.u32()?,
            })),
            TAG_APPEND_ENTRIES => {
                let term = r.u64()?;
                let leader_id = r.u32()?;
                let prev_log_index = r.u64()?;
                let prev_log_term = r.u64()?;
                let n = r.u32()? as usize;
                // Min per-entry wire size: term(u64=8) + index(u64=8) +
                // payload_len(u32=4) = 20 bytes. Cap the pre-allocation.
                let mut entries = Vec::with_capacity(r.cap_hint(n, 20));
                for _ in 0..n {
                    let term = r.u64()?;
                    let index = r.u64()?;
                    let len = r.u32()? as usize;
                    let payload = r.bytes(len)?;
                    entries.push(LogEntry {
                        term,
                        index,
                        payload,
                    });
                }
                let leader_commit = r.u64()?;
                Ok(Self::AppendEntries(AppendEntries {
                    term,
                    leader_id,
                    prev_log_index,
                    prev_log_term,
                    entries,
                    leader_commit,
                }))
            }
            TAG_APPEND_ENTRIES_RESP => Ok(Self::AppendEntriesResp(AppendEntriesResp {
                term: r.u64()?,
                success: r.u8()? != 0,
                responder_id: r.u32()?,
                match_index: r.u64()?,
            })),
            TAG_INSTALL_SNAPSHOT => {
                let term = r.u64()?;
                let leader_id = r.u32()?;
                let last_index = r.u64()?;
                let last_term = r.u64()?;
                let offset = r.u64()?;
                let done = r.u8()? != 0;
                let data_len = r.u32()? as usize;
                let data = r.bytes(data_len)?;
                Ok(Self::InstallSnapshot(InstallSnapshot {
                    term,
                    leader_id,
                    last_index,
                    last_term,
                    offset,
                    done,
                    data,
                }))
            }
            TAG_INSTALL_SNAPSHOT_RESP => Ok(Self::InstallSnapshotResp(InstallSnapshotResp {
                term: r.u64()?,
                success: r.u8()? != 0,
                responder_id: r.u32()?,
            })),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown raft tag {:#x}", other),
            )),
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
    /// Bounded capacity hint — never pre-allocate from an untrusted wire count.
    fn cap_hint(&self, count: usize, min_item_bytes: usize) -> usize {
        count.min(self.remaining() / min_item_bytes.max(1))
    }
    fn ensure(&self, n: usize) -> io::Result<()> {
        if self.bytes.len() - self.pos < n {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short"))
        } else {
            Ok(())
        }
    }
    fn u8(&mut self) -> io::Result<u8> {
        self.ensure(1)?;
        let v = self.bytes[self.pos];
        self.pos += 1;
        Ok(v)
    }
    fn u32(&mut self) -> io::Result<u32> {
        self.ensure(4)?;
        let v = u32::from_be_bytes(self.bytes[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }
    fn u64(&mut self) -> io::Result<u64> {
        self.ensure(8)?;
        let v = u64::from_be_bytes(self.bytes[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }
    fn bytes(&mut self, n: usize) -> io::Result<Vec<u8>> {
        self.ensure(n)?;
        let v = self.bytes[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_vote_roundtrip() {
        let m = Message::RequestVote(RequestVote {
            term: 7,
            candidate_id: 42,
            last_log_index: 100,
            last_log_term: 6,
        });
        let bytes = m.encode();
        let back = Message::decode(&bytes).unwrap();
        match back {
            Message::RequestVote(v) => {
                assert_eq!(v.term, 7);
                assert_eq!(v.candidate_id, 42);
                assert_eq!(v.last_log_index, 100);
                assert_eq!(v.last_log_term, 6);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn append_entries_with_entries_roundtrip() {
        let m = Message::AppendEntries(AppendEntries {
            term: 3,
            leader_id: 1,
            prev_log_index: 5,
            prev_log_term: 2,
            entries: vec![
                LogEntry {
                    term: 3,
                    index: 6,
                    payload: vec![0xAB, 0xCD],
                },
                LogEntry {
                    term: 3,
                    index: 7,
                    payload: vec![],
                },
            ],
            leader_commit: 5,
        });
        let bytes = m.encode();
        let back = Message::decode(&bytes).unwrap();
        match back {
            Message::AppendEntries(v) => {
                assert_eq!(v.term, 3);
                assert_eq!(v.entries.len(), 2);
                assert_eq!(v.entries[0].payload, vec![0xAB, 0xCD]);
                assert_eq!(v.entries[1].payload.len(), 0);
            }
            _ => panic!("wrong variant"),
        }
    }
}
