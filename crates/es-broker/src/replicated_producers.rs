//! Idempotent-producer state of one Raft partition, replicated with it.
//!
//! On a plain partition the broker that accepts a write is the only one that
//! will ever see the partition, and [`crate::producers::ProducerRegistry`]
//! keeps the windows. A Raft partition is written by whichever broker leads
//! it, so the windows travel with the writes instead: the log entry of an
//! idempotent produce names the producer, its owner and the first sequence,
//! and **every replica** updates its windows when it applies the entry. A new
//! leader then knows every sequence its predecessors committed, and a retry
//! is recognised whichever broker it reaches.
//!
//! The table is a pure function of the entries applied, in order: nothing in
//! it reads the local clock. Idle producers are forgotten against the newest
//! timestamp the log has carried (`clock_ms`), so every replica forgets the
//! same producers after the same entry, and a snapshot taken on one replica
//! restores exactly what the others hold.
//!
//! # Encoding
//!
//! Carried in the partition's snapshot after the state end offset, and in the
//! trailing field of a snapshot transfer:
//!
//! ```text
//!   "PRD1" | applied u64 | clock_ms i64 | swept_ms i64 | flags u8 | count u32
//!   per producer:
//!     id (u16 len) | owner (u16 len) | last_used_ms i64
//!     last_seen i64 | last_offset u64 | recent_len u16 | (seq i64, offset u64)…
//! ```

use std::collections::{BTreeMap, VecDeque};

use anyhow::{anyhow, bail, Result};

use crate::producers::{PartitionWindow, PRODUCER_EXPIRY, WINDOW};
use crate::raft::LogIndex;

const MAGIC: [u8; 4] = *b"PRD1";
/// `flags`: some entry carrying producer data has been applied.
const FLAG_REPLICATED: u8 = 0x01;
/// How far the replicated clock moves between two sweeps for idle producers.
/// Each sweep walks the whole table, so not on every entry.
const SWEEP_EVERY_MS: i64 = 60_000;
/// Longest producer id or owner a table will hold. The broker refuses ids
/// over 200 bytes and key ids are far shorter; this only bounds a forged one.
const MAX_NAME: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Producer {
    owner: String,
    last_used_ms: i64,
    window: PartitionWindow,
}

/// One partition's producers, as of the entry `applied`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicatedProducers {
    /// The last log entry reflected here. An entry at or below it is already
    /// in, whether it was applied or arrived inside a snapshot, and applying
    /// it again changes nothing.
    pub(crate) applied: LogIndex,
    /// The newest timestamp an applied entry carried.
    clock_ms: i64,
    /// `clock_ms` at the last sweep for idle producers.
    swept_ms: i64,
    /// Whether this partition's log has carried producer data. Once it has,
    /// every member understood it (see `RaftPartition::producer_state`), and
    /// later leaders keep writing it without asking again.
    replicated: bool,
    producers: BTreeMap<String, Producer>,
}

impl ReplicatedProducers {
    /// A table that already reflects everything through `applied`, with no
    /// producers: what a snapshot without a producer section restores.
    pub fn at(applied: LogIndex) -> Self {
        Self {
            applied,
            ..Self::default()
        }
    }

    pub fn applied(&self) -> LogIndex {
        self.applied
    }

    pub fn replicated(&self) -> bool {
        self.replicated
    }

    pub fn owner(&self, producer_id: &str) -> Option<&str> {
        self.producers.get(producer_id).map(|p| p.owner.as_str())
    }

    pub fn window(&self, producer_id: &str) -> Option<&PartitionWindow> {
        self.producers.get(producer_id).map(|p| &p.window)
    }

    /// Every producer with its window, by id.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &PartitionWindow)> {
        self.producers
            .iter()
            .map(|(id, p)| (id.as_str(), &p.window))
    }

    /// Apply an entry's producer data: for a produce, `count` records stored
    /// from `base_offset` on, the first with the op's `first_sequence`.
    ///
    /// A producer id belongs to the owner the log first recorded for it. An
    /// entry from another owner can only come from a leader that had not yet
    /// seen that record; its records are stored like any others, but they do
    /// not move the owner's window.
    pub fn apply(&mut self, op: &ProducerOp, base_offset: u64, count: u64) {
        self.tick(op.ts_ms());
        self.replicated = true;
        let (producer_id, owner, first_sequence) = match op {
            ProducerOp::Forget { producer_id, .. } => {
                self.producers.remove(producer_id);
                return;
            }
            ProducerOp::Produce {
                producer_id,
                owner,
                first_sequence,
                ..
            } => (producer_id, owner, *first_sequence),
        };
        let clock = self.clock_ms;
        let p = self
            .producers
            .entry(producer_id.clone())
            .or_insert_with(|| Producer {
                owner: owner.clone(),
                last_used_ms: clock,
                window: PartitionWindow::default(),
            });
        if p.owner != *owner {
            return;
        }
        p.last_used_ms = clock;
        for i in 0..count {
            let Some(seq) = first_sequence.checked_add(i as i64) else {
                break;
            };
            p.window.record(seq, base_offset.saturating_add(i));
        }
    }

    /// Advance the replicated clock and, once a minute of it has passed,
    /// forget the producers idle for [`PRODUCER_EXPIRY`].
    fn tick(&mut self, ts_ms: i64) {
        self.clock_ms = self.clock_ms.max(ts_ms);
        if self.clock_ms.saturating_sub(self.swept_ms) < SWEEP_EVERY_MS {
            return;
        }
        self.swept_ms = self.clock_ms;
        let cutoff = self
            .clock_ms
            .saturating_sub(PRODUCER_EXPIRY.as_millis() as i64);
        self.producers.retain(|_, p| p.last_used_ms >= cutoff);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 33 + self.producers.len() * 64);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.applied.to_be_bytes());
        out.extend_from_slice(&self.clock_ms.to_be_bytes());
        out.extend_from_slice(&self.swept_ms.to_be_bytes());
        out.push(if self.replicated { FLAG_REPLICATED } else { 0 });
        out.extend_from_slice(&(self.producers.len() as u32).to_be_bytes());
        for (id, p) in &self.producers {
            put_str(&mut out, id);
            put_str(&mut out, &p.owner);
            out.extend_from_slice(&p.last_used_ms.to_be_bytes());
            out.extend_from_slice(&p.window.last_seen.to_be_bytes());
            out.extend_from_slice(&p.window.last_offset.to_be_bytes());
            out.extend_from_slice(&(p.window.recent.len() as u16).to_be_bytes());
            for (s, o) in &p.window.recent {
                out.extend_from_slice(&s.to_be_bytes());
                out.extend_from_slice(&o.to_be_bytes());
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader { b: bytes, p: 0 };
        if r.take(4)? != MAGIC {
            bail!("not a producer table");
        }
        let applied = r.u64()?;
        let clock_ms = r.u64()? as i64;
        let swept_ms = r.u64()? as i64;
        let flags = r.u8()?;
        let count = r.u32()? as usize;
        // Bounded by the bytes present, not by the count the sender claims:
        // the smallest producer is 38 bytes.
        if count > bytes.len() / 38 {
            bail!(
                "producer table claims {count} producers in {} bytes",
                bytes.len()
            );
        }
        let mut producers = BTreeMap::new();
        for _ in 0..count {
            let id = r.str()?;
            let owner = r.str()?;
            let last_used_ms = r.u64()? as i64;
            let last_seen = r.u64()? as i64;
            let last_offset = r.u64()?;
            let n = r.u16()? as usize;
            if n > WINDOW {
                bail!("producer '{id}' carries {n} sequences; the window is {WINDOW}");
            }
            let mut recent = VecDeque::with_capacity(n);
            for _ in 0..n {
                recent.push_back((r.u64()? as i64, r.u64()?));
            }
            producers.insert(
                id,
                Producer {
                    owner,
                    last_used_ms,
                    window: PartitionWindow {
                        last_seen,
                        last_offset,
                        recent,
                    },
                },
            );
        }
        if r.p != bytes.len() {
            bail!("trailing bytes after the producer table");
        }
        Ok(Self {
            applied,
            clock_ms,
            swept_ms,
            replicated: flags & FLAG_REPLICATED != 0,
            producers,
        })
    }
}

/// What a log entry says about a producer, in the trailer of a batch entry.
///
/// ```text
///   'P' | ts_ms i64 | id (u16 len) | owner (u16 len) | first_sequence i64
///   'F' | ts_ms i64 | id (u16 len)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProducerOp {
    /// The entry's records are `producer_id`'s, sequenced from
    /// `first_sequence`, written for `owner`.
    Produce {
        ts_ms: i64,
        producer_id: String,
        owner: String,
        first_sequence: i64,
    },
    /// Forget `producer_id`. The entry has no records.
    Forget { ts_ms: i64, producer_id: String },
}

const OP_PRODUCE: u8 = b'P';
const OP_FORGET: u8 = b'F';

impl ProducerOp {
    pub fn producer_id(&self) -> &str {
        match self {
            Self::Produce { producer_id, .. } | Self::Forget { producer_id, .. } => producer_id,
        }
    }

    pub fn ts_ms(&self) -> i64 {
        match self {
            Self::Produce { ts_ms, .. } | Self::Forget { ts_ms, .. } => *ts_ms,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Produce {
                ts_ms,
                producer_id,
                owner,
                first_sequence,
            } => {
                out.push(OP_PRODUCE);
                out.extend_from_slice(&ts_ms.to_be_bytes());
                put_str(out, producer_id);
                put_str(out, owner);
                out.extend_from_slice(&first_sequence.to_be_bytes());
            }
            Self::Forget { ts_ms, producer_id } => {
                out.push(OP_FORGET);
                out.extend_from_slice(&ts_ms.to_be_bytes());
                put_str(out, producer_id);
            }
        }
    }

    /// Decode a trailer that must fill `bytes` exactly.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader { b: bytes, p: 0 };
        let op = match r.u8()? {
            OP_PRODUCE => Self::Produce {
                ts_ms: r.u64()? as i64,
                producer_id: r.str()?,
                owner: r.str()?,
                first_sequence: r.u64()? as i64,
            },
            OP_FORGET => Self::Forget {
                ts_ms: r.u64()? as i64,
                producer_id: r.str()?,
            },
            other => bail!("unknown producer trailer {other:#x}"),
        };
        if r.p != bytes.len() {
            bail!("trailing bytes after the producer trailer");
        }
        Ok(op)
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    let b = &s.as_bytes()[..s.len().min(MAX_NAME)];
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .p
            .checked_add(n)
            .ok_or_else(|| anyhow!("length overflow"))?;
        let s = self
            .b
            .get(self.p..end)
            .ok_or_else(|| anyhow!("producer data truncated"))?;
        self.p = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn str(&mut self) -> Result<String> {
        let n = self.u16()? as usize;
        if n > MAX_NAME {
            bail!("name of {n} bytes in producer data");
        }
        Ok(std::str::from_utf8(self.take(n)?)
            .map_err(|_| anyhow!("producer data holds a name that is not UTF-8"))?
            .to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::producers::DedupeOutcome;

    fn produce(id: &str, owner: &str, ts: i64, first: i64) -> ProducerOp {
        ProducerOp::Produce {
            ts_ms: ts,
            producer_id: id.into(),
            owner: owner.into(),
            first_sequence: first,
        }
    }

    #[test]
    fn a_table_roundtrips() {
        let mut t = ReplicatedProducers::at(3);
        t.apply(&produce("p1", "k", 1_000, 0), 10, 3);
        t.apply(&produce("p2", "j", 2_000, 7), 13, 1);
        t.applied = 9;
        let back = ReplicatedProducers::decode(&t.encode()).unwrap();
        assert_eq!(back, t);
        assert!(back.replicated());
        assert_eq!(
            back.window("p1").unwrap().check(1),
            DedupeOutcome::Duplicate { prev_offset: 11 }
        );
        assert_eq!(back.window("p2").unwrap().check(8), DedupeOutcome::Accept);
    }

    #[test]
    fn a_damaged_table_is_refused() {
        let mut t = ReplicatedProducers::at(1);
        t.apply(&produce("p1", "k", 1, 0), 0, 2);
        let bytes = t.encode();
        for cut in [0, 4, bytes.len() - 1] {
            assert!(ReplicatedProducers::decode(&bytes[..cut]).is_err(), "{cut}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(ReplicatedProducers::decode(&longer).is_err());
    }

    #[test]
    fn the_first_owner_keeps_the_id() {
        let mut t = ReplicatedProducers::default();
        t.apply(&produce("p1", "a", 1, 0), 0, 1);
        t.apply(&produce("p1", "b", 2, 1), 1, 1);
        assert_eq!(t.owner("p1"), Some("a"));
        assert_eq!(t.window("p1").unwrap().last_seen(), 0);
    }

    /// Expiry runs on the log's timestamps, so two replicas applying the same
    /// entries forget the same producers, whatever their own clocks say.
    #[test]
    fn idle_producers_expire_on_the_replicated_clock() {
        let week = PRODUCER_EXPIRY.as_millis() as i64;
        let mut t = ReplicatedProducers::default();
        t.apply(&produce("old", "k", 1_000, 0), 0, 1);
        t.apply(&produce("kept", "k", 2_000, 0), 1, 1);
        let mut replica = t.clone();
        let later = produce("kept", "k", 1_000 + week + SWEEP_EVERY_MS, 1);
        t.apply(&later, 2, 1);
        replica.apply(&later, 2, 1);
        assert_eq!(t.owner("old"), None, "idle for over a week");
        assert_eq!(t.owner("kept"), Some("k"));
        assert_eq!(t, replica);
        // A timestamp from a leader whose clock is behind does not move the
        // clock back.
        t.apply(&produce("kept", "k", 5, 2), 3, 1);
        assert_eq!(t.clock_ms, 1_000 + week + SWEEP_EVERY_MS);
    }

    #[test]
    fn a_producer_op_roundtrips_and_refuses_garbage() {
        for op in [
            produce("p.1", "key_a", -5, 42),
            ProducerOp::Forget {
                ts_ms: 9,
                producer_id: "p.1".into(),
            },
        ] {
            let mut b = Vec::new();
            op.encode(&mut b);
            assert_eq!(ProducerOp::decode(&b).unwrap(), op);
            assert!(ProducerOp::decode(&b[..b.len() - 1]).is_err());
            b.push(0);
            assert!(ProducerOp::decode(&b).is_err());
        }
        assert!(ProducerOp::decode(b"Z").is_err());
    }
}
