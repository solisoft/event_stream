//! A [`Partition`] backed by a Raft group.
//!
//! # Write path
//!
//! A produce request becomes **one** log entry carrying all of its records,
//! the offset the first of them gets, and their timestamps — all assigned by
//! the leader when it proposes. Replicas apply the entry by storing each record
//! under exactly that offset (`Partition::append_batch` with explicit offsets),
//! so every replica holds the same record at the same offset with the same
//! timestamp, and re-applying an entry after a restart is a no-op.
//!
//! The proposer waits for its entry by **proposal id**, not by log index: if
//! leadership changes and another leader's entry lands at the index this one
//! was given, the waiter is told so instead of being handed that entry's
//! offsets as its own.
//!
//! # Snapshots
//!
//! The partition log *is* the state machine, so a snapshot is just "the
//! partition up to offset E, synced". A follower too far behind for the
//! leader's Raft log is caught up by streaming it the records it is missing
//! from the leader's partition ([`SnapshotTransfer`]).
//!
//! # Idempotent producers
//!
//! A produce with a `producer_id` carries the producer, its owner and the
//! first sequence in a trailer of its entry, and every replica applies them
//! to the partition's [`ReplicatedProducers`] along with the records. The
//! table goes into each snapshot after the state end, and to a lagging
//! follower beside the last chunk of a transfer; a restart restores it from
//! the snapshot and re-applies the log after it. Whoever leads next knows
//! every sequence committed before it.
//!
//! The leader decides a retry against the table **and** its own log past what
//! the table has applied: an entry proposed but not yet committed — its own,
//! or one a previous leader left — is waited for before the producer's next
//! request is checked ([`RaftPartition::producer_state`]), and re-checked as
//! the proposal is made, so a sequence cannot be accepted twice while its
//! first copy is in flight.
//!
//! A 0.3.0 or 0.2 broker cannot decode such an entry and would stop applying.
//! So a leader writes producer data only once every voter has advertised that
//! it understands it, or once the log already holds some (every member then
//! did); until then the partition keeps the per-broker windows of
//! [`crate::producers::ProducerRegistry`].
//!
//! # Reads
//!
//! A plain read serves whatever this replica has applied, which can be behind
//! the leader, or — on a leader cut off from its majority — behind a newer
//! leader. [`RaftPartition::read_barrier`] makes the read that follows it
//! linearizable with the read-index protocol (dissertation §6.4): the leader
//! fixes its commit index as the read index, confirms with a heartbeat round
//! that a majority still follows it, and waits until the partition has
//! applied through that index. No clock is involved, so no bound on clock
//! drift is assumed — which is what a lease read would need.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::partition::{now_ms, AppendRecord, Durability, Partition};
use crate::producers::PartitionWindow;
use crate::raft::messages::FEATURE_PRODUCER_STATE;
use crate::raft::state::{is_config_entry, ChangeRefused, RaftState};
use crate::raft::{
    spawn_node_with_options,
    transport::{RaftHub, Transport},
    JsonStore, LogIndex, MemberChange, NodeHandle, NodeId, NodeOptions, Outbound, ProposeReply,
    RaftStore, ReadIndexReply, SnapshotSender, SnapshotTransfer, Timing,
};
use crate::replicated_producers::{ProducerOp, ReplicatedProducers};
use tokio::sync::Mutex as TokioMutex;

/// Version tag of a data entry. Entries written before batching began with an
/// `i32` key length instead, whose first byte is 0x00 or 0xFF.
///
/// ```text
///   0x01 | proposal u64 | base_offset u64 | count u32
///   per record: ts i64 | key (i32 len, -1 = none) | value (u32 len)
///   [producer trailer]                       see `ProducerOp`
/// ```
///
/// The trailer is optional: entries without one — every entry 0.2 and 0.3.0
/// wrote — decode as before.
const ENTRY_V1: u8 = 0x01;

/// A decoded data entry.
#[derive(Debug, PartialEq)]
enum Command {
    Batch {
        proposal: u64,
        base_offset: u64,
        records: Vec<(i64, Option<Vec<u8>>, Vec<u8>)>,
        producer: Option<ProducerOp>,
    },
    /// The pre-batching single-record format. Its offset was the entry's
    /// index minus one by construction.
    Legacy {
        key: Option<Vec<u8>>,
        value: Vec<u8>,
    },
}

fn encode_batch(
    proposal: u64,
    base_offset: u64,
    ts: i64,
    records: &[AppendRecord],
    producer: Option<&ProducerOp>,
) -> Vec<u8> {
    let size: usize = records
        .iter()
        .map(|r| 8 + 4 + r.key.as_ref().map_or(0, |k| k.len()) + 4 + r.value.len())
        .sum();
    let mut out = Vec::with_capacity(1 + 8 + 8 + 4 + size);
    out.push(ENTRY_V1);
    out.extend_from_slice(&proposal.to_be_bytes());
    out.extend_from_slice(&base_offset.to_be_bytes());
    out.extend_from_slice(&(records.len() as u32).to_be_bytes());
    for r in records {
        out.extend_from_slice(&r.timestamp_ms.unwrap_or(ts).to_be_bytes());
        match &r.key {
            Some(k) => {
                out.extend_from_slice(&(k.len() as i32).to_be_bytes());
                out.extend_from_slice(k);
            }
            None => out.extend_from_slice(&(-1i32).to_be_bytes()),
        }
        out.extend_from_slice(&(r.value.len() as u32).to_be_bytes());
        out.extend_from_slice(&r.value);
    }
    if let Some(op) = producer {
        op.encode(&mut out);
    }
    out
}

/// Just the producer trailer of a batch entry, without copying records.
fn producer_op(bytes: &[u8]) -> Option<ProducerOp> {
    if bytes.first() != Some(&ENTRY_V1) {
        return None;
    }
    let mut c = Cur { b: bytes, p: 17 };
    let n = c.u32().ok()?;
    for _ in 0..n {
        c.take(8).ok()?;
        let k = c.i32().ok()?;
        if k > 0 {
            c.take(k as usize).ok()?;
        }
        let v = c.u32().ok()? as usize;
        c.take(v).ok()?;
    }
    if c.p == bytes.len() {
        return None;
    }
    ProducerOp::decode(&bytes[c.p..]).ok()
}

/// Just the `(base_offset, count)` of a batch entry, without copying records.
fn batch_span(bytes: &[u8]) -> Option<(u64, u64)> {
    if bytes.len() < 21 || bytes[0] != ENTRY_V1 {
        return None;
    }
    let base = u64::from_be_bytes(bytes[9..17].try_into().ok()?);
    let count = u32::from_be_bytes(bytes[17..21].try_into().ok()?) as u64;
    Some((base, count))
}

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .p
            .checked_add(n)
            .ok_or_else(|| anyhow!("length overflow"))?;
        let s = self
            .b
            .get(self.p..end)
            .ok_or_else(|| anyhow!("entry truncated"))?;
        self.p = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn opt_bytes(&mut self) -> Result<Option<Vec<u8>>> {
        let n = self.i32()?;
        if n < 0 {
            return Ok(None);
        }
        Ok(Some(self.take(n as usize)?.to_vec()))
    }
    fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
}

fn decode_command(bytes: &[u8]) -> Result<Command> {
    if bytes.first() == Some(&ENTRY_V1) {
        let mut c = Cur { b: bytes, p: 1 };
        let proposal = c.u64()?;
        let base_offset = c.u64()?;
        let n = c.u32()? as usize;
        let mut records = Vec::with_capacity(n.min(bytes.len() / 16));
        for _ in 0..n {
            let ts = c.u64()? as i64;
            let key = c.opt_bytes()?;
            let value = c.bytes()?;
            records.push((ts, key, value));
        }
        let producer = if c.p == bytes.len() {
            None
        } else {
            Some(ProducerOp::decode(&bytes[c.p..]).context("batch entry trailer")?)
        };
        return Ok(Command::Batch {
            proposal,
            base_offset,
            records,
            producer,
        });
    }
    let mut c = Cur { b: bytes, p: 0 };
    let key = c.opt_bytes()?;
    let value = c.bytes()?;
    if c.p != bytes.len() {
        return Err(anyhow!("trailing bytes after append command"));
    }
    Ok(Command::Legacy { key, value })
}

/// How long an accepted proposal is given to commit before the caller is told
/// it did not. Only reached when the leader has lost its majority — a healthy
/// cluster commits in the time one round trip takes.
const COMMIT_TIMEOUT: Duration = Duration::from_secs(10);

/// A proposal refused because this node does not lead the partition. Typed so
/// the produce path can tell it from a failure and answer with a retryable
/// error rather than an internal one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotLeader {
    pub leader_hint: Option<NodeId>,
}

impl std::fmt::Display for NotLeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "not leader (hint: {:?}); produce must be routed to the leader",
            self.leader_hint
        )
    }
}

impl std::error::Error for NotLeader {}

/// Who leads a partition, as this node sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leadership {
    /// This node: a write can be proposed here.
    Local,
    /// Another node, if this one knows which.
    Remote(Option<NodeId>),
}

/// Why a linearizable read could not be served. Every case is retryable:
/// leadership moves, and a leader that timed out may succeed a moment later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadBarrierError {
    /// This replica is not the partition's leader (or stopped being it
    /// before its leadership was confirmed). Retry against `leader_hint`.
    NotLeader { leader_hint: Option<NodeId> },
    /// Leadership was not confirmed by a majority, or the read index not
    /// applied, within the bound.
    TimedOut(Duration),
    /// The Raft node or the apply loop has stopped.
    Stopped(String),
}

impl std::fmt::Display for ReadBarrierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotLeader {
                leader_hint: Some(id),
            } => write!(
                f,
                "not leader for this partition; linearizable reads go to the leader (node {id})"
            ),
            Self::NotLeader { leader_hint: None } => write!(
                f,
                "not leader for this partition and no leader is known; retry shortly"
            ),
            Self::TimedOut(d) => write!(
                f,
                "linearizable read timed out after {:?}: the leader could not confirm its \
                 leadership with a majority",
                d
            ),
            Self::Stopped(m) => write!(f, "linearizable read failed: {m}"),
        }
    }
}

impl std::error::Error for ReadBarrierError {}

/// An idempotent produce that cannot be decided now but can be retried: an
/// earlier write of the same producer is still in flight, or the producer's
/// state moved between the check and the proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerRetry(pub String);

impl std::fmt::Display for ProducerRetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProducerRetry {}

/// What this replica knows of one producer on this partition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProducerView {
    /// The key the log first recorded the producer id for.
    pub owner: Option<String>,
    /// The producer's window here, through every entry it has committed.
    pub window: Option<PartitionWindow>,
    /// Whether the partition replicates producer state: a write may carry
    /// it, and `window` is the partition's, not this broker's.
    pub replicated: bool,
}

/// The producer data a write carries. See [`RaftPartition::append_batch_as`].
#[derive(Debug, Clone)]
pub struct ProducerWrite {
    pub producer_id: String,
    pub owner: String,
    /// Sequence of the first record; the others follow it one by one.
    pub first_sequence: i64,
    /// The window's last sequence when the request was checked, `None` if
    /// the partition had no window for the producer.
    pub checked_last_seen: Option<i64>,
}

/// What an entry does to the producer table, before it has a timestamp.
enum ProducerChange {
    Write(ProducerWrite),
    Forget(String),
}

#[derive(Debug)]
pub struct AppendResult {
    pub offset: u64,
}

struct Waiter {
    tx: oneshot::Sender<Result<Vec<u64>, String>>,
    /// The log index the proposal was given, once known.
    index: Option<LogIndex>,
}

type Waiters = Arc<Mutex<HashMap<u64, Waiter>>>;

pub struct RaftPartition {
    partition: Arc<Partition>,
    /// Idempotent-producer state, as of the last entry applied.
    producers: Arc<Mutex<ReplicatedProducers>>,
    raft: NodeHandle,
    waiters: Waiters,
    /// Serializes "assign offsets, propose" so proposals enter the log in
    /// offset order.
    propose_lock: TokioMutex<()>,
    proposal_nonce: u64,
    proposal_counter: AtomicU64,
    cancel: CancellationToken,
    apply_join: Mutex<Option<JoinHandle<()>>>,
    node_join: Mutex<Option<JoinHandle<()>>>,
    /// Held aside after construction; consumed by `connect_transport`.
    outbound_rx: Mutex<Option<mpsc::UnboundedReceiver<Outbound>>>,
    /// Set by `connect_transport`.
    transport: Mutex<Option<Transport>>,
    /// Index of the last entry the apply loop has written to the partition.
    applied: watch::Receiver<LogIndex>,
}

#[derive(Debug, Clone)]
pub struct RaftPartitionConfig {
    pub node_id: NodeId,
    pub peers: Vec<NodeId>,
    pub raft_store_path: PathBuf,
    pub timing: Timing,
    pub snapshot_after_applies: u32,
    /// See [`crate::raft::NodeOptions::joining`].
    pub joining: bool,
}

#[derive(Debug, Clone)]
pub struct RaftTransportConfig {
    pub bind: SocketAddr,
    pub peer_addrs: BTreeMap<NodeId, SocketAddr>,
    /// Pre-shared secret peers must present in the raft handshake. `None`
    /// disables peer authentication (only allowed on a loopback bind).
    pub shared_secret: Option<crate::raft::SharedSecret>,
}

impl RaftPartitionConfig {
    pub fn with_defaults(node_id: NodeId, raft_store_path: PathBuf) -> Self {
        Self {
            node_id,
            peers: Vec::new(),
            raft_store_path,
            timing: Timing::default(),
            snapshot_after_applies: 1024,
            joining: false,
        }
    }
}

/// Bound on any offset a peer hands us, in a snapshot or a log entry. No real
/// partition gets near it, so a value past it is a forged or corrupt message —
/// and a snapshot ending at `u64::MAX` would move this replica's next offset
/// past every record it could ever store, silently skipping all of them. The
/// headroom also keeps `offset + 1` from overflowing anywhere downstream.
const MAX_OFFSET: u64 = i64::MAX as u64;

/// Largest producer table sent with a snapshot: with the last chunk (at most
/// [`crate::raft::node::SNAPSHOT_CHUNK_BYTES`]) it stays well under the
/// transport's frame limit. About ten thousand producers with full windows.
const MAX_SNAPSHOT_PRODUCERS_BYTES: usize = 32 * 1024 * 1024;

/// Ships partition records to a lagging follower.
///
/// Chunk format: `end u64` (the state end of the snapshot being installed),
/// then records as `offset u64 | ts i64 | key (i32 len, -1 = none) | value
/// (u32 len)`.
struct PartitionTransfer {
    partition: Arc<Partition>,
    producers: Arc<Mutex<ReplicatedProducers>>,
}

impl SnapshotTransfer for PartitionTransfer {
    fn read_chunk(&self, from: u64, end: u64, max_bytes: usize) -> Result<(Vec<u8>, bool)> {
        let mut out = Vec::with_capacity(max_bytes.min(1 << 20) + 64);
        out.extend_from_slice(&end.to_be_bytes());
        let mut cursor = from;
        while cursor < end && out.len() < max_bytes {
            let (records, next, _) = self.partition.read_records_raw(
                cursor,
                usize::MAX,
                max_bytes - out.len().min(max_bytes),
            )?;
            for r in records.iter().filter(|r| r.offset < end) {
                out.extend_from_slice(&r.offset.to_be_bytes());
                out.extend_from_slice(&r.timestamp_ms.to_be_bytes());
                match &r.key {
                    Some(k) => {
                        out.extend_from_slice(&(k.len() as i32).to_be_bytes());
                        out.extend_from_slice(k);
                    }
                    None => out.extend_from_slice(&(-1i32).to_be_bytes()),
                }
                out.extend_from_slice(&(r.value.len() as u32).to_be_bytes());
                out.extend_from_slice(&r.value);
            }
            if next <= cursor {
                break;
            }
            cursor = next;
        }
        Ok((out, cursor >= end))
    }

    fn apply_chunk(&self, data: &[u8], done: bool, extra: Option<&[u8]>) -> Result<()> {
        // Before anything is stored: a chunk refused is retried whole.
        let table = extra
            .filter(|_| done)
            .map(ReplicatedProducers::decode)
            .transpose()
            .context("snapshot producer table")?;
        let mut c = Cur { b: data, p: 0 };
        let end = c.u64()?;
        if end > MAX_OFFSET {
            return Err(anyhow!(
                "snapshot chunk declares state end {end}, past any real offset"
            ));
        }
        let mut recs = Vec::new();
        while c.p < data.len() {
            let offset = c.u64()?;
            // Records at or past the end are not part of this snapshot. Ones
            // below our position are a resent chunk: already stored, and
            // skipped by `append_batch`.
            if offset >= end {
                return Err(anyhow!(
                    "snapshot chunk carries offset {offset}, at or past its end {end}"
                ));
            }
            let ts = c.u64()? as i64;
            let key = c.opt_bytes()?;
            let value = c.bytes()?;
            recs.push(AppendRecord {
                key,
                value,
                timestamp_ms: Some(ts),
                offset: Some(offset),
            });
        }
        self.partition.append_batch(&recs, Durability::Deferred)?;
        if done {
            // Offsets with no record (retention on the leader, entries with
            // nothing to store) still count as covered.
            self.partition.advance_to(end);
            // The Raft log behind this snapshot is about to be dropped.
            self.partition.sync_all()?;
            if let Some(t) = table {
                let mut ours = self.producers.lock().unwrap();
                if t.applied() > ours.applied() {
                    *ours = t;
                }
            }
        }
        Ok(())
    }

    fn progress(&self) -> u64 {
        self.partition.end_offset()
    }

    fn snapshot_end(&self, data: &[u8]) -> u64 {
        data.get(0..8)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0)
    }

    fn snapshot_extra(&self, data: &[u8]) -> Option<Vec<u8>> {
        let table = data.get(8..).filter(|t| !t.is_empty())?;
        if table.len() > MAX_SNAPSHOT_PRODUCERS_BYTES {
            // It rides in one message beside a chunk, and a message over the
            // transport's frame limit would fail the transfer every time it
            // was retried. The follower catches up without the windows.
            tracing::warn!(
                partition = self.partition.id,
                bytes = table.len(),
                "raft_partition: producer table too large to send with a snapshot; the \
                 follower gets none"
            );
            return None;
        }
        Some(table.to_vec())
    }

    fn installed(&self, last_index: LogIndex) -> Vec<u8> {
        let mut table = self.producers.lock().unwrap();
        // From a leader that sent no table, ours is all there is; it still
        // covers everything through the snapshot from now on.
        if table.applied() < last_index {
            table.applied = last_index;
        }
        snapshot_data(self.partition.end_offset(), &table)
    }
}

/// A snapshot's data: the state end, then the producer table.
fn snapshot_data(end: u64, producers: &ReplicatedProducers) -> Vec<u8> {
    let mut out = end.to_be_bytes().to_vec();
    out.extend_from_slice(&producers.encode());
    out
}

/// The producer table a stored snapshot restores: the one it carries, or an
/// empty one from a snapshot that predates them.
fn snapshot_producers(snap: &crate::raft::PersistedSnapshot) -> Result<ReplicatedProducers> {
    let mut table = match snap.data.get(8..).filter(|t| !t.is_empty()) {
        Some(t) => ReplicatedProducers::decode(t).context("snapshot producer table")?,
        None => ReplicatedProducers::default(),
    };
    if table.applied() < snap.last_index {
        table.applied = snap.last_index;
    }
    Ok(table)
}

impl RaftPartition {
    pub fn open(
        partition_dir: PathBuf,
        partition_id: u32,
        segment_bytes: u64,
        flush_every_records: u32,
        config: RaftPartitionConfig,
    ) -> Result<Arc<Self>> {
        let partition = Partition::open(
            partition_dir,
            partition_id,
            segment_bytes,
            flush_every_records,
        )?;
        let store: Arc<dyn RaftStore> = Arc::new(JsonStore::new(config.raft_store_path));
        // The windows as of the snapshot; the apply loop re-applies the log
        // after it.
        let producers = match store.load_snapshot()? {
            Some(snap) => snapshot_producers(&snap)?,
            None => ReplicatedProducers::default(),
        };
        let producers = Arc::new(Mutex::new(producers));
        let options = NodeOptions {
            noop_on_elect: true,
            transfer: Some(Arc::new(PartitionTransfer {
                partition: partition.clone(),
                producers: producers.clone(),
            })),
            joining: config.joining,
        };
        let mut raft = spawn_node_with_options(
            config.node_id,
            config.peers,
            config.timing,
            store.clone(),
            options,
        )?;

        let outbound_rx = raft.take_outbound();
        let node_join = raft.join.take();
        let waiters: Waiters = Arc::new(Mutex::new(HashMap::new()));
        let cancel = CancellationToken::new();

        let committed = raft
            .take_committed()
            .ok_or_else(|| anyhow!("raft node committed receiver already taken"))?;

        let (applied_tx, applied_rx) = watch::channel(raft.applied_at_start());
        let apply = ApplyLoop {
            partition: partition.clone(),
            producers: producers.clone(),
            waiters: waiters.clone(),
            snapshot_after_applies: config.snapshot_after_applies,
            applied: applied_tx,
        };
        let raft_for_apply = raft.snapshot_sender();
        let cancel_for_apply = cancel.clone();
        let apply_join = tokio::spawn(async move {
            apply.run(committed, cancel_for_apply, raft_for_apply).await;
        });

        let mut nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);

        Ok(Arc::new(Self {
            partition,
            producers,
            raft,
            waiters,
            propose_lock: TokioMutex::new(()),
            proposal_nonce: u64::from_be_bytes(nonce),
            proposal_counter: AtomicU64::new(0),
            cancel,
            apply_join: Mutex::new(Some(apply_join)),
            node_join: Mutex::new(node_join),
            outbound_rx: Mutex::new(outbound_rx),
            transport: Mutex::new(None),
            applied: applied_rx,
        }))
    }

    /// Route this partition's Raft traffic over a hub shared with every other
    /// partition on this broker. Must be called after `open()` and before any
    /// appends; without it the node operates in single-node mode.
    pub fn attach_to_hub(&self, hub: &Arc<RaftHub>, group: &str) -> Result<()> {
        let outbound_rx = self.take_outbound()?;
        hub.register(group, self.raft.inbound.clone(), outbound_rx)
            .with_context(|| format!("register raft group '{group}'"))?;
        Ok(())
    }

    fn take_outbound(&self) -> Result<mpsc::UnboundedReceiver<Outbound>> {
        let mut guard = self.outbound_rx.lock().unwrap();
        guard
            .take()
            .ok_or_else(|| anyhow!("this partition's raft transport is already connected"))
    }

    /// Connect this Raft partition to peer nodes via TCP on a hub of its own.
    /// Must be called after `open()` and before any appends. Without this, the
    /// node operates in single-node mode.
    pub async fn connect_transport(&self, tcfg: RaftTransportConfig) -> Result<()> {
        let outbound_rx = self.take_outbound()?;
        let transport = crate::raft::spawn_transport(
            self.raft.id,
            tcfg.bind,
            tcfg.peer_addrs,
            self.raft.inbound.clone(),
            outbound_rx,
            Duration::from_secs(2),
            tcfg.shared_secret,
        )
        .await?;
        *self.transport.lock().unwrap() = Some(transport);
        Ok(())
    }

    /// Propose a single-server membership change for this partition's
    /// group. See [`NodeHandle::change_membership`].
    pub async fn change_membership(
        &self,
        change: MemberChange,
    ) -> Result<std::result::Result<LogIndex, ChangeRefused>> {
        self.raft.change_membership(change).await
    }

    /// The Raft state machine behind this partition, for reporting only.
    pub fn raft_state(&self) -> &Arc<TokioMutex<RaftState>> {
        &self.raft.state
    }

    /// Which peers this node has heard from recently. See
    /// [`NodeHandle::peers_heard_from`].
    pub async fn peers_heard_from(&self, within: Duration) -> Vec<NodeId> {
        self.raft.peers_heard_from(within).await
    }

    pub fn partition(&self) -> &Arc<Partition> {
        &self.partition
    }

    /// Whether this node leads the partition, and if not, who it believes
    /// does. Leadership can move right after this returns; a proposal made on
    /// the strength of `Local` can still be refused with [`NotLeader`].
    pub async fn leadership(&self) -> Leadership {
        let state = self.raft.state.lock().await;
        if state.role == crate::raft::state::Role::Leader {
            Leadership::Local
        } else {
            Leadership::Remote(state.leader_hint.filter(|l| *l != self.raft.id && *l != 0))
        }
    }

    pub async fn append(&self, key: Option<&[u8]>, value: &[u8]) -> Result<u64> {
        let offs = self
            .append_batch(vec![AppendRecord::new(
                key.map(|k| k.to_vec()),
                value.to_vec(),
            )])
            .await?;
        Ok(offs[0])
    }

    /// The offset the next proposal starts at: past every record already in
    /// the partition and every record any entry in the log will produce — a
    /// new leader's log can hold uncommitted entries from its predecessor that
    /// will commit, and their offsets must not be handed out twice.
    async fn next_assignable_offset(&self) -> u64 {
        let state = self.raft.state.lock().await;
        let mut from_log = None;
        for e in state.log.entries.iter().rev() {
            if e.payload.is_empty() || is_config_entry(&e.payload) {
                continue;
            }
            from_log = Some(match batch_span(&e.payload) {
                Some((base, count)) => base + count,
                // Legacy single-record entry: its offset is index - 1.
                None => e.index,
            });
            break;
        }
        drop(state);
        from_log.unwrap_or(0).max(self.partition.end_offset())
    }

    /// Propose `records` as one entry and wait for it to be applied. Returns
    /// each record's offset.
    pub async fn append_batch(&self, records: Vec<AppendRecord>) -> Result<Vec<u64>> {
        if records.is_empty() {
            return Ok(Vec::new());
        }
        self.propose(records, None).await
    }

    /// [`Self::append_batch`] for an idempotent producer: the entry carries
    /// `producer`, and every replica records the sequences when it applies
    /// it.
    ///
    /// The caller has checked the sequences against [`Self::producer_state`].
    /// If that state has moved since — the producer's window, its owner, or a
    /// write of it now in flight — nothing is proposed and the answer is a
    /// [`ProducerRetry`].
    pub async fn append_batch_as(
        &self,
        records: Vec<AppendRecord>,
        producer: ProducerWrite,
    ) -> Result<Vec<u64>> {
        if records.is_empty() {
            return Ok(Vec::new());
        }
        self.propose(records, Some(ProducerChange::Write(producer)))
            .await
    }

    /// Forget `producer_id` on every replica of this partition. `false` when
    /// there was nothing to forget here, or this broker cannot do it: it does
    /// not lead the partition, or producer state is not replicated on it.
    pub async fn forget_producer(&self, producer_id: &str) -> Result<bool> {
        let (view, _) = self.producer_view(producer_id).await;
        if !view.replicated || (view.owner.is_none() && view.window.is_none()) {
            return Ok(false);
        }
        match self
            .propose(
                Vec::new(),
                Some(ProducerChange::Forget(producer_id.to_string())),
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(e) if e.is::<NotLeader>() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Every producer's window on this partition, as applied here.
    pub fn producer_windows(&self) -> Vec<(String, PartitionWindow)> {
        self.producers
            .lock()
            .unwrap()
            .iter()
            .map(|(id, w)| (id.to_string(), w.clone()))
            .collect()
    }

    /// `producer_id`'s state on this partition, once every write of it this
    /// replica's log holds has been applied.
    ///
    /// A write proposed but not committed — this leader's, after its caller
    /// gave up waiting, or one a previous leader left in the log — is waited
    /// for, up to `timeout`, so a retry of it is recognised rather than
    /// accepted a second time. Past `timeout` the answer is a
    /// [`ProducerRetry`].
    pub async fn producer_state(
        &self,
        producer_id: &str,
        timeout: Duration,
    ) -> Result<ProducerView> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let (view, pending) = self.producer_view(producer_id).await;
            let Some(index) = pending else {
                return Ok(view);
            };
            if tokio::time::Instant::now() >= deadline {
                return Err(ProducerRetry(format!(
                    "an earlier write of producer '{producer_id}' (raft entry {index}) has not \
                     committed yet; retry"
                ))
                .into());
            }
            // Not only the applied index: an entry can also leave the log,
            // replaced by a new leader's, and nothing is applied in its place
            // until the next write.
            let mut applied = self.applied.clone();
            let _ =
                tokio::time::timeout(Duration::from_millis(20), applied.wait_for(|a| *a >= index))
                    .await;
        }
    }

    /// The producer's applied state, and the last entry in this replica's
    /// log past it that writes the producer, if any.
    async fn producer_view(&self, producer_id: &str) -> (ProducerView, Option<LogIndex>) {
        let mut attempts = 0;
        loop {
            let (applied, owner, window, latched) = {
                let t = self.producers.lock().unwrap();
                (
                    t.applied(),
                    t.owner(producer_id).map(str::to_string),
                    t.window(producer_id).cloned(),
                    t.replicated(),
                )
            };
            let state = self.raft.state.lock().await;
            // Entries were applied and compacted between the two locks: the
            // log no longer holds everything past what was read.
            attempts += 1;
            if state.log.base_index > applied && attempts < 10 {
                drop(state);
                tokio::task::yield_now().await;
                continue;
            }
            let mut pending = None;
            let mut carried = false;
            for e in state.log.entries.iter().filter(|e| e.index > applied) {
                if let Some(op) = producer_op(&e.payload) {
                    carried = true;
                    if op.producer_id() == producer_id {
                        pending = Some(e.index);
                    }
                }
            }
            // The log carrying producer data means every member understood
            // it when it was written; until then, every voter must say so.
            let replicated = latched || carried || state.peers_support(FEATURE_PRODUCER_STATE);
            let view = ProducerView {
                owner,
                window,
                replicated,
            };
            return (view, pending);
        }
    }

    async fn propose(
        &self,
        records: Vec<AppendRecord>,
        producer: Option<ProducerChange>,
    ) -> Result<Vec<u64>> {
        let proposal = self
            .proposal_nonce
            .wrapping_add(self.proposal_counter.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = oneshot::channel();
        // Registered before proposing: on a single-node cluster the entry can
        // be applied before `propose` even returns.
        self.waiters
            .lock()
            .unwrap()
            .insert(proposal, Waiter { tx, index: None });

        let reply = async {
            let _guard = self.propose_lock.lock().await;
            let ts = now_ms();
            // Checked again under the lock that orders proposals, so nothing
            // for this producer can enter the log between the check and ours.
            let op = match producer {
                None => None,
                Some(ProducerChange::Forget(producer_id)) => Some(ProducerOp::Forget {
                    ts_ms: ts,
                    producer_id,
                }),
                Some(ProducerChange::Write(w)) => {
                    let (view, pending) = self.producer_view(&w.producer_id).await;
                    let moved = pending.is_some()
                        || view.window.as_ref().map(PartitionWindow::last_seen)
                            != w.checked_last_seen
                        || view.owner.as_deref().is_some_and(|o| o != w.owner);
                    if moved {
                        return Err(ProducerRetry(format!(
                            "producer '{}' wrote to this partition while this request was \
                             being checked; retry",
                            w.producer_id
                        ))
                        .into());
                    }
                    Some(ProducerOp::Produce {
                        ts_ms: ts,
                        producer_id: w.producer_id,
                        owner: w.owner,
                        first_sequence: w.first_sequence,
                    })
                }
            };
            let base = self.next_assignable_offset().await;
            let payload = encode_batch(proposal, base, ts, &records, op.as_ref());
            self.raft.propose(payload).await
        }
        .await;
        let index = match reply {
            Ok(ProposeReply::Accepted { index }) => index,
            Ok(ProposeReply::NotLeader { leader_hint }) => {
                self.waiters.lock().unwrap().remove(&proposal);
                return Err(NotLeader { leader_hint }.into());
            }
            Err(e) => {
                self.waiters.lock().unwrap().remove(&proposal);
                return Err(e);
            }
        };
        if let Some(w) = self.waiters.lock().unwrap().get_mut(&proposal) {
            w.index = Some(index);
        }

        // Bounded: an entry proposed while the quorum is gone never commits,
        // and an unbounded wait would hold the client for the whole outage.
        match tokio::time::timeout(COMMIT_TIMEOUT, rx).await {
            Ok(Ok(Ok(offsets))) => Ok(offsets),
            Ok(Ok(Err(e))) => Err(anyhow!(e)),
            Ok(Err(_)) => Err(anyhow!(
                "raft apply task exited before this entry was applied"
            )),
            Err(_) => {
                self.waiters.lock().unwrap().remove(&proposal);
                Err(anyhow!(
                    "raft entry {} was accepted into the log but did not commit within {:?}: the \
                     leader cannot reach a majority of the cluster",
                    index,
                    COMMIT_TIMEOUT
                ))
            }
        }
    }

    /// Wait until a read of this partition is linearizable: it will see every
    /// write acknowledged before this call began, from any leader.
    ///
    /// Leader only. A follower refuses with `NotLeader` rather than asking the
    /// leader for a read index: that would need a new Raft message, which a
    /// broker of an earlier version drops along with its connection, and the
    /// follower would still wait to apply what the leader already has — the
    /// client is better served reading from the leader directly.
    pub async fn read_barrier(&self, timeout: Duration) -> Result<(), ReadBarrierError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let reply = match tokio::time::timeout_at(deadline, self.raft.read_index()).await {
            Err(_) => return Err(ReadBarrierError::TimedOut(timeout)),
            Ok(Err(e)) => return Err(ReadBarrierError::Stopped(e.to_string())),
            Ok(Ok(r)) => r,
        };
        let target = match reply {
            ReadIndexReply::Ready { apply_through } => apply_through,
            ReadIndexReply::NotLeader { leader_hint } => {
                return Err(ReadBarrierError::NotLeader { leader_hint })
            }
        };
        let mut applied = self.applied.clone();
        let waited = tokio::time::timeout_at(deadline, async {
            applied.wait_for(|a| *a >= target).await.map(|_| ())
        })
        .await;
        match waited {
            Err(_) => Err(ReadBarrierError::TimedOut(timeout)),
            Ok(Err(_)) => Err(ReadBarrierError::Stopped(
                "the apply loop has stopped".to_string(),
            )),
            Ok(Ok(())) => Ok(()),
        }
    }

    pub async fn shutdown(&self) {
        self.cancel.cancel();
        self.raft.cancel.cancel();
        if let Some(t) = self.transport.lock().unwrap().take() {
            t.cancel.cancel();
        }
        let apply = self.apply_join.lock().unwrap().take();
        if let Some(j) = apply {
            let _ = j.await;
        }
        let node = self.node_join.lock().unwrap().take();
        if let Some(j) = node {
            let _ = j.await;
        }
        for (_, w) in self.waiters.lock().unwrap().drain() {
            let _ = w.tx.send(Err("raft partition shutdown".to_string()));
        }
    }
}

struct ApplyLoop {
    partition: Arc<Partition>,
    producers: Arc<Mutex<ReplicatedProducers>>,
    waiters: Waiters,
    snapshot_after_applies: u32,
    /// Advanced after each entry is in the partition; read barriers wait on it.
    applied: watch::Sender<LogIndex>,
}

impl ApplyLoop {
    async fn run(
        self,
        mut committed: mpsc::UnboundedReceiver<crate::raft::messages::LogEntry>,
        cancel: CancellationToken,
        raft: SnapshotSender,
    ) {
        let mut applies_since_snapshot: u32 = 0;
        loop {
            let entry = tokio::select! {
                _ = cancel.cancelled() => break,
                msg = committed.recv() => match msg {
                    Some(e) => e,
                    None => break,
                },
            };
            let index = entry.index;
            if let Err(e) = self.apply(entry).await {
                // The partition is fenced (or the entry is garbage): applying
                // later entries on top would diverge from the other replicas.
                tracing::error!(
                    partition = self.partition.id,
                    index,
                    error = %e,
                    "raft apply failed; this replica stops applying"
                );
                break;
            }
            self.applied.send_replace(index);
            applies_since_snapshot += 1;
            if self.snapshot_after_applies > 0
                && applies_since_snapshot >= self.snapshot_after_applies
            {
                applies_since_snapshot = 0;
                if let Err(e) = self.snapshot(&raft, index).await {
                    tracing::warn!(partition = self.partition.id, error = %e, "raft_partition: snapshot failed");
                }
            }
        }
        // Whoever is still waiting will not be answered.
        for (_, w) in self.waiters.lock().unwrap().drain() {
            let _ = w.tx.send(Err("raft apply loop stopped".to_string()));
        }
        tracing::debug!("raft_partition: apply loop exited");
    }

    async fn apply(&self, entry: crate::raft::messages::LogEntry) -> Result<()> {
        let mut producer = None;
        let (proposal, records) = match decode_command(&entry.payload)? {
            Command::Batch {
                proposal,
                base_offset,
                records,
                producer: op,
            } => {
                producer = op.map(|op| (op, base_offset, records.len() as u64));
                // Checked: in a release build a batch running past u64::MAX
                // wraps to low offsets, which `append_batch` takes for records
                // it already has, and the batch is silently lost.
                let recs = records
                    .into_iter()
                    .enumerate()
                    .map(|(i, (ts, key, value))| {
                        let offset = base_offset
                            .checked_add(i as u64)
                            .filter(|o| *o < MAX_OFFSET)
                            .ok_or_else(|| {
                                anyhow!(
                                    "raft entry {}: offsets overflow from base {base_offset}",
                                    entry.index
                                )
                            })?;
                        Ok(AppendRecord {
                            key,
                            value,
                            timestamp_ms: Some(ts),
                            offset: Some(offset),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                (Some(proposal), recs)
            }
            Command::Legacy { key, value } => (
                None,
                vec![AppendRecord {
                    key,
                    value,
                    timestamp_ms: None,
                    offset: Some(entry.index.saturating_sub(1)),
                }],
            ),
        };
        let offsets = if records.is_empty() {
            Vec::new()
        } else {
            let p = self.partition.clone();
            tokio::task::spawn_blocking(move || p.append_batch(&records, Durability::Deferred))
                .await
                .map_err(|e| anyhow!("apply task: {e}"))??
        };
        {
            let mut table = self.producers.lock().unwrap();
            // At or below `applied`, the entry is already in the table: it
            // came with a snapshot, or is applied again after a restart.
            if entry.index > table.applied() {
                if let Some((op, base, count)) = &producer {
                    table.apply(op, *base, *count);
                }
                table.applied = entry.index;
            }
        }

        let mut waiters = self.waiters.lock().unwrap();
        if let Some(pid) = proposal {
            if let Some(w) = waiters.remove(&pid) {
                let _ = w.tx.send(Ok(offsets));
            }
        }
        // A proposal that was given this index but is not this entry lost it
        // to another leader's entry: it will never be applied.
        let superseded: Vec<u64> = waiters
            .iter()
            .filter(|(_, w)| w.index.is_some_and(|i| i <= entry.index))
            .map(|(pid, _)| *pid)
            .collect();
        for pid in superseded {
            if let Some(w) = waiters.remove(&pid) {
                let _ = w.tx.send(Err(format!(
                    "raft entry at index {} was replaced by another leader's entry; the write \
                     was not applied",
                    w.index.unwrap_or_default()
                )));
            }
        }
        Ok(())
    }

    /// Snapshot through `through`: everything up to it has been applied, and
    /// the partition is synced before the log behind it may be dropped.
    async fn snapshot(&self, raft: &SnapshotSender, through: LogIndex) -> Result<()> {
        let p = self.partition.clone();
        let end = tokio::task::spawn_blocking(move || -> Result<u64> {
            p.sync_all()?;
            Ok(p.end_offset())
        })
        .await
        .map_err(|e| anyhow!("snapshot sync task: {e}"))??;
        // Taken between two entries, the table holds everything through
        // `through`. A snapshot installed meanwhile can have taken it
        // further; it says how far (`applied`), and a restart re-applies only
        // the entries past that.
        let data = snapshot_data(end, &self.producers.lock().unwrap());
        raft.take(data, Some(through)).await?;
        tracing::debug!(
            partition = self.partition.id,
            through,
            end,
            "raft_partition: snapshot taken"
        );
        Ok(())
    }
}

pub fn test_timing() -> Timing {
    Timing {
        election_min: Duration::from_millis(50),
        election_max: Duration::from_millis(100),
        heartbeat: Duration::from_millis(20),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_command_roundtrip() {
        let recs = vec![
            AppendRecord::new(Some(b"k1".to_vec()), b"hello\x00world".to_vec()),
            AppendRecord::new(None, b"v-only".to_vec()),
            AppendRecord::new(Some(Vec::new()), Vec::new()),
        ];
        let bytes = encode_batch(42, 100, 7, &recs, None);
        assert_eq!(batch_span(&bytes), Some((100, 3)));
        match decode_command(&bytes).unwrap() {
            Command::Batch {
                proposal,
                base_offset,
                records,
                producer,
            } => {
                assert_eq!(producer, None);
                assert_eq!(proposal, 42);
                assert_eq!(base_offset, 100);
                assert_eq!(
                    records[0],
                    (7, Some(b"k1".to_vec()), b"hello\x00world".to_vec())
                );
                assert_eq!(records[1], (7, None, b"v-only".to_vec()));
                assert_eq!(records[2], (7, Some(Vec::new()), Vec::new()));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// A batch entry as 0.2 and 0.3.0 wrote it, built by hand: no trailer.
    #[test]
    fn a_batch_entry_without_producer_data_still_decodes() {
        let mut bytes = vec![ENTRY_V1];
        bytes.extend_from_slice(&7u64.to_be_bytes());
        bytes.extend_from_slice(&40u64.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&123i64.to_be_bytes());
        bytes.extend_from_slice(&(-1i32).to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(b"hi");
        assert_eq!(
            decode_command(&bytes).unwrap(),
            Command::Batch {
                proposal: 7,
                base_offset: 40,
                records: vec![(123, None, b"hi".to_vec())],
                producer: None,
            }
        );
        assert_eq!(producer_op(&bytes), None);
        // What this build writes for a plain produce is that same entry.
        let ours = encode_batch(7, 40, 123, &[AppendRecord::new(None, b"hi".to_vec())], None);
        assert_eq!(ours, bytes);
    }

    #[test]
    fn a_producer_trailer_roundtrips_and_leaves_the_span_alone() {
        let op = ProducerOp::Produce {
            ts_ms: 5,
            producer_id: "orders.svc".into(),
            owner: "key_a".into(),
            first_sequence: 9,
        };
        let recs = [
            AppendRecord::new(Some(b"k".to_vec()), b"v1".to_vec()),
            AppendRecord::new(None, b"v2".to_vec()),
        ];
        let bytes = encode_batch(1, 30, 5, &recs, Some(&op));
        assert_eq!(batch_span(&bytes), Some((30, 2)));
        assert_eq!(producer_op(&bytes), Some(op.clone()));
        match decode_command(&bytes).unwrap() {
            Command::Batch {
                records, producer, ..
            } => {
                assert_eq!(records.len(), 2);
                assert_eq!(producer, Some(op));
            }
            other => panic!("unexpected {other:?}"),
        }
        // A forget carries no records.
        let forget = ProducerOp::Forget {
            ts_ms: 6,
            producer_id: "orders.svc".into(),
        };
        let bytes = encode_batch(2, 32, 6, &[], Some(&forget));
        assert_eq!(batch_span(&bytes), Some((32, 0)));
        assert_eq!(producer_op(&bytes), Some(forget));
        // Garbage after the records is still refused.
        let mut bad = encode_batch(3, 0, 0, &recs, None);
        bad.extend_from_slice(b"??");
        assert!(decode_command(&bad).is_err());
    }

    /// Applying an entry records its sequences, on any replica, and applying
    /// it again — after a restart, or below a snapshot — changes nothing.
    #[tokio::test]
    async fn applying_an_entry_records_its_sequences_once() {
        let d = tempfile::tempdir().unwrap();
        let p = Partition::open(d.path().to_path_buf(), 0, 4096, 1).unwrap();
        let apply = ApplyLoop {
            partition: p.clone(),
            producers: Default::default(),
            waiters: Arc::new(Mutex::new(HashMap::new())),
            snapshot_after_applies: 0,
            applied: watch::channel(0).0,
        };
        let op = ProducerOp::Produce {
            ts_ms: 1,
            producer_id: "p".into(),
            owner: "k".into(),
            first_sequence: 4,
        };
        let recs = [
            AppendRecord::new(None, b"a".to_vec()),
            AppendRecord::new(None, b"b".to_vec()),
        ];
        let entry = crate::raft::messages::LogEntry {
            term: 1,
            index: 3,
            payload: encode_batch(1, 0, 1, &recs, Some(&op)),
        };
        apply.apply(entry.clone()).await.unwrap();
        apply.apply(entry).await.unwrap();
        let table = apply.producers.lock().unwrap().clone();
        assert_eq!(table.applied(), 3);
        let w = table.window("p").unwrap();
        assert_eq!(
            w.check(5),
            crate::producers::DedupeOutcome::Duplicate { prev_offset: 1 }
        );
        assert_eq!(w.recent.len(), 2, "recorded once");
        assert_eq!(p.end_offset(), 2);
    }

    #[test]
    fn legacy_command_still_decodes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2i32.to_be_bytes());
        bytes.extend_from_slice(b"k1");
        bytes.extend_from_slice(&5u32.to_be_bytes());
        bytes.extend_from_slice(b"hello");
        assert_eq!(
            decode_command(&bytes).unwrap(),
            Command::Legacy {
                key: Some(b"k1".to_vec()),
                value: b"hello".to_vec()
            }
        );
    }

    #[test]
    fn decode_rejects_truncated_input() {
        assert!(decode_command(&[]).is_err());
        let mut bytes = encode_batch(
            1,
            0,
            0,
            &[AppendRecord::new(Some(b"k".to_vec()), b"v".to_vec())],
            None,
        );
        bytes.truncate(bytes.len() - 1);
        assert!(decode_command(&bytes).is_err());
    }

    #[test]
    fn transfer_chunks_roundtrip_between_partitions() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let src = Partition::open(a.path().to_path_buf(), 0, 4096, 1).unwrap();
        let dst = Partition::open(b.path().to_path_buf(), 0, 4096, 1).unwrap();
        let recs: Vec<AppendRecord> = (0..300)
            .map(|i| AppendRecord::new(None, format!("record-{i}").into_bytes()))
            .collect();
        src.append_batch(&recs, Durability::Policy).unwrap();
        let tx = PartitionTransfer {
            partition: src.clone(),
            producers: Default::default(),
        };
        let rx = PartitionTransfer {
            partition: dst.clone(),
            producers: Default::default(),
        };
        let end = src.end_offset();
        let mut from = rx.progress();
        loop {
            let (chunk, done) = tx.read_chunk(from, end, 2048).unwrap();
            rx.apply_chunk(&chunk, done, None).unwrap();
            from = rx.progress();
            if done {
                break;
            }
        }
        assert_eq!(dst.end_offset(), 300);
        let (got, _, _) = dst.read_records_raw(299, 1, 1 << 20).unwrap();
        assert_eq!(got[0].value, b"record-299");
    }

    /// One record, as `read_chunk` encodes it.
    fn chunk_record(out: &mut Vec<u8>, offset: u64) {
        out.extend_from_slice(&offset.to_be_bytes());
        out.extend_from_slice(&0i64.to_be_bytes());
        out.extend_from_slice(&(-1i32).to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.push(b'v');
    }

    #[test]
    fn a_snapshot_chunk_out_of_bounds_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = Partition::open(d.path().to_path_buf(), 0, 4096, 1).unwrap();
        let rx = PartitionTransfer {
            partition: p.clone(),
            producers: Default::default(),
        };

        // An end of u64::MAX would push the next offset past everything.
        let chunk = u64::MAX.to_be_bytes().to_vec();
        assert!(rx.apply_chunk(&chunk, true, None).is_err());
        assert_eq!(p.end_offset(), 0);

        // A record at or past the declared end is not part of the snapshot.
        let mut chunk = 5u64.to_be_bytes().to_vec();
        chunk_record(&mut chunk, 2);
        chunk_record(&mut chunk, 5);
        assert!(rx.apply_chunk(&chunk, false, None).is_err());
        assert_eq!(p.end_offset(), 0, "nothing of a refused chunk is stored");

        let mut chunk = 5u64.to_be_bytes().to_vec();
        chunk_record(&mut chunk, 2);
        rx.apply_chunk(&chunk, true, None).unwrap();
        assert_eq!(p.end_offset(), 5);
    }

    #[tokio::test]
    async fn an_entry_whose_offsets_overflow_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = Partition::open(d.path().to_path_buf(), 0, 4096, 1).unwrap();
        let apply = ApplyLoop {
            partition: p.clone(),
            producers: Default::default(),
            waiters: Arc::new(Mutex::new(HashMap::new())),
            snapshot_after_applies: 0,
            applied: watch::channel(0).0,
        };
        let recs = [
            AppendRecord::new(None, b"a".to_vec()),
            AppendRecord::new(None, b"b".to_vec()),
        ];
        for base in [u64::MAX, u64::MAX - 1, MAX_OFFSET] {
            let entry = crate::raft::messages::LogEntry {
                term: 1,
                index: 1,
                payload: encode_batch(1, base, 0, &recs, None),
            };
            assert!(apply.apply(entry).await.is_err(), "base {base}");
        }
        assert_eq!(p.end_offset(), 0);
    }

    #[test]
    fn append_refuses_an_offset_with_no_successor() {
        let d = tempfile::tempdir().unwrap();
        let p = Partition::open(d.path().to_path_buf(), 0, 4096, 1).unwrap();
        let mut rec = AppendRecord::new(None, b"x".to_vec());
        rec.offset = Some(u64::MAX);
        assert!(p.append_batch(&[rec], Durability::Deferred).is_err());
    }
}
