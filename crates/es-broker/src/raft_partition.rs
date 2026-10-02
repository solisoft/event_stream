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

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::partition::{now_ms, AppendRecord, Durability, Partition};
use crate::raft::state::{is_config_entry, RaftState};
use crate::raft::{
    spawn_node_with_options,
    transport::{RaftHub, Transport},
    JsonStore, LogIndex, NodeHandle, NodeId, NodeOptions, Outbound, ProposeReply, RaftStore,
    SnapshotSender, SnapshotTransfer, Timing,
};
use tokio::sync::Mutex as TokioMutex;

/// Version tag of a data entry. Entries written before batching began with an
/// `i32` key length instead, whose first byte is 0x00 or 0xFF.
const ENTRY_V1: u8 = 0x01;

/// A decoded data entry.
#[derive(Debug, PartialEq)]
enum Command {
    Batch {
        proposal: u64,
        base_offset: u64,
        records: Vec<(i64, Option<Vec<u8>>, Vec<u8>)>,
    },
    /// The pre-batching single-record format. Its offset was the entry's
    /// index minus one by construction.
    Legacy {
        key: Option<Vec<u8>>,
        value: Vec<u8>,
    },
}

fn encode_batch(proposal: u64, base_offset: u64, ts: i64, records: &[AppendRecord]) -> Vec<u8> {
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
    out
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
        if c.p != bytes.len() {
            return Err(anyhow!("trailing bytes after batch entry"));
        }
        return Ok(Command::Batch {
            proposal,
            base_offset,
            records,
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
}

#[derive(Debug, Clone)]
pub struct RaftPartitionConfig {
    pub node_id: NodeId,
    pub peers: Vec<NodeId>,
    pub raft_store_path: PathBuf,
    pub timing: Timing,
    pub snapshot_after_applies: u32,
}

#[derive(Debug, Clone)]
pub struct RaftTransportConfig {
    pub bind: SocketAddr,
    pub peer_addrs: BTreeMap<NodeId, SocketAddr>,
    /// Pre-shared secret peers must present in the raft handshake. `None`
    /// disables peer authentication (only allowed on a loopback bind).
    pub shared_secret: Option<String>,
}

impl RaftPartitionConfig {
    pub fn with_defaults(node_id: NodeId, raft_store_path: PathBuf) -> Self {
        Self {
            node_id,
            peers: Vec::new(),
            raft_store_path,
            timing: Timing::default(),
            snapshot_after_applies: 1024,
        }
    }
}

/// Ships partition records to a lagging follower.
///
/// Chunk format: `end u64` (the state end of the snapshot being installed),
/// then records as `offset u64 | ts i64 | key (i32 len, -1 = none) | value
/// (u32 len)`.
struct PartitionTransfer {
    partition: Arc<Partition>,
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

    fn apply_chunk(&self, data: &[u8], done: bool) -> Result<()> {
        let mut c = Cur { b: data, p: 0 };
        let end = c.u64()?;
        let mut recs = Vec::new();
        while c.p < data.len() {
            let offset = c.u64()?;
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
        let options = NodeOptions {
            noop_on_elect: true,
            transfer: Some(Arc::new(PartitionTransfer {
                partition: partition.clone(),
            })),
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

        let apply = ApplyLoop {
            partition: partition.clone(),
            waiters: waiters.clone(),
            snapshot_after_applies: config.snapshot_after_applies,
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

        let reply = {
            let _guard = self.propose_lock.lock().await;
            let base = self.next_assignable_offset().await;
            let payload = encode_batch(proposal, base, now_ms(), &records);
            self.raft.propose(payload).await
        };
        let index = match reply {
            Ok(ProposeReply::Accepted { index }) => index,
            Ok(ProposeReply::NotLeader { leader_hint }) => {
                self.waiters.lock().unwrap().remove(&proposal);
                return Err(anyhow!(
                    "not leader (hint: {:?}); produce must be routed to the leader",
                    leader_hint
                ));
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
    waiters: Waiters,
    snapshot_after_applies: u32,
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
        let (proposal, records) = match decode_command(&entry.payload)? {
            Command::Batch {
                proposal,
                base_offset,
                records,
            } => {
                let recs: Vec<AppendRecord> = records
                    .into_iter()
                    .enumerate()
                    .map(|(i, (ts, key, value))| AppendRecord {
                        key,
                        value,
                        timestamp_ms: Some(ts),
                        offset: Some(base_offset + i as u64),
                    })
                    .collect();
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
        let p = self.partition.clone();
        let offsets =
            tokio::task::spawn_blocking(move || p.append_batch(&records, Durability::Deferred))
                .await
                .map_err(|e| anyhow!("apply task: {e}"))??;

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
        raft.take(end.to_be_bytes().to_vec(), Some(through)).await?;
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
        let bytes = encode_batch(42, 100, 7, &recs);
        assert_eq!(batch_span(&bytes), Some((100, 3)));
        match decode_command(&bytes).unwrap() {
            Command::Batch {
                proposal,
                base_offset,
                records,
            } => {
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
        };
        let rx = PartitionTransfer {
            partition: dst.clone(),
        };
        let end = src.end_offset();
        let mut from = rx.progress();
        loop {
            let (chunk, done) = tx.read_chunk(from, end, 2048).unwrap();
            rx.apply_chunk(&chunk, done).unwrap();
            from = rx.progress();
            if done {
                break;
            }
        }
        assert_eq!(dst.end_offset(), 300);
        let (got, _, _) = dst.read_records_raw(299, 1, 1 << 20).unwrap();
        assert_eq!(got[0].value, b"record-299");
    }
}
