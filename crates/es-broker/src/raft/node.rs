//! Raft node driver.
//!
//! Owns the [`RaftState`], the election + heartbeat timers, inbound messages,
//! outbound messages, the persistent store, and the committed-entry stream.
//!
//! Every write to the store goes through this loop, and every one completes —
//! durably — before any message that depends on it is sent. A store that
//! fails stops the node (fail-stop): answering after a failed write is how a
//! node votes twice in one term or acknowledges entries it does not have.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use rand::Rng;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::log::{PersistOp, PersistedSnapshot, RaftStore};
use super::messages::{InstallSnapshot, LogEntry, LogIndex, Message, NodeId, PROBE_OFFSET};
use super::state::{Action, ProposeOutcome, RaftState, Role};

#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub election_min: Duration,
    pub election_max: Duration,
    pub heartbeat: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            election_min: Duration::from_millis(150),
            election_max: Duration::from_millis(300),
            heartbeat: Duration::from_millis(50),
        }
    }
}

#[derive(Debug)]
pub enum Outbound {
    SendTo(NodeId, Message),
    Broadcast(Message),
}

/// Reply to a propose request.
#[derive(Debug)]
pub enum ProposeReply {
    Accepted { index: LogIndex },
    NotLeader { leader_hint: Option<NodeId> },
}

/// Reply to a read-index request (dissertation §6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadIndexReply {
    /// Leadership was confirmed by a majority after the request arrived. A
    /// read is linearizable once the state machine has applied every entry
    /// up to `apply_through` — the last entry handed to the `committed`
    /// stream when the read index was fixed, which covers every entry up to
    /// the read index.
    Ready { apply_through: LogIndex },
    /// This node is not the leader, or stopped being it before the read was
    /// confirmed.
    NotLeader { leader_hint: Option<NodeId> },
}

/// Moves state-machine contents to a follower that is behind the leader's
/// snapshot. Implemented by Raft partitions, which ship records rather than an
/// opaque blob. All methods are blocking and are called on a blocking thread.
pub trait SnapshotTransfer: Send + Sync {
    /// Leader: up to `max_bytes` of state starting at position `from`, for a
    /// snapshot whose state ends at `end`. Returns the chunk and whether it is
    /// the last one.
    fn read_chunk(&self, from: u64, end: u64, max_bytes: usize) -> Result<(Vec<u8>, bool)>;
    /// Follower: apply a chunk produced by `read_chunk`.
    fn apply_chunk(&self, data: &[u8], done: bool) -> Result<()>;
    /// Follower: current state-machine position.
    fn progress(&self) -> u64;
    /// Decode the state end position from a snapshot's `data`.
    fn snapshot_end(&self, data: &[u8]) -> u64;
}

/// Bytes of state per snapshot chunk.
pub const SNAPSHOT_CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Clone, Default)]
pub struct NodeOptions {
    /// See [`RaftState::noop_on_elect`].
    pub noop_on_elect: bool,
    /// Chunked state transfer for lagging followers. Without one, a snapshot
    /// is sent as its stored bytes in a single message.
    pub transfer: Option<Arc<dyn SnapshotTransfer>>,
}

struct ProposeReq {
    payload: Vec<u8>,
    ack: oneshot::Sender<ProposeReply>,
}

struct ReadReq {
    ack: oneshot::Sender<ReadIndexReply>,
}

/// A read waiting for its round to be confirmed.
struct PendingRead {
    seq: u64,
    term: u64,
    ack: oneshot::Sender<ReadIndexReply>,
}

struct SnapshotReq {
    data: Vec<u8>,
    through: Option<LogIndex>,
    ack: oneshot::Sender<Result<PersistedSnapshot>>,
}

/// A cloneable way to ask the node loop for a snapshot.
#[derive(Clone)]
pub struct SnapshotSender {
    tx: mpsc::UnboundedSender<SnapshotReq>,
}

impl SnapshotSender {
    /// See [`NodeHandle::take_snapshot_through`].
    pub async fn take(
        &self,
        data: Vec<u8>,
        through: Option<LogIndex>,
    ) -> Result<PersistedSnapshot> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(SnapshotReq {
                data,
                through,
                ack: tx,
            })
            .map_err(|_| anyhow::anyhow!("node loop exited"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("snapshot ack dropped"))?
    }
}

pub struct NodeHandle {
    pub id: NodeId,
    pub state: Arc<Mutex<RaftState>>,
    pub inbound: mpsc::UnboundedSender<Message>,
    outbound: Option<mpsc::UnboundedReceiver<Outbound>>,
    /// Stream of committed log entries. Take this with [`Self::take_committed`]
    /// to drive a state-machine apply loop; otherwise the entries accumulate
    /// in the buffer.
    pub committed: Option<mpsc::UnboundedReceiver<LogEntry>>,
    pub cancel: CancellationToken,
    pub join: Option<JoinHandle<()>>,
    propose_tx: mpsc::UnboundedSender<ProposeReq>,
    snapshot_tx: mpsc::UnboundedSender<SnapshotReq>,
    read_tx: mpsc::UnboundedSender<ReadReq>,
    /// See [`Self::applied_at_start`].
    applied_at_start: LogIndex,
    pub store: Arc<dyn RaftStore>,
    /// When each peer was last heard from, in monotonic time.
    ///
    /// Kept out here rather than in [`RaftState`] on purpose: the state machine is
    /// pure and has no clock, and giving it one to answer a reporting question
    /// would be the wrong trade. Written by the node loop as messages arrive.
    last_contact: Arc<Mutex<BTreeMap<NodeId, Instant>>>,
    failed: Arc<AtomicBool>,
}

impl NodeHandle {
    /// Peers heard from within `within`.
    ///
    /// This is what makes a quorum report mean something. `match_index` records
    /// what a peer once acknowledged and keeps saying so after the peer dies, so a
    /// leader that has lost its majority still looks like it has one.
    pub async fn peers_heard_from(&self, within: Duration) -> Vec<NodeId> {
        let now = Instant::now();
        let map = self.last_contact.lock().await;
        let mut alive: Vec<NodeId> = map
            .iter()
            .filter(|(_, seen)| now.duration_since(**seen) <= within)
            .map(|(peer, _)| *peer)
            .collect();
        alive.sort_unstable();
        alive
    }

    /// Whether the node stopped after its store failed.
    pub fn has_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    pub async fn role(&self) -> Role {
        self.state.lock().await.role
    }
    pub async fn current_term(&self) -> u64 {
        self.state.lock().await.current_term
    }
    pub async fn commit_index(&self) -> u64 {
        self.state.lock().await.commit_index
    }
    pub async fn last_log_index(&self) -> u64 {
        self.state.lock().await.log.last_index()
    }

    /// The index the state machine already reflects when the node starts:
    /// the restored snapshot's. Entries after it reach the state machine
    /// again through `committed`.
    pub fn applied_at_start(&self) -> LogIndex {
        self.applied_at_start
    }

    /// Ask for a read index (dissertation §6.4). On the leader, resolves once
    /// a majority has acknowledged a heartbeat round sent after this call and
    /// the leader has committed an entry of its own term. On any other node,
    /// or if leadership is lost first, resolves to `NotLeader`.
    ///
    /// Does not time out by itself: a leader cut off from its majority keeps
    /// the request pending until it learns of a newer term. Callers bound the
    /// wait; a dropped request is forgotten at the next heartbeat.
    pub async fn read_index(&self) -> Result<ReadIndexReply> {
        let (tx, rx) = oneshot::channel();
        self.read_tx
            .send(ReadReq { ack: tx })
            .map_err(|_| anyhow::anyhow!("node loop exited"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("read index ack dropped"))
    }

    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(j) = self.join.take() {
            let _ = j.await;
        }
    }

    pub fn take_outbound(&mut self) -> Option<mpsc::UnboundedReceiver<Outbound>> {
        self.outbound.take()
    }

    pub fn try_recv_outbound(&mut self) -> Option<Outbound> {
        self.outbound.as_mut().and_then(|r| r.try_recv().ok())
    }

    pub fn take_committed(&mut self) -> Option<mpsc::UnboundedReceiver<LogEntry>> {
        self.committed.take()
    }

    pub fn try_recv_committed(&mut self) -> Option<LogEntry> {
        self.committed.as_mut().and_then(|r| r.try_recv().ok())
    }

    /// Capture a snapshot at the current `last_applied` and persist it.
    pub async fn take_snapshot(&self, data: Vec<u8>) -> Result<PersistedSnapshot> {
        self.take_snapshot_through(data, None).await
    }

    /// Capture a snapshot through `through` (what the application has really
    /// applied) and compact the log behind it. Runs on the node loop, so it is
    /// ordered with every other write to the store.
    pub async fn take_snapshot_through(
        &self,
        data: Vec<u8>,
        through: Option<LogIndex>,
    ) -> Result<PersistedSnapshot> {
        self.snapshot_sender().take(data, through).await
    }

    pub fn snapshot_sender(&self) -> SnapshotSender {
        SnapshotSender {
            tx: self.snapshot_tx.clone(),
        }
    }

    /// Propose a new log entry. Resolves once the entry has been appended to
    /// the leader's log *durably* (NOT yet when committed). Callers monitor
    /// commitment via the `committed` receiver.
    pub async fn propose(&self, payload: Vec<u8>) -> Result<ProposeReply> {
        let (tx, rx) = oneshot::channel();
        self.propose_tx
            .send(ProposeReq { payload, ack: tx })
            .map_err(|_| anyhow::anyhow!("node loop exited"))?;
        rx.await.map_err(|_| anyhow::anyhow!("propose ack dropped"))
    }
}

/// Spawn the node loop.
pub fn spawn_node_with_store(
    me: NodeId,
    peers: Vec<NodeId>,
    timing: Timing,
    store: Arc<dyn RaftStore>,
) -> Result<NodeHandle> {
    spawn_node_with_options(me, peers, timing, store, NodeOptions::default())
}

/// Spawn the node loop with extra behavior.
pub fn spawn_node_with_options(
    me: NodeId,
    peers: Vec<NodeId>,
    timing: Timing,
    store: Arc<dyn RaftStore>,
    options: NodeOptions,
) -> Result<NodeHandle> {
    let mut initial = RaftState::new(me, peers.clone());
    initial.noop_on_elect = options.noop_on_elect;
    let snap = store.load()?;
    let snapshot = store.load_snapshot()?;
    initial.restore(snap, snapshot.as_ref())?;
    let applied_at_start = initial.last_applied;
    let state = Arc::new(Mutex::new(initial));

    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<Message>();
    let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Outbound>();
    let (committed_tx, committed_rx) = mpsc::unbounded_channel::<LogEntry>();
    let (propose_tx, mut propose_rx) = mpsc::unbounded_channel::<ProposeReq>();
    let (snapshot_tx, mut snapshot_rx) = mpsc::unbounded_channel::<SnapshotReq>();
    let (read_tx, mut read_rx) = mpsc::unbounded_channel::<ReadReq>();
    let cancel = CancellationToken::new();
    let failed = Arc::new(AtomicBool::new(false));

    let state_for_task = state.clone();
    let cancel_for_task = cancel.clone();
    let store_for_handle = store.clone();
    let failed_for_task = failed.clone();
    let last_contact: Arc<Mutex<BTreeMap<NodeId, Instant>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let last_contact_for_task = last_contact.clone();
    let join = tokio::spawn(async move {
        let mut d = Driver {
            state: state_for_task,
            store,
            outbound: outbound_tx,
            committed: committed_tx,
            election_deadline: randomized_deadline(timing),
            timing,
            transfer: options.transfer,
            last_leader_contact: None,
            last_handed: applied_at_start,
            pending_reads: Vec::new(),
        };
        let mut heartbeat_tick = tokio::time::interval(timing.heartbeat);
        heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let outcome: Result<()> = async {
            loop {
                // Whatever the last event was — an ack, a commit, a lost
                // election — it may have settled a pending read.
                d.resolve_reads().await;
                let role = d.state.lock().await.role;
                tokio::select! {
                    _ = cancel_for_task.cancelled() => return Ok(()),

                    msg = inbound_rx.recv() => {
                        let Some(msg) = msg else { return Ok(()); };
                        last_contact_for_task
                            .lock()
                            .await
                            .insert(msg.sender(), Instant::now());
                        d.on_message(msg).await?;
                    }

                    req = propose_rx.recv() => {
                        let Some(req) = req else { return Ok(()); };
                        let (reply, actions) = {
                            let mut s = d.state.lock().await;
                            let (outcome, mut actions) = s.try_propose(req.payload);
                            match outcome {
                                ProposeOutcome::Accepted { index } => {
                                    // Replicate now rather than at the next tick.
                                    actions.extend(s.on_heartbeat_tick());
                                    (ProposeReply::Accepted { index }, actions)
                                }
                                ProposeOutcome::NotLeader(hint) => {
                                    (ProposeReply::NotLeader { leader_hint: hint }, actions)
                                }
                            }
                        };
                        // Persist BEFORE acking — the entry must be durable
                        // before anyone is told it was accepted.
                        d.apply_and_persist(actions).await?;
                        let _ = req.ack.send(reply);
                    }

                    req = read_rx.recv() => {
                        let Some(req) = req else { return Ok(()); };
                        d.begin_read(req.ack).await?;
                    }

                    req = snapshot_rx.recv() => {
                        let Some(req) = req else { return Ok(()); };
                        // Outer error: the store failed (fatal). Inner: the
                        // request itself was refused (nothing to snapshot).
                        match d.take_snapshot(req.data, req.through).await {
                            Ok(result) => {
                                let _ = req.ack.send(result);
                            }
                            Err(e) => {
                                let _ = req.ack.send(Err(anyhow::anyhow!("raft store failed: {e:#}")));
                                return Err(e);
                            }
                        }
                    }

                    _ = tokio::time::sleep_until(d.election_deadline) => {
                        let actions = d.state.lock().await.on_election_timeout();
                        d.election_deadline = randomized_deadline(timing);
                        d.apply_and_persist(actions).await?;
                    }

                    _ = heartbeat_tick.tick(), if role == Role::Leader => {
                        let actions = d.state.lock().await.on_heartbeat_tick();
                        d.apply_and_persist(actions).await?;
                    }
                }
            }
        }
        .await;
        if let Err(e) = outcome {
            failed_for_task.store(true, Ordering::Release);
            tracing::error!(node = me, error = %format!("{e:#}"), "raft node stopped: its store failed");
        }
        tracing::debug!(node = me, "raft node loop exited");
    });

    Ok(NodeHandle {
        id: me,
        state,
        inbound: inbound_tx,
        outbound: Some(outbound_rx),
        committed: Some(committed_rx),
        cancel,
        join: Some(join),
        propose_tx,
        snapshot_tx,
        read_tx,
        applied_at_start,
        store: store_for_handle,
        last_contact,
        failed,
    })
}

/// Backwards-compat helper: spawn with an in-memory store.
pub fn spawn_node(me: NodeId, peers: Vec<NodeId>, timing: Timing) -> NodeHandle {
    let store: Arc<dyn RaftStore> = Arc::new(crate::raft::log::MemStore::new());
    spawn_node_with_store(me, peers, timing, store).expect("MemStore can't fail")
}

struct Driver {
    state: Arc<Mutex<RaftState>>,
    store: Arc<dyn RaftStore>,
    outbound: mpsc::UnboundedSender<Outbound>,
    committed: mpsc::UnboundedSender<LogEntry>,
    election_deadline: tokio::time::Instant,
    timing: Timing,
    transfer: Option<Arc<dyn SnapshotTransfer>>,
    /// When an AppendEntries / InstallSnapshot from a current leader last
    /// arrived.
    last_leader_contact: Option<Instant>,
    /// Index of the last entry handed to the `committed` stream.
    last_handed: LogIndex,
    /// Reads waiting for a majority to confirm their round.
    pending_reads: Vec<PendingRead>,
}

impl Driver {
    /// Register a read and send its heartbeat round at once, rather than at
    /// the next tick. A follower answers straight away: it does not ask the
    /// leader for a read index (see `RaftPartition::read_barrier`).
    async fn begin_read(&mut self, ack: oneshot::Sender<ReadIndexReply>) -> Result<()> {
        let (started, term, hint) = {
            let mut s = self.state.lock().await;
            (s.begin_read(), s.current_term, s.leader_hint)
        };
        let Some((seq, actions)) = started else {
            let _ = ack.send(ReadIndexReply::NotLeader { leader_hint: hint });
            return Ok(());
        };
        self.pending_reads.push(PendingRead { seq, term, ack });
        self.apply_and_persist(actions).await
    }

    /// Answer every pending read the state now settles: confirmed ones with
    /// their read index, all of them with `NotLeader` once this node no
    /// longer leads the term they were registered in. A read whose caller has
    /// given up is dropped.
    async fn resolve_reads(&mut self) {
        if self.pending_reads.is_empty() {
            return;
        }
        let (leading_term, hint, confirmed, ready) = {
            let s = self.state.lock().await;
            let leading = (s.role == Role::Leader).then_some(s.current_term);
            (
                leading,
                s.leader_hint,
                s.read_confirmed_seq(),
                s.committed_in_current_term(),
            )
        };
        // Every entry up to the commit index has been handed over by now:
        // the state hands out committed entries in the same step that
        // commits them, and the driver forwards them before coming back here.
        let apply_through = self.last_handed;
        for r in std::mem::take(&mut self.pending_reads) {
            if r.ack.is_closed() {
                continue;
            }
            if leading_term != Some(r.term) {
                let _ = r.ack.send(ReadIndexReply::NotLeader { leader_hint: hint });
            } else if ready && r.seq <= confirmed {
                let _ = r.ack.send(ReadIndexReply::Ready { apply_through });
            } else {
                self.pending_reads.push(r);
            }
        }
    }

    async fn on_message(&mut self, msg: Message) -> Result<()> {
        // Leader stickiness (Raft thesis §4.2.3): a node that heard from a live
        // leader within the minimum election timeout ignores vote requests. A
        // partitioned node that rejoins with a higher term would otherwise
        // depose a healthy leader every time it comes back.
        if let Message::RequestVote(_) = &msg {
            if let Some(t) = self.last_leader_contact {
                if t.elapsed() < self.timing.election_min {
                    return Ok(());
                }
            }
        }
        // Validate before acting: a message from a leader is a sign of life,
        // and a snapshot chunk is written into the state machine, only once
        // the state machine has agreed it would accept the message — member
        // sender, plausible term, not stale, no other leader for that term.
        // Doing either first let a forged chunk with an absurd term write
        // records and silence elections before Raft ever looked at it.
        let from_leader = match &msg {
            Message::AppendEntries(ae) => Some((ae.leader_id, ae.term)),
            Message::InstallSnapshot(is) => Some((is.leader_id, is.term)),
            _ => None,
        };
        let accepted = match from_leader {
            Some((leader, term)) => self.state.lock().await.accepts_from_leader(leader, term),
            None => false,
        };
        if accepted {
            self.last_leader_contact = Some(Instant::now());
        }

        let Message::InstallSnapshot(is) = msg else {
            let actions = self.state.lock().await.on_message(msg);
            return self.apply_and_persist(actions).await;
        };

        // Install path. With a transfer, state chunks are applied to the state
        // machine *before* Raft hears about them, so a `done` chunk is only
        // acknowledged once the state behind it is really there.
        let mut progress = 0u64;
        let mut ok = true;
        if accepted {
            if let Some(t) = self.transfer.clone() {
                if !is.is_probe() {
                    let data = is.data.clone();
                    let done = is.done;
                    let t2 = t.clone();
                    match tokio::task::spawn_blocking(move || t2.apply_chunk(&data, done)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            tracing::error!(error = %e, "raft: applying a snapshot chunk failed");
                            ok = false;
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "raft: snapshot chunk task panicked");
                            ok = false;
                        }
                    }
                }
                progress = t.progress();
            }
        }
        if !ok {
            // Answer with a failure so the leader retries this chunk.
            let (term, me) = {
                let s = self.state.lock().await;
                (s.current_term, s.me)
            };
            let _ = self.outbound.send(Outbound::SendTo(
                is.leader_id,
                Message::InstallSnapshotResp(super::messages::InstallSnapshotResp {
                    term,
                    success: false,
                    responder_id: me,
                    next_offset: progress,
                    installed_index: 0,
                }),
            ));
            return Ok(());
        }
        let pending_snapshot = PersistedSnapshot {
            last_index: is.last_index,
            last_term: is.last_term,
            data: if self.transfer.is_some() {
                // Our own copy of the state ends where the leader's did.
                let end = self
                    .transfer
                    .as_ref()
                    .map(|t| t.progress())
                    .unwrap_or_default();
                end.to_be_bytes().to_vec()
            } else {
                is.data.clone()
            },
        };
        let done = is.done;
        let (actions, installed) = {
            let mut s = self.state.lock().await;
            let before = s.log.base_index;
            let actions = s.on_message_with_progress(Message::InstallSnapshot(is), progress);
            (actions, done && s.log.base_index > before)
        };
        if installed {
            // The snapshot must be on disk before the log compaction it allows.
            let store = self.store.clone();
            let snap = pending_snapshot;
            tokio::task::spawn_blocking(move || store.save_snapshot(&snap))
                .await
                .map_err(|e| anyhow::anyhow!("persist: snapshot task: {e}"))?
                .map_err(|e| anyhow::anyhow!("persist: save received snapshot: {e:#}"))?;
        }
        self.apply_and_persist(actions).await
    }

    async fn take_snapshot(
        &mut self,
        data: Vec<u8>,
        through: Option<LogIndex>,
    ) -> Result<Result<PersistedSnapshot>> {
        let (snap, ops) = {
            let mut s = self.state.lock().await;
            let snap = match s.take_snapshot(data, through) {
                Ok(snap) => snap,
                Err(e) => return Ok(Err(e)),
            };
            // Only the compaction op; anything else pending is persisted by
            // the call below in the same order.
            (snap, s.take_persist_ops())
        };
        let store = self.store.clone();
        let snap_for_store = snap.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            // Snapshot first, then the compaction: a crash in between leaves a
            // longer log, which restore trims.
            store.save_snapshot(&snap_for_store)?;
            store.persist(&ops)
        })
        .await
        .map_err(|e| anyhow::anyhow!("persist: snapshot task: {e}"))?
        .map_err(|e| anyhow::anyhow!("persist: snapshot: {e:#}"))?;
        Ok(Ok(snap))
    }

    /// Make pending state durable, then carry out `actions`.
    async fn apply_and_persist(&mut self, actions: Vec<Action>) -> Result<()> {
        let ops: Vec<PersistOp> = self.state.lock().await.take_persist_ops();
        if !ops.is_empty() {
            let store = self.store.clone();
            tokio::task::spawn_blocking(move || store.persist(&ops))
                .await
                .map_err(|e| anyhow::anyhow!("persist task: {e}"))?
                .map_err(|e| anyhow::anyhow!("persist raft state: {e:#}"))?;
        }
        for a in actions {
            match a {
                Action::SendTo(peer, msg) => {
                    let _ = self.outbound.send(Outbound::SendTo(peer, msg));
                }
                Action::Broadcast(msg) => {
                    let _ = self.outbound.send(Outbound::Broadcast(msg));
                }
                Action::ResetElectionTimer => {
                    self.election_deadline = randomized_deadline(self.timing);
                }
                Action::Apply(entry) => {
                    self.last_handed = entry.index;
                    let _ = self.committed.send(entry);
                }
                Action::SendSnapshot(peer) => self.send_snapshot(peer).await,
            }
        }
        Ok(())
    }

    async fn send_snapshot(&mut self, peer: NodeId) {
        let (term, me, base_index, cursor) = {
            let s = self.state.lock().await;
            (
                s.current_term,
                s.me,
                s.log.base_index,
                s.snapshot_cursor.get(&peer).copied(),
            )
        };
        let store = self.store.clone();
        let snap = match tokio::task::spawn_blocking(move || store.load_snapshot()).await {
            Ok(Ok(Some(s))) => s,
            Ok(Ok(None)) => {
                let mut s = self.state.lock().await;
                s.next_index.insert(peer, base_index + 1);
                tracing::warn!(peer, "raft: SendSnapshot but no snapshot available");
                return;
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, "raft: failed to load snapshot");
                return;
            }
            Err(e) => {
                tracing::error!(error = %e, "raft: snapshot load task panicked");
                return;
            }
        };
        let msg = match (&self.transfer, cursor) {
            (None, _) => InstallSnapshot {
                term,
                leader_id: me,
                last_index: snap.last_index,
                last_term: snap.last_term,
                offset: 0,
                done: true,
                data: snap.data,
            },
            (Some(_), None) => InstallSnapshot {
                term,
                leader_id: me,
                last_index: snap.last_index,
                last_term: snap.last_term,
                offset: PROBE_OFFSET,
                done: false,
                data: Vec::new(),
            },
            (Some(t), Some(from)) => {
                let t = t.clone();
                let end = t.snapshot_end(&snap.data);
                let chunk = tokio::task::spawn_blocking(move || {
                    t.read_chunk(from, end, SNAPSHOT_CHUNK_BYTES)
                })
                .await;
                let (data, done) = match chunk {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => {
                        tracing::error!(error = %e, peer, "raft: reading a snapshot chunk failed");
                        return;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "raft: snapshot chunk task panicked");
                        return;
                    }
                };
                InstallSnapshot {
                    term,
                    leader_id: me,
                    last_index: snap.last_index,
                    last_term: snap.last_term,
                    offset: from,
                    done,
                    data,
                }
            }
        };
        let _ = self
            .outbound
            .send(Outbound::SendTo(peer, Message::InstallSnapshot(msg)));
    }
}

fn randomized_deadline(timing: Timing) -> tokio::time::Instant {
    let span = timing.election_max - timing.election_min;
    let extra = if span.is_zero() {
        Duration::ZERO
    } else {
        let nanos = rand::thread_rng().gen_range(0..span.as_nanos() as u64);
        Duration::from_nanos(nanos)
    };
    tokio::time::Instant::now() + timing.election_min + extra
}

/// Test-only helper: drain each node's outbound queue and route messages
/// directly to the destination nodes' inbound channels.
pub async fn pump_outbound(
    handles: &mut std::collections::BTreeMap<NodeId, NodeHandle>,
    deadline: std::time::Instant,
) -> Result<()> {
    use std::time::Instant;
    let inbound_for: std::collections::BTreeMap<NodeId, mpsc::UnboundedSender<Message>> = handles
        .iter()
        .map(|(k, v)| (*k, v.inbound.clone()))
        .collect();

    loop {
        let mut delivered_any = false;
        for (id, h) in handles.iter_mut() {
            while let Some(out) = h.try_recv_outbound() {
                delivered_any = true;
                match out {
                    Outbound::SendTo(peer, msg) => {
                        if let Some(s) = inbound_for.get(&peer) {
                            let _ = s.send(msg);
                        }
                    }
                    Outbound::Broadcast(msg) => {
                        for (other_id, s) in inbound_for.iter() {
                            if *other_id == *id {
                                continue;
                            }
                            let _ = s.send(msg.clone());
                        }
                    }
                }
            }
        }
        if !delivered_any {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        if Instant::now() >= deadline {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::messages::{AppendEntries, RequestVote, Term};

    /// Records every chunk the driver hands to the state machine.
    #[derive(Default)]
    struct Recorder {
        chunks: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl SnapshotTransfer for Recorder {
        fn read_chunk(&self, _: u64, _: u64, _: usize) -> Result<(Vec<u8>, bool)> {
            Ok((Vec::new(), true))
        }
        fn apply_chunk(&self, data: &[u8], _done: bool) -> Result<()> {
            self.chunks.lock().unwrap().push(data.to_vec());
            Ok(())
        }
        fn progress(&self) -> u64 {
            0
        }
        fn snapshot_end(&self, _: &[u8]) -> u64 {
            0
        }
    }

    /// Node 2 of {1, 2, 3}, with timers too long to fire during a test.
    fn follower() -> (NodeHandle, Arc<Recorder>) {
        let rec = Arc::new(Recorder::default());
        let timing = Timing {
            election_min: Duration::from_secs(30),
            election_max: Duration::from_secs(60),
            heartbeat: Duration::from_secs(30),
        };
        let store: Arc<dyn RaftStore> = Arc::new(crate::raft::log::MemStore::new());
        let options = NodeOptions {
            noop_on_elect: false,
            transfer: Some(rec.clone()),
        };
        let h = spawn_node_with_options(2, vec![1, 3], timing, store, options).unwrap();
        (h, rec)
    }

    fn chunk(leader: NodeId, term: Term, marker: &[u8]) -> Message {
        Message::InstallSnapshot(InstallSnapshot {
            term,
            leader_id: leader,
            last_index: 10,
            last_term: term,
            offset: 0,
            done: false,
            data: marker.to_vec(),
        })
    }

    async fn next_outbound(h: &mut NodeHandle) -> Option<Outbound> {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Some(o) = h.try_recv_outbound() {
                return Some(o);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        None
    }

    #[tokio::test]
    async fn a_snapshot_chunk_is_applied_only_from_the_accepted_leader() {
        let (mut h, rec) = follower();
        // Node 1 leads term 1.
        h.inbound
            .send(Message::AppendEntries(AppendEntries {
                term: 1,
                leader_id: 1,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
                read_seq: 0,
            }))
            .unwrap();
        assert!(next_outbound(&mut h).await.is_some(), "heartbeat answered");

        h.inbound.send(chunk(3, 1, b"second leader")).unwrap();
        h.inbound.send(chunk(9, 1, b"non-member")).unwrap();
        h.inbound.send(chunk(1, Term::MAX, b"absurd term")).unwrap();
        h.inbound
            .send(chunk(1, 1 + (1 << 21), b"term jump"))
            .unwrap();
        h.inbound.send(chunk(1, 0, b"stale term")).unwrap();
        h.inbound.send(chunk(1, 1, b"leader")).unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        while rec.chunks.lock().unwrap().is_empty() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Messages are handled in order, so the leader's chunk arriving means
        // every earlier one was already turned away.
        assert_eq!(*rec.chunks.lock().unwrap(), vec![b"leader".to_vec()]);
        assert_eq!(h.current_term().await, 1, "no forged term was adopted");
        h.shutdown().await;
    }

    /// A refused message is no sign of a live leader: it must not make the
    /// node ignore an election.
    #[tokio::test]
    async fn a_refused_snapshot_does_not_suppress_elections() {
        let (mut h, rec) = follower();
        h.inbound.send(chunk(1, Term::MAX, b"absurd term")).unwrap();
        h.inbound
            .send(Message::RequestVote(RequestVote {
                term: 1,
                candidate_id: 3,
                last_log_index: 0,
                last_log_term: 0,
            }))
            .unwrap();
        let reply = next_outbound(&mut h).await;
        assert!(
            matches!(
                reply,
                Some(Outbound::SendTo(3, Message::RequestVoteResp(ref r))) if r.vote_granted
            ),
            "the vote request must be answered: {reply:?}"
        );
        assert!(rec.chunks.lock().unwrap().is_empty());
        h.shutdown().await;
    }
}
