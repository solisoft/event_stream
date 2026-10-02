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
    let state = Arc::new(Mutex::new(initial));

    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<Message>();
    let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Outbound>();
    let (committed_tx, committed_rx) = mpsc::unbounded_channel::<LogEntry>();
    let (propose_tx, mut propose_rx) = mpsc::unbounded_channel::<ProposeReq>();
    let (snapshot_tx, mut snapshot_rx) = mpsc::unbounded_channel::<SnapshotReq>();
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
        };
        let mut heartbeat_tick = tokio::time::interval(timing.heartbeat);
        heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let outcome: Result<()> = async {
            loop {
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
}

impl Driver {
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
        let current_term = self.state.lock().await.current_term;
        match &msg {
            Message::AppendEntries(ae) if ae.term >= current_term => {
                self.last_leader_contact = Some(Instant::now());
            }
            Message::InstallSnapshot(is) if is.term >= current_term => {
                self.last_leader_contact = Some(Instant::now());
            }
            _ => {}
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
        if is.term >= current_term {
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
