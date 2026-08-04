//! Raft node driver.
//!
//! Owns the [`RaftState`], the election + heartbeat timers, inbound messages,
//! outbound messages, the persistent store, and the committed-entry stream.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use rand::Rng;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::log::{PersistedSnapshot, RaftStore};
use super::messages::{InstallSnapshot, LogEntry, LogIndex, Message, NodeId};
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

struct ProposeReq {
    payload: Vec<u8>,
    ack: oneshot::Sender<ProposeReply>,
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
    /// Shared with the node loop so application-triggered snapshots can be
    /// persisted alongside everything else the loop persists.
    pub store: Arc<dyn RaftStore>,
    /// When each peer was last heard from, in monotonic time.
    ///
    /// Kept out here rather than in [`RaftState`] on purpose: the state machine is
    /// pure and has no clock, and giving it one to answer a reporting question
    /// would be the wrong trade. Written by the node loop as messages arrive.
    last_contact: Arc<Mutex<BTreeMap<NodeId, Instant>>>,
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

    /// Capture a Raft snapshot at the current `last_applied` and persist it.
    /// The log is compacted in-memory and on the next persist cycle the
    /// shrunken log file is written out.
    pub async fn take_snapshot(&self, data: Vec<u8>) -> Result<PersistedSnapshot> {
        let (snap, persisted) = {
            let mut s = self.state.lock().await;
            let snap = s.take_snapshot(data)?;
            // The log was compacted; capture a fresh persisted-log snapshot
            // so save_all writes the trimmed version.
            let persisted = s.snapshot_persistent();
            (snap, persisted)
        };
        // Persist snapshot first, then the trimmed log. If we crash between
        // these, the snapshot is durable and the larger log is harmless — on
        // restart we'd re-apply log entries above the snapshot, which is the
        // normal behavior.
        self.store.save_snapshot(&snap)?;
        self.store.save_all(&persisted)?;
        Ok(snap)
    }

    /// Propose a new log entry. Resolves when the entry has been appended to
    /// the leader's log (NOT yet when committed). Callers monitor commitment
    /// via the `committed` receiver.
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
    let mut initial = RaftState::new(me, peers.clone());
    let snap = store.load()?;
    let snapshot = store.load_snapshot()?;
    initial.restore(snap, snapshot.as_ref())?;
    let state = Arc::new(Mutex::new(initial));

    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<Message>();
    let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Outbound>();
    let (committed_tx, committed_rx) = mpsc::unbounded_channel::<LogEntry>();
    let (propose_tx, mut propose_rx) = mpsc::unbounded_channel::<ProposeReq>();
    let cancel = CancellationToken::new();

    let state_for_task = state.clone();
    let cancel_for_task = cancel.clone();
    let store_for_handle = store.clone();
    // Written by the loop as messages arrive, read by `peers_heard_from`.
    let last_contact: Arc<Mutex<BTreeMap<NodeId, Instant>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let last_contact_for_task = last_contact.clone();
    let join = tokio::spawn(async move {
        let mut election_deadline = randomized_deadline(timing);
        let mut heartbeat_tick = tokio::time::interval(timing.heartbeat);
        heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            let role = state_for_task.lock().await.role;

            tokio::select! {
                _ = cancel_for_task.cancelled() => break,

                msg = inbound_rx.recv() => {
                    let Some(msg) = msg else { break; };
                    // Before anything else: this peer is alive. Recorded for every
                    // message, request or response, because either one proves the
                    // same thing.
                    last_contact_for_task
                        .lock()
                        .await
                        .insert(msg.sender(), Instant::now());
                    // Hold the snapshot bytes aside and persist them only if the
                    // state machine actually accepts the snapshot. Persisting
                    // before validation lets a rejected or forged InstallSnapshot
                    // land on disk and corrupt state on the next restart.
                    let pending_snapshot = if let Message::InstallSnapshot(ref is) = msg {
                        Some(PersistedSnapshot {
                            last_index: is.last_index,
                            last_term: is.last_term,
                            data: is.data.clone(),
                        })
                    } else {
                        None
                    };
                    let (actions, snapshot_accepted) = {
                        let mut s = state_for_task.lock().await;
                        let before_base = s.log.base_index;
                        let actions = s.on_message(msg);
                        // A snapshot is accepted iff it advanced the log's base.
                        (actions, s.log.base_index > before_base)
                    };
                    if snapshot_accepted {
                        if let Some(snap) = pending_snapshot {
                            if let Err(e) = store.save_snapshot(&snap) {
                                tracing::error!(error = %e, "raft: failed to save received snapshot");
                            }
                        }
                    }
                    apply_and_persist(&state_for_task, &store, &outbound_tx, &committed_tx,
                                      &mut election_deadline, timing, actions).await;
                }

                req = propose_rx.recv() => {
                    let Some(req) = req else { break; };
                    let (reply, mut actions) = {
                        let mut s = state_for_task.lock().await;
                        let (outcome, apply_actions) = s.try_propose(req.payload);
                        match outcome {
                            ProposeOutcome::Accepted { index } => {
                                // Trigger immediate replication on top of any
                                // Apply actions (single-node clusters commit
                                // synchronously).
                                let mut all = apply_actions;
                                all.extend(s.on_heartbeat_tick());
                                (ProposeReply::Accepted { index }, all)
                            }
                            ProposeOutcome::NotLeader(hint) => {
                                (ProposeReply::NotLeader { leader_hint: hint }, apply_actions)
                            }
                        }
                    };
                    // Persist BEFORE acking — Raft requires the new log entry
                    // to be durable before we tell the client it succeeded.
                    apply_and_persist(&state_for_task, &store, &outbound_tx, &committed_tx,
                                      &mut election_deadline, timing, std::mem::take(&mut actions)).await;
                    let _ = req.ack.send(reply);
                }

                _ = tokio::time::sleep_until(election_deadline) => {
                    let actions = {
                        let mut s = state_for_task.lock().await;
                        s.on_election_timeout()
                    };
                    apply_and_persist(&state_for_task, &store, &outbound_tx, &committed_tx,
                                      &mut election_deadline, timing, actions).await;
                    election_deadline = randomized_deadline(timing);
                }

                _ = heartbeat_tick.tick(), if role == Role::Leader => {
                    let actions = {
                        let mut s = state_for_task.lock().await;
                        s.on_heartbeat_tick()
                    };
                    apply_and_persist(&state_for_task, &store, &outbound_tx, &committed_tx,
                                      &mut election_deadline, timing, actions).await;
                }
            }
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
        store: store_for_handle,
        last_contact,
    })
}

/// Backwards-compat helper: spawn with an in-memory store.
pub fn spawn_node(me: NodeId, peers: Vec<NodeId>, timing: Timing) -> NodeHandle {
    let store: Arc<dyn RaftStore> = Arc::new(crate::raft::log::MemStore::new());
    spawn_node_with_store(me, peers, timing, store).expect("MemStore can't fail")
}

async fn apply_and_persist(
    state: &Arc<Mutex<RaftState>>,
    store: &Arc<dyn RaftStore>,
    outbound: &mpsc::UnboundedSender<Outbound>,
    committed: &mpsc::UnboundedSender<LogEntry>,
    election_deadline: &mut tokio::time::Instant,
    timing: Timing,
    actions: Vec<Action>,
) {
    // Persistence MUST happen before any outbound messages — Raft requires
    // current_term / voted_for / log to be durable before responding.
    let dirty = state.lock().await.take_dirty();
    if dirty {
        let snap = state.lock().await.snapshot_persistent();
        // store.save_all is sync (file write + fsync). Tiny pause OK for step 2.
        if let Err(e) = store.save_all(&snap) {
            tracing::error!(error = %e, "raft store save failed");
        }
    }
    for a in actions {
        match a {
            Action::SendTo(peer, msg) => {
                let _ = outbound.send(Outbound::SendTo(peer, msg));
            }
            Action::Broadcast(msg) => {
                let _ = outbound.send(Outbound::Broadcast(msg));
            }
            Action::ResetElectionTimer => {
                *election_deadline = randomized_deadline(timing);
            }
            Action::Apply(entry) => {
                let _ = committed.send(entry);
            }
            Action::SendSnapshot(peer) => {
                let (term, my_id, base_index) = {
                    let s = state.lock().await;
                    (s.current_term, s.me, s.log.base_index)
                };
                match store.load_snapshot() {
                    Ok(Some(snap)) => {
                        let msg = Message::InstallSnapshot(InstallSnapshot {
                            term,
                            leader_id: my_id,
                            last_index: snap.last_index,
                            last_term: snap.last_term,
                            offset: 0,
                            done: true,
                            data: snap.data,
                        });
                        let _ = outbound.send(Outbound::SendTo(peer, msg));
                    }
                    Ok(None) => {
                        let mut s = state.lock().await;
                        s.next_index.insert(peer, base_index + 1);
                        tracing::warn!(peer = peer, "raft: SendSnapshot but no snapshot available");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "raft: failed to load snapshot");
                    }
                }
            }
        }
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
