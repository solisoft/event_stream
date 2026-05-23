//! Raft node driver. Owns the [`RaftState`], the election + heartbeat timers,
//! the inbound message queue, and an outbound channel to the transport.
//!
//! The state machine itself is pure; this module is the impure shell that
//! actually executes [`Action`]s and fires timers.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rand::Rng;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::messages::{Message, NodeId};
use super::state::{Action, RaftState, Role};

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

/// Things the driver emits to the transport: "deliver this message to that peer."
#[derive(Debug)]
pub enum Outbound {
    SendTo(NodeId, Message),
    Broadcast(Message),
}

/// Handle returned to the surrounding code so it can observe / shut down the node.
pub struct NodeHandle {
    pub id: NodeId,
    pub state: Arc<Mutex<RaftState>>,
    pub inbound: mpsc::UnboundedSender<Message>,
    /// Outbound messages emitted by the node loop. `take_outbound()` hands
    /// ownership to a transport; `pump_outbound()` consumes it directly for
    /// in-process tests.
    outbound: Option<mpsc::UnboundedReceiver<Outbound>>,
    pub cancel: CancellationToken,
    pub join: Option<JoinHandle<()>>,
}

impl NodeHandle {
    pub async fn role(&self) -> Role {
        self.state.lock().await.role
    }
    pub async fn current_term(&self) -> u64 {
        self.state.lock().await.current_term
    }
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(j) = self.join.take() {
            let _ = j.await;
        }
    }
    /// Take ownership of the outbound channel — typically to hand it to a
    /// `Transport`. Returns `None` if it's already been taken.
    pub fn take_outbound(&mut self) -> Option<mpsc::UnboundedReceiver<Outbound>> {
        self.outbound.take()
    }
    /// Receive one outbound message (test helper / `pump_outbound`). Returns
    /// `None` if the channel was already taken or the node loop exited.
    pub fn try_recv_outbound(&mut self) -> Option<Outbound> {
        self.outbound.as_mut().and_then(|r| r.try_recv().ok())
    }
}

/// Spawn the node loop. Returns the handle holding inbound/outbound channels
/// plus the shared state for observation.
///
/// The caller wires `inbound`/`outbound` up to a transport. For the in-process
/// integration test, that's a hub that just forwards messages between nodes.
pub fn spawn_node(me: NodeId, peers: Vec<NodeId>, timing: Timing) -> NodeHandle {
    let state = Arc::new(Mutex::new(RaftState::new(me, peers)));
    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<Message>();
    let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Outbound>();
    let cancel = CancellationToken::new();

    let state_for_task = state.clone();
    let cancel_for_task = cancel.clone();
    let join = tokio::spawn(async move {
        let mut election_deadline = randomized_deadline(timing);
        let mut heartbeat_tick = tokio::time::interval(timing.heartbeat);
        heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            // Snapshot whether we're currently the leader; that decides whether
            // the heartbeat tick is meaningful this loop.
            let role = state_for_task.lock().await.role;

            tokio::select! {
                _ = cancel_for_task.cancelled() => break,

                msg = inbound_rx.recv() => {
                    let Some(msg) = msg else { break; };
                    let actions = state_for_task.lock().await.on_message(msg);
                    apply(&state_for_task, &outbound_tx, &mut election_deadline, timing, actions).await;
                }

                _ = tokio::time::sleep_until(election_deadline) => {
                    let actions = state_for_task.lock().await.on_election_timeout();
                    apply(&state_for_task, &outbound_tx, &mut election_deadline, timing, actions).await;
                    // Always reset the deadline after firing.
                    election_deadline = randomized_deadline(timing);
                }

                _ = heartbeat_tick.tick(), if role == Role::Leader => {
                    let actions = state_for_task.lock().await.on_heartbeat_tick();
                    apply(&state_for_task, &outbound_tx, &mut election_deadline, timing, actions).await;
                }
            }
        }
        tracing::debug!(node = me, "raft node loop exited");
    });

    NodeHandle {
        id: me,
        state,
        inbound: inbound_tx,
        outbound: Some(outbound_rx),
        cancel,
        join: Some(join),
    }
}

async fn apply(
    _state: &Arc<Mutex<RaftState>>,
    outbound: &mpsc::UnboundedSender<Outbound>,
    election_deadline: &mut tokio::time::Instant,
    timing: Timing,
    actions: Vec<Action>,
) {
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
/// directly to the destination nodes' inbound channels. Real deployments use
/// the TCP transport (`transport.rs`).
pub async fn pump_outbound(
    handles: &mut std::collections::BTreeMap<NodeId, NodeHandle>,
    deadline: std::time::Instant,
) -> Result<()> {
    use std::time::Instant;
    // Snapshot inbound senders once — they're cheap to clone (mpsc Sender is Arc-y).
    let inbound_for: std::collections::BTreeMap<NodeId, mpsc::UnboundedSender<Message>> =
        handles
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
