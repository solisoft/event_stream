//! Raft state machine: election, log replication, commit advancement,
//! snapshots.
//!
//! Pure (no I/O). The driver in `node.rs` calls one of `on_*` per event and
//! executes the returned [`Action`]s. Every change to persistent state
//! (`current_term`, `voted_for`, the log) is recorded as a [`PersistOp`]; the
//! driver drains them with [`RaftState::take_persist_ops`] and makes them
//! durable **before** sending any message the actions contain.

use std::collections::{BTreeMap, HashSet};

use super::log::{Log, PersistOp, PersistedRaft, PersistedSnapshot};
use super::messages::{
    AppendEntries, AppendEntriesResp, InstallSnapshot, InstallSnapshotResp, LogEntry, LogIndex,
    Message, NodeId, RequestVote, RequestVoteResp, Term,
};

/// Most entries one AppendEntries carries.
pub const MAX_APPEND_ENTRIES: usize = 1024;
/// Most payload bytes one AppendEntries carries (a single larger entry is
/// still sent alone). Keeps every frame far below the transport's cap: an
/// unbounded batch to a lagging follower used to exceed it, the follower
/// dropped the connection, and the leader rebuilt the same frame forever.
pub const MAX_APPEND_BYTES: usize = 4 * 1024 * 1024;
/// A message whose term is further than this ahead of ours is ignored. Terms
/// grow by one per election; a jump of a million is not a partition healing,
/// it is a forged or corrupt message — and one carrying `u64::MAX` would pin
/// every node at a term no election can ever exceed.
pub const MAX_TERM_JUMP: Term = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Follower,
    Candidate,
    Leader,
}

#[derive(Debug, Clone)]
pub enum Action {
    SendTo(NodeId, Message),
    Broadcast(Message),
    ResetElectionTimer,
    /// Hand a committed entry to the state machine.
    Apply(LogEntry),
    /// Leader needs to send (the next chunk of) a snapshot to this peer.
    SendSnapshot(NodeId),
}

#[derive(Debug)]
pub struct RaftState {
    pub me: NodeId,
    pub peers: Vec<NodeId>,
    pub role: Role,
    pub current_term: Term,
    pub voted_for: Option<NodeId>,
    pub leader_hint: Option<NodeId>,

    pub log: Log,
    pub commit_index: LogIndex,
    /// Highest index handed to the state machine (queued for application —
    /// not necessarily applied yet; the application tracks that itself).
    pub last_applied: LogIndex,

    /// Leader-only: highest log index known to be replicated on each peer.
    pub match_index: BTreeMap<NodeId, LogIndex>,
    /// Leader-only: next log index the leader will send to each peer.
    pub next_index: BTreeMap<NodeId, LogIndex>,
    /// Leader-only: state-machine position of an in-progress snapshot
    /// transfer per peer. Absent means the next snapshot message is a probe.
    pub snapshot_cursor: BTreeMap<NodeId, u64>,

    /// Append an empty entry on winning an election, so entries from earlier
    /// terms commit (§5.4.2 forbids committing them by counting) without
    /// waiting for a client write.
    pub noop_on_elect: bool,

    votes_received: HashSet<NodeId>,
    pending: Vec<PersistOp>,
}

const CONFIG_MAGIC: [u8; 4] = [0xEE, 0xEE, 0xEE, 0xEE];

pub fn encode_config_change(add: Vec<NodeId>, remove: Vec<NodeId>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&CONFIG_MAGIC);
    out.extend_from_slice(&(add.len() as u32).to_be_bytes());
    for id in &add {
        out.extend_from_slice(&id.to_be_bytes());
    }
    out.extend_from_slice(&(remove.len() as u32).to_be_bytes());
    for id in &remove {
        out.extend_from_slice(&id.to_be_bytes());
    }
    out
}

fn decode_config_change(payload: &[u8]) -> Option<(Vec<NodeId>, Vec<NodeId>)> {
    if payload.len() < 8 || payload[..4] != CONFIG_MAGIC {
        return None;
    }
    // Bounds-checked reader over the payload. `take_u32` uses `.get(..)` so a
    // truncated or lying length field yields `None` instead of panicking, and
    // capacities are bounded by the bytes actually remaining so a huge declared
    // count can't drive a giant allocation.
    fn take_u32(payload: &[u8], pos: &mut usize) -> Option<u32> {
        let end = pos.checked_add(4)?;
        let slice = payload.get(*pos..end)?;
        *pos = end;
        Some(u32::from_be_bytes(slice.try_into().ok()?))
    }
    fn take_ids(payload: &[u8], pos: &mut usize) -> Option<Vec<NodeId>> {
        let len = take_u32(payload, pos)? as usize;
        let remaining_ids = payload.len().saturating_sub(*pos) / 4;
        let mut out = Vec::with_capacity(len.min(remaining_ids));
        for _ in 0..len {
            out.push(take_u32(payload, pos)?);
        }
        Some(out)
    }
    let mut pos = 4usize;
    let add = take_ids(payload, &mut pos)?;
    let remove = take_ids(payload, &mut pos)?;
    Some((add, remove))
}

pub fn is_config_entry(payload: &[u8]) -> bool {
    payload.len() >= 4 && payload[..4] == CONFIG_MAGIC
}

impl RaftState {
    pub fn new(me: NodeId, peers: Vec<NodeId>) -> Self {
        Self {
            me,
            peers,
            role: Role::Follower,
            current_term: 0,
            voted_for: None,
            leader_hint: None,
            log: Log::default(),
            commit_index: 0,
            last_applied: 0,
            match_index: BTreeMap::new(),
            next_index: BTreeMap::new(),
            snapshot_cursor: BTreeMap::new(),
            noop_on_elect: false,
            votes_received: HashSet::new(),
            pending: Vec::new(),
        }
    }

    /// Restore from persisted state + an optional state-machine snapshot.
    /// When a snapshot is present, its `last_index` becomes the log's base —
    /// any log entries the driver re-applies will only carry indices above it.
    pub fn restore(
        &mut self,
        persisted: PersistedRaft,
        snapshot: Option<&PersistedSnapshot>,
    ) -> anyhow::Result<()> {
        self.current_term = persisted.current_term;
        self.voted_for = persisted.voted_for;
        self.log = persisted.into_log()?;
        if let Some(snap) = snapshot {
            // A crash between saving the snapshot and compacting the log leaves
            // entries the snapshot already covers: drop them now, and on disk
            // with the next persist.
            if self
                .log
                .entries
                .first()
                .is_some_and(|e| e.index <= snap.last_index)
            {
                self.pending
                    .push(PersistOp::CompactThrough(snap.last_index));
            }
            self.log.compact_through(snap.last_index, snap.last_term);
            self.log.base_index = snap.last_index;
            self.log.base_term = snap.last_term;
            // The application is responsible for re-applying the snapshot to
            // its state machine; from Raft's perspective everything up to
            // last_index is committed AND applied.
            if snap.last_index > self.commit_index {
                self.commit_index = snap.last_index;
            }
            if snap.last_index > self.last_applied {
                self.last_applied = snap.last_index;
            }
        }
        if let Some(first) = self.log.entries.first() {
            if first.index != self.log.base_index + 1 {
                anyhow::bail!(
                    "raft log starts at index {} but the snapshot ends at {}: entries are missing",
                    first.index,
                    self.log.base_index
                );
            }
        }
        Ok(())
    }

    pub fn snapshot_persistent(&self) -> PersistedRaft {
        PersistedRaft::from_runtime(self.current_term, self.voted_for, &self.log)
    }

    /// Capture a snapshot through `through` (capped at `last_applied`) and
    /// compact the log through that point. `data` is the state-machine payload
    /// (opaque to Raft).
    ///
    /// `through` must be what the application has actually applied:
    /// `last_applied` only says what was *handed* to it, and compacting
    /// entries still queued would lose them on a crash.
    pub fn take_snapshot(
        &mut self,
        data: Vec<u8>,
        through: Option<LogIndex>,
    ) -> anyhow::Result<PersistedSnapshot> {
        let through = through.unwrap_or(self.last_applied).min(self.last_applied);
        if through == 0 || through <= self.log.base_index {
            anyhow::bail!("nothing to snapshot yet (through={through})");
        }
        let term = self
            .log
            .term_at(through)
            .ok_or_else(|| anyhow::anyhow!("entry {through} not in log"))?;
        self.log.compact_through(through, term);
        self.pending.push(PersistOp::CompactThrough(through));
        Ok(PersistedSnapshot {
            last_index: through,
            last_term: term,
            data,
        })
    }

    /// Persistence work recorded since the last call, in order.
    pub fn take_persist_ops(&mut self) -> Vec<PersistOp> {
        std::mem::take(&mut self.pending)
    }

    fn persist_hard_state(&mut self) {
        // Only the newest hard state matters; collapse repeats.
        self.pending
            .retain(|op| !matches!(op, PersistOp::HardState { .. }));
        self.pending.push(PersistOp::HardState {
            term: self.current_term,
            voted_for: self.voted_for,
        });
    }

    fn quorum(&self) -> usize {
        // Cluster size is peers + self. A majority is floor(N/2)+1. `peers`
        // excludes self, so N = peers.len()+1 and majority = ceil(peers/2)+1.
        self.peers.len().div_ceil(2) + 1
    }

    fn is_member(&self, id: NodeId) -> bool {
        self.peers.contains(&id)
    }

    // ---------- timer-driven events ----------

    pub fn on_election_timeout(&mut self) -> Vec<Action> {
        if self.role == Role::Leader {
            return Vec::new();
        }
        self.start_election()
    }

    /// Called periodically when Leader. Sends AppendEntries to each peer with
    /// whatever entries that peer is missing (or empty if caught up).
    pub fn on_heartbeat_tick(&mut self) -> Vec<Action> {
        if self.role != Role::Leader {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(self.peers.len());
        for peer in self.peers.clone() {
            out.push(self.replicate_to(peer));
        }
        out
    }

    fn replicate_to(&self, peer: NodeId) -> Action {
        let next = self.next_index.get(&peer).copied().unwrap_or(1);
        if next <= self.log.base_index {
            Action::SendSnapshot(peer)
        } else {
            Action::SendTo(peer, self.build_append_for(peer))
        }
    }

    // ---------- message handlers ----------

    pub fn on_message(&mut self, msg: Message) -> Vec<Action> {
        self.on_message_with_progress(msg, 0)
    }

    /// [`Self::on_message`], with the state machine's position for a snapshot
    /// chunk the driver has just applied (reported back to the leader).
    pub fn on_message_with_progress(&mut self, msg: Message, progress: u64) -> Vec<Action> {
        let sender = msg.sender();
        if !self.is_member(sender) {
            tracing::warn!(
                me = self.me,
                sender,
                "raft: ignoring message from a non-member"
            );
            return Vec::new();
        }
        let msg_term = msg.term();
        if msg_term > self.current_term.saturating_add(MAX_TERM_JUMP) || msg_term == Term::MAX {
            tracing::warn!(
                me = self.me,
                sender,
                msg_term,
                current_term = self.current_term,
                "raft: ignoring message with an implausible term"
            );
            return Vec::new();
        }
        let stepped_down = if msg_term > self.current_term {
            self.step_down_to(msg_term);
            true
        } else {
            false
        };

        let mut actions = match msg {
            Message::RequestVote(rv) => self.handle_request_vote(rv),
            Message::RequestVoteResp(rvr) => self.handle_request_vote_resp(rvr),
            Message::AppendEntries(ae) => self.handle_append_entries(ae),
            Message::AppendEntriesResp(aer) => self.handle_append_entries_resp(aer),
            Message::InstallSnapshot(is) => self.handle_install_snapshot(is, progress),
            Message::InstallSnapshotResp(isr) => self.handle_install_snapshot_resp(isr),
        };

        if stepped_down
            && !actions
                .iter()
                .any(|a| matches!(a, Action::ResetElectionTimer))
        {
            actions.insert(0, Action::ResetElectionTimer);
        }

        actions.extend(self.drain_apply_actions());
        actions
    }

    /// Propose a membership change. Must be called on the Leader.
    pub fn try_change_membership(
        &mut self,
        add: Vec<NodeId>,
        remove: Vec<NodeId>,
    ) -> (ProposeOutcome, Vec<Action>) {
        if self.role != Role::Leader {
            return (ProposeOutcome::NotLeader(self.leader_hint), Vec::new());
        }
        self.try_propose(encode_config_change(add, remove))
    }

    /// Client / broker calls this on the Leader to append a new entry.
    /// Returns the propose outcome plus any [`Action::Apply`]s for entries that
    /// became committed as a result (relevant for single-node clusters where
    /// the leader is the majority).
    pub fn try_propose(&mut self, payload: Vec<u8>) -> (ProposeOutcome, Vec<Action>) {
        if self.role != Role::Leader {
            return (ProposeOutcome::NotLeader(self.leader_hint), Vec::new());
        }
        let next_idx = self.append_local(payload);
        // Single-node cluster: leader IS the majority, so the entry commits
        // immediately. For multi-node clusters this is a no-op until an
        // AppendEntriesResp comes back.
        self.recompute_commit_index();
        let actions = self.drain_apply_actions();
        (ProposeOutcome::Accepted { index: next_idx }, actions)
    }

    fn append_local(&mut self, payload: Vec<u8>) -> LogIndex {
        let next_idx = self.log.last_index() + 1;
        let entry = LogEntry {
            term: self.current_term,
            index: next_idx,
            payload,
        };
        self.pending.push(PersistOp::Append(vec![entry.clone()]));
        self.log.entries.push(entry);
        next_idx
    }

    fn drain_apply_actions(&mut self) -> Vec<Action> {
        let mut out = Vec::new();
        while self.last_applied < self.commit_index {
            self.last_applied += 1;
            let Some(e) = self.log.get(self.last_applied) else {
                continue;
            };
            if e.payload.is_empty() {
                // A leader's election no-op: nothing to apply.
                continue;
            }
            if let Some((add, remove)) = decode_config_change(&e.payload) {
                self.apply_config_change(add, remove);
            } else {
                out.push(Action::Apply(e.clone()));
            }
        }
        out
    }

    fn apply_config_change(&mut self, add: Vec<NodeId>, remove: Vec<NodeId>) {
        for id in &remove {
            self.peers.retain(|p| p != id);
            self.match_index.remove(id);
            self.next_index.remove(id);
            self.snapshot_cursor.remove(id);
        }
        for id in &add {
            if !self.peers.contains(id) && *id != self.me {
                self.peers.push(*id);
                self.next_index.insert(*id, 1);
                self.match_index.insert(*id, 0);
            }
        }
        self.peers.sort_unstable();
        tracing::info!(
            me = self.me,
            added = ?add,
            removed = ?remove,
            new_peers = ?self.peers,
            "raft: config change applied"
        );
    }

    // ---------- internals ----------

    fn step_down_to(&mut self, term: Term) {
        let mut changed = false;
        if term > self.current_term {
            self.current_term = term;
            changed = true;
        }
        if self.voted_for.is_some() {
            self.voted_for = None;
            changed = true;
        }
        if changed {
            self.persist_hard_state();
        }
        self.role = Role::Follower;
        self.votes_received.clear();
        self.leader_hint = None;
        self.match_index.clear();
        self.next_index.clear();
        self.snapshot_cursor.clear();
    }

    fn start_election(&mut self) -> Vec<Action> {
        // saturating_add so a maxed-out term can't panic in debug builds.
        self.current_term = self.current_term.saturating_add(1);
        self.role = Role::Candidate;
        self.voted_for = Some(self.me);
        self.persist_hard_state();
        self.votes_received.clear();
        self.votes_received.insert(self.me);
        self.leader_hint = None;

        let rv = RequestVote {
            term: self.current_term,
            candidate_id: self.me,
            last_log_index: self.log.last_index(),
            last_log_term: self.log.last_term(),
        };

        if self.peers.is_empty() {
            self.become_leader();
            let mut out = self.on_heartbeat_tick();
            out.extend(self.drain_apply_actions());
            return out;
        }
        vec![
            Action::ResetElectionTimer,
            Action::Broadcast(Message::RequestVote(rv)),
        ]
    }

    fn handle_request_vote(&mut self, rv: RequestVote) -> Vec<Action> {
        let mut grant = false;
        if rv.term >= self.current_term {
            // §5.4.1 — voter only grants if candidate's log is at least as up-to-date.
            let our_last_term = self.log.last_term();
            let our_last_index = self.log.last_index();
            let up_to_date = (rv.last_log_term > our_last_term)
                || (rv.last_log_term == our_last_term && rv.last_log_index >= our_last_index);
            let can_vote = self.voted_for.is_none() || self.voted_for == Some(rv.candidate_id);
            if up_to_date && can_vote {
                grant = true;
                if self.voted_for != Some(rv.candidate_id) {
                    self.voted_for = Some(rv.candidate_id);
                    self.persist_hard_state();
                }
            }
        }
        let resp = Message::RequestVoteResp(RequestVoteResp {
            term: self.current_term,
            vote_granted: grant,
            voter_id: self.me,
        });
        let mut out = vec![Action::SendTo(rv.candidate_id, resp)];
        if grant {
            out.push(Action::ResetElectionTimer);
        }
        out
    }

    fn handle_request_vote_resp(&mut self, rvr: RequestVoteResp) -> Vec<Action> {
        if self.role != Role::Candidate || rvr.term != self.current_term {
            return Vec::new();
        }
        if rvr.vote_granted {
            self.votes_received.insert(rvr.voter_id);
            if self.votes_received.len() >= self.quorum() {
                self.become_leader();
                return self.on_heartbeat_tick();
            }
        }
        Vec::new()
    }

    fn handle_append_entries(&mut self, ae: AppendEntries) -> Vec<Action> {
        let mut success = false;
        let mut match_index = 0u64;
        let mut from_current_leader = false;
        if ae.term >= self.current_term {
            from_current_leader = true;
            // Accept this leader for the term.
            if ae.term > self.current_term {
                self.current_term = ae.term;
                self.voted_for = None;
                self.persist_hard_state();
            }
            self.role = Role::Follower;
            self.leader_hint = Some(ae.leader_id);

            // Log-consistency check: we must have prev_log_index with matching term.
            let consistent = if ae.prev_log_index == 0 {
                true
            } else if ae.prev_log_index < self.log.base_index {
                // Inside our snapshot: committed, therefore identical.
                true
            } else {
                match self.log.term_at(ae.prev_log_index) {
                    Some(t) => t == ae.prev_log_term,
                    None => false,
                }
            };
            if consistent {
                let n = ae.entries.len() as LogIndex;
                // append_at refuses to truncate committed entries; if it does,
                // we reject the whole AppendEntries rather than silently
                // reporting success on a log we didn't fully apply.
                let applied = if ae.entries.is_empty() {
                    true
                } else {
                    let start = ae.prev_log_index.saturating_add(1);
                    match self.log.append_at(start, ae.entries, self.commit_index) {
                        Ok(Some(first_changed)) => {
                            self.pending.push(PersistOp::TruncateFrom(first_changed));
                            let changed = self.log.slice(first_changed, LogIndex::MAX);
                            self.pending.push(PersistOp::Append(changed));
                            true
                        }
                        Ok(None) => true,
                        Err(()) => false,
                    }
                };
                if applied {
                    // What this RPC proves we share with the leader — and
                    // nothing more. Reporting our whole log here let a leader
                    // count stale entries past `prev + n` that it had never
                    // checked, and commit an index only it actually held.
                    let last_new = ae.prev_log_index.saturating_add(n);
                    if ae.leader_commit > self.commit_index {
                        self.commit_index = ae.leader_commit.min(last_new).max(self.commit_index);
                    }
                    match_index = last_new;
                    success = true;
                }
            }
            if !success {
                // Hint for the leader: we have nothing past our last index.
                match_index = self.log.last_index();
            }
        }

        let resp = Message::AppendEntriesResp(AppendEntriesResp {
            term: self.current_term,
            success,
            responder_id: self.me,
            match_index,
        });
        let mut out = vec![Action::SendTo(ae.leader_id, resp)];
        // Any AppendEntries from the current leader proves it is alive, even
        // one we had to reject. Not resetting on a rejection let a follower
        // still catching up time out and depose a perfectly healthy leader.
        if from_current_leader {
            out.push(Action::ResetElectionTimer);
        }
        out
    }

    fn handle_append_entries_resp(&mut self, aer: AppendEntriesResp) -> Vec<Action> {
        if self.role != Role::Leader || aer.term != self.current_term {
            return Vec::new();
        }
        let peer = aer.responder_id;
        if aer.success {
            // Clamp a peer-reported match_index to our own last index — a peer
            // can't have replicated further than we've written.
            let mi = aer.match_index.min(self.log.last_index());
            let cur = self.match_index.get(&peer).copied().unwrap_or(0);
            if mi > cur {
                self.match_index.insert(peer, mi);
            }
            let mi = mi.max(cur);
            self.next_index.insert(peer, mi.saturating_add(1));
            // Recompute commit_index: largest N such that majority of match_index >= N
            // AND log[N].term == current_term (§5.4.2 — no commit from past terms).
            self.recompute_commit_index();
            // Only follow up when the peer is still missing entries. Answering
            // every acknowledgement of an up-to-date peer with another
            // AppendEntries made each heartbeat start a ping-pong that never
            // ended; heartbeats are the timer's job.
            if mi < self.log.last_index() {
                return vec![self.replicate_to(peer)];
            }
            Vec::new()
        } else {
            // Back off: to just past the follower's last entry if that is
            // lower than one step back, so a far-behind follower is found in
            // one round trip rather than one per missing entry.
            let cur = self.next_index.get(&peer).copied().unwrap_or(1);
            let hinted = aer.match_index.saturating_add(1);
            let next = cur.saturating_sub(1).min(hinted).max(1);
            self.next_index.insert(peer, next);
            vec![self.replicate_to(peer)]
        }
    }

    fn handle_install_snapshot(&mut self, is: InstallSnapshot, progress: u64) -> Vec<Action> {
        if is.term < self.current_term {
            return vec![Action::SendTo(
                is.leader_id,
                Message::InstallSnapshotResp(InstallSnapshotResp {
                    term: self.current_term,
                    success: false,
                    responder_id: self.me,
                    next_offset: progress,
                    installed_index: 0,
                }),
            )];
        }
        self.role = Role::Follower;
        self.leader_hint = Some(is.leader_id);
        if is.term > self.current_term {
            self.current_term = is.term;
            self.voted_for = None;
            self.persist_hard_state();
        }
        let mut installed_index = 0;
        if is.done {
            if is.last_index > self.log.base_index {
                let kept = self.log.install_snapshot(is.last_index, is.last_term);
                if kept {
                    self.pending.push(PersistOp::CompactThrough(is.last_index));
                } else {
                    self.pending.push(PersistOp::TruncateFrom(0));
                }
            }
            if is.last_index > self.commit_index {
                self.commit_index = is.last_index;
            }
            if is.last_index > self.last_applied {
                self.last_applied = is.last_index;
            }
            installed_index = is.last_index.max(self.log.base_index);
        }
        let resp = Message::InstallSnapshotResp(InstallSnapshotResp {
            term: self.current_term,
            success: true,
            responder_id: self.me,
            next_offset: progress,
            installed_index,
        });
        vec![
            Action::SendTo(is.leader_id, resp),
            Action::ResetElectionTimer,
        ]
    }

    fn handle_install_snapshot_resp(&mut self, isr: InstallSnapshotResp) -> Vec<Action> {
        if self.role != Role::Leader || isr.term != self.current_term {
            return Vec::new();
        }
        let peer = isr.responder_id;
        if !isr.success {
            // Retried by the next heartbeat.
            return Vec::new();
        }
        if isr.installed_index > 0 {
            // The follower's log now starts after `installed_index`.
            let installed = isr.installed_index.min(self.log.last_index());
            let cur = self.match_index.get(&peer).copied().unwrap_or(0);
            let mi = cur.max(installed);
            self.match_index.insert(peer, mi);
            self.next_index.insert(peer, mi + 1);
            self.snapshot_cursor.remove(&peer);
            self.recompute_commit_index();
            if mi < self.log.last_index() || self.log.base_index > mi {
                return vec![self.replicate_to(peer)];
            }
            return Vec::new();
        }
        // A chunk (or the probe) landed: continue from where the follower is.
        self.snapshot_cursor.insert(peer, isr.next_offset);
        vec![Action::SendSnapshot(peer)]
    }

    fn become_leader(&mut self) {
        self.role = Role::Leader;
        self.leader_hint = Some(self.me);
        self.match_index.clear();
        self.next_index.clear();
        self.snapshot_cursor.clear();
        if self.noop_on_elect {
            self.append_local(Vec::new());
        }
        let last = self.log.last_index();
        for p in &self.peers {
            self.match_index.insert(*p, 0);
            self.next_index.insert(*p, last + 1);
        }
        self.votes_received.clear();
        self.recompute_commit_index();
    }

    fn build_append_for(&self, peer: NodeId) -> Message {
        let next = self.next_index.get(&peer).copied().unwrap_or(1);
        let prev_log_index = next.saturating_sub(1);
        let prev_log_term = self.log.term_at(prev_log_index).unwrap_or(0);
        let entries = self
            .log
            .slice_bounded(next, MAX_APPEND_ENTRIES, MAX_APPEND_BYTES);
        Message::AppendEntries(AppendEntries {
            term: self.current_term,
            leader_id: self.me,
            prev_log_index,
            prev_log_term,
            entries,
            leader_commit: self.commit_index,
        })
    }

    fn recompute_commit_index(&mut self) {
        // Build the multiset of replicated indices (including leader's own),
        // counting only current members.
        let mut indices: Vec<LogIndex> = self
            .peers
            .iter()
            .map(|p| self.match_index.get(p).copied().unwrap_or(0))
            .collect();
        indices.push(self.log.last_index());
        indices.sort_unstable();
        // The highest index replicated on a majority: with N members sorted
        // ascending, the entry at position N - quorum.
        let n = indices.len();
        let candidate = indices[n - self.quorum()];
        if candidate > self.commit_index {
            // §5.4.2: only entries from the current term can be committed
            // directly by counting.
            if self.log.term_at(candidate) == Some(self.current_term) {
                self.commit_index = candidate;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProposeOutcome {
    Accepted { index: LogIndex },
    NotLeader(Option<NodeId>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::messages::LogEntry;

    fn n(me: NodeId, peers: &[NodeId]) -> RaftState {
        RaftState::new(me, peers.to_vec())
    }

    fn leader_of_three() -> RaftState {
        let mut s = n(1, &[2, 3]);
        s.on_election_timeout();
        s.on_message(Message::RequestVoteResp(RequestVoteResp {
            term: s.current_term,
            vote_granted: true,
            voter_id: 2,
        }));
        assert_eq!(s.role, Role::Leader);
        s
    }

    #[test]
    fn decode_config_change_rejects_truncated_payload() {
        let mut payload = CONFIG_MAGIC.to_vec();
        payload.extend_from_slice(&1u32.to_be_bytes());
        assert!(decode_config_change(&payload).is_none());
        let mut huge = CONFIG_MAGIC.to_vec();
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_config_change(&huge).is_none());
    }

    #[test]
    fn quorum_requires_true_majority() {
        assert_eq!(n(1, &[2]).quorum(), 2);
        assert_eq!(n(1, &[2, 3]).quorum(), 2);
        assert_eq!(n(1, &[2, 3, 4]).quorum(), 3);
    }

    #[test]
    fn propose_only_on_leader() {
        let mut s = n(1, &[2, 3]);
        let (outcome, _) = s.try_propose(b"x".to_vec());
        assert!(matches!(outcome, ProposeOutcome::NotLeader(_)));
        let mut s = leader_of_three();
        let (outcome, _) = s.try_propose(b"hello".to_vec());
        assert!(matches!(outcome, ProposeOutcome::Accepted { index: 1 }));
        assert_eq!(s.log.last_index(), 1);
    }

    #[test]
    fn append_entries_consistent_check_rejects_mismatched_prev() {
        let mut s = n(2, &[1, 3]);
        let actions = s.on_message(Message::AppendEntries(AppendEntries {
            term: 1,
            leader_id: 1,
            prev_log_index: 5,
            prev_log_term: 1,
            entries: vec![LogEntry {
                term: 1,
                index: 6,
                payload: vec![],
            }],
            leader_commit: 0,
        }));
        let rejected = actions.iter().any(|a| {
            matches!(
                a,
                Action::SendTo(
                    _,
                    Message::AppendEntriesResp(AppendEntriesResp { success: false, .. })
                )
            )
        });
        assert!(rejected, "follower should reject mismatched prev");
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::ResetElectionTimer)),
            "a rejected AppendEntries from the current leader still resets the timer"
        );
        assert_eq!(s.log.last_index(), 0);
    }

    #[test]
    fn commit_index_advances_with_majority() {
        let mut s = leader_of_three();
        let _ = s.try_propose(b"a".to_vec());
        s.on_message(Message::AppendEntriesResp(AppendEntriesResp {
            term: 1,
            success: true,
            responder_id: 2,
            match_index: 1,
        }));
        assert_eq!(s.commit_index, 1);
    }

    /// The scenario that lost acknowledged writes: a follower holding a stale
    /// entry past `prev_log_index` must not report it as matched.
    #[test]
    fn follower_reports_only_what_the_rpc_proved() {
        let mut f = n(2, &[1, 3]);
        // Follower has [1t1, 2t1, 3t2] — entry 3 is from a deposed leader.
        f.current_term = 3;
        f.log.entries = vec![
            LogEntry {
                term: 1,
                index: 1,
                payload: b"a".to_vec(),
            },
            LogEntry {
                term: 1,
                index: 2,
                payload: b"b".to_vec(),
            },
            LogEntry {
                term: 2,
                index: 3,
                payload: b"stale".to_vec(),
            },
        ];
        let actions = f.on_message(Message::AppendEntries(AppendEntries {
            term: 3,
            leader_id: 1,
            prev_log_index: 2,
            prev_log_term: 1,
            entries: vec![],
            leader_commit: 3,
        }));
        let mi = actions
            .iter()
            .find_map(|a| match a {
                Action::SendTo(_, Message::AppendEntriesResp(r)) if r.success => {
                    Some(r.match_index)
                }
                _ => None,
            })
            .expect("heartbeat accepted");
        assert_eq!(mi, 2, "entry 3 was never checked against the leader");
        assert_eq!(f.commit_index, 2, "commit capped at what was verified");
    }

    #[test]
    fn caught_up_follower_gets_no_follow_up() {
        let mut s = leader_of_three();
        let _ = s.try_propose(b"a".to_vec());
        let actions = s.on_message(Message::AppendEntriesResp(AppendEntriesResp {
            term: s.current_term,
            success: true,
            responder_id: 2,
            match_index: 1,
        }));
        assert!(
            actions.iter().all(|a| !matches!(a, Action::SendTo(2, _))),
            "an up-to-date follower must not be sent another AppendEntries: {actions:?}"
        );
    }

    #[test]
    fn append_entries_are_batched() {
        let mut s = leader_of_three();
        for _ in 0..(MAX_APPEND_ENTRIES + 10) {
            s.try_propose(vec![1]);
        }
        s.next_index.insert(2, 1);
        match s.build_append_for(2) {
            Message::AppendEntries(ae) => assert_eq!(ae.entries.len(), MAX_APPEND_ENTRIES),
            _ => unreachable!(),
        }
    }

    #[test]
    fn non_members_and_absurd_terms_are_ignored() {
        let mut s = n(1, &[2, 3]);
        let a = s.on_message(Message::RequestVote(RequestVote {
            term: 5,
            candidate_id: 99,
            last_log_index: 0,
            last_log_term: 0,
        }));
        assert!(a.is_empty());
        assert_eq!(s.current_term, 0);
        let a = s.on_message(Message::RequestVote(RequestVote {
            term: Term::MAX,
            candidate_id: 2,
            last_log_index: 0,
            last_log_term: 0,
        }));
        assert!(a.is_empty());
        assert_eq!(s.current_term, 0, "a forged u64::MAX term must not stick");
    }

    #[test]
    fn snapshot_install_advances_the_leader() {
        let mut s = leader_of_three();
        let _ = s.try_propose(b"a".to_vec());
        s.next_index.insert(2, 1);
        let a = s.on_message(Message::InstallSnapshotResp(InstallSnapshotResp {
            term: s.current_term,
            success: true,
            responder_id: 2,
            next_offset: 7,
            installed_index: 0,
        }));
        assert_eq!(s.snapshot_cursor.get(&2), Some(&7));
        assert!(matches!(a[..], [Action::SendSnapshot(2)]));
        s.on_message(Message::InstallSnapshotResp(InstallSnapshotResp {
            term: s.current_term,
            success: true,
            responder_id: 2,
            next_offset: 9,
            installed_index: 1,
        }));
        assert_eq!(s.match_index.get(&2), Some(&1));
        assert_eq!(s.next_index.get(&2), Some(&2));
        assert!(!s.snapshot_cursor.contains_key(&2));
    }

    #[test]
    fn noop_on_elect_commits_earlier_terms() {
        let mut s = n(1, &[]);
        s.noop_on_elect = true;
        s.current_term = 1;
        s.log.entries = vec![LogEntry {
            term: 1,
            index: 1,
            payload: b"old".to_vec(),
        }];
        let actions = s.on_election_timeout();
        assert_eq!(s.role, Role::Leader);
        assert_eq!(s.log.last_index(), 2);
        assert_eq!(s.commit_index, 2);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Apply(e) if e.index == 1)));
    }
}
