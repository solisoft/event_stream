//! Raft state machine — step 2: log replication + commit advancement.
//!
//! Pure (no I/O). The driver in `node.rs` calls one of `on_*` per event and
//! executes the returned [`Action`]s. `dirty` becomes `true` whenever the
//! persistent fields (`current_term`, `voted_for`, log) change; the driver
//! drains it via [`RaftState::take_dirty`] and persists the snapshot from
//! [`RaftState::snapshot_persistent`] before sending any reply.
//!
//! What changed from step 1:
//!   * `Log` is now real; entries are appended and replicated.
//!   * Leader tracks `next_index` / `match_index` per peer and advances a
//!     `commit_index`.
//!   * `RequestVote` enforces the up-to-date check from §5.4.1 of the paper.
//!   * `AppendEntries` validates `prev_log_index` / `prev_log_term`, truncates
//!     conflicting entries, and applies new ones.
//!   * `Action::Apply` carries a committed entry to the state machine.

use std::collections::{BTreeMap, HashSet};

use super::log::{Log, PersistedRaft, PersistedSnapshot};
use super::messages::{
    AppendEntries, AppendEntriesResp, InstallSnapshot, InstallSnapshotResp, LogEntry, LogIndex,
    Message, NodeId, RequestVote, RequestVoteResp, Term,
};

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
    /// Leader needs to send a snapshot to this peer (follower's log is behind).
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
    pub last_applied: LogIndex,

    /// Leader-only: highest log index known to be replicated on each peer.
    pub match_index: BTreeMap<NodeId, LogIndex>,
    /// Leader-only: next log index the leader will send to each peer.
    pub next_index: BTreeMap<NodeId, LogIndex>,

    votes_received: HashSet<NodeId>,
    dirty: bool,
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
            votes_received: HashSet::new(),
            dirty: false,
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
        self.dirty = false;
        Ok(())
    }

    pub fn snapshot_persistent(&self) -> PersistedRaft {
        PersistedRaft::from_runtime(self.current_term, self.voted_for, &self.log)
    }

    /// Capture a snapshot at `last_applied` and compact the log through that
    /// point. `data` is the state-machine-specific payload (opaque to Raft).
    pub fn take_snapshot(&mut self, data: Vec<u8>) -> anyhow::Result<PersistedSnapshot> {
        if self.last_applied == 0 {
            anyhow::bail!("nothing to snapshot yet (last_applied=0)");
        }
        let term = self
            .log
            .term_at(self.last_applied)
            .ok_or_else(|| anyhow::anyhow!("last_applied entry not in log"))?;
        self.log.compact_through(self.last_applied, term);
        self.dirty = true;
        Ok(PersistedSnapshot {
            last_index: self.last_applied,
            last_term: term,
            data,
        })
    }

    pub fn take_dirty(&mut self) -> bool {
        let d = self.dirty;
        self.dirty = false;
        d
    }

    fn quorum(&self) -> usize {
        // Cluster size is peers + self. A majority is floor(N/2)+1. `peers`
        // excludes self, so N = peers.len()+1 and majority = ceil(peers/2)+1.
        // The previous `(peers+2)/2` was an off-by-one for even N (it let a
        // candidate self-elect in a 2-node cluster → split-brain).
        self.peers.len().div_ceil(2) + 1
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
            let next = self.next_index.get(&peer).copied().unwrap_or(1);
            if next <= self.log.base_index {
                out.push(Action::SendSnapshot(peer));
            } else {
                out.push(Action::SendTo(peer, self.build_append_for(peer)));
            }
        }
        out
    }

    // ---------- message handlers ----------

    pub fn on_message(&mut self, msg: Message) -> Vec<Action> {
        let msg_term = msg.term();
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
            Message::InstallSnapshot(is) => self.handle_install_snapshot(is),
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
        let next_idx = self.log.last_index() + 1;
        self.log.append_assign_indices(vec![LogEntry {
            term: self.current_term,
            index: next_idx,
            payload,
        }]);
        self.dirty = true;
        // Single-node cluster: leader IS the majority, so the entry commits
        // immediately. For multi-node clusters this is a no-op until an
        // AppendEntriesResp comes back.
        self.recompute_commit_index();
        let actions = self.drain_apply_actions();
        (ProposeOutcome::Accepted { index: next_idx }, actions)
    }

    fn drain_apply_actions(&mut self) -> Vec<Action> {
        let mut out = Vec::new();
        while self.last_applied < self.commit_index {
            self.last_applied += 1;
            if let Some(first) = self.log.entries.first() {
                let first_idx = first.index;
                if self.last_applied >= first_idx {
                    let pos = (self.last_applied - first_idx) as usize;
                    if let Some(e) = self.log.entries.get(pos) {
                        if let Some((add, remove)) = decode_config_change(&e.payload) {
                            self.apply_config_change(add, remove);
                        } else {
                            out.push(Action::Apply(e.clone()));
                        }
                    }
                }
            }
        }
        out
    }

    fn apply_config_change(&mut self, add: Vec<NodeId>, remove: Vec<NodeId>) {
        for id in &remove {
            self.peers.retain(|p| p != id);
            self.match_index.remove(id);
            self.next_index.remove(id);
        }
        for id in &add {
            if !self.peers.contains(id) && *id != self.me {
                self.peers.push(*id);
                self.next_index.insert(*id, 1);
                self.match_index.insert(*id, 0);
            }
        }
        self.peers.sort_unstable();
        self.dirty = true;
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
        if term > self.current_term {
            self.current_term = term;
            self.dirty = true;
        }
        if self.voted_for.is_some() {
            self.voted_for = None;
            self.dirty = true;
        }
        self.role = Role::Follower;
        self.votes_received.clear();
        self.leader_hint = None;
        self.match_index.clear();
        self.next_index.clear();
    }

    fn start_election(&mut self) -> Vec<Action> {
        // saturating_add so a maxed-out term (e.g. one forced by a peer message)
        // can't panic here in debug builds.
        self.current_term = self.current_term.saturating_add(1);
        self.role = Role::Candidate;
        self.voted_for = Some(self.me);
        self.dirty = true;
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
            return self.on_heartbeat_tick();
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
                    self.dirty = true;
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
        if ae.term >= self.current_term {
            // Accept this leader for the term.
            if ae.term > self.current_term {
                self.current_term = ae.term;
                self.voted_for = None;
                self.dirty = true;
            }
            self.role = Role::Follower;
            self.leader_hint = Some(ae.leader_id);

            // Log-consistency check: we must have prev_log_index with matching term.
            let consistent = if ae.prev_log_index == 0 {
                true
            } else {
                match self.log.term_at(ae.prev_log_index) {
                    Some(t) => t == ae.prev_log_term,
                    None => false,
                }
            };
            if consistent {
                // append_at refuses to truncate committed entries; if it does,
                // we reject the whole AppendEntries rather than silently
                // reporting success on a log we didn't fully apply.
                let applied = if !ae.entries.is_empty() {
                    let start = ae.prev_log_index.saturating_add(1);
                    let ok = self
                        .log
                        .append_at(start, ae.entries.clone(), self.commit_index);
                    if ok {
                        self.dirty = true;
                    }
                    ok
                } else {
                    true
                };
                if applied {
                    // Update commit_index. Per the paper:
                    // commit_index = min(leader_commit, index_of_last_new_entry).
                    let last_new = if ae.entries.is_empty() {
                        self.log.last_index()
                    } else {
                        ae.prev_log_index.saturating_add(ae.entries.len() as LogIndex)
                    };
                    if ae.leader_commit > self.commit_index {
                        self.commit_index = ae.leader_commit.min(last_new);
                    }
                    match_index = self.log.last_index();
                    success = true;
                }
            }
        }

        let resp = Message::AppendEntriesResp(AppendEntriesResp {
            term: self.current_term,
            success,
            responder_id: self.me,
            match_index,
        });
        let mut out = vec![Action::SendTo(ae.leader_id, resp)];
        if success {
            out.push(Action::ResetElectionTimer);
        }
        out
    }

    fn handle_append_entries_resp(&mut self, aer: AppendEntriesResp) -> Vec<Action> {
        if self.role != Role::Leader || aer.term != self.current_term {
            return Vec::new();
        }
        if aer.success {
            // Clamp a peer-reported match_index to our own last index — a peer
            // can't have replicated further than we've written — and use
            // saturating_add so match_index=u64::MAX can't overflow next_index.
            let mi = aer.match_index.min(self.log.last_index());
            self.match_index.insert(aer.responder_id, mi);
            self.next_index
                .insert(aer.responder_id, mi.saturating_add(1));
            // Recompute commit_index: largest N such that majority of match_index >= N
            // AND log[N].term == current_term (§5.4.2 — no commit from past terms).
            self.recompute_commit_index();
        } else {
            // Back off and retry next heartbeat. Floor at 1 to keep send valid.
            let cur = self.next_index.get(&aer.responder_id).copied().unwrap_or(1);
            self.next_index
                .insert(aer.responder_id, cur.saturating_sub(1).max(1));
        }
        // Send an immediate AppendEntries to this peer to flush the next batch
        // or retry the failed one.
        let next = self.next_index.get(&aer.responder_id).copied().unwrap_or(1);
        if next <= self.log.base_index {
            vec![Action::SendSnapshot(aer.responder_id)]
        } else {
            vec![Action::SendTo(
                aer.responder_id,
                self.build_append_for(aer.responder_id),
            )]
        }
    }

    fn handle_install_snapshot(&mut self, is: InstallSnapshot) -> Vec<Action> {
        if is.term < self.current_term {
            return vec![Action::SendTo(
                is.leader_id,
                Message::InstallSnapshotResp(InstallSnapshotResp {
                    term: self.current_term,
                    success: false,
                    responder_id: self.me,
                }),
            )];
        }
        self.role = Role::Follower;
        self.leader_hint = Some(is.leader_id);
        if is.term > self.current_term {
            self.current_term = is.term;
            self.voted_for = None;
            self.dirty = true;
        }
        if is.last_index > self.log.base_index {
            self.log.compact_through(is.last_index, is.last_term);
        }
        if is.last_index > self.commit_index {
            self.commit_index = is.last_index;
        }
        if is.last_index > self.last_applied {
            self.last_applied = is.last_index;
        }
        self.dirty = true;
        let resp = Message::InstallSnapshotResp(InstallSnapshotResp {
            term: self.current_term,
            success: true,
            responder_id: self.me,
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
        if isr.success {
            self.recompute_commit_index();
        }
        Vec::new()
    }

    fn become_leader(&mut self) {
        self.role = Role::Leader;
        self.leader_hint = Some(self.me);
        let last = self.log.last_index();
        self.match_index.clear();
        self.next_index.clear();
        for p in &self.peers {
            self.match_index.insert(*p, 0);
            self.next_index.insert(*p, last + 1);
        }
        self.votes_received.clear();
    }

    fn build_append_for(&self, peer: NodeId) -> Message {
        let next = self.next_index.get(&peer).copied().unwrap_or(1);
        let prev_log_index = next.saturating_sub(1);
        let prev_log_term = self.log.term_at(prev_log_index).unwrap_or(0);
        let entries = if next <= self.log.last_index() {
            self.log.slice(next, self.log.last_index() + 1)
        } else {
            Vec::new()
        };
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
        // Build the multiset of replicated indices (including leader's own).
        let mut indices: Vec<LogIndex> = self.match_index.values().copied().collect();
        indices.push(self.log.last_index());
        indices.sort_unstable();
        // The median (rounded down) of indices is the highest index replicated
        // on a majority. For a cluster of 2k+1 nodes, the (k+1)-th smallest
        // index is replicated on >= k+1 nodes; for 2k, it's the k-th.
        let n = indices.len();
        let majority_idx = if n % 2 == 1 { n / 2 } else { n / 2 - 1 };
        let candidate = indices[majority_idx];
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

    #[test]
    fn decode_config_change_rejects_truncated_payload() {
        // Declares one add id but carries no id bytes — must return None, not
        // panic on an out-of-bounds slice.
        let mut payload = CONFIG_MAGIC.to_vec();
        payload.extend_from_slice(&1u32.to_be_bytes());
        assert!(decode_config_change(&payload).is_none());
        // A hostile length must not drive a giant allocation; returns None.
        let mut huge = CONFIG_MAGIC.to_vec();
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_config_change(&huge).is_none());
    }

    #[test]
    fn quorum_requires_true_majority() {
        // 2-node cluster (self + 1 peer): a candidate needs both votes, so a
        // single vote must NOT be enough (guards against split-brain).
        let s = n(1, &[2]);
        assert_eq!(s.quorum(), 2);
        // 3-node: majority is 2.
        let s = n(1, &[2, 3]);
        assert_eq!(s.quorum(), 2);
        // 4-node: majority is 3.
        let s = n(1, &[2, 3, 4]);
        assert_eq!(s.quorum(), 3);
    }

    #[test]
    fn propose_only_on_leader() {
        let mut s = n(1, &[2, 3]);
        let (outcome, _) = s.try_propose(b"x".to_vec());
        assert!(matches!(outcome, ProposeOutcome::NotLeader(_)));
        s.on_election_timeout();
        s.on_message(Message::RequestVoteResp(RequestVoteResp {
            term: s.current_term,
            vote_granted: true,
            voter_id: 2,
        }));
        assert_eq!(s.role, Role::Leader);
        let (outcome, _) = s.try_propose(b"hello".to_vec());
        assert!(matches!(outcome, ProposeOutcome::Accepted { index: 1 }));
        assert_eq!(s.log.last_index(), 1);
    }

    #[test]
    fn append_entries_consistent_check_rejects_mismatched_prev() {
        let mut s = n(2, &[1, 3]);
        // Leader 1 sends AppendEntries with prev_log_index=5 but our log is empty.
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
        assert_eq!(s.log.last_index(), 0);
    }

    #[test]
    fn commit_index_advances_with_majority() {
        let mut s = n(1, &[2, 3]);
        // Become leader at term 1 with empty log.
        s.on_election_timeout();
        s.on_message(Message::RequestVoteResp(RequestVoteResp {
            term: s.current_term,
            vote_granted: true,
            voter_id: 2,
        }));
        assert_eq!(s.role, Role::Leader);

        // Propose entry → index 1, term 1.
        let _ = s.try_propose(b"a".to_vec());
        // Peer 2 acks match_index=1.
        s.on_message(Message::AppendEntriesResp(AppendEntriesResp {
            term: 1,
            success: true,
            responder_id: 2,
            match_index: 1,
        }));
        // Leader + peer 2 = majority of 3 → commit_index advances.
        assert_eq!(s.commit_index, 1);
    }
}
