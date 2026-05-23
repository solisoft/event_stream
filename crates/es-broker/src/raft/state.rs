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

use super::log::{Log, PersistedRaft};
use super::messages::{
    AppendEntries, AppendEntriesResp, LogEntry, LogIndex, Message, NodeId, RequestVote,
    RequestVoteResp, Term,
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

    /// Restore from a persisted snapshot (used by the driver on boot).
    pub fn restore(&mut self, snap: PersistedRaft) -> anyhow::Result<()> {
        self.current_term = snap.current_term;
        self.voted_for = snap.voted_for;
        self.log = snap.into_log()?;
        self.dirty = false;
        Ok(())
    }

    pub fn snapshot_persistent(&self) -> PersistedRaft {
        PersistedRaft::from_runtime(self.current_term, self.voted_for, &self.log)
    }

    pub fn take_dirty(&mut self) -> bool {
        let d = self.dirty;
        self.dirty = false;
        d
    }

    fn quorum(&self) -> usize {
        (self.peers.len() + 2) / 2
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
            out.push(Action::SendTo(peer, self.build_append_for(peer)));
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
        };

        if stepped_down && !actions.iter().any(|a| matches!(a, Action::ResetElectionTimer)) {
            actions.insert(0, Action::ResetElectionTimer);
        }

        actions.extend(self.drain_apply_actions());
        actions
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
            if let Some(e) = self.log.entries.get((self.last_applied - 1) as usize) {
                out.push(Action::Apply(e.clone()));
            }
        }
        out
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
        self.current_term += 1;
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
            let can_vote =
                self.voted_for.is_none() || self.voted_for == Some(rv.candidate_id);
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
                if !ae.entries.is_empty() {
                    let start = ae.prev_log_index + 1;
                    self.log.append_at(start, ae.entries.clone());
                    self.dirty = true;
                }
                // Update commit_index. Per the paper:
                // commit_index = min(leader_commit, index_of_last_new_entry).
                let last_new = if ae.entries.is_empty() {
                    self.log.last_index()
                } else {
                    ae.prev_log_index + ae.entries.len() as LogIndex
                };
                if ae.leader_commit > self.commit_index {
                    self.commit_index = ae.leader_commit.min(last_new);
                }
                match_index = self.log.last_index();
                success = true;
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
            self.match_index.insert(aer.responder_id, aer.match_index);
            self.next_index
                .insert(aer.responder_id, aer.match_index + 1);
            // Recompute commit_index: largest N such that majority of match_index >= N
            // AND log[N].term == current_term (§5.4.2 — no commit from past terms).
            self.recompute_commit_index();
        } else {
            // Back off and retry next heartbeat. Floor at 1 to keep send valid.
            let cur = self
                .next_index
                .get(&aer.responder_id)
                .copied()
                .unwrap_or(1);
            self.next_index
                .insert(aer.responder_id, cur.saturating_sub(1).max(1));
        }
        // Send an immediate AppendEntries to this peer to flush the next batch
        // or retry the failed one.
        vec![Action::SendTo(
            aer.responder_id,
            self.build_append_for(aer.responder_id),
        )]
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
            entries: vec![LogEntry { term: 1, index: 6, payload: vec![] }],
            leader_commit: 0,
        }));
        let rejected = actions.iter().any(|a| matches!(
            a,
            Action::SendTo(_, Message::AppendEntriesResp(AppendEntriesResp { success: false, .. }))
        ));
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
