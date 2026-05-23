//! Pure Raft state machine for leader election.
//!
//! Step 1 of the Raft implementation. Tracks `current_term`, `voted_for`, and
//! a `Role` (Follower / Candidate / Leader). Consumes events and emits
//! `Action`s for the surrounding driver to execute (send a message, reset a
//! timer). All state is in memory; persistence is a step-2 concern.
//!
//! What this does NOT do yet (deferred to step 2):
//!   * Log replication. `AppendEntries.entries` is always empty in step 1.
//!   * Committed-index advancement.
//!   * Snapshot transfer.
//!   * Linearizable client reads.
//!
//! What it DOES enforce:
//!   * Election safety: a node only votes once per term.
//!   * Term updates: any message with a higher term forces the node back to
//!     Follower at that term, clearing `voted_for`.
//!   * One leader per term: only a Candidate that wins a majority becomes
//!     Leader; only Leader sends AppendEntries heartbeats.

use std::collections::HashSet;

use super::messages::{
    AppendEntries, AppendEntriesResp, Message, NodeId, RequestVote, RequestVoteResp, Term,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Follower,
    Candidate,
    Leader,
}

/// What the surrounding driver should do in response to an event.
#[derive(Debug, Clone)]
pub enum Action {
    /// Send a message to a specific peer.
    SendTo(NodeId, Message),
    /// Send a message to every peer except self.
    Broadcast(Message),
    /// Reset the election timer (with a new randomized timeout). Followers and
    /// candidates use this; leaders ignore the election timer.
    ResetElectionTimer,
}

#[derive(Debug)]
pub struct RaftState {
    pub me: NodeId,
    pub peers: Vec<NodeId>,
    pub role: Role,
    pub current_term: Term,
    pub voted_for: Option<NodeId>,
    pub leader_hint: Option<NodeId>,
    /// Votes received in the current candidate term.
    votes_received: HashSet<NodeId>,
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
            votes_received: HashSet::new(),
        }
    }

    fn quorum(&self) -> usize {
        // Cluster size = 1 (self) + peer count.
        (self.peers.len() + 2) / 2
    }

    /// Election timeout fires (only meaningful for Follower / Candidate).
    pub fn on_election_timeout(&mut self) -> Vec<Action> {
        match self.role {
            Role::Leader => Vec::new(),
            _ => self.start_election(),
        }
    }

    /// Heartbeat tick — relevant only for Leader. Broadcasts an empty
    /// AppendEntries to assert leadership.
    pub fn on_heartbeat_tick(&mut self) -> Vec<Action> {
        if self.role != Role::Leader {
            return Vec::new();
        }
        let msg = Message::AppendEntries(AppendEntries {
            term: self.current_term,
            leader_id: self.me,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: Vec::new(),
            leader_commit: 0,
        });
        vec![Action::Broadcast(msg)]
    }

    /// Handle a message received from a peer.
    pub fn on_message(&mut self, msg: Message) -> Vec<Action> {
        // Universal rule: if RPC term > current_term, step down before
        // processing further.
        let msg_term = msg.term();
        let stepped_down = if msg_term > self.current_term {
            self.step_down_to(msg_term);
            true
        } else {
            false
        };

        let actions = match msg {
            Message::RequestVote(rv) => self.handle_request_vote(rv),
            Message::RequestVoteResp(rvr) => self.handle_request_vote_resp(rvr),
            Message::AppendEntries(ae) => self.handle_append_entries(ae),
            Message::AppendEntriesResp(aer) => self.handle_append_entries_resp(aer),
        };

        if stepped_down && actions.is_empty() {
            // We changed role/term but the handler didn't tell us to reset the
            // election timer. Do it ourselves so the next election can fire.
            vec![Action::ResetElectionTimer]
        } else {
            actions
        }
    }

    // -- internal --

    fn step_down_to(&mut self, term: Term) {
        self.current_term = term;
        self.voted_for = None;
        self.role = Role::Follower;
        self.votes_received.clear();
        self.leader_hint = None;
    }

    fn start_election(&mut self) -> Vec<Action> {
        self.current_term += 1;
        self.role = Role::Candidate;
        self.voted_for = Some(self.me);
        self.votes_received.clear();
        self.votes_received.insert(self.me);
        self.leader_hint = None;

        let rv = RequestVote {
            term: self.current_term,
            candidate_id: self.me,
            last_log_index: 0,
            last_log_term: 0,
        };

        // A 1-node cluster wins its own election immediately.
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
        if rv.term >= self.current_term
            && (self.voted_for.is_none() || self.voted_for == Some(rv.candidate_id))
        {
            // Log-up-to-date check is trivial in step 1 (we have no log).
            grant = true;
            self.voted_for = Some(rv.candidate_id);
        }
        let resp = Message::RequestVoteResp(RequestVoteResp {
            term: self.current_term,
            vote_granted: grant,
            voter_id: self.me,
        });
        let mut out = vec![Action::SendTo(rv.candidate_id, resp)];
        if grant {
            // Granting a vote restarts our election timer — gives the new leader
            // time to assert itself before we start a fresh election.
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
        if ae.term >= self.current_term {
            // Valid leader for this term. If we were a Candidate at the same
            // term, step back to Follower.
            self.current_term = ae.term;
            self.role = Role::Follower;
            self.voted_for = None;
            self.votes_received.clear();
            self.leader_hint = Some(ae.leader_id);
            // Step 1: we accept all heartbeats; step 2 will check prev_log.
            success = true;
        }
        let resp = Message::AppendEntriesResp(AppendEntriesResp {
            term: self.current_term,
            success,
            responder_id: self.me,
            match_index: 0,
        });
        let mut out = vec![Action::SendTo(ae.leader_id, resp)];
        if success {
            out.push(Action::ResetElectionTimer);
        }
        out
    }

    fn handle_append_entries_resp(&mut self, _aer: AppendEntriesResp) -> Vec<Action> {
        // Step 1 leader has nothing useful to do with this — there's no log
        // to advance. Step 2 will track next_index / match_index per peer.
        Vec::new()
    }

    fn become_leader(&mut self) {
        self.role = Role::Leader;
        self.leader_hint = Some(self.me);
        self.votes_received.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(me: NodeId, peers: &[NodeId]) -> RaftState {
        RaftState::new(me, peers.to_vec())
    }

    #[test]
    fn single_node_cluster_self_elects() {
        let mut s = n(1, &[]);
        let actions = s.on_election_timeout();
        assert_eq!(s.role, Role::Leader);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Broadcast(Message::AppendEntries(_)))));
    }

    #[test]
    fn higher_term_forces_step_down() {
        let mut s = n(1, &[2, 3]);
        // Start election → candidate at term 1.
        s.on_election_timeout();
        assert_eq!(s.role, Role::Candidate);
        // Peer 2 sends an AppendEntries at term 5 — we step down.
        let actions = s.on_message(Message::AppendEntries(AppendEntries {
            term: 5,
            leader_id: 2,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        }));
        assert_eq!(s.role, Role::Follower);
        assert_eq!(s.current_term, 5);
        assert_eq!(s.leader_hint, Some(2));
        assert!(actions.iter().any(|a| matches!(a, Action::ResetElectionTimer)));
    }

    #[test]
    fn vote_only_once_per_term() {
        let mut s = n(1, &[2, 3]);
        // Two candidates ask in the same term.
        let r1 = s.on_message(Message::RequestVote(RequestVote {
            term: 7,
            candidate_id: 2,
            last_log_index: 0,
            last_log_term: 0,
        }));
        let r2 = s.on_message(Message::RequestVote(RequestVote {
            term: 7,
            candidate_id: 3,
            last_log_index: 0,
            last_log_term: 0,
        }));
        assert_eq!(s.voted_for, Some(2));
        // First grants; second denies (already voted for 2).
        let granted = |actions: &[Action]| {
            actions.iter().any(|a| {
                matches!(
                    a,
                    Action::SendTo(_, Message::RequestVoteResp(RequestVoteResp { vote_granted: true, .. }))
                )
            })
        };
        assert!(granted(&r1));
        assert!(!granted(&r2));
    }

    #[test]
    fn three_node_wins_with_majority() {
        let mut s = n(1, &[2, 3]);
        s.on_election_timeout();
        assert_eq!(s.role, Role::Candidate);
        // Peer 2 grants — that's 2/3, quorum met.
        let actions = s.on_message(Message::RequestVoteResp(RequestVoteResp {
            term: s.current_term,
            vote_granted: true,
            voter_id: 2,
        }));
        assert_eq!(s.role, Role::Leader);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Broadcast(Message::AppendEntries(_)))));
    }
}
