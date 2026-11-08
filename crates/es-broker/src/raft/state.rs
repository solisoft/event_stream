//! Raft state machine: election, log replication, commit advancement,
//! snapshots, single-server membership changes.
//!
//! Pure (no I/O). The driver in `node.rs` calls one of `on_*` per event and
//! executes the returned [`Action`]s. Every change to persistent state
//! (`current_term`, `voted_for`, the log) is recorded as a [`PersistOp`]; the
//! driver drains them with [`RaftState::take_persist_ops`] and makes them
//! durable **before** sending any message the actions contain.
//!
//! The group's configuration is derived, never stored on its own: the one at
//! the log's base (from the snapshot, or the command line), with every config
//! entry in the log applied on top. See [`super::membership`] for the rules.

use std::collections::{BTreeMap, HashSet};

use super::log::{Log, PersistOp, PersistedRaft, PersistedSnapshot};
use super::membership::{decode_config_change, encode_member_change, MemberChange, Membership};
pub use super::membership::{encode_config_change, is_config_entry};
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

/// A group's configuration as the transport needs it: the latest one, in
/// effect since its entry was appended, and the last committed one. Until the
/// latest commits, members of either may still be talking to us — a removed
/// leader is still replicating the entry that removes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipView {
    pub latest: Membership,
    pub committed: Membership,
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
    /// The group's configuration changed: the transport follows it.
    Membership(MembershipView),
}

/// Why a membership change was not proposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeRefused {
    NotLeader(Option<NodeId>),
    /// The previous change, at this index, has not committed yet.
    InProgress(LogIndex),
    /// This leader has not yet committed an entry of its own term; a change
    /// proposed now could overlap one its predecessor left uncommitted.
    LeaderNotReady,
    /// The change is already in effect: the node is (or is not) a voter.
    AlreadyInEffect,
    /// Removing the last voter would leave a group nobody can lead.
    LastVoter,
}

impl std::fmt::Display for ChangeRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotLeader(Some(l)) => write!(f, "not the leader; node {l} is"),
            Self::NotLeader(None) => write!(f, "not the leader, and no leader is known"),
            Self::InProgress(i) => {
                write!(f, "a membership change (entry {i}) has not committed yet")
            }
            Self::LeaderNotReady => {
                write!(f, "the leader has not committed an entry of its term yet")
            }
            Self::AlreadyInEffect => write!(f, "the change is already in effect"),
            Self::LastVoter => write!(f, "removing the last voter would leave no one to lead"),
        }
    }
}

#[derive(Debug)]
pub struct RaftState {
    pub me: NodeId,
    /// The other voters of the latest configuration: whom a leader replicates
    /// to and counts. Derived from `config`; never set directly.
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

    /// Latest read-index round handed out (§6.4). Never reset, so a round
    /// number is never reused, not even across terms.
    read_seq: u64,
    /// Leader-only: the highest read round each peer has acknowledged in the
    /// current term. Cleared on every change of role.
    read_acks: BTreeMap<NodeId, u64>,
    /// The configuration at the log's base: what the snapshot recorded, or
    /// what this node was started with.
    pub base_config: Membership,
    /// The latest configuration: in effect since its entry was appended.
    pub config: Membership,
    /// The configuration as of `commit_index`.
    pub committed_config: Membership,
    /// Index of the entry that set `config` (the base index when none did).
    pub config_index: LogIndex,
    /// What `config` was last derived from, so it is rederived only when the
    /// log or commit index moved past a config entry.
    config_marks: (LogIndex, LogIndex, Term, LogIndex),

    votes_received: HashSet<NodeId>,
    pending: Vec<PersistOp>,
}

impl RaftState {
    pub fn new(me: NodeId, peers: Vec<NodeId>) -> Self {
        let config = Membership::new(peers.iter().copied().chain([me]));
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
            read_seq: 0,
            read_acks: BTreeMap::new(),
            base_config: config.clone(),
            committed_config: config.clone(),
            config,
            config_index: 0,
            config_marks: (0, 0, 0, 0),
            votes_received: HashSet::new(),
            pending: Vec::new(),
        }
    }

    /// Start as a non-voter: a broker joining an existing cluster, waiting
    /// for a leader to add it. It replicates whatever it is sent but never
    /// campaigns, so it cannot disrupt the cluster with elections it can only
    /// lose. Call before [`Self::restore`]: a log that already holds the
    /// change adding this node makes it a voter again.
    pub fn set_joining(&mut self) {
        self.base_config.voters.remove(&self.me);
        self.reload_config();
    }

    /// Rederive the configuration from scratch, discarding what it was.
    fn reload_config(&mut self) {
        self.config_marks = (LogIndex::MAX, 0, 0, 0);
        self.config = Membership::default();
        let _ = self.refresh_config();
    }

    /// Where the config entries are: the base index, the last config entry
    /// (index and term — a truncated and rewritten entry has another term),
    /// and the last one at or below the commit index.
    fn current_marks(&self) -> (LogIndex, LogIndex, Term, LogIndex) {
        let mut latest = None;
        let mut committed = None;
        for e in self.log.entries.iter().rev() {
            if !is_config_entry(&e.payload) {
                continue;
            }
            if latest.is_none() {
                latest = Some((e.index, e.term));
            }
            if e.index <= self.commit_index {
                committed = Some(e.index);
                break;
            }
        }
        let (li, lt) = latest.unwrap_or((0, 0));
        (self.log.base_index, li, lt, committed.unwrap_or(0))
    }

    /// The configuration in effect at `index`, and the index of the entry
    /// that set it.
    pub fn config_through(&self, index: LogIndex) -> (Membership, LogIndex) {
        let mut config = self.base_config.clone();
        let mut at = self.log.base_index;
        for e in &self.log.entries {
            if e.index > index {
                break;
            }
            if let Some(change) = decode_config_change(&e.payload) {
                config.apply(&change);
                at = e.index;
            }
        }
        (config, at)
    }

    /// Bring `config` and `committed_config` up to date with the log, and
    /// say so when either changed.
    fn refresh_config(&mut self) -> Option<Action> {
        let marks = self.current_marks();
        if marks == self.config_marks {
            return None;
        }
        self.config_marks = marks;
        let (latest, latest_index) = self.config_through(LogIndex::MAX);
        let (committed, _) = self.config_through(self.commit_index);
        self.config_index = latest_index;
        if latest == self.config && committed == self.committed_config {
            return None;
        }
        let was: Vec<NodeId> = self.config.ids().collect();
        self.config = latest;
        self.committed_config = committed;
        self.peers = self.config.ids().filter(|id| *id != self.me).collect();
        if self.role == Role::Leader {
            let next = self.log.last_index() + 1;
            for p in &self.peers {
                if !was.contains(p) {
                    self.next_index.insert(*p, next);
                    self.match_index.insert(*p, 0);
                }
            }
            let peers = self.peers.clone();
            self.next_index.retain(|p, _| peers.contains(p));
            self.match_index.retain(|p, _| peers.contains(p));
            self.snapshot_cursor.retain(|p, _| peers.contains(p));
        }
        tracing::info!(
            me = self.me,
            voters = ?self.config.ids().collect::<Vec<_>>(),
            committed = ?self.committed_config.ids().collect::<Vec<_>>(),
            "raft: configuration changed"
        );
        Some(Action::Membership(self.membership_view()))
    }

    pub fn membership_view(&self) -> MembershipView {
        MembershipView {
            latest: self.config.clone(),
            committed: self.committed_config.clone(),
        }
    }

    /// Whether a membership change is appended but not yet committed.
    pub fn has_uncommitted_change(&self) -> bool {
        self.config_index > self.commit_index
    }

    /// What follows any event that may have moved the log or the commit
    /// index: the transport learns of a new configuration, and a leader the
    /// latest one leaves out steps down once that is committed.
    fn after_change(&mut self) -> Vec<Action> {
        let mut out: Vec<Action> = self.refresh_config().into_iter().collect();
        if self.role == Role::Leader
            && !self.config.contains(self.me)
            && self.commit_index >= self.config_index
        {
            // One last round, so the others learn the change committed and
            // stop counting this node before it goes quiet (§4.2.2).
            out.extend(self.on_heartbeat_tick());
            tracing::info!(me = self.me, "raft: removed from the group; stepping down");
            self.role = Role::Follower;
            self.leader_hint = None;
            self.match_index.clear();
            self.next_index.clear();
            self.snapshot_cursor.clear();
        }
        out
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
            // The voters as of the snapshot; a 0.2 snapshot recorded none, and
            // the configuration this node was started with stands.
            if let Some(members) = &snap.members {
                self.base_config = members.clone();
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
        self.reload_config();
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
        // The config entries up to `through` are about to leave the log; the
        // snapshot carries what they amounted to.
        let (members, _) = self.config_through(through);
        self.log.compact_through(through, term);
        self.base_config = members.clone();
        self.pending.push(PersistOp::CompactThrough(through));
        Ok(PersistedSnapshot {
            last_index: through,
            last_term: term,
            data,
            members: Some(members),
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

    /// A majority of the latest configuration's voters, floor(N/2)+1. During
    /// a single-server change, any majority of the old configuration and any
    /// of the new one overlap, which is why counting only the latest is safe.
    fn quorum(&self) -> usize {
        self.config.len() / 2 + 1
    }

    /// Whether `id` may talk to this group at all: a voter of the latest
    /// configuration, or of the committed one while a change is pending — a
    /// leader being removed still replicates the entry that removes it.
    fn is_member(&self, id: NodeId) -> bool {
        id != self.me && (self.config.contains(id) || self.committed_config.contains(id))
    }

    /// Whether `term` is one a real peer could send: not absurdly far ahead
    /// of ours, and not the value that would pin every node forever.
    fn term_is_plausible(&self, term: Term) -> bool {
        term <= self.current_term.saturating_add(MAX_TERM_JUMP) && term != Term::MAX
    }

    /// Whether `leader` claiming leadership of `term` contradicts what this
    /// node already knows about `term`. A term has at most one leader: if it
    /// is us, or one we already follow, any other claimant is lying.
    fn conflicts_with_known_leader(&self, leader: NodeId, term: Term) -> bool {
        term == self.current_term
            && (self.role == Role::Leader || self.leader_hint.is_some_and(|h| h != leader))
    }

    /// Whether an AppendEntries or InstallSnapshot from `leader` for `term`
    /// would be acted on — checked by the driver **before** it applies
    /// snapshot data to the state machine or counts the message as a sign of
    /// a live leader. Pure: the same checks [`Self::on_message`] makes, without
    /// the side effects.
    pub fn accepts_from_leader(&self, leader: NodeId, term: Term) -> bool {
        self.is_member(leader)
            && self.term_is_plausible(term)
            && term >= self.current_term
            && !self.conflicts_with_known_leader(leader, term)
    }

    // ---------- timer-driven events ----------

    pub fn on_election_timeout(&mut self) -> Vec<Action> {
        if self.role == Role::Leader {
            return Vec::new();
        }
        // A node outside the latest configuration — joining and not yet
        // added, or removed — never campaigns: it could only lose, and its
        // ever higher terms would depose the leaders of the real group.
        if !self.config.contains(self.me) {
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

    // ---------- read index (dissertation §6.4) ----------

    /// Start a read-index round: a new round number, and an AppendEntries to
    /// every peer carrying it. The read may be served once
    /// [`Self::read_confirmed_seq`] reaches the returned round and
    /// [`Self::committed_in_current_term`] holds; its read index is the
    /// commit index at that moment.
    ///
    /// Only answers sent for this round (or a later one) count. An answer to
    /// an earlier AppendEntries may have been written before the read began,
    /// and proves nothing about who led the cluster when it did. `None` when
    /// not leader.
    pub fn begin_read(&mut self) -> Option<(u64, Vec<Action>)> {
        if self.role != Role::Leader {
            return None;
        }
        self.read_seq += 1;
        Some((self.read_seq, self.on_heartbeat_tick()))
    }

    /// The highest read round a majority (counting this leader) has
    /// acknowledged in the current term: every read registered at or below
    /// it was started while this node was still the leader a majority
    /// followed. Zero when not leader.
    pub fn read_confirmed_seq(&self) -> u64 {
        if self.role != Role::Leader {
            return 0;
        }
        let mut acks: Vec<u64> = self
            .peers
            .iter()
            .map(|p| self.read_acks.get(p).copied().unwrap_or(0))
            .collect();
        // The leader vouches for itself only while it is a voter: a leader
        // that is removing itself is not in the latest configuration, and the
        // quorum is counted among that configuration's voters.
        if self.config.contains(self.me) {
            acks.push(self.read_seq);
        }
        let quorum = self.quorum();
        if quorum == 0 || acks.len() < quorum {
            return 0;
        }
        acks.sort_unstable();
        acks[acks.len() - quorum]
    }

    /// Whether this leader has committed an entry of its own term. Until it
    /// has, its commit index may lag entries a previous leader committed, so
    /// it cannot be a read index (§6.4 step 1; the election no-op is what
    /// makes this hold one round trip after winning).
    pub fn committed_in_current_term(&self) -> bool {
        self.role == Role::Leader && self.log.term_at(self.commit_index) == Some(self.current_term)
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
        // Votes count only within the latest configuration, so a request
        // from outside it (a removed node, or one whose addition we have not
        // seen) can win nothing here, and must not depose anyone either.
        if matches!(msg, Message::RequestVote(_)) && !self.config.contains(sender) {
            return Vec::new();
        }
        if !self.term_is_plausible(msg_term) {
            tracing::warn!(
                me = self.me,
                sender,
                msg_term,
                current_term = self.current_term,
                "raft: ignoring message with an implausible term"
            );
            return Vec::new();
        }
        if matches!(msg, Message::AppendEntries(_) | Message::InstallSnapshot(_))
            && self.conflicts_with_known_leader(sender, msg_term)
        {
            tracing::warn!(
                me = self.me,
                sender,
                msg_term,
                "raft: ignoring a second leader's message for the current term"
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
        actions.extend(self.after_change());
        actions
    }

    /// Propose a single-server membership change (§4.1). Must be called on
    /// the leader. The new configuration is in effect from the moment its
    /// entry is appended, here, before anything is replicated.
    pub fn propose_member_change(
        &mut self,
        change: &MemberChange,
    ) -> Result<(LogIndex, Vec<Action>), ChangeRefused> {
        if self.role != Role::Leader {
            return Err(ChangeRefused::NotLeader(self.leader_hint));
        }
        if self.has_uncommitted_change() {
            return Err(ChangeRefused::InProgress(self.config_index));
        }
        if self.log.term_at(self.commit_index) != Some(self.current_term) {
            return Err(ChangeRefused::LeaderNotReady);
        }
        match change {
            MemberChange::Add { id, .. } if self.config.contains(*id) => {
                return Err(ChangeRefused::AlreadyInEffect)
            }
            MemberChange::Remove { id } if !self.config.contains(*id) => {
                return Err(ChangeRefused::AlreadyInEffect)
            }
            MemberChange::Remove { .. } if self.config.len() == 1 => {
                return Err(ChangeRefused::LastVoter)
            }
            _ => {}
        }
        let index = self.append_local(encode_member_change(change));
        let mut actions: Vec<Action> = self.refresh_config().into_iter().collect();
        // A group of one commits on its own; and removing a node can leave
        // the entries already acknowledged by the rest a majority.
        self.recompute_commit_index();
        actions.extend(self.drain_apply_actions());
        actions.extend(self.after_change());
        Ok((index, actions))
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
        let mut actions = self.drain_apply_actions();
        actions.extend(self.after_change());
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
            // A leader's election no-op has nothing to apply, and a config
            // entry took effect when it was appended.
            if e.payload.is_empty() || is_config_entry(&e.payload) {
                continue;
            }
            out.push(Action::Apply(e.clone()));
        }
        out
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
        self.read_acks.clear();
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
            out.extend(self.after_change());
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
            let votes = self
                .votes_received
                .iter()
                .filter(|v| self.config.contains(**v))
                .count();
            if votes >= self.quorum() {
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
            read_seq: ae.read_seq,
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
        // Any answer in our term — a rejection included — shows the peer
        // still followed us when it wrote it, which is all a read round asks.
        if aer.read_seq > 0 {
            let acked = self.read_acks.entry(peer).or_insert(0);
            *acked = (*acked).max(aer.read_seq.min(self.read_seq));
        }
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
                // The snapshot replaces the config entries it covers: adopt
                // the voters it carries, or — from a 0.2 leader, which sends
                // none — what our own log says they were at that point.
                let at_snapshot = match is.members {
                    Some(m) => m,
                    None => self.config_through(is.last_index).0,
                };
                let kept = self.log.install_snapshot(is.last_index, is.last_term);
                self.base_config = at_snapshot;
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
        self.read_acks.clear();
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
            read_seq: self.read_seq,
        })
    }

    fn recompute_commit_index(&mut self) {
        // Build the multiset of replicated indices of the latest
        // configuration's voters — the leader's own only if it is one: a
        // leader removing itself manages the change without counting toward
        // it (§4.2.2).
        let mut indices: Vec<LogIndex> = self
            .peers
            .iter()
            .map(|p| self.match_index.get(p).copied().unwrap_or(0))
            .collect();
        if self.config.contains(self.me) {
            indices.push(self.log.last_index());
        }
        if indices.is_empty() {
            return;
        }
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
            read_seq: 0,
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
            read_seq: 0,
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
            read_seq: 0,
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
            read_seq: 0,
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

    fn heartbeat(term: Term, leader: NodeId) -> Message {
        Message::AppendEntries(AppendEntries {
            term,
            leader_id: leader,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
            read_seq: 0,
        })
    }

    fn snapshot_done(term: Term, leader: NodeId, last_index: LogIndex) -> Message {
        Message::InstallSnapshot(InstallSnapshot {
            term,
            leader_id: leader,
            last_index,
            last_term: term,
            offset: 0,
            done: true,
            data: Vec::new(),
            members: None,
        })
    }

    #[test]
    fn accepts_from_leader_applies_every_guard() {
        let mut f = n(2, &[1, 3]);
        f.on_message(heartbeat(4, 1));
        assert_eq!((f.current_term, f.leader_hint), (4, Some(1)));
        assert!(f.accepts_from_leader(1, 4), "the known leader");
        assert!(
            f.accepts_from_leader(3, 5),
            "a newer term may have a new leader"
        );
        assert!(
            !f.accepts_from_leader(3, 4),
            "a second leader for the same term"
        );
        assert!(!f.accepts_from_leader(9, 5), "a non-member");
        assert!(!f.accepts_from_leader(1, 3), "a stale term");
        assert!(!f.accepts_from_leader(1, Term::MAX), "the pinning term");
        assert!(
            !f.accepts_from_leader(1, 4 + MAX_TERM_JUMP + 1),
            "an absurd jump"
        );

        let l = leader_of_three();
        assert!(
            !l.accepts_from_leader(2, l.current_term),
            "a leader has no other leader in its own term"
        );
    }

    #[test]
    fn a_second_leaders_snapshot_is_not_installed() {
        let mut f = n(2, &[1, 3]);
        f.on_message(heartbeat(4, 1));
        let a = f.on_message(snapshot_done(4, 3, 50));
        assert!(a.is_empty(), "{a:?}");
        assert_eq!(f.log.base_index, 0);
        assert_eq!(f.commit_index, 0);
        assert_eq!(f.leader_hint, Some(1));

        let mut l = leader_of_three();
        let term = l.current_term;
        assert!(l.on_message(snapshot_done(term, 2, 50)).is_empty());
        assert_eq!(
            l.role,
            Role::Leader,
            "a forged same-term leader must not depose us"
        );
        assert_eq!(l.log.base_index, 0);
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

    fn ack(term: Term, from: NodeId, match_index: LogIndex, read_seq: u64) -> Message {
        Message::AppendEntriesResp(AppendEntriesResp {
            term,
            success: true,
            responder_id: from,
            match_index,
            read_seq,
        })
    }

    /// A leader of {1, 2, 3} that has committed an entry of its term.
    fn ready_leader() -> RaftState {
        let mut s = leader_of_three();
        let _ = s.try_propose(b"a".to_vec());
        s.on_message(ack(s.current_term, 2, 1, 0));
        assert!(s.committed_in_current_term());
        s
    }

    #[test]
    fn a_read_round_is_confirmed_by_a_majority_of_its_own_acks() {
        let mut s = ready_leader();
        let term = s.current_term;
        let (seq, actions) = s.begin_read().expect("leader");
        assert_eq!(seq, 1);
        // The round goes out at once, to every peer, carrying its number.
        for peer in [2, 3] {
            assert!(
                actions.iter().any(|a| matches!(a,
                    Action::SendTo(p, Message::AppendEntries(ae)) if *p == peer && ae.read_seq == seq)),
                "{actions:?}"
            );
        }
        assert_eq!(s.read_confirmed_seq(), 0, "the leader alone is no majority");

        // An answer to an AppendEntries sent before the read began does not
        // count, however recent it is.
        s.on_message(ack(term, 2, 1, 0));
        assert_eq!(s.read_confirmed_seq(), 0);

        // A rejection still shows the peer follows us.
        s.on_message(Message::AppendEntriesResp(AppendEntriesResp {
            term,
            success: false,
            responder_id: 3,
            match_index: 0,
            read_seq: seq,
        }));
        assert_eq!(s.read_confirmed_seq(), seq);

        // A later round needs its own acks; the earlier one stays confirmed.
        let (seq2, _) = s.begin_read().unwrap();
        assert_eq!(s.read_confirmed_seq(), seq);
        s.on_message(ack(term, 2, 1, seq2));
        assert_eq!(s.read_confirmed_seq(), seq2);
    }

    #[test]
    fn read_acks_from_another_term_or_beyond_the_round_do_not_count() {
        let mut s = ready_leader();
        let term = s.current_term;
        let (seq, _) = s.begin_read().unwrap();
        // A forged round far ahead is clamped to the rounds really issued.
        s.on_message(ack(term, 2, 1, u64::MAX));
        assert_eq!(s.read_confirmed_seq(), seq);
        let (seq2, _) = s.begin_read().unwrap();
        assert_eq!(s.read_confirmed_seq(), seq, "{seq2} was never acked");

        // A newer term deposes the leader and forgets every ack.
        s.on_message(ack(term + 1, 3, 0, seq2));
        assert_eq!(s.role, Role::Follower);
        assert!(s.begin_read().is_none());
        assert_eq!(s.read_confirmed_seq(), 0);
        assert!(!s.committed_in_current_term());
    }

    #[test]
    fn a_new_leader_is_not_read_ready_until_it_commits_in_its_term() {
        let mut s = leader_of_three();
        let (seq, _) = s.begin_read().unwrap();
        s.on_message(ack(s.current_term, 2, 0, seq));
        assert_eq!(s.read_confirmed_seq(), seq);
        assert!(
            !s.committed_in_current_term(),
            "its commit index may still lag what the previous leader committed"
        );
    }

    #[test]
    fn a_single_node_confirms_its_own_reads() {
        let mut s = n(1, &[]);
        s.noop_on_elect = true;
        s.on_election_timeout();
        let (seq, actions) = s.begin_read().unwrap();
        assert!(actions.is_empty());
        assert_eq!(s.read_confirmed_seq(), seq);
        assert!(s.committed_in_current_term());
    }

    #[test]
    fn followers_echo_the_read_round() {
        let mut f = n(2, &[1, 3]);
        let actions = f.on_message(Message::AppendEntries(AppendEntries {
            term: 1,
            leader_id: 1,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
            read_seq: 42,
        }));
        assert!(actions.iter().any(|a| matches!(a,
            Action::SendTo(1, Message::AppendEntriesResp(r)) if r.read_seq == 42)));
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

    // ---------- membership (Bonfire #731) ----------

    fn add(id: NodeId) -> MemberChange {
        MemberChange::Add {
            id,
            addr: format!("10.0.0.{id}:6000"),
        }
    }

    fn ack(s: &mut RaftState, peer: NodeId, index: LogIndex) -> Vec<Action> {
        s.on_message(Message::AppendEntriesResp(AppendEntriesResp {
            term: s.current_term,
            success: true,
            responder_id: peer,
            match_index: index,
        }))
    }

    /// A leader of {1, 2, 3} that has committed an entry of its term, and so
    /// may change the configuration.
    fn ready_leader() -> RaftState {
        let mut s = leader_of_three();
        s.try_propose(b"x".to_vec());
        ack(&mut s, 2, 1);
        assert_eq!(s.commit_index, 1);
        s
    }

    fn entry(term: Term, index: LogIndex, payload: Vec<u8>) -> LogEntry {
        LogEntry {
            term,
            index,
            payload,
        }
    }

    fn append(term: Term, leader: NodeId, entries: Vec<LogEntry>, commit: LogIndex) -> Message {
        Message::AppendEntries(AppendEntries {
            term,
            leader_id: leader,
            prev_log_index: 0,
            prev_log_term: 0,
            entries,
            leader_commit: commit,
        })
    }

    #[test]
    fn a_change_takes_effect_when_appended_not_when_committed() {
        let mut s = ready_leader();
        let (index, actions) = s.propose_member_change(&add(4)).unwrap();
        assert_eq!(index, 2);
        assert!(s.config.contains(4) && s.peers.contains(&4));
        assert_eq!(s.quorum(), 3, "four voters: three make a majority");
        assert!(s.has_uncommitted_change());
        assert!(!s.committed_config.contains(4));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Membership(v) if v.latest.contains(4))),
            "the transport is told at once: {actions:?}"
        );
        assert_eq!(
            s.config.voters.get(&4).map(String::as_str),
            Some("10.0.0.4:6000")
        );

        ack(&mut s, 2, 2);
        assert_eq!(s.commit_index, 1, "two of four is not a majority any more");
        ack(&mut s, 4, 2);
        assert_eq!(s.commit_index, 2);
        assert!(s.committed_config.contains(4));
        assert!(!s.has_uncommitted_change());
    }

    #[test]
    fn a_second_change_is_refused_while_the_first_is_uncommitted() {
        let mut s = ready_leader();
        s.propose_member_change(&add(4)).unwrap();
        assert_eq!(
            s.propose_member_change(&add(5)).unwrap_err(),
            ChangeRefused::InProgress(2)
        );
        assert_eq!(
            s.propose_member_change(&MemberChange::Remove { id: 3 })
                .unwrap_err(),
            ChangeRefused::InProgress(2)
        );
        ack(&mut s, 2, 2);
        ack(&mut s, 3, 2);
        assert!(s.propose_member_change(&add(5)).is_ok(), "once committed");
    }

    #[test]
    fn a_new_leader_must_commit_in_its_term_before_changing_membership() {
        let mut s = leader_of_three();
        assert_eq!(
            s.propose_member_change(&add(4)).unwrap_err(),
            ChangeRefused::LeaderNotReady
        );
        let mut f = n(2, &[1, 3]);
        assert_eq!(
            f.propose_member_change(&add(4)).unwrap_err(),
            ChangeRefused::NotLeader(None)
        );
    }

    #[test]
    fn a_change_already_in_effect_or_removing_the_last_voter_is_refused() {
        let mut s = ready_leader();
        assert_eq!(
            s.propose_member_change(&add(2)).unwrap_err(),
            ChangeRefused::AlreadyInEffect
        );
        assert_eq!(
            s.propose_member_change(&MemberChange::Remove { id: 9 })
                .unwrap_err(),
            ChangeRefused::AlreadyInEffect
        );
        let mut solo = n(1, &[]);
        solo.on_election_timeout();
        solo.try_propose(b"x".to_vec());
        assert_eq!(
            solo.propose_member_change(&MemberChange::Remove { id: 1 })
                .unwrap_err(),
            ChangeRefused::LastVoter
        );
    }

    #[test]
    fn a_follower_adopts_a_config_on_append_and_drops_it_on_truncation() {
        let mut f = n(2, &[1, 3]);
        let change = encode_member_change(&add(4));
        let a = f.on_message(append(1, 1, vec![entry(1, 1, change)], 0));
        assert!(f.config.contains(4) && f.peers.contains(&4));
        assert!(!f.committed_config.contains(4));
        assert!(a.iter().any(|a| matches!(a, Action::Membership(_))));
        // A message from the new member is now heard...
        assert!(f.is_member(4));

        // ...until a new leader overwrites the uncommitted entry.
        f.on_message(append(2, 3, vec![entry(2, 1, b"data".to_vec())], 0));
        assert!(
            !f.config.contains(4),
            "the truncated entry's config is undone"
        );
        assert!(!f.is_member(4));
    }

    #[test]
    fn a_removed_leader_steps_down_once_the_change_commits() {
        let mut s = ready_leader();
        s.propose_member_change(&MemberChange::Remove { id: 1 })
            .unwrap();
        assert_eq!(
            s.role,
            Role::Leader,
            "it manages the change until it commits"
        );
        assert_eq!(s.peers, vec![2, 3]);
        ack(&mut s, 2, 2);
        assert_eq!(
            s.commit_index, 1,
            "the leader does not count itself in a configuration it is not in"
        );
        let actions = ack(&mut s, 3, 2);
        assert_eq!(s.commit_index, 2);
        assert_eq!(s.role, Role::Follower);
        for peer in [2, 3] {
            assert!(
                actions.iter().any(|a| matches!(
                    a,
                    Action::SendTo(p, Message::AppendEntries(ae)) if *p == peer && ae.leader_commit == 2
                )),
                "the others hear the change committed: {actions:?}"
            );
        }
        assert!(s.on_election_timeout().is_empty(), "and it never campaigns");
    }

    #[test]
    fn a_node_outside_the_configuration_never_campaigns() {
        let mut s = n(4, &[1, 2, 3]);
        s.set_joining();
        assert!(!s.config.contains(4));
        assert!(s.on_election_timeout().is_empty());
        assert_eq!(s.current_term, 0);
        // The leader adds it: from then on it is a voter like any other.
        s.on_message(append(
            1,
            1,
            vec![entry(1, 1, encode_member_change(&add(4)))],
            0,
        ));
        assert!(s.config.contains(4));
        assert!(!s.on_election_timeout().is_empty());
        assert_eq!(s.current_term, 2);
    }

    #[test]
    fn vote_requests_from_outside_the_latest_configuration_are_ignored() {
        let mut f = n(2, &[1, 3]);
        let remove = encode_member_change(&MemberChange::Remove { id: 3 });
        f.on_message(append(1, 1, vec![entry(1, 1, remove)], 0));
        let a = f.on_message(Message::RequestVote(RequestVote {
            term: 5,
            candidate_id: 3,
            last_log_index: 9,
            last_log_term: 4,
        }));
        assert!(a.is_empty());
        assert_eq!(f.current_term, 1, "a removed node cannot bump our term");
    }

    #[test]
    fn a_snapshot_records_the_membership_and_a_restart_restores_it() {
        let mut s = ready_leader();
        s.propose_member_change(&add(4)).unwrap();
        ack(&mut s, 2, 2);
        ack(&mut s, 3, 2);
        let snap = s.take_snapshot(Vec::new(), None).unwrap();
        assert!(snap.members.as_ref().unwrap().contains(4));
        assert!(s.log.entries.is_empty(), "the config entry was compacted");
        assert!(s.config.contains(4), "and its effect stays");

        let mut restarted = n(1, &[2, 3]);
        restarted
            .restore(PersistedRaft::default(), Some(&snap))
            .unwrap();
        assert!(restarted.config.contains(4));
        assert_eq!(restarted.peers, vec![2, 3, 4]);
    }

    #[test]
    fn an_installed_snapshot_brings_its_membership() {
        let mut f = n(2, &[1, 3]);
        let mut members = Membership::new([1, 2, 3]);
        members.voters.insert(4, "10.0.0.4:6000".into());
        f.on_message(Message::InstallSnapshot(InstallSnapshot {
            term: 1,
            leader_id: 1,
            last_index: 5,
            last_term: 1,
            offset: 0,
            done: true,
            data: Vec::new(),
            members: Some(members),
        }));
        assert!(f.config.contains(4));
        assert!(f.peers.contains(&4));
    }
}
