//! `GET /raft` — what each replicated partition's consensus actually looks like.
//!
//! Built because there was no way to answer "is this member replicating, or
//! merely running?" from outside the process. `/healthz` answers a static
//! "healthy", `/readyz` a static "ready", and `/metrics` says nothing about Raft
//! — so a broker that had lost contact with its peers, or one that was a cluster
//! of one because it was started without them, reported exactly what a healthy
//! member reports.
//!
//! That is the state an operator most needs to be able to see, and the one an
//! orchestrator has to check before it starts the next member.
//!
//! # Why this needs a token
//!
//! It reports the cluster's topology: node ids, who leads, and how far each peer
//! has replicated. None of that is record data, and an attacker on the path
//! already sees the addresses — but serving it to anyone who can reach the port
//! is a different thing from it leaking to someone already on the wire. Admin
//! grant, like the other endpoints that describe the cluster rather than its
//! contents.

use std::sync::Arc;

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::broker::Broker;
use crate::partition_handle::PartitionHandle;
use crate::raft::Role;

use super::auth_ext::AuthedKey;
use super::error::{AppError, AppResult};

/// How recently a peer must have been heard from to count toward a quorum.
///
/// Several heartbeat intervals, not one: a single missed heartbeat is normal on a
/// busy machine, and reporting a healthy cluster as broken is its own kind of
/// wrong. Long enough to absorb jitter, short enough that a dead member stops
/// counting well before anyone notices the cluster is stuck.
const PEER_LIVENESS_WINDOW: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftStatus {
    /// This broker's Raft node id, or `None` when it is not a cluster member.
    pub node_id: Option<u32>,
    /// Every member of the group this node belongs to, itself included.
    pub members: Vec<u32>,
    /// One entry per Raft-backed partition.
    pub partitions: Vec<PartitionStatus>,
    /// True when every Raft-backed partition is replicating *from this node's own
    /// vantage point*.
    ///
    /// Which is a different question on a leader than on a follower, and getting
    /// that wrong made this field useless on two nodes out of three: a follower
    /// keeps no `match_index` — that is leader state — so it can never report a
    /// quorum, and requiring one meant every follower answered `false` while
    /// replicating perfectly.
    ///
    /// So: a **leader** is replicating when a majority of members have caught up
    /// to its commit index. A **follower** is replicating when it knows who leads,
    /// because that is exactly what it can attest to. A **candidate** is not
    /// replicating — an election is in progress and nothing is committing.
    ///
    /// Both answers are needed, which is why an orchestrator asks every member:
    /// the leader's answer proves a majority exists, and each follower's proves it
    /// is one of them.
    pub replicating: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionStatus {
    pub topic: String,
    pub partition: u32,
    /// `leader`, `follower` or `candidate`.
    pub role: String,
    pub term: u64,
    /// Who this node believes leads, if anyone. `None` is the honest answer
    /// during an election, and the one that must not be confused with "me".
    pub leader: Option<u32>,
    pub commit_index: u64,
    pub last_log_index: u64,
    /// Members known to hold everything up to `commit_index`, this node included.
    ///
    /// A leader knows this from its `match_index` map. A follower keeps no such
    /// map, so it reports only itself — not because the others are behind, but
    /// because it cannot see.
    pub caught_up: Vec<u32>,
    /// Whether `caught_up` is a majority of the group, or `None` on a node that
    /// cannot know.
    ///
    /// `None` rather than `false` on a follower, deliberately: `false` reads as
    /// "there is no quorum", and a follower reporting that about a perfectly
    /// healthy cluster would send an operator looking for a fault that is not
    /// there.
    pub has_quorum: Option<bool>,
}

pub async fn raft_status(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
) -> AppResult<Json<RaftStatus>> {
    if !key.is_admin() {
        return Err(AppError::forbidden("admin grant required"));
    }

    let node_id = broker.config.raft_node_id;
    let mut members: Vec<u32> = broker.config.raft_peer_addrs.keys().copied().collect();
    if let Some(me) = node_id {
        members.push(me);
    }
    members.sort_unstable();

    // A majority of the configured group, not of whatever is currently reachable.
    // Counting reachable nodes would make a partition of one report a quorum of
    // one, which is the failure this endpoint exists to expose.
    let majority = members.len() / 2 + 1;

    let mut partitions = Vec::new();
    let mut names: Vec<String> = broker.list_topics();
    names.sort();
    for name in names {
        let Some(topic) = broker.topic(&name) else {
            continue;
        };
        for handle in topic.raft_partitions() {
            let PartitionHandle::Raft(raft) = handle else {
                continue;
            };
            // Liveness first, and it is not optional. `match_index` records what a
            // peer once acknowledged and goes on saying so after the peer dies, so
            // a leader that had lost two of three members still reported a quorum
            // of three — measured, not hypothetical.
            let alive = raft.peers_heard_from(PEER_LIVENESS_WINDOW).await;

            let state = raft.raft_state().lock().await;
            let me = state.me;
            let mut caught_up: Vec<u32> = state
                .match_index
                .iter()
                .filter(|(peer, index)| **index >= state.commit_index && alive.contains(peer))
                .map(|(peer, _)| *peer)
                .collect();
            // This node holds its own log up to its own commit index by
            // definition, so it counts — a leader that forgot to count itself
            // would report a three-member cluster as short by one.
            caught_up.push(me);
            caught_up.sort_unstable();
            caught_up.dedup();

            let role = match state.role {
                Role::Leader => "leader",
                Role::Follower => "follower",
                Role::Candidate => "candidate",
            };
            // Only a leader can answer this. See `RaftStatus::replicating`.
            let has_quorum = match state.role {
                Role::Leader => Some(caught_up.len() >= majority),
                Role::Follower | Role::Candidate => None,
            };
            partitions.push(PartitionStatus {
                topic: name.clone(),
                partition: raft.partition().id,
                role: role.to_string(),
                term: state.current_term,
                leader: state.leader_hint,
                commit_index: state.commit_index,
                last_log_index: state.log.last_index(),
                has_quorum,
                caught_up,
            });
        }
    }

    // Vacuously true with no Raft partitions, so callers must not read this alone
    // as "the cluster is up" — `partitions` being empty is the case to check, and
    // the CLI does.
    let replicating = partitions.iter().all(is_replicating);

    Ok(Json(RaftStatus {
        node_id,
        members,
        partitions,
        replicating,
    }))
}

/// Whether one partition is replicating, from this node's own vantage point.
///
/// Split out and tested because getting it wrong is easy and silent: requiring a
/// quorum from every role made every *follower* report `false` while replicating
/// perfectly, since a follower keeps no `match_index` to count.
fn is_replicating(p: &PartitionStatus) -> bool {
    match p.has_quorum {
        // A leader: it holds a majority of live, caught-up members, or it does not.
        Some(quorum) => quorum,
        // A follower attests to one thing — that it knows who leads. A candidate
        // knows nobody, and nothing commits during an election.
        None => p.leader.is_some() && p.role == "follower",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(role: &str, has_quorum: Option<bool>, leader: Option<u32>) -> PartitionStatus {
        PartitionStatus {
            topic: "events".into(),
            partition: 0,
            role: role.into(),
            term: 7,
            leader,
            commit_index: 12,
            last_log_index: 12,
            caught_up: vec![1],
            has_quorum,
        }
    }

    #[test]
    fn a_follower_that_knows_its_leader_is_replicating() {
        // The case that was wrong. A follower has no `match_index`, so demanding a
        // quorum from it reported two nodes out of three as broken while the
        // cluster was healthy.
        assert!(is_replicating(&status("follower", None, Some(2))));
    }

    #[test]
    fn a_follower_with_no_leader_is_not() {
        assert!(!is_replicating(&status("follower", None, None)));
    }

    #[test]
    fn a_candidate_is_never_replicating() {
        // Even one that voted for itself and so has a leader hint: an election is
        // in progress and nothing is committing.
        assert!(!is_replicating(&status("candidate", None, Some(1))));
    }

    #[test]
    fn a_leader_is_replicating_only_with_a_quorum() {
        assert!(is_replicating(&status("leader", Some(true), Some(1))));
        assert!(!is_replicating(&status("leader", Some(false), Some(1))));
    }
}
