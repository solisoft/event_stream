//! `/admin/raft/members` — add or remove one broker at a time, without a
//! restart.
//!
//! Every partition is its own Raft group with its own leader, and only a
//! group's leader can change its configuration. A request therefore changes
//! the partitions **this broker leads**, and reports every other partition as
//! led elsewhere, naming the leader: the operator sends the same request to
//! each broker in turn, and a partition already changed reports so. The change
//! is the same single-server step in every group (see
//! [`crate::raft::membership`]), and taking the steps in any order is safe.
//!
//! One change at a time: a request is refused with 409 while any partition on
//! this broker still has a change that has not committed, so a second change
//! can never overlap the first in any group.
//!
//! Admin grant, like the rest of `/admin`: changing who votes is changing who
//! holds the data.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::broker::Broker;
use crate::partition_handle::PartitionHandle;
use crate::raft::state::ChangeRefused;
use crate::raft::{MemberChange, NodeId};
use crate::raft_partition::RaftPartition;

use super::auth_ext::AuthedKey;
use super::error::{AppError, AppResult};

/// How long a request waits for the entries it proposed to commit. A healthy
/// cluster commits in one round trip; past this the report says `pending`.
const COMMIT_WAIT: Duration = Duration::from_secs(5);
/// How long a new leader is given to commit its first entry, which it must
/// before it may change the configuration.
const LEADER_READY_WAIT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub id: NodeId,
    /// The new broker's Raft address, `host:port`, as its `--raft-bind`.
    pub addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipChangeReport {
    /// The broker that handled the request.
    pub node: NodeId,
    /// `add` or `remove`.
    pub change: String,
    /// The broker being added or removed.
    pub member: NodeId,
    pub partitions: Vec<PartitionChange>,
    /// Every partition on this broker has the change committed. When false,
    /// send the same request to the leaders named in `partitions`.
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionChange {
    pub topic: String,
    pub partition: u32,
    /// `committed`: proposed here and committed. `already`: the change was
    /// already committed. `pending`: proposed here, not committed yet.
    /// `not_leader`: another broker leads this partition; ask it.
    pub status: String,
    /// The log index of the change, when this broker proposed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u64>,
    /// Who leads the partition, when this broker does not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leader: Option<NodeId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembersResponse {
    pub node: NodeId,
    /// The brokers this one connects to, itself excluded, and their Raft
    /// addresses: the union of every partition's configuration.
    pub peers: Vec<MemberDto>,
    pub partitions: Vec<PartitionMembers>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberDto {
    pub id: NodeId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionMembers {
    pub topic: String,
    pub partition: u32,
    /// The latest configuration's voters, in effect since appended.
    pub voters: Vec<NodeId>,
    /// A change is appended but not committed: the next one is refused.
    pub change_pending: bool,
}

fn require_admin(key: &crate::auth::ApiKey) -> AppResult<()> {
    if !key.is_admin() {
        return Err(AppError::forbidden("admin grant required"));
    }
    Ok(())
}

fn node_id(broker: &Broker) -> AppResult<NodeId> {
    broker
        .config
        .raft_node_id
        .ok_or_else(|| AppError::bad_request("this broker is not a Raft cluster member"))
}

/// Every Raft-backed partition on this broker, in a stable order.
fn raft_partitions(broker: &Broker) -> Vec<(String, u32, Arc<RaftPartition>)> {
    let mut out = Vec::new();
    for name in broker.list_topics() {
        let Some(topic) = broker.topic(&name) else {
            continue;
        };
        for handle in topic.raft_partitions() {
            if let PartitionHandle::Raft(raft) = handle {
                out.push((name.clone(), raft.partition().id, raft.clone()));
            }
        }
    }
    out
}

pub async fn list(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
) -> AppResult<Json<MembersResponse>> {
    require_admin(&key)?;
    let node = node_id(&broker)?;
    let peers = broker
        .raft_hub()
        .map(|hub| hub.members())
        .unwrap_or_default()
        .into_iter()
        .map(|(id, addr)| MemberDto {
            id,
            addr: addr.map(|a| a.to_string()),
        })
        .collect();
    let mut partitions = Vec::new();
    for (topic, partition, raft) in raft_partitions(&broker) {
        let s = raft.raft_state().lock().await;
        partitions.push(PartitionMembers {
            topic,
            partition,
            voters: s.config.ids().collect(),
            change_pending: s.has_uncommitted_change(),
        });
    }
    Ok(Json(MembersResponse {
        node,
        peers,
        partitions,
    }))
}

pub async fn add(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Json(req): Json<AddMemberRequest>,
) -> AppResult<Json<MembershipChangeReport>> {
    require_admin(&key)?;
    if req.id == 0 {
        return Err(AppError::bad_request(
            "node id 0 is the 'no leader known' sentinel and cannot name a member",
        ));
    }
    // An IP address, like `--raft-peer`: the transport admits connections by
    // source address, and a host name names none.
    let addr: SocketAddr = req.addr.trim().parse().map_err(|_| {
        AppError::bad_request(format!(
            "'{}' is not an ip:port address; give the new broker's --raft-bind",
            req.addr
        ))
    })?;
    let change = MemberChange::Add {
        id: req.id,
        addr: addr.to_string(),
    };
    apply(&broker, change).await.map(Json)
}

pub async fn remove(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(id): Path<NodeId>,
) -> AppResult<Json<MembershipChangeReport>> {
    require_admin(&key)?;
    apply(&broker, MemberChange::Remove { id }).await.map(Json)
}

/// Whether `config` already reflects `change`.
fn reflects(config: &crate::raft::Membership, change: &MemberChange) -> bool {
    match change {
        MemberChange::Add { id, .. } => config.contains(*id),
        MemberChange::Remove { id } => !config.contains(*id),
    }
}

async fn apply(broker: &Broker, change: MemberChange) -> AppResult<MembershipChangeReport> {
    let node = node_id(broker)?;
    let _one_at_a_time = broker.membership_lock.try_lock().map_err(|_| {
        AppError::conflict("a membership change is already being applied on this broker")
    })?;
    let partitions = raft_partitions(broker);
    if partitions.is_empty() {
        return Err(AppError::bad_request(
            "this broker has no replicated partitions: the membership lives in each \
             partition's Raft group, so there is nothing to change yet. Change --raft-peer \
             and restart instead.",
        ));
    }

    // Refuse before touching anything: a second change proposed while the
    // first is uncommitted in some group is how two majorities stop
    // overlapping.
    for (topic, partition, raft) in &partitions {
        let s = raft.raft_state().lock().await;
        // The same change, appended by an earlier request, is not a second
        // one: retrying a request reports it as pending.
        if s.has_uncommitted_change() && !reflects(&s.config, &change) {
            return Err(AppError::conflict(format!(
                "a membership change is still uncommitted in {topic}/{partition} (entry {}); \
                 retry once it commits",
                s.config_index
            )));
        }
    }

    let mut report = Vec::with_capacity(partitions.len());
    let mut proposed: Vec<(usize, Arc<RaftPartition>, u64, u64)> = Vec::new();
    for (topic, partition, raft) in &partitions {
        let mut entry = PartitionChange {
            topic: topic.clone(),
            partition: *partition,
            status: String::new(),
            index: None,
            leader: None,
        };
        let (latest, committed) = {
            let s = raft.raft_state().lock().await;
            (
                reflects(&s.config, &change),
                reflects(&s.committed_config, &change),
            )
        };
        if latest {
            entry.status = if committed { "already" } else { "pending" }.into();
            report.push(entry);
            continue;
        }
        let give_up = Instant::now() + LEADER_READY_WAIT;
        loop {
            let outcome = raft
                .change_membership(change.clone())
                .await
                .map_err(AppError::internal)?;
            match outcome {
                Ok(index) => {
                    let term = raft.raft_state().lock().await.current_term;
                    entry.status = "pending".into();
                    entry.index = Some(index);
                    proposed.push((report.len(), raft.clone(), index, term));
                }
                Err(ChangeRefused::NotLeader(leader)) => {
                    entry.status = "not_leader".into();
                    entry.leader = leader;
                }
                Err(ChangeRefused::AlreadyInEffect) => {
                    // Appended, by an earlier request, and not committed yet.
                    entry.status = "pending".into();
                }
                Err(ChangeRefused::LeaderNotReady) if Instant::now() < give_up => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                Err(refused @ ChangeRefused::LeaderNotReady) => {
                    entry.status = "pending".into();
                    tracing::warn!(topic, partition, %refused, "raft: membership change not proposed");
                }
                Err(refused @ (ChangeRefused::InProgress(_) | ChangeRefused::LastVoter)) => {
                    return Err(AppError::conflict(format!(
                        "{topic}/{partition}: {refused}"
                    )));
                }
            }
            break;
        }
        report.push(entry);
    }

    // Wait for what this broker proposed to commit. An entry this leader
    // appended commits only if it is still at its index with its term: a
    // leader deposed meanwhile may have lost it.
    let deadline = Instant::now() + COMMIT_WAIT;
    while !proposed.is_empty() && Instant::now() < deadline {
        let mut still = Vec::new();
        for (slot, raft, index, term) in proposed {
            let committed = {
                let s = raft.raft_state().lock().await;
                s.commit_index >= index && s.log.term_at(index).is_none_or(|t| t == term)
            };
            if committed {
                report[slot].status = "committed".into();
            } else {
                still.push((slot, raft, index, term));
            }
        }
        proposed = still;
        if !proposed.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    let complete = report
        .iter()
        .all(|p| p.status == "committed" || p.status == "already");
    let (kind, member) = match &change {
        MemberChange::Add { id, .. } => ("add", *id),
        MemberChange::Remove { id } => ("remove", *id),
    };
    tracing::info!(
        change = kind,
        member,
        complete,
        "raft: membership change requested"
    );
    Ok(MembershipChangeReport {
        node,
        change: kind.to_string(),
        member,
        partitions: report,
        complete,
    })
}
