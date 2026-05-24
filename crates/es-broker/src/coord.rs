//! Consumer-group coordinator.
//!
//! Each group goes through a join → heartbeat → (optional) leave lifecycle.
//! Members subscribe to a set of topics; the coordinator assigns the union of
//! those topics' partitions across the members. Failure detection is heartbeat
//! based — a member that doesn't ping within `member_timeout` is evicted, and
//! eviction triggers a rebalance (new generation, new assignment).
//!
//! Assignment is round-robin over `(topic, partition)` pairs sorted by name +
//! partition id. Same input → same output; stable enough for tests.
//!
//! State is in-memory. A real production coordinator would persist `(group,
//! generation, members)` so reboots don't reset the world; we don't because
//! group *offsets* are already persistent (see [`crate::groups`]) and that's
//! the durability-critical piece.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use rand::RngCore;
use tokio::sync::Mutex;

use crate::broker::Broker;

#[derive(Debug, Clone)]
pub struct Member {
    pub id: String,
    pub topics: Vec<String>,
    pub last_heartbeat: Instant,
}

#[derive(Debug, Clone, Default)]
pub struct GroupState {
    pub generation: u64,
    pub members: BTreeMap<String, Member>,
    pub assignment: BTreeMap<String, Vec<(String, u32)>>, // member_id -> [(topic, partition)]
}

pub struct GroupCoordinator {
    pub member_timeout: Duration,
    state: DashMap<String, Arc<Mutex<GroupState>>>,
}

impl GroupCoordinator {
    pub fn new(member_timeout: Duration) -> Self {
        Self {
            member_timeout,
            state: DashMap::new(),
        }
    }

    fn slot(&self, group: &str) -> Arc<Mutex<GroupState>> {
        if let Some(s) = self.state.get(group) {
            return s.clone();
        }
        let new = Arc::new(Mutex::new(GroupState::default()));
        self.state.entry(group.to_string()).or_insert(new).clone()
    }

    /// Returns every group name currently tracked. Used by the background
    /// expiry sweep.
    pub fn group_names(&self) -> Vec<String> {
        let mut out: Vec<String> = self.state.iter().map(|kv| kv.key().clone()).collect();
        out.sort();
        out
    }

    /// Join a group. If `member_id` is empty the coordinator picks one.
    /// Returns (member_id, generation, assignment_for_this_member).
    pub async fn join(
        &self,
        broker: &Arc<Broker>,
        group: &str,
        member_id: Option<String>,
        topics: Vec<String>,
    ) -> Result<JoinReply> {
        validate_group_name(group)?;
        let mid = member_id
            .filter(|s| !s.is_empty())
            .unwrap_or_else(generate_member_id);

        // Validate all subscribed topics exist.
        for t in &topics {
            if broker.topic(t).is_none() {
                return Err(anyhow!("topic '{}' not found", t));
            }
        }

        let slot = self.slot(group);
        let mut state = slot.lock().await;
        let now = Instant::now();
        let inserted_or_changed = match state.members.get_mut(&mid) {
            Some(existing) => {
                let changed = existing.topics != topics;
                existing.topics = topics.clone();
                existing.last_heartbeat = now;
                changed
            }
            None => {
                state.members.insert(
                    mid.clone(),
                    Member {
                        id: mid.clone(),
                        topics: topics.clone(),
                        last_heartbeat: now,
                    },
                );
                true
            }
        };
        if inserted_or_changed {
            recompute_assignment(broker, &mut state);
        }
        let my_assignment = state.assignment.get(&mid).cloned().unwrap_or_default();
        Ok(JoinReply {
            member_id: mid,
            generation: state.generation,
            assignment: my_assignment,
        })
    }

    /// Heartbeat from a known member. Returns the current generation; if the
    /// member is unknown (was evicted), the caller must rejoin.
    pub async fn heartbeat(
        &self,
        group: &str,
        member_id: &str,
        generation: u64,
    ) -> Result<HeartbeatReply> {
        let slot = self.slot(group);
        let mut state = slot.lock().await;
        match state.members.get_mut(member_id) {
            None => Ok(HeartbeatReply::UnknownMember {
                current_generation: state.generation,
            }),
            Some(m) => {
                m.last_heartbeat = Instant::now();
                if generation != state.generation {
                    Ok(HeartbeatReply::RebalanceRequired {
                        current_generation: state.generation,
                    })
                } else {
                    Ok(HeartbeatReply::Ok {
                        generation: state.generation,
                    })
                }
            }
        }
    }

    pub async fn leave(&self, broker: &Arc<Broker>, group: &str, member_id: &str) -> Result<()> {
        let slot = self.slot(group);
        let mut state = slot.lock().await;
        if state.members.remove(member_id).is_some() {
            recompute_assignment(broker, &mut state);
        }
        Ok(())
    }

    pub async fn assignment(&self, group: &str, member_id: &str) -> AssignmentReply {
        let slot = self.slot(group);
        let state = slot.lock().await;
        if !state.members.contains_key(member_id) {
            return AssignmentReply::UnknownMember {
                current_generation: state.generation,
            };
        }
        AssignmentReply::Ok {
            generation: state.generation,
            assignment: state.assignment.get(member_id).cloned().unwrap_or_default(),
        }
    }

    /// Sweep expired members across all groups. Each eviction triggers a
    /// rebalance for that group.
    pub async fn expire_stale(&self, broker: &Arc<Broker>) {
        let now = Instant::now();
        let groups: Vec<String> = self.group_names();
        for g in groups {
            let slot = self.slot(&g);
            let mut state = slot.lock().await;
            let stale: Vec<String> = state
                .members
                .iter()
                .filter(|(_, m)| now.duration_since(m.last_heartbeat) > self.member_timeout)
                .map(|(id, _)| id.clone())
                .collect();
            if !stale.is_empty() {
                for id in &stale {
                    state.members.remove(id);
                }
                recompute_assignment(broker, &mut state);
                tracing::info!(group = %g, evicted = stale.len(),
                    generation = state.generation, "coord: members evicted");
            }
        }
    }

    /// Snapshot every group's full state for the `/admin/groups` debug view.
    pub async fn debug_snapshot(&self) -> BTreeMap<String, GroupState> {
        let mut out = BTreeMap::new();
        for kv in self.state.iter() {
            let s = kv.value().lock().await.clone();
            out.insert(kv.key().clone(), s);
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct JoinReply {
    pub member_id: String,
    pub generation: u64,
    pub assignment: Vec<(String, u32)>,
}

#[derive(Debug, Clone)]
pub enum HeartbeatReply {
    Ok { generation: u64 },
    RebalanceRequired { current_generation: u64 },
    UnknownMember { current_generation: u64 },
}

#[derive(Debug, Clone)]
pub enum AssignmentReply {
    Ok {
        generation: u64,
        assignment: Vec<(String, u32)>,
    },
    UnknownMember {
        current_generation: u64,
    },
}

/// Bump generation and re-assign every (topic, partition) the union of
/// subscribed topics covers, using a **sticky** algorithm:
///
///   1. Keep each member's previous (topic, partition) tuples that are still
///      valid (member still exists, still subscribed to that topic, partition
///      still exists), capped at `ceil(total / members)` so no member is over
///      its fair share.
///   2. Distribute orphan partitions (no previous owner or owner departed)
///      round-robin to the least-loaded subscribed members.
///
/// The result is balanced (no member has more than `ceil(N/M)`) and stable —
/// members keep what they had unless they were over-allocated or unsubscribed.
fn recompute_assignment(broker: &Arc<Broker>, state: &mut GroupState) {
    let previous = std::mem::take(&mut state.assignment);
    state.generation += 1;
    if state.members.is_empty() {
        return;
    }

    // Set of (topic, partition) that *should* be assigned to someone in this group.
    let mut all_partitions: BTreeSet<(String, u32)> = BTreeSet::new();
    for m in state.members.values() {
        for t in &m.topics {
            if let Some(topic) = broker.topic(t) {
                for p in &topic.partitions {
                    all_partitions.insert((t.clone(), p.id()));
                }
            }
        }
    }

    let member_ids: Vec<String> = state.members.keys().cloned().collect();
    let m_count = member_ids.len();
    let total = all_partitions.len();
    let target_max = total.div_ceil(m_count);

    let mut current: BTreeMap<String, Vec<(String, u32)>> = BTreeMap::new();
    for mid in &member_ids {
        current.insert(mid.clone(), Vec::new());
    }
    let mut assigned: BTreeSet<(String, u32)> = BTreeSet::new();

    // Pass 1 — sticky. Iterate previous owners in sorted order so the choice
    // is deterministic when two members both have a claim.
    for (prev_owner, prev_parts) in &previous {
        let Some(member) = state.members.get(prev_owner) else {
            continue;
        };
        let bucket = current.get_mut(prev_owner).unwrap();
        for tp in prev_parts {
            if !all_partitions.contains(tp) {
                continue; // partition gone (topic deleted or partition count shrank)
            }
            if !member.topics.contains(&tp.0) {
                continue; // member no longer subscribed
            }
            if bucket.len() >= target_max {
                continue; // would exceed fair share
            }
            bucket.push(tp.clone());
            assigned.insert(tp.clone());
        }
    }

    // Pass 2 — distribute orphans to least-loaded subscribed member.
    let orphans: Vec<(String, u32)> = all_partitions
        .iter()
        .filter(|tp| !assigned.contains(*tp))
        .cloned()
        .collect();
    for tp in orphans {
        let mut best: Option<String> = None;
        let mut best_load = usize::MAX;
        for mid in &member_ids {
            let m = state.members.get(mid).unwrap();
            if !m.topics.contains(&tp.0) {
                continue;
            }
            let load = current[mid].len();
            if load < target_max && load < best_load {
                best = Some(mid.clone());
                best_load = load;
            }
        }
        if let Some(mid) = best {
            current.get_mut(&mid).unwrap().push(tp);
        }
    }

    // Sort each member's assignment for stable ordering on the wire.
    for v in current.values_mut() {
        v.sort();
    }
    state.assignment = current;
}

fn validate_group_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 200 {
        anyhow::bail!("group name length must be 1..=200");
    }
    Ok(())
}

fn generate_member_id() -> String {
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("m_");
    for b in &bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
