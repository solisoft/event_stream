//! Proof-of-concept integration: a [`Partition`] backed by a Raft node.
//!
//! Appends are proposed through the Raft leader's `propose` API. When the
//! resulting log entry commits, a background apply task decodes the command
//! and writes it to the underlying partition's segmented log; the proposer
//! waits on a per-log-index `oneshot` to receive the assigned partition
//! offset.
//!
//! Scope of this step:
//!   * Single-broker only — typically a 1-node Raft cluster.
//!   * The broker's HTTP / binary produce paths are NOT yet routed through
//!     this; `RaftPartition` is exercised by integration tests only.
//!   * No leader-routing for clients (proposing to a follower returns
//!     `NotLeader` and the test fails loudly).
//!   * No follower-side reads / read-index — readers go straight to the
//!     underlying `Partition` snapshot.
//!
//! What the next step would do: replace `Topic::partitions: Vec<Arc<Partition>>`
//! with `Vec<Arc<RaftPartition>>`; introduce a cluster-membership config so
//! each partition's Raft group can have multiple voters; teach the HTTP
//! produce handler to route to the leader.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::partition::Partition;
use crate::raft::{
    JsonStore, LogIndex, NodeHandle, NodeId, ProposeReply, RaftStore, Timing,
    spawn_node_with_store,
};

/// Wire format for a Raft-replicated append command.
///
/// ```text
/// key_len: i32 BE   (-1 = null)
/// key bytes
/// value_len: u32 BE
/// value bytes
/// ```
fn encode_append_command(key: Option<&[u8]>, value: &[u8]) -> Vec<u8> {
    let key_len_field: i32 = key.map(|k| k.len() as i32).unwrap_or(-1);
    let mut out = Vec::with_capacity(4 + key.map_or(0, |k| k.len()) + 4 + value.len());
    out.extend_from_slice(&key_len_field.to_be_bytes());
    if let Some(k) = key {
        out.extend_from_slice(k);
    }
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
    out
}

fn decode_append_command(bytes: &[u8]) -> Result<(Option<Vec<u8>>, Vec<u8>)> {
    if bytes.len() < 8 {
        return Err(anyhow!("append command too short"));
    }
    let key_len = i32::from_be_bytes(bytes[0..4].try_into().unwrap());
    let (key, mut pos): (Option<Vec<u8>>, usize) = if key_len < 0 {
        (None, 4)
    } else {
        let kl = key_len as usize;
        if bytes.len() < 4 + kl + 4 {
            return Err(anyhow!("append command truncated in key"));
        }
        let k = bytes[4..4 + kl].to_vec();
        (Some(k), 4 + kl)
    };
    let value_len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    if bytes.len() < pos + value_len {
        return Err(anyhow!("append command truncated in value"));
    }
    let value = bytes[pos..pos + value_len].to_vec();
    Ok((key, value))
}

#[derive(Debug)]
pub struct AppendResult {
    pub offset: u64,
}

/// One slot per in-flight or recently-applied Raft index. The races resolve
/// because both the propose path and the apply task take the same `Mutex`
/// around the map. Held briefly; never across an `.await`.
enum Slot {
    Pending(oneshot::Sender<Result<AppendResult, String>>),
    Applied(Result<AppendResult, String>),
}

pub struct RaftPartition {
    partition: Arc<Partition>,
    raft: NodeHandle,
    slots: Arc<Mutex<HashMap<LogIndex, Slot>>>,
    cancel: CancellationToken,
    apply_join: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Debug, Clone)]
pub struct RaftPartitionConfig {
    pub node_id: NodeId,
    pub peers: Vec<NodeId>,
    /// Where the Raft persistent state lives.
    pub raft_store_path: PathBuf,
    pub timing: Timing,
}

impl RaftPartition {
    /// Open a Raft-backed partition. The underlying `Partition` is opened on
    /// `partition_dir` with the standard recovery flow; Raft state lives at
    /// `raft_store_path`.
    pub fn open(
        partition_dir: PathBuf,
        partition_id: u32,
        segment_bytes: u64,
        flush_every_records: u32,
        config: RaftPartitionConfig,
    ) -> Result<Arc<Self>> {
        let partition = Partition::open(
            partition_dir,
            partition_id,
            segment_bytes,
            flush_every_records,
        )?;
        let store: Arc<dyn RaftStore> = Arc::new(JsonStore::new(config.raft_store_path));
        let mut raft = spawn_node_with_store(config.node_id, config.peers, config.timing, store)?;

        let slots: Arc<Mutex<HashMap<LogIndex, Slot>>> = Arc::new(Mutex::new(HashMap::new()));
        let cancel = CancellationToken::new();

        let committed = raft
            .take_committed()
            .ok_or_else(|| anyhow!("raft node committed receiver already taken"))?;

        let p_for_apply = partition.clone();
        let slots_for_apply = slots.clone();
        let cancel_for_apply = cancel.clone();
        let apply_join = tokio::spawn(async move {
            apply_loop(committed, p_for_apply, slots_for_apply, cancel_for_apply).await;
        });

        Ok(Arc::new(Self {
            partition,
            raft,
            slots,
            cancel,
            apply_join: Mutex::new(Some(apply_join)),
        }))
    }

    /// Underlying storage handle for direct reads (we don't go through Raft
    /// for reads in this step).
    pub fn partition(&self) -> &Arc<Partition> {
        &self.partition
    }

    /// Propose an append. Returns the assigned partition offset once the
    /// committed entry has been applied. Errors if this node isn't the leader
    /// (clients are expected to retry against the leader; that routing is the
    /// next integration step and lives in the broker, not here).
    pub async fn append(&self, key: Option<&[u8]>, value: &[u8]) -> Result<u64> {
        let cmd = encode_append_command(key, value);
        let reply = self.raft.propose(cmd).await?;
        let index = match reply {
            ProposeReply::Accepted { index } => index,
            ProposeReply::NotLeader { leader_hint } => {
                return Err(anyhow!(
                    "not leader (hint: {:?}); produce must be routed to the leader",
                    leader_hint
                ));
            }
        };

        // Register a oneshot for this index, OR pick up an already-applied
        // result. Mutex held briefly; never across await.
        let rx = {
            let mut slots = self.slots.lock().unwrap();
            match slots.remove(&index) {
                Some(Slot::Applied(res)) => return res.map(|r| r.offset).map_err(|e| anyhow!(e)),
                Some(Slot::Pending(_)) => {
                    // Should be impossible — same index proposed twice — but
                    // re-insert and return an error rather than panic.
                    return Err(anyhow!("duplicate pending slot for raft index {}", index));
                }
                None => {
                    let (tx, rx) = oneshot::channel();
                    slots.insert(index, Slot::Pending(tx));
                    rx
                }
            }
        };

        match rx.await {
            Ok(Ok(result)) => Ok(result.offset),
            Ok(Err(e)) => Err(anyhow!(e)),
            Err(_) => Err(anyhow!("raft apply task exited before this entry was applied")),
        }
    }

    pub async fn shutdown(&self) {
        self.cancel.cancel();
        let join = {
            let mut guard = self.apply_join.lock().unwrap();
            guard.take()
        };
        if let Some(j) = join {
            // We can't shut down `raft` here cheaply because it's not an Arc;
            // the test owns the RaftPartition and Drop on the underlying
            // NodeHandle's cancel token will stop the node.
            let _ = j.await;
        }
        // Best-effort wake any remaining waiters with a friendly error.
        let mut slots = self.slots.lock().unwrap();
        for (_, slot) in slots.drain() {
            if let Slot::Pending(tx) = slot {
                let _ = tx.send(Err("raft partition shutdown".to_string()));
            }
        }
    }
}

async fn apply_loop(
    mut committed: tokio::sync::mpsc::UnboundedReceiver<crate::raft::messages::LogEntry>,
    partition: Arc<Partition>,
    slots: Arc<Mutex<HashMap<LogIndex, Slot>>>,
    cancel: CancellationToken,
) {
    // Invariant: Raft index N corresponds to partition offset N-1. On restart,
    // the partition has already been written through to its end_offset, but
    // Raft replays its log from the beginning. Skip everything already applied.
    let skip_at_or_below = partition.end_offset();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            msg = committed.recv() => {
                let Some(entry) = msg else { break; };
                if entry.index <= skip_at_or_below {
                    let already = AppendResult { offset: entry.index.saturating_sub(1) };
                    let mut s = slots.lock().unwrap();
                    match s.remove(&entry.index) {
                        Some(Slot::Pending(tx)) => { let _ = tx.send(Ok(already)); }
                        _ => { s.insert(entry.index, Slot::Applied(Ok(already))); }
                    }
                    continue;
                }
                let outcome = match decode_append_command(&entry.payload) {
                    Ok((key, value)) => {
                        match partition.append(key.as_deref(), &value).await {
                            Ok(offset) => Ok(AppendResult { offset }),
                            Err(e) => Err(format!("partition append: {}", e)),
                        }
                    }
                    Err(e) => Err(format!("decode: {}", e)),
                };
                let mut s = slots.lock().unwrap();
                match s.remove(&entry.index) {
                    Some(Slot::Pending(tx)) => { let _ = tx.send(outcome); }
                    Some(Slot::Applied(_)) => {
                        // Re-applied — shouldn't happen.
                    }
                    None => {
                        // No proposer waiting (single-node fast path or
                        // follower-side apply). Store for the proposer to
                        // pick up; followers won't have a waiter so the entry
                        // will eventually be evicted on shutdown.
                        s.insert(entry.index, Slot::Applied(outcome));
                    }
                }
            }
        }
    }
    // Drain anything still in the receiver to fulfill last-in-flight waiters.
    while let Ok(entry) = committed.try_recv() {
        let outcome = match decode_append_command(&entry.payload) {
            Ok((key, value)) => partition
                .append(key.as_deref(), &value)
                .await
                .map(|offset| AppendResult { offset })
                .map_err(|e| format!("partition append: {}", e)),
            Err(e) => Err(format!("decode: {}", e)),
        };
        let mut s = slots.lock().unwrap();
        if let Some(Slot::Pending(tx)) = s.remove(&entry.index) {
            let _ = tx.send(outcome);
        } else {
            s.insert(entry.index, Slot::Applied(outcome));
        }
    }
    tracing::debug!("raft_partition: apply loop exited");
}

/// Default fast timing for tests.
pub fn test_timing() -> Timing {
    Timing {
        election_min: Duration::from_millis(50),
        election_max: Duration::from_millis(100),
        heartbeat: Duration::from_millis(20),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_command_roundtrip() {
        let bytes = encode_append_command(Some(b"k1"), b"hello\x00world");
        let (k, v) = decode_append_command(&bytes).unwrap();
        assert_eq!(k.as_deref(), Some(&b"k1"[..]));
        assert_eq!(v, b"hello\x00world");

        let bytes = encode_append_command(None, b"v-only");
        let (k, v) = decode_append_command(&bytes).unwrap();
        assert!(k.is_none());
        assert_eq!(v, b"v-only");

        let bytes = encode_append_command(Some(b""), b"");
        let (k, v) = decode_append_command(&bytes).unwrap();
        assert_eq!(k.as_deref(), Some(&b""[..]));
        assert_eq!(v, b"");
    }

    #[test]
    fn decode_rejects_truncated_input() {
        assert!(decode_append_command(&[]).is_err());
        let mut bytes = encode_append_command(Some(b"k"), b"v");
        bytes.truncate(bytes.len() - 1);
        assert!(decode_append_command(&bytes).is_err());
    }

    // Suppress dead-code on test_timing when no integration tests build.
    fn _use_test_timing() -> Timing {
        test_timing()
    }
}

// Re-export Context for downstream users of `with_context`.
#[allow(unused_imports)]
use Context as _;
