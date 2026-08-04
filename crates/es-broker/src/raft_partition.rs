//! Proof-of-concept integration: a [`Partition`] backed by a Raft node.
//!
//! Appends are proposed through the Raft leader's `propose` API. When the
//! resulting log entry commits, a background apply task decodes the command
//! and writes it to the underlying partition's segmented log; the proposer
//! waits on a per-log-index `oneshot` to receive the assigned partition
//! offset.
//!
//! Multi-node operation: call [`RaftPartition::connect_transport`] after
//! opening to set up TCP connections between peers. Without it, the node
//! operates in single-node mode (no replication).

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::partition::Partition;
use crate::raft::state::RaftState;
use crate::raft::{
    spawn_node_with_store,
    transport::{RaftHub, Transport},
    JsonStore, LogIndex, NodeHandle, NodeId, Outbound, ProposeReply, RaftStore, Timing,
};
use tokio::sync::Mutex as TokioMutex;

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

/// How long an accepted proposal is given to commit before the caller is told
/// it did not. Only reached when the leader has lost its majority — a healthy
/// cluster commits in the time one round trip takes.
const COMMIT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct AppendResult {
    pub offset: u64,
}

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
    /// Held aside after construction; consumed by `connect_transport`.
    outbound_rx: Mutex<Option<mpsc::UnboundedReceiver<Outbound>>>,
    /// Set by `connect_transport`.
    transport: Mutex<Option<Transport>>,
}

#[derive(Debug, Clone)]
pub struct RaftPartitionConfig {
    pub node_id: NodeId,
    pub peers: Vec<NodeId>,
    pub raft_store_path: PathBuf,
    pub timing: Timing,
    pub snapshot_after_applies: u32,
}

#[derive(Debug, Clone)]
pub struct RaftTransportConfig {
    pub bind: SocketAddr,
    pub peer_addrs: BTreeMap<NodeId, SocketAddr>,
    /// Pre-shared secret peers must present in the raft handshake. `None`
    /// disables peer authentication (only safe on a trusted/loopback network).
    pub shared_secret: Option<String>,
}

impl RaftPartitionConfig {
    pub fn with_defaults(node_id: NodeId, raft_store_path: PathBuf) -> Self {
        Self {
            node_id,
            peers: Vec::new(),
            raft_store_path,
            timing: Timing::default(),
            snapshot_after_applies: 1024,
        }
    }
}

impl RaftPartition {
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
        let mut raft =
            spawn_node_with_store(config.node_id, config.peers, config.timing, store.clone())?;
        let raft_state = raft.state.clone();

        // Take the outbound channel now so transport can use it later.
        let outbound_rx = raft.take_outbound();

        let slots: Arc<Mutex<HashMap<LogIndex, Slot>>> = Arc::new(Mutex::new(HashMap::new()));
        let cancel = CancellationToken::new();

        let committed = raft
            .take_committed()
            .ok_or_else(|| anyhow!("raft node committed receiver already taken"))?;

        let p_for_apply = partition.clone();
        let slots_for_apply = slots.clone();
        let cancel_for_apply = cancel.clone();
        let store_for_apply = store.clone();
        let snapshot_threshold = config.snapshot_after_applies;
        let apply_join = tokio::spawn(async move {
            apply_loop(
                committed,
                p_for_apply,
                slots_for_apply,
                cancel_for_apply,
                raft_state,
                store_for_apply,
                snapshot_threshold,
            )
            .await;
        });

        Ok(Arc::new(Self {
            partition,
            raft,
            slots,
            cancel,
            apply_join: Mutex::new(Some(apply_join)),
            outbound_rx: Mutex::new(outbound_rx),
            transport: Mutex::new(None),
        }))
    }

    /// Route this partition's Raft traffic over a hub shared with every other
    /// partition on this broker. Must be called after `open()` and before any
    /// appends; without it the node operates in single-node mode.
    ///
    /// This is the path a real cluster uses. `connect_transport` below is the
    /// same thing with a hub of its own, for a single partition.
    pub fn attach_to_hub(&self, hub: &Arc<RaftHub>, group: &str) -> Result<()> {
        let outbound_rx = self.take_outbound()?;
        hub.register(group, self.raft.inbound.clone(), outbound_rx)
            .with_context(|| format!("register raft group '{group}'"))?;
        // The dispatcher handle is dropped: the hub's cancellation token stops
        // it, and the task must outlive this call.
        Ok(())
    }

    fn take_outbound(&self) -> Result<mpsc::UnboundedReceiver<Outbound>> {
        let mut guard = self.outbound_rx.lock().unwrap();
        guard
            .take()
            .ok_or_else(|| anyhow!("this partition's raft transport is already connected"))
    }

    /// Connect this Raft partition to peer nodes via TCP on a hub of its own.
    /// Must be called after `open()` and before any appends. Without this, the
    /// node operates in single-node mode.
    pub async fn connect_transport(&self, tcfg: RaftTransportConfig) -> Result<()> {
        let outbound_rx = self.take_outbound()?;
        let transport = crate::raft::spawn_transport(
            self.raft.id,
            tcfg.bind,
            tcfg.peer_addrs,
            self.raft.inbound.clone(),
            outbound_rx,
            Duration::from_secs(2),
            tcfg.shared_secret,
        )
        .await?;
        {
            let mut guard = self.transport.lock().unwrap();
            *guard = Some(transport);
        }
        Ok(())
    }

    pub fn partition(&self) -> &Arc<Partition> {
        &self.partition
    }

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

        let rx = {
            let mut slots = self.slots.lock().unwrap();
            match slots.remove(&index) {
                Some(Slot::Applied(res)) => return res.map(|r| r.offset).map_err(|e| anyhow!(e)),
                Some(Slot::Pending(_)) => {
                    return Err(anyhow!("duplicate pending slot for raft index {}", index));
                }
                None => {
                    let (tx, rx) = oneshot::channel();
                    slots.insert(index, Slot::Pending(tx));
                    rx
                }
            }
        };

        // Bounded, because an entry proposed while the quorum is gone never
        // commits and an unbounded wait would hold the client's connection for
        // as long as the outage lasts. The slot is left in place on purpose: the
        // apply loop removes it if the entry does eventually commit, so giving
        // up here leaks nothing.
        match tokio::time::timeout(COMMIT_TIMEOUT, rx).await {
            Ok(Ok(Ok(result))) => Ok(result.offset),
            Ok(Ok(Err(e))) => Err(anyhow!(e)),
            Ok(Err(_)) => Err(anyhow!(
                "raft apply task exited before this entry was applied"
            )),
            Err(_) => Err(anyhow!(
                "raft entry {} was accepted into the log but did not commit within {:?}: the \
                 leader cannot reach a majority of the cluster",
                index,
                COMMIT_TIMEOUT
            )),
        }
    }

    pub async fn shutdown(&self) {
        self.cancel.cancel();
        {
            let mut guard = self.transport.lock().unwrap();
            if let Some(t) = guard.take() {
                t.cancel.cancel();
            }
        }
        let join = {
            let mut guard = self.apply_join.lock().unwrap();
            guard.take()
        };
        if let Some(j) = join {
            let _ = j.await;
        }
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
    raft_state: Arc<TokioMutex<RaftState>>,
    store: Arc<dyn RaftStore>,
    snapshot_after_applies: u32,
) {
    let skip_at_or_below = partition.end_offset();
    let mut applies_since_snapshot: u32 = 0;
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
                let succeeded = outcome.is_ok();
                {
                    let mut s = slots.lock().unwrap();
                    match s.remove(&entry.index) {
                        Some(Slot::Pending(tx)) => { let _ = tx.send(outcome); }
                        Some(Slot::Applied(_)) => {}
                        None => {
                            s.insert(entry.index, Slot::Applied(outcome));
                        }
                    }
                }
                if succeeded {
                    applies_since_snapshot += 1;
                    if snapshot_after_applies > 0
                        && applies_since_snapshot >= snapshot_after_applies
                    {
                        if let Err(e) = take_snapshot(&raft_state, &store, &partition).await {
                            tracing::warn!(error = %e, "raft_partition: snapshot failed");
                        }
                        applies_since_snapshot = 0;
                    }
                }
            }
        }
    }
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

async fn take_snapshot(
    state: &Arc<TokioMutex<RaftState>>,
    store: &Arc<dyn RaftStore>,
    partition: &Arc<Partition>,
) -> anyhow::Result<()> {
    let data = partition.end_offset().to_be_bytes().to_vec();
    let (snap, persisted) = {
        let mut s = state.lock().await;
        if s.last_applied == 0 {
            return Ok(());
        }
        let snap = s.take_snapshot(data)?;
        let persisted = s.snapshot_persistent();
        (snap, persisted)
    };
    store.save_snapshot(&snap)?;
    store.save_all(&persisted)?;
    tracing::info!(
        last_index = snap.last_index,
        last_term = snap.last_term,
        "raft_partition: snapshot taken"
    );
    Ok(())
}

pub fn test_timing() -> Timing {
    Timing {
        election_min: Duration::from_millis(50),
        election_max: Duration::from_millis(100),
        heartbeat: Duration::from_millis(20),
    }
}

#[allow(unused_imports)]
use Context as _;

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

    fn _use_test_timing() -> Timing {
        test_timing()
    }
}
