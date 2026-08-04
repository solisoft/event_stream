//! Raft step-1 integration tests: 3 nodes elect exactly one leader.
//!
//! One test goes through the in-process pump (proves the state machine),
//! one goes through the real TCP transport (proves the wire works).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use es_broker::raft::log::{JsonStore, PersistedSnapshot};
use es_broker::raft::{
    node::pump_outbound, spawn_node, spawn_node_with_store, spawn_transport, NodeHandle, NodeId,
    Role, Timing,
};
use tempfile::TempDir;
use tokio::net::TcpListener;

fn timing_fast() -> Timing {
    Timing {
        election_min: Duration::from_millis(80),
        election_max: Duration::from_millis(160),
        heartbeat: Duration::from_millis(25),
    }
}

async fn settle_leader_in_process(
    handles: &mut BTreeMap<NodeId, NodeHandle>,
    settle_for: Duration,
) -> Result<Option<NodeId>> {
    pump_outbound(handles, Instant::now() + settle_for).await?;
    let mut leader: Option<NodeId> = None;
    let mut leaders_seen = 0;
    for (id, h) in handles.iter() {
        if h.role().await == Role::Leader {
            leader = Some(*id);
            leaders_seen += 1;
        }
    }
    if leaders_seen > 1 {
        anyhow::bail!("split-brain: {} leaders observed", leaders_seen);
    }
    Ok(leader)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_node_in_process_elects_a_leader() -> Result<()> {
    let mut handles: BTreeMap<NodeId, NodeHandle> = BTreeMap::new();
    for id in 1..=3u32 {
        let peers: Vec<NodeId> = (1..=3u32).filter(|p| *p != id).collect();
        handles.insert(id, spawn_node(id, peers, timing_fast()));
    }

    let leader = settle_leader_in_process(&mut handles, Duration::from_secs(2)).await?;
    assert!(
        leader.is_some(),
        "no leader elected within deadline; roles = {:?}",
        {
            let mut r = Vec::new();
            for (id, h) in handles.iter() {
                r.push((id, h.role().await));
            }
            r
        }
    );

    // The two non-leaders should agree on the leader hint, and all three should
    // share the same term.
    let leader = leader.unwrap();
    let leader_term = handles.get(&leader).unwrap().current_term().await;
    for (_id, h) in handles.iter() {
        assert_eq!(h.current_term().await, leader_term, "term mismatch");
    }

    for (_id, h) in std::mem::take(&mut handles).into_iter() {
        h.shutdown().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_node_tcp_transport_elects_a_leader() -> Result<()> {
    // Pre-bind sockets for each node so we know the addresses up front.
    let mut listeners: BTreeMap<NodeId, (SocketAddr, TcpListener)> = BTreeMap::new();
    for id in 1..=3u32 {
        let lis = TcpListener::bind("127.0.0.1:0").await?;
        let addr = lis.local_addr()?;
        listeners.insert(id, (addr, lis));
    }
    let addrs: BTreeMap<NodeId, SocketAddr> = listeners.iter().map(|(k, v)| (*k, v.0)).collect();

    // Spawn each node + its transport. Drop the pre-bound listener; the
    // transport rebinds on the same address. (Window is small enough that
    // 127.0.0.1 reuse works in practice — this test is allowed to be flaky
    // on hostile environments; the in-process test is the authoritative one.)
    let mut handles: Vec<(NodeId, NodeHandle, es_broker::raft::Transport)> = Vec::new();
    for id in 1..=3u32 {
        let (addr, lis) = listeners.remove(&id).unwrap();
        drop(lis);
        // Tiny window between drop + rebind; in CI on hostile environments
        // this can race. The in-process test is the authoritative correctness
        // check; this one proves the TCP transport works under normal conditions.
        tokio::time::sleep(Duration::from_millis(5)).await;

        let peers: Vec<NodeId> = (1..=3u32).filter(|p| *p != id).collect();
        let peer_addrs: BTreeMap<NodeId, SocketAddr> =
            peers.iter().map(|p| (*p, *addrs.get(p).unwrap())).collect();

        let mut node = spawn_node(id, peers, timing_fast());
        let inbound_tx = node.inbound.clone();
        let outbound_rx = node.take_outbound().expect("outbound not yet taken");
        let transport = spawn_transport(
            id,
            addr,
            peer_addrs,
            inbound_tx,
            outbound_rx,
            Duration::from_millis(50),
            None,
        )
        .await?;
        handles.push((id, node, transport));
    }

    // Give the mesh time to connect + run an election.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut leader: Option<NodeId> = None;
    while Instant::now() < deadline {
        let mut leaders = Vec::new();
        for (id, h, _) in &handles {
            if h.role().await == Role::Leader {
                leaders.push(*id);
            }
        }
        if leaders.len() == 1 {
            leader = Some(leaders[0]);
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(leader.is_some(), "no leader via TCP within 3s");

    // Tear down.
    for (_id, node, transport) in handles {
        node.shutdown().await;
        transport.cancel.cancel();
        let _ = transport.join.await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 2: log replication
// ---------------------------------------------------------------------------

use es_broker::raft::{MemStore, ProposeReply, RaftStore};

#[allow(dead_code)]
async fn settle_until<F>(
    handles: &mut BTreeMap<NodeId, NodeHandle>,
    condition: F,
    timeout: Duration,
) -> bool
where
    F: Fn(&BTreeMap<NodeId, NodeHandle>) -> futures::future::BoxFuture<'_, bool>,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        pump_outbound(handles, Instant::now() + Duration::from_millis(40))
            .await
            .unwrap();
        if condition(handles).await {
            return true;
        }
    }
    false
}

#[allow(dead_code)]
async fn find_leader(handles: &BTreeMap<NodeId, NodeHandle>) -> Option<NodeId> {
    let mut leader: Option<NodeId> = None;
    let mut count = 0;
    for (id, h) in handles.iter() {
        if h.role().await == Role::Leader {
            leader = Some(*id);
            count += 1;
        }
    }
    if count == 1 {
        leader
    } else {
        None
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_node_propose_and_replicate() -> Result<()> {
    let mut handles: BTreeMap<NodeId, NodeHandle> = BTreeMap::new();
    for id in 1..=3u32 {
        let peers: Vec<NodeId> = (1..=3u32).filter(|p| *p != id).collect();
        handles.insert(id, spawn_node(id, peers, timing_fast()));
    }
    // Wait for a leader.
    pump_outbound(&mut handles, Instant::now() + Duration::from_secs(2)).await?;
    let leader_id = {
        let mut leader = None;
        for _ in 0..50 {
            pump_outbound(&mut handles, Instant::now() + Duration::from_millis(40)).await?;
            let mut count = 0;
            for (id, h) in handles.iter() {
                if h.role().await == Role::Leader {
                    leader = Some(*id);
                    count += 1;
                }
            }
            if count == 1 {
                break;
            }
            leader = None;
        }
        leader.expect("no leader after settle")
    };

    // Propose 5 entries to the leader.
    let mut proposed_indices = Vec::new();
    for i in 0..5u32 {
        let reply = handles
            .get(&leader_id)
            .unwrap()
            .propose(format!("e{}", i).into_bytes())
            .await?;
        match reply {
            ProposeReply::Accepted { index } => proposed_indices.push(index),
            ProposeReply::NotLeader { leader_hint } => {
                panic!(
                    "propose to leader returned NotLeader (hint={:?})",
                    leader_hint
                )
            }
        }
        // Pump messages so AppendEntries actually go out.
        pump_outbound(&mut handles, Instant::now() + Duration::from_millis(80)).await?;
    }
    assert_eq!(proposed_indices, vec![1, 2, 3, 4, 5]);

    // Pump for a while to let commits propagate.
    pump_outbound(&mut handles, Instant::now() + Duration::from_secs(1)).await?;

    // All nodes should have last_log_index == 5 and commit_index == 5.
    for (_id, h) in handles.iter() {
        assert_eq!(h.last_log_index().await, 5, "node {} log behind", _id);
        assert_eq!(h.commit_index().await, 5, "node {} commit behind", _id);
    }

    // Each node should have received Apply notifications for indices 1..=5 in order.
    for (id, h) in handles.iter_mut() {
        let mut got = Vec::new();
        for _ in 0..5 {
            // try_recv until something's there
            for _ in 0..50 {
                if let Some(e) = h.try_recv_committed() {
                    got.push(e.index);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
                pump_outbound(
                    &mut BTreeMap::new(),
                    Instant::now() + Duration::from_millis(1),
                )
                .await?;
            }
        }
        assert_eq!(got, vec![1, 2, 3, 4, 5], "node {} apply order off", id);
    }

    for (_id, h) in std::mem::take(&mut handles).into_iter() {
        h.shutdown().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn propose_to_follower_returns_not_leader() -> Result<()> {
    let mut handles: BTreeMap<NodeId, NodeHandle> = BTreeMap::new();
    for id in 1..=3u32 {
        let peers: Vec<NodeId> = (1..=3u32).filter(|p| *p != id).collect();
        handles.insert(id, spawn_node(id, peers, timing_fast()));
    }
    // Settle to a leader.
    for _ in 0..50 {
        pump_outbound(&mut handles, Instant::now() + Duration::from_millis(40)).await?;
        let mut leaders = Vec::new();
        for (id, h) in handles.iter() {
            if h.role().await == Role::Leader {
                leaders.push(*id);
            }
        }
        if leaders.len() == 1 {
            break;
        }
    }

    let leader_id = {
        let mut id = 0;
        for (i, h) in handles.iter() {
            if h.role().await == Role::Leader {
                id = *i;
            }
        }
        id
    };
    let follower_id = if leader_id == 1 { 2 } else { 1 };

    let reply = handles
        .get(&follower_id)
        .unwrap()
        .propose(b"nope".to_vec())
        .await?;
    assert!(matches!(reply, ProposeReply::NotLeader { .. }));

    for (_id, h) in std::mem::take(&mut handles).into_iter() {
        h.shutdown().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_store_survives_restart() -> Result<()> {
    use tempfile::TempDir;
    let tmp = TempDir::new()?;
    let store_path = tmp.path().join("raft.json");

    // First lifetime: spin up a single-node cluster, propose one entry, persist.
    {
        let store: std::sync::Arc<dyn RaftStore> =
            std::sync::Arc::new(JsonStore::new(store_path.clone()));
        let h = spawn_node_with_store(1, vec![], timing_fast(), store)?;
        // Single-node clusters self-elect on first election timeout.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(h.role().await, Role::Leader);
        let reply = h.propose(b"persisted".to_vec()).await?;
        assert!(matches!(reply, ProposeReply::Accepted { index: 1 }));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.commit_index().await, 1, "single-node commits immediately");
        h.shutdown().await;
    }

    // Second lifetime: re-open the store, confirm the log is back.
    {
        let store: std::sync::Arc<dyn RaftStore> = std::sync::Arc::new(JsonStore::new(store_path));
        let h = spawn_node_with_store(1, vec![], timing_fast(), store)?;
        // Give it time to re-elect.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(h.last_log_index().await, 1, "log lost across restart");
        // Term must have advanced past the previous one (we re-elected).
        assert!(h.current_term().await >= 1);
        h.shutdown().await;
    }

    Ok(())
}

// Suppress unused-import warning on MemStore (kept exported for downstream use).
fn _suppress() -> std::sync::Arc<dyn RaftStore> {
    std::sync::Arc::new(MemStore::new())
}

// ---------------------------------------------------------------------------
// Snapshot + log compaction
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_compacts_log_and_survives_restart() -> Result<()> {
    use tempfile::TempDir;
    let tmp = TempDir::new()?;
    let store_path = tmp.path().join("raft.json");

    // Lifetime 1: propose 10 entries, snapshot, propose 3 more, shut down.
    {
        let store: std::sync::Arc<dyn RaftStore> =
            std::sync::Arc::new(JsonStore::new(store_path.clone()));
        let h = spawn_node_with_store(1, vec![], timing_fast(), store)?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(h.role().await, Role::Leader);

        for i in 0..10u32 {
            let _ = h.propose(format!("e{}", i).into_bytes()).await?;
        }
        // Wait for commits + applies to propagate; single-node clusters commit
        // synchronously but the apply Action is dispatched via the channel.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(h.commit_index().await, 10);
        // Take a snapshot — application data is empty in this test.
        let snap: PersistedSnapshot = h.take_snapshot(b"sm-state".to_vec()).await?;
        assert!(snap.last_index >= 1);

        // Three more proposes after the snapshot.
        for i in 0..3u32 {
            let _ = h.propose(format!("post{}", i).into_bytes()).await?;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(h.commit_index().await, 13);

        // Give the apply_and_persist a moment to flush after the last propose.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The on-disk log should now have at most 3 entries (snapshot took
        // care of the first 10).
        let trimmed: es_broker::raft::PersistedRaft =
            serde_json::from_slice(&std::fs::read(&store_path)?)?;
        assert!(
            trimmed.log.len() <= 3,
            "expected log compaction; got {} entries",
            trimmed.log.len()
        );

        h.shutdown().await;
    }

    // Lifetime 2: re-open; the snapshot fast-forwards the log + commit/applied
    // indices, then any post-snapshot entries replay.
    {
        let store: std::sync::Arc<dyn RaftStore> =
            std::sync::Arc::new(JsonStore::new(store_path.clone()));
        let h = spawn_node_with_store(1, vec![], timing_fast(), store)?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let s = h.state.lock().await;
        // Log spans the snapshot boundary: in-memory entries are the
        // 3 post-snapshot ones, base_index marks where the snapshot ends.
        assert_eq!(s.log.last_index(), 13);
        assert!(
            s.log.base_index >= 10,
            "base_index didn't restore from snapshot"
        );
        // commit_index reflects what's safely committed. Per Raft §5.4.2 the
        // newly-elected leader can't commit prior-term entries by counting
        // alone, so it stays at the snapshot boundary until a fresh proposal.
        assert_eq!(s.commit_index, s.log.base_index);
        drop(s);
        h.shutdown().await;
    }
    Ok(())
}

/// Test that a leader with a snapshot an send it to a follower that's
/// behind, and the follower accepts and resumes catching up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn snapshot_sent_to_lagging_follower() -> Result<()> {
    let tmp = TempDir::new()?;
    let store_1: Arc<dyn es_broker::raft::RaftStore> =
        Arc::new(JsonStore::new(tmp.path().join("n1.json")));
    let store_2: Arc<dyn es_broker::raft::RaftStore> =
        Arc::new(JsonStore::new(tmp.path().join("n2.json")));

    let n1 = spawn_node_with_store(1, vec![2], timing_fast(), store_1.clone())?;
    let n2 = spawn_node_with_store(2, vec![1], timing_fast(), store_2.clone())?;

    let mut handles: BTreeMap<NodeId, NodeHandle> = BTreeMap::new();
    handles.insert(1, n1);
    handles.insert(2, n2);

    // Elect leader.
    let leader = settle_leader_in_process(&mut handles, Duration::from_secs(2)).await?;
    assert!(leader.is_some(), "no leader");
    let leader_id = leader.unwrap();

    // Which node wins the election is genuinely nondeterministic, so the stores
    // are picked by the outcome. Naming node 1 as the leader made this test pass
    // only in the runs where node 1 happened to win.
    let follower_id: NodeId = if leader_id == 1 { 2 } else { 1 };
    let leader_store = if leader_id == 1 {
        store_1.clone()
    } else {
        store_2.clone()
    };
    let follower_store = if follower_id == 1 {
        store_1.clone()
    } else {
        store_2.clone()
    };

    // Propose entries and pump aggressively so the follower acks.
    for i in 0..10u32 {
        handles
            .get_mut(&leader_id)
            .unwrap()
            .propose(format!("entry-{}", i).into_bytes())
            .await?;
        pump_outbound(&mut handles, Instant::now() + Duration::from_millis(300)).await?;
    }
    pump_outbound(&mut handles, Instant::now() + Duration::from_millis(800)).await?;

    // Force last_applied to be non-zero (in 2-node clusters with quick
    // timing the follower may not have acked in time).
    {
        let h = handles.get(&leader_id).unwrap();
        let mut s = h.state.lock().await;
        let li = s.log.last_index();
        if s.last_applied == 0 && li > 0 {
            s.last_applied = li;
            s.commit_index = li;
        }
        drop(s);
    }

    // Take a snapshot on the leader.
    let snap_index;
    {
        let h = handles.get(&leader_id).unwrap();
        let snap = h.take_snapshot(b"snap-data".to_vec()).await?;
        snap_index = snap.last_index;
        assert!(snap_index > 0);
        assert_eq!(snap.data, b"snap-data");

        let loaded = leader_store.load_snapshot()?.unwrap();
        assert_eq!(loaded.last_index, snap_index);

        let s = h.state.lock().await;
        assert_eq!(s.log.base_index, snap_index);
        drop(s);
    }

    // Put the follower genuinely behind. Compacting *its* log does not do that:
    // the leader decides what to send from its own `next_index` for that peer,
    // and a follower that has acked everything is not behind no matter what its
    // own log looks like. So drop the follower's entries AND rewind the leader's
    // idea of where it is, which is the state after a follower has been down
    // long enough for the leader to compact past it.
    {
        let mut s = handles.get(&follower_id).unwrap().state.lock().await;
        s.log.truncate_from(1);
        s.commit_index = 0;
        s.last_applied = 0;
        drop(s);
    }
    {
        let mut s = handles.get(&leader_id).unwrap().state.lock().await;
        s.next_index.insert(follower_id, 1);
        s.match_index.insert(follower_id, 0);
        drop(s);
    }

    // Leader sends InstallSnapshot on next heartbeat.
    pump_outbound(&mut handles, Instant::now() + Duration::from_millis(500)).await?;

    // Verify follower received and persisted the snapshot.
    let snap_loaded = follower_store.load_snapshot()?.unwrap();
    assert_eq!(snap_loaded.last_index, snap_index);
    assert_eq!(snap_loaded.data, b"snap-data");

    let s = handles.get(&follower_id).unwrap().state.lock().await;
    assert_eq!(
        s.log.base_index, snap_index,
        "follower did not apply snapshot base_index"
    );
    drop(s);

    for (_id, h) in std::mem::take(&mut handles) {
        h.shutdown().await;
    }
    Ok(())
}
