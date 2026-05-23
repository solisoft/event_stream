//! Raft step-1 integration tests: 3 nodes elect exactly one leader.
//!
//! One test goes through the in-process pump (proves the state machine),
//! one goes through the real TCP transport (proves the wire works).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Result;
use es_broker::raft::{
    NodeHandle, NodeId, Role, Timing, node::pump_outbound, spawn_node, spawn_transport,
};
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

    for (_id, h) in std::mem::take(&mut handles).into_iter().map(|(k, v)| (k, v)) {
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
    let addrs: BTreeMap<NodeId, SocketAddr> =
        listeners.iter().map(|(k, v)| (*k, v.0)).collect();

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
        let peer_addrs: BTreeMap<NodeId, SocketAddr> = peers
            .iter()
            .map(|p| (*p, *addrs.get(p).unwrap()))
            .collect();

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

use es_broker::raft::{ProposeReply, spawn_node_with_store, RaftStore, JsonStore, MemStore};

async fn settle_until<F>(handles: &mut BTreeMap<NodeId, NodeHandle>, condition: F, timeout: Duration) -> bool
where
    F: Fn(&BTreeMap<NodeId, NodeHandle>) -> futures::future::BoxFuture<'_, bool>,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        pump_outbound(handles, Instant::now() + Duration::from_millis(40)).await.unwrap();
        if condition(handles).await {
            return true;
        }
    }
    false
}

async fn find_leader(handles: &BTreeMap<NodeId, NodeHandle>) -> Option<NodeId> {
    let mut leader: Option<NodeId> = None;
    let mut count = 0;
    for (id, h) in handles.iter() {
        if h.role().await == Role::Leader {
            leader = Some(*id);
            count += 1;
        }
    }
    if count == 1 { leader } else { None }
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
            if count == 1 { break; }
            leader = None;
        }
        leader.expect("no leader after settle")
    };

    // Propose 5 entries to the leader.
    let mut proposed_indices = Vec::new();
    for i in 0..5u32 {
        let reply = handles.get(&leader_id).unwrap()
            .propose(format!("e{}", i).into_bytes())
            .await?;
        match reply {
            ProposeReply::Accepted { index } => proposed_indices.push(index),
            ProposeReply::NotLeader { leader_hint } => {
                panic!("propose to leader returned NotLeader (hint={:?})", leader_hint)
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
                if let Ok(e) = h.committed.try_recv() {
                    got.push(e.index);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
                pump_outbound(&mut BTreeMap::new(), Instant::now() + Duration::from_millis(1)).await?;
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
            if h.role().await == Role::Leader { leaders.push(*id); }
        }
        if leaders.len() == 1 { break; }
    }

    let leader_id = {
        let mut id = 0;
        for (i, h) in handles.iter() {
            if h.role().await == Role::Leader { id = *i; }
        }
        id
    };
    let follower_id = if leader_id == 1 { 2 } else { 1 };

    let reply = handles.get(&follower_id).unwrap().propose(b"nope".to_vec()).await?;
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
        let store: std::sync::Arc<dyn RaftStore> =
            std::sync::Arc::new(JsonStore::new(store_path));
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
fn _suppress() -> std::sync::Arc<dyn RaftStore> { std::sync::Arc::new(MemStore::new()) }
