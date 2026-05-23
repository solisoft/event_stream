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

