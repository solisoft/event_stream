//! A replica that joins after the leader has compacted its Raft log can only be
//! caught up from a snapshot. Before the fix the snapshot was an 8-byte offset
//! that nothing applied: the follower's partition stayed empty, and the leader
//! never learned the transfer was done and resent it forever.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use es_broker::raft::Timing;
use es_broker::raft_partition::{RaftPartition, RaftPartitionConfig, RaftTransportConfig};
use tempfile::TempDir;

fn free_addrs(n: usize) -> Vec<SocketAddr> {
    let ls: Vec<std::net::TcpListener> = (0..n)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    ls.iter().map(|l| l.local_addr().unwrap()).collect()
}

async fn open_node(id: u32, addrs: &[SocketAddr], dir: &TempDir) -> Result<Arc<RaftPartition>> {
    let timing = Timing {
        election_min: Duration::from_millis(200),
        election_max: Duration::from_millis(400),
        heartbeat: Duration::from_millis(30),
    };
    let peers: Vec<u32> = (1..=addrs.len() as u32).filter(|p| *p != id).collect();
    let rp = RaftPartition::open(
        dir.path().join("p0"),
        0,
        1 << 20,
        1,
        RaftPartitionConfig {
            node_id: id,
            peers: peers.clone(),
            raft_store_path: dir.path().join("raft").join("0"),
            timing,
            snapshot_after_applies: 20,
        },
    )?;
    let peer_addrs: BTreeMap<u32, SocketAddr> =
        peers.iter().map(|p| (*p, addrs[*p as usize - 1])).collect();
    rp.connect_transport(RaftTransportConfig {
        bind: addrs[id as usize - 1],
        peer_addrs,
        shared_secret: Some("test-cluster-secret".into()),
    })
    .await?;
    Ok(rp)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_replica_catches_up_from_the_leaders_snapshot() -> Result<()> {
    let addrs = free_addrs(3);
    let dirs: Vec<TempDir> = (0..3).map(|_| TempDir::new().unwrap()).collect();
    let n1 = open_node(1, &addrs, &dirs[0]).await?;
    let n2 = open_node(2, &addrs, &dirs[1]).await?;

    // Find the leader by trying to write.
    let deadline = Instant::now() + Duration::from_secs(10);
    let leader = loop {
        if n1.append(None, b"probe").await.is_ok() {
            break n1.clone();
        }
        if n2.append(None, b"probe").await.is_ok() {
            break n2.clone();
        }
        assert!(Instant::now() < deadline, "no leader elected");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    for i in 0..120u32 {
        leader
            .append(Some(format!("k{i}").as_bytes()), format!("v{i}").as_bytes())
            .await?;
    }
    // The leader has compacted its log: entry 1 is gone, so a newcomer can
    // only be served a snapshot.
    let deadline = Instant::now() + Duration::from_secs(5);
    while leader.raft_state().lock().await.log.base_index == 0 {
        assert!(Instant::now() < deadline, "leader never snapshotted");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let want = leader.partition().end_offset();

    let n3 = open_node(3, &addrs, &dirs[2]).await?;
    let deadline = Instant::now() + Duration::from_secs(20);
    while n3.partition().end_offset() < want {
        assert!(
            Instant::now() < deadline,
            "late replica stuck at {} of {}",
            n3.partition().end_offset(),
            want
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let (theirs, _, _) = leader.partition().read_records_raw(0, 1000, 1 << 20)?;
    let (ours, _, _) = n3.partition().read_records_raw(0, 1000, 1 << 20)?;
    assert_eq!(ours.len(), theirs.len());
    for (a, b) in ours.iter().zip(&theirs) {
        assert_eq!(
            (a.offset, &a.key, &a.value, a.timestamp_ms),
            (b.offset, &b.key, &b.value, b.timestamp_ms)
        );
    }

    // And it keeps replicating normally afterwards.
    let off = leader.append(None, b"after").await?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while n3.partition().end_offset() <= off {
        assert!(
            Instant::now() < deadline,
            "replication did not resume after the snapshot"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    for n in [&n1, &n2, &n3] {
        n.shutdown().await;
    }
    Ok(())
}

/// Replicas store the leader's offsets and timestamps, not their own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replicas_hold_identical_records() -> Result<()> {
    let addrs = free_addrs(3);
    let dirs: Vec<TempDir> = (0..3).map(|_| TempDir::new().unwrap()).collect();
    let mut nodes = Vec::new();
    for id in 1..=3 {
        nodes.push(open_node(id, &addrs, &dirs[id as usize - 1]).await?);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let leader = 'found: loop {
        for n in &nodes {
            if n.append(None, b"probe").await.is_ok() {
                break 'found n.clone();
            }
        }
        assert!(Instant::now() < deadline, "no leader elected");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let batch: Vec<es_broker::partition::AppendRecord> = (0..50)
        .map(|i| es_broker::partition::AppendRecord::new(None, format!("b{i}").into_bytes()))
        .collect();
    let offs = leader.append_batch(batch).await?;
    assert_eq!(offs.len(), 50);
    assert!(
        offs.windows(2).all(|w| w[1] == w[0] + 1),
        "one batch, contiguous offsets"
    );

    let want = leader.partition().end_offset();
    let deadline = Instant::now() + Duration::from_secs(10);
    for n in &nodes {
        while n.partition().end_offset() < want {
            assert!(Instant::now() < deadline, "replica behind");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    let reference = leader.partition().read_records_raw(0, 1000, 1 << 20)?.0;
    for n in &nodes {
        let got = n.partition().read_records_raw(0, 1000, 1 << 20)?.0;
        let a: Vec<_> = got
            .iter()
            .map(|r| (r.offset, r.timestamp_ms, r.value.clone()))
            .collect();
        let b: Vec<_> = reference
            .iter()
            .map(|r| (r.offset, r.timestamp_ms, r.value.clone()))
            .collect();
        assert_eq!(a, b);
    }
    for n in &nodes {
        n.shutdown().await;
    }
    Ok(())
}
