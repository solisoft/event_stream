//! Integration tests for `RaftPartition` — appends routed through a single-node
//! Raft cluster end up in the underlying segmented log.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use es_broker::partition_handle::{PartitionHandle, RaftConfig};
use es_broker::raft::Timing;
use es_broker::raft_partition::{
    test_timing, RaftPartition, RaftPartitionConfig, RaftTransportConfig,
};
use tempfile::TempDir;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_node_append_roundtrip() -> Result<()> {
    let tmp = TempDir::new()?;
    let part_dir = tmp.path().join("p0");
    let raft_path = tmp.path().join("raft.json");

    let rp = RaftPartition::open(
        part_dir.clone(),
        0,
        1 << 20,
        1,
        RaftPartitionConfig {
            node_id: 1,
            peers: vec![],
            raft_store_path: raft_path.clone(),
            timing: test_timing(),
            snapshot_after_applies: 0, // disabled for this test
        },
    )?;

    // Wait for the 1-node cluster to self-elect.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Append 20 records through Raft.
    let mut offsets = Vec::new();
    for i in 0..20u32 {
        let off = rp
            .append(
                Some(format!("k{}", i).as_bytes()),
                format!("v{}", i).as_bytes(),
            )
            .await?;
        offsets.push(off);
    }
    assert_eq!(offsets, (0..20u64).collect::<Vec<_>>());

    // Verify the underlying Partition saw all 20.
    let p = rp.partition();
    assert_eq!(p.end_offset(), 20);

    // Read them back through Partition::read_records_raw directly.
    let (records, _next, hwm) = p.read_records_raw(0, 100, 1 << 20)?;
    assert_eq!(hwm, 20);
    assert_eq!(records.len(), 20);
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.offset, i as u64);
        assert_eq!(r.key.as_deref(), Some(format!("k{}", i).as_bytes()));
        assert_eq!(r.value, format!("v{}", i).into_bytes());
    }

    rp.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raft_partition_state_survives_restart() -> Result<()> {
    let tmp = TempDir::new()?;
    let part_dir = tmp.path().join("p0");
    let raft_path = tmp.path().join("raft.json");

    // Lifetime 1: write 5 records.
    {
        let rp = RaftPartition::open(
            part_dir.clone(),
            0,
            1 << 20,
            1,
            RaftPartitionConfig {
                node_id: 1,
                peers: vec![],
                raft_store_path: raft_path.clone(),
                timing: test_timing(),
                snapshot_after_applies: 0,
            },
        )?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        for i in 0..5u32 {
            rp.append(None, format!("first-{}", i).as_bytes()).await?;
        }
        assert_eq!(rp.partition().end_offset(), 5);
        rp.shutdown().await;
        // Drop the Arc so the underlying file handles release before reopen.
        drop(rp);
    }

    // Lifetime 2: reopen, append 3 more.
    {
        let rp = RaftPartition::open(
            part_dir.clone(),
            0,
            1 << 20,
            1,
            RaftPartitionConfig {
                node_id: 1,
                peers: vec![],
                raft_store_path: raft_path,
                timing: test_timing(),
                snapshot_after_applies: 0,
            },
        )?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        // Underlying partition should have recovered to offset 5.
        assert_eq!(
            rp.partition().end_offset(),
            5,
            "partition log lost across restart"
        );

        for i in 0..3u32 {
            let off = rp.append(None, format!("second-{}", i).as_bytes()).await?;
            assert_eq!(off, 5 + i as u64);
        }
        assert_eq!(rp.partition().end_offset(), 8);
        rp.shutdown().await;
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_snapshot_keeps_raft_log_bounded() -> Result<()> {
    let tmp = TempDir::new()?;
    let part_dir = tmp.path().join("p0");
    let raft_path = tmp.path().join("raft.json");

    let rp = RaftPartition::open(
        part_dir.clone(),
        0,
        1 << 20,
        1,
        RaftPartitionConfig {
            node_id: 1,
            peers: vec![],
            raft_store_path: raft_path.clone(),
            timing: test_timing(),
            snapshot_after_applies: 50, // small so we see multiple snapshots
        },
    )?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let n = 300u32;
    for i in 0..n {
        rp.append(None, format!("v{}", i).as_bytes()).await?;
    }
    // Give the apply loop a tick to land the final snapshot.
    tokio::time::sleep(Duration::from_millis(80)).await;

    // The partition has every record …
    assert_eq!(rp.partition().end_offset(), n as u64);
    // … and the on-disk Raft log has been compacted: at most one batch worth
    // of entries past the snapshot boundary.
    let raft: es_broker::raft::PersistedRaft = serde_json::from_slice(&std::fs::read(&raft_path)?)?;
    assert!(
        raft.log.len() as u32 <= 50,
        "raft log not compacted: {} entries",
        raft.log.len()
    );
    // The snapshot file exists and reflects what was committed.
    let snap_path = tmp.path().join("raft.snapshot.json");
    assert!(snap_path.exists(), "snapshot file should be written");
    let snap: es_broker::raft::PersistedSnapshot =
        serde_json::from_slice(&std::fs::read(&snap_path)?)?;
    assert!(snap.last_index > 0);

    rp.shutdown().await;
    drop(rp);

    // Restart: the partition has all 300 records, Raft state catches up via
    // the snapshot + the remaining trimmed log.
    let rp = RaftPartition::open(
        part_dir,
        0,
        1 << 20,
        1,
        RaftPartitionConfig {
            node_id: 1,
            peers: vec![],
            raft_store_path: raft_path,
            timing: test_timing(),
            snapshot_after_applies: 50,
        },
    )?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(rp.partition().end_offset(), n as u64);

    // A fresh append lands at the right offset after restart.
    let off = rp.append(None, b"after-restart").await?;
    assert_eq!(off, n as u64);

    rp.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partition_handle_raft_roundtrip() -> Result<()> {
    let tmp = TempDir::new()?;
    let part_dir = tmp.path().join("p0");
    let raft_dir = tmp.path().join("raft");

    let handle = PartitionHandle::open(
        part_dir.clone(),
        0,
        1 << 20,
        1,
        Some(&RaftConfig {
            node_id: 1,
            peers: vec![],
            raft_store_dir: raft_dir.clone(),
            timing: Timing {
                election_min: Duration::from_millis(50),
                election_max: Duration::from_millis(100),
                heartbeat: Duration::from_millis(20),
            },
            snapshot_after_applies: 0,
            bind: None,
            peer_addrs: BTreeMap::new(),
            shared_secret: None,
        }),
    )?;

    tokio::time::sleep(Duration::from_millis(150)).await;

    for i in 0..10u32 {
        let off = handle
            .append(
                Some(format!("k{}", i).as_bytes()),
                format!("v{}", i).as_bytes(),
            )
            .await?;
        assert_eq!(off, i as u64);
    }

    assert_eq!(handle.end_offset(), 10);
    assert_eq!(handle.start_offset(), 0);
    assert_eq!(handle.id(), 0);
    assert_eq!(handle.segment_count(), 1);

    let (records, next, hwm) = handle.read_records_raw(0, 100, 1 << 20)?;
    assert_eq!(hwm, 10);
    assert_eq!(next, 10);
    assert_eq!(records.len(), 10);
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.offset, i as u64);
        assert_eq!(r.key.as_deref(), Some(format!("k{}", i).as_bytes()));
        assert_eq!(r.value, format!("v{}", i).into_bytes());
    }

    handle.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partition_handle_raft_survives_restart() -> Result<()> {
    let tmp = TempDir::new()?;
    let part_dir = tmp.path().join("p0");
    let raft_dir = tmp.path().join("raft");
    let cfg = RaftConfig {
        node_id: 1,
        peers: vec![],
        raft_store_dir: raft_dir.clone(),
        timing: Timing {
            election_min: Duration::from_millis(50),
            election_max: Duration::from_millis(100),
            heartbeat: Duration::from_millis(20),
        },
        snapshot_after_applies: 0,
        bind: None,
        peer_addrs: BTreeMap::new(),
        shared_secret: None,
    };

    {
        let handle = PartitionHandle::open(part_dir.clone(), 0, 1 << 20, 1, Some(&cfg))?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        for i in 0..5u32 {
            handle.append(None, format!("v{}", i).as_bytes()).await?;
        }
        assert_eq!(handle.end_offset(), 5);
        handle.shutdown().await;
        drop(handle);
    }

    {
        let handle = PartitionHandle::open(part_dir.clone(), 0, 1 << 20, 1, Some(&cfg))?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(handle.end_offset(), 5, "data lost across restart");
        handle.append(None, b"after-restart").await?;
        assert_eq!(handle.end_offset(), 6);
        handle.shutdown().await;
    }

    Ok(())
}

/// Two RaftPartitions connected via TCP: produce on the leader, read from
/// the follower to confirm replication over the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn two_node_tcp_replication() -> Result<()> {
    let tmp1 = TempDir::new()?;
    let tmp2 = TempDir::new()?;

    // Bind ephemeral listeners to find free ports, then reuse those ports.
    let l1 = std::net::TcpListener::bind("127.0.0.1:0")?;
    let l2 = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr1 = l1.local_addr()?;
    let addr2 = l2.local_addr()?;
    // Set SO_REUSEADDR so we can re-bind immediately after dropping.
    l1.set_nonblocking(true).ok();
    l2.set_nonblocking(true).ok();
    drop(l1);
    drop(l2);
    // Small delay to let the kernel release the ports.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let timing = Timing {
        election_min: Duration::from_millis(300),
        election_max: Duration::from_millis(600),
        heartbeat: Duration::from_millis(100),
    };

    let cfg1 = RaftPartitionConfig {
        node_id: 1,
        peers: vec![2],
        raft_store_path: tmp1.path().join("raft.json"),
        timing,
        snapshot_after_applies: 0,
    };
    let cfg2 = RaftPartitionConfig {
        node_id: 2,
        peers: vec![1],
        raft_store_path: tmp2.path().join("raft.json"),
        timing,
        snapshot_after_applies: 0,
    };

    let rp1 = RaftPartition::open(tmp1.path().join("p0"), 0, 1 << 20, 1, cfg1)?;
    let rp2 = RaftPartition::open(tmp2.path().join("p0"), 0, 1 << 20, 1, cfg2)?;

    // Connect TCP transports.
    let mut peers_for_1 = BTreeMap::new();
    peers_for_1.insert(2u32, addr2);
    let mut peers_for_2 = BTreeMap::new();
    peers_for_2.insert(1u32, addr1);
    rp1.connect_transport(RaftTransportConfig {
        bind: addr1,
        peer_addrs: peers_for_1,
        shared_secret: None,
    })
    .await?;
    rp2.connect_transport(RaftTransportConfig {
        bind: addr2,
        peer_addrs: peers_for_2,
        shared_secret: None,
    })
    .await?;

    // Wait for election + initial heartbeats.
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Find the leader by trial: propose to each node, one will succeed.
    let (leader, follower) = {
        let r1 = rp1.append(None, b"probe").await;
        if r1.is_ok() {
            (&rp1, &rp2)
        } else {
            // Try the other node.
            rp2.append(None, b"probe").await?;
            (&rp2, &rp1)
        }
    };

    // The probe landed; now produce a batch through the leader.
    let n = 50u32;
    for i in 0..n {
        let off = leader.append(None, format!("v{}", i).as_bytes()).await?;
        assert_eq!(off, (i + 1) as u64, "offset mismatch at record {}", i);
    }

    // Wait for replication to catch up.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if follower.partition().end_offset() >= (n + 1) as u64 {
            break;
        }
        if std::time::Instant::now() > deadline {
            anyhow::bail!(
                "follower didn't catch up: end_offset={}",
                follower.partition().end_offset()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Read from the follower's partition to verify all records replicated.
    let (records, _next, hwm) = follower.partition().read_records_raw(0, 100, 1 << 20)?;
    assert_eq!(hwm, (n + 1) as u64);
    assert_eq!(records.len(), (n + 1) as usize);
    // First record is the probe.
    assert_eq!(records[0].value, b"probe");
    for i in 0..n as usize {
        assert_eq!(records[i + 1].value, format!("v{}", i).into_bytes());
    }

    rp1.shutdown().await;
    rp2.shutdown().await;
    Ok(())
}
