//! Integration tests for `RaftPartition` — appends routed through a single-node
//! Raft cluster end up in the underlying segmented log.

use std::time::Duration;

use anyhow::Result;
use es_broker::raft_partition::{RaftPartition, RaftPartitionConfig, test_timing};
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
        },
    )?;

    // Wait for the 1-node cluster to self-elect.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Append 20 records through Raft.
    let mut offsets = Vec::new();
    for i in 0..20u32 {
        let off = rp
            .append(Some(format!("k{}", i).as_bytes()), format!("v{}", i).as_bytes())
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
