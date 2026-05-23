use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use es_broker::auth::AuthMode;
use es_broker::{Config, spawn};
use es_protocol::{
    AclActionDto, AclRuleDto, CleanupPolicyDto, CommitRequest, ConsumeResponse,
    CreateKeyRequest, CreateKeyResponse, CreateTopicRequest, DescribeTopicResponse,
    GroupOffsetsResponse, ListProducersResponse, ListTopicsResponse, ProduceRecord,
    ProduceRequest, ProduceResponse, ResetOffsetsRequest, ResetOffsetsResponse,
    TopicConfigDto, TopicConfigPatch,
};
use reqwest::Client;
use tempfile::TempDir;

fn ephemeral_bind() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

async fn boot(tmp: &TempDir, segment_bytes: u64) -> Result<(String, es_broker::BrokerHandle)> {
    let data_dir: PathBuf = tmp.path().to_path_buf();
    let cfg = Config::new(data_dir, ephemeral_bind(), segment_bytes);
    let handle = spawn(cfg).await?;
    Ok((handle.base_url(), handle))
}

/// Boot with aggressive background-task intervals so retention/compaction
/// trigger inside test deadlines.
async fn boot_fast(
    tmp: &TempDir,
    segment_bytes: u64,
) -> Result<(String, es_broker::BrokerHandle)> {
    let data_dir: PathBuf = tmp.path().to_path_buf();
    let mut cfg = Config::new(data_dir, ephemeral_bind(), segment_bytes);
    cfg.retention_check_interval = Duration::from_millis(150);
    cfg.compaction_check_interval = Duration::from_millis(150);
    cfg.segment_delete_grace = Duration::from_millis(50);
    let handle = spawn(cfg).await?;
    Ok((handle.base_url(), handle))
}

async fn create_topic(client: &Client, base: &str, name: &str, partitions: u32) -> Result<()> {
    let resp = client
        .post(format!("{}/topics", base))
        .json(&CreateTopicRequest {
            name: name.to_string(),
            partitions,
            config: None,
        })
        .send()
        .await?;
    assert!(resp.status().is_success(), "create topic failed: {}", resp.status());
    Ok(())
}

async fn produce(
    client: &Client,
    base: &str,
    topic: &str,
    records: Vec<ProduceRecord>,
) -> Result<ProduceResponse> {
    let resp: ProduceResponse = client
        .post(format!("{}/topics/{}/produce", base, topic))
        .json(&ProduceRequest { records,
 producer_id: None,
})
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(resp)
}

async fn consume(
    client: &Client,
    base: &str,
    topic: &str,
    partition: u32,
    offset: u64,
    max: usize,
) -> Result<ConsumeResponse> {
    Ok(client
        .get(format!(
            "{}/topics/{}/consume?partition={}&offset={}&max_records={}",
            base, topic, partition, offset, max
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn produce_then_consume_with_segment_rolls() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot(&tmp, 512).await?;
    let client = Client::new();

    create_topic(&client, &base, "orders", 1).await?;

    let records: Vec<ProduceRecord> = (0..100)
        .map(|i| ProduceRecord {
            key: Some(format!("k{}", i)),
            value: format!("v{}", i),
            partition: Some(0),
            sequence: None,
        })
        .collect();
    let p = produce(&client, &base, "orders", records).await?;
    assert_eq!(p.results.len(), 100);
    for (i, r) in p.results.iter().enumerate() {
        assert_eq!(r.partition, 0);
        assert_eq!(r.offset, i as u64);
    }

    let desc: DescribeTopicResponse = client
        .get(format!("{}/topics/orders", base))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(desc.partitions.len(), 1);
    assert!(
        desc.partitions[0].segment_count >= 2,
        "expected segment roll, got {}",
        desc.partitions[0].segment_count
    );
    assert_eq!(desc.partitions[0].end_offset, 100);

    // Pull all 100 in multiple batches (single-segment-per-poll by design).
    let mut all = Vec::new();
    let mut next_offset = 0u64;
    while next_offset < 100 {
        let resp = consume(&client, &base, "orders", 0, next_offset, 100).await?;
        if resp.records.is_empty() {
            panic!("consume returned no records at offset {}", next_offset);
        }
        next_offset = resp.next_offset;
        all.extend(resp.records);
    }
    assert_eq!(all.len(), 100);
    for (i, r) in all.iter().enumerate() {
        assert_eq!(r.offset, i as u64, "non-contiguous offsets");
        assert_eq!(r.value, format!("v{}", i));
    }

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn group_resume_and_restart_persistence() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot(&tmp, 1024).await?;
    let client = Client::new();
    create_topic(&client, &base, "events", 1).await?;
    let records: Vec<ProduceRecord> = (0..20)
        .map(|i| ProduceRecord {
            key: None,
            value: format!("e{}", i),
            partition: Some(0),
            sequence: None,
        })
        .collect();
    produce(&client, &base, "events", records).await?;

    // Group reads from the beginning.
    let resp: ConsumeResponse = client
        .get(format!(
            "{}/groups/g1/consume?topic=events&partition=0&max_records=5",
            base
        ))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(resp.records.first().unwrap().offset, 0);
    let next = resp.next_offset;
    assert!(next > 0);

    // Commit and re-consume — should resume.
    let commit_resp = client
        .post(format!("{}/groups/g1/commit", base))
        .json(&CommitRequest {
            topic: "events".to_string(),
            partition: 0,
            offset: next,
        })
        .send()
        .await?;
    assert!(commit_resp.status().is_success());

    let resp2: ConsumeResponse = client
        .get(format!(
            "{}/groups/g1/consume?topic=events&partition=0&max_records=5",
            base
        ))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(resp2.records.first().unwrap().offset, next);

    // Persist offset further along to test restart resume.
    client
        .post(format!("{}/groups/g1/commit", base))
        .json(&CommitRequest {
            topic: "events".to_string(),
            partition: 0,
            offset: 12,
        })
        .send()
        .await?
        .error_for_status()?;

    handle.shutdown().await?;

    // Restart on the same data dir.
    let (base2, handle2) = boot(&tmp, 1024).await?;
    let client = Client::new();

    let topics: ListTopicsResponse = client
        .get(format!("{}/topics", base2))
        .send()
        .await?
        .json()
        .await?;
    assert!(topics.topics.contains(&"events".to_string()));

    let g: GroupOffsetsResponse = client
        .get(format!("{}/groups/g1/offsets", base2))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(*g.offsets.get("events").unwrap().get(&0).unwrap(), 12);

    let resp3: ConsumeResponse = client
        .get(format!(
            "{}/groups/g1/consume?topic=events&partition=0&max_records=20",
            base2
        ))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(resp3.records.first().unwrap().offset, 12);
    assert_eq!(resp3.records.last().unwrap().value, "e19");

    handle2.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovers_from_torn_write() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot(&tmp, 4096).await?;
    let client = Client::new();
    create_topic(&client, &base, "t", 1).await?;
    let records: Vec<ProduceRecord> = (0..10)
        .map(|i| ProduceRecord {
            key: None,
            value: format!("rec{}", i),
            partition: Some(0),
            sequence: None,
        })
        .collect();
    produce(&client, &base, "t", records).await?;
    handle.shutdown().await?;

    // Append 5 random bytes to the active .log so a torn record is at the tail.
    let part_dir = tmp.path().join("topics").join("t").join("0");
    let mut entries: Vec<_> = std::fs::read_dir(&part_dir)?
        .filter_map(Result::ok)
        .filter(|e| {
            e.path().extension().and_then(|s| s.to_str()) == Some("log")
        })
        .collect();
    entries.sort_by_key(|e| e.path());
    let active = entries.last().unwrap().path();
    let pre_len = std::fs::metadata(&active)?.len();
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&active)?;
        f.write_all(&[0xDE, 0xAD, 0xBE, 0xEF, 0x42])?;
    }
    assert_eq!(std::fs::metadata(&active)?.len(), pre_len + 5);

    let (base, handle) = boot(&tmp, 4096).await?;
    let client = Client::new();

    let desc: DescribeTopicResponse = client
        .get(format!("{}/topics/t", base))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(desc.partitions[0].end_offset, 10, "torn-write tail should be truncated");

    // Final size on disk should match the pre-corruption length.
    assert_eq!(std::fs::metadata(&active)?.len(), pre_len);

    // Producing post-recovery should continue from offset 10.
    let r = produce(
        &client,
        &base,
        "t",
        vec![ProduceRecord {
            key: None,
            value: "after-recovery".to_string(),
            partition: Some(0),
            sequence: None,
        }],
    )
    .await?;
    assert_eq!(r.results[0].offset, 10);

    handle.shutdown().await?;
    Ok(())
}

async fn create_topic_with_config(
    client: &Client,
    base: &str,
    name: &str,
    partitions: u32,
    patch: TopicConfigPatch,
) -> Result<()> {
    let resp = client
        .post(format!("{}/topics", base))
        .json(&CreateTopicRequest {
            name: name.to_string(),
            partitions,
            config: Some(patch),
        })
        .send()
        .await?;
    assert!(resp.status().is_success(), "create topic failed: {}", resp.status());
    Ok(())
}

async fn describe(client: &Client, base: &str, name: &str) -> Result<DescribeTopicResponse> {
    Ok(client
        .get(format!("{}/topics/{}", base, name))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_time_based_deletes_old_segments() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot_fast(&tmp, 256).await?;
    let client = Client::new();

    create_topic_with_config(
        &client,
        &base,
        "t",
        1,
        TopicConfigPatch {
            retention_ms: Some(400),
            cleanup_policy: Some(CleanupPolicyDto::Delete),
            ..Default::default()
        },
    )
    .await?;

    // Produce enough records to roll segments multiple times.
    let records: Vec<ProduceRecord> = (0..40)
        .map(|i| ProduceRecord {
            key: None,
            value: format!("v{}", i),
            partition: Some(0),
            sequence: None,
        })
        .collect();
    produce(&client, &base, "t", records).await?;
    let before = describe(&client, &base, "t").await?;
    assert!(
        before.partitions[0].segment_count >= 2,
        "expected multiple segments, got {}",
        before.partitions[0].segment_count
    );

    // Wait past retention + a couple reaper ticks.
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let after = describe(&client, &base, "t").await?;
    assert!(
        after.partitions[0].segment_count < before.partitions[0].segment_count,
        "segments should have been reaped: before={}, after={}",
        before.partitions[0].segment_count,
        after.partitions[0].segment_count
    );
    assert!(
        after.partitions[0].start_offset > 0,
        "start_offset should have advanced past 0"
    );

    // Reading from offset 0 must not error — it should clamp to start_offset.
    let resp = consume(&client, &base, "t", 0, 0, 100).await?;
    if !resp.records.is_empty() {
        assert!(
            resp.records[0].offset >= after.partitions[0].start_offset,
            "first record offset {} below start_offset {}",
            resp.records[0].offset,
            after.partitions[0].start_offset
        );
    }

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_size_based_deletes_oldest() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot_fast(&tmp, 256).await?;
    let client = Client::new();

    create_topic_with_config(
        &client,
        &base,
        "t",
        1,
        TopicConfigPatch {
            retention_bytes: Some(1024),
            cleanup_policy: Some(CleanupPolicyDto::Delete),
            ..Default::default()
        },
    )
    .await?;

    // Produce ~5KB worth.
    let records: Vec<ProduceRecord> = (0..80)
        .map(|i| ProduceRecord {
            key: None,
            value: format!("payload-{:04}", i),
            partition: Some(0),
            sequence: None,
        })
        .collect();
    produce(&client, &base, "t", records).await?;
    tokio::time::sleep(Duration::from_millis(700)).await;

    let after = describe(&client, &base, "t").await?;
    // Allow one segment of slack — retention deletes whole sealed segments.
    let budget = 1024u64 + 256;
    assert!(
        after.partitions[0].size_bytes <= budget,
        "size_bytes {} exceeds budget {}",
        after.partitions[0].size_bytes,
        budget
    );

    // Producing still works after retention.
    let r = produce(
        &client,
        &base,
        "t",
        vec![ProduceRecord {
            key: None,
            value: "post-retention".to_string(),
            partition: Some(0),
            sequence: None,
        }],
    )
    .await?;
    assert_eq!(r.results.len(), 1);

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compaction_collapses_duplicate_keys() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot_fast(&tmp, 256).await?;
    let client = Client::new();

    create_topic_with_config(
        &client,
        &base,
        "t",
        1,
        TopicConfigPatch {
            cleanup_policy: Some(CleanupPolicyDto::Compact),
            ..Default::default()
        },
    )
    .await?;

    // 5 keys cycling, 6 versions each = 30 records. Tiny segment size → multiple rolls.
    let mut records: Vec<ProduceRecord> = Vec::with_capacity(30);
    for v in 0..6 {
        for k in 0..5 {
            records.push(ProduceRecord {
                key: Some(format!("k{}", k)),
                value: format!("k{}-v{}", k, v),
                partition: Some(0),
                sequence: None,
            });
        }
    }
    produce(&client, &base, "t", records).await?;

    let before = describe(&client, &base, "t").await?;
    assert!(
        before.partitions[0].segment_count >= 2,
        "expected multiple segments, got {}",
        before.partitions[0].segment_count
    );

    // Wait past a compaction tick.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // After compaction, sealed segments should collapse to at most one segment
    // plus the active one.
    let after = describe(&client, &base, "t").await?;
    assert!(
        after.partitions[0].segment_count <= 2,
        "expected <= 2 segments after compaction, got {}",
        after.partitions[0].segment_count
    );

    // Consume everything and verify each key surviving in the *latest* version.
    let mut all = Vec::new();
    let mut off = 0u64;
    for _ in 0..20 {
        let resp = consume(&client, &base, "t", 0, off, 100).await?;
        if resp.records.is_empty() {
            break;
        }
        off = resp.next_offset;
        all.extend(resp.records);
        if off >= resp.high_watermark {
            break;
        }
    }
    use std::collections::HashMap;
    let mut latest: HashMap<String, String> = HashMap::new();
    for r in &all {
        if let Some(k) = &r.key {
            latest.insert(k.clone(), r.value.clone());
        }
    }
    // Each surviving key must hold its v=5 value (the last produced).
    for k in 0..5 {
        let key = format!("k{}", k);
        let expected = format!("k{}-v5", k);
        assert_eq!(
            latest.get(&key).map(|s| s.as_str()),
            Some(expected.as_str()),
            "key {} did not collapse to last version",
            key
        );
    }

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_preserves_config_and_post_deletion_state() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot_fast(&tmp, 256).await?;
    let client = Client::new();

    create_topic_with_config(
        &client,
        &base,
        "t",
        1,
        TopicConfigPatch {
            retention_ms: Some(400),
            cleanup_policy: Some(CleanupPolicyDto::Delete),
            ..Default::default()
        },
    )
    .await?;

    let records: Vec<ProduceRecord> = (0..30)
        .map(|i| ProduceRecord {
            key: None,
            value: format!("v{}", i),
            partition: Some(0),
            sequence: None,
        })
        .collect();
    produce(&client, &base, "t", records).await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let pre = describe(&client, &base, "t").await?;
    let pre_start = pre.partitions[0].start_offset;
    assert!(pre_start > 0, "retention should have advanced start_offset");

    handle.shutdown().await?;

    let (base2, handle2) = boot_fast(&tmp, 256).await?;
    let client = Client::new();
    let post = describe(&client, &base2, "t").await?;
    assert_eq!(
        post.partitions[0].start_offset, pre_start,
        "start_offset should survive restart"
    );
    assert_eq!(post.partitions[0].end_offset, pre.partitions[0].end_offset);

    let cfg: TopicConfigDto = client
        .get(format!("{}/topics/t/config", base2))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(cfg.retention_ms, Some(400));
    assert!(matches!(cfg.cleanup_policy, CleanupPolicyDto::Delete));

    handle2.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_during_compaction_recovers() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot(&tmp, 1 << 20).await?;
    let client = Client::new();
    create_topic(&client, &base, "t", 1).await?;
    produce(
        &client,
        &base,
        "t",
        vec![ProduceRecord {
            key: Some("k".to_string()),
            value: "v".to_string(),
            partition: Some(0),
            sequence: None,
        }],
    )
    .await?;
    handle.shutdown().await?;

    // Simulate an interrupted compaction: leftover tmp file in the partition dir.
    let part_dir = tmp.path().join("topics").join("t").join("0");
    let tmp_log = part_dir.join("00000000000000000000.compact.tmp.log");
    let tmp_idx = part_dir.join("00000000000000000000.compact.tmp.index");
    std::fs::write(&tmp_log, b"garbage-bytes")?;
    std::fs::write(&tmp_idx, b"garbage-bytes")?;
    assert!(tmp_log.exists());
    assert!(tmp_idx.exists());

    let (base, handle) = boot(&tmp, 1 << 20).await?;
    let client = Client::new();
    let desc = describe(&client, &base, "t").await?;
    assert_eq!(desc.partitions[0].end_offset, 1, "data should be intact");
    assert!(!tmp_log.exists(), "leftover compaction tmp must be swept");
    assert!(!tmp_idx.exists(), "leftover compaction tmp must be swept");

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_endpoint_reports_produce_consume_counters() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot(&tmp, 1 << 20).await?;
    let client = Client::new();
    create_topic(&client, &base, "m", 1).await?;
    produce(
        &client,
        &base,
        "m",
        (0..5)
            .map(|i| ProduceRecord {
                key: Some(format!("k{}", i)),
                value: format!("payload-{}", i),
                partition: Some(0),
                sequence: None,
            })
            .collect(),
    )
    .await?;
    let _ = consume(&client, &base, "m", 0, 0, 100).await?;

    let body = client
        .get(format!("{}/metrics", base))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    assert!(body.contains("# TYPE es_topic_records_produced_total counter"));
    assert!(body.contains(r#"es_topic_records_produced_total{topic="m"} 5"#));
    assert!(body.contains(r#"es_topic_records_consumed_total{topic="m"} 5"#));
    assert!(body.contains(r#"es_partition_end_offset{topic="m",partition="0"} 5"#));
    assert!(body.contains("es_partition_size_bytes"));

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_emits_group_lag() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot(&tmp, 1 << 20).await?;
    let client = Client::new();
    create_topic(&client, &base, "lag", 1).await?;
    produce(
        &client,
        &base,
        "lag",
        (0..10)
            .map(|i| ProduceRecord {
                key: None,
                value: format!("v{}", i),
                partition: Some(0),
                sequence: None,
            })
            .collect(),
    )
    .await?;

    client
        .post(format!("{}/groups/g/commit", base))
        .json(&CommitRequest {
            topic: "lag".to_string(),
            partition: 0,
            offset: 3,
        })
        .send()
        .await?
        .error_for_status()?;

    let body = client
        .get(format!("{}/metrics", base))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    assert!(body.contains(r#"es_group_committed_offset{group="g",topic="lag",partition="0"} 3"#));
    // hwm=10, committed=3 → lag=7
    assert!(body.contains(r#"es_group_lag{group="g",topic="lag",partition="0"} 7"#));

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_run_retention_forces_deletion() -> Result<()> {
    let tmp = TempDir::new()?;
    // boot_fast uses a short segment_delete_grace so the synchronous admin
    // retention call returns quickly. (Default grace is 60s.)
    let (base, handle) = boot_fast(&tmp, 256).await?;
    let client = Client::new();

    // Create with retention disabled, so the background reaper can't act
    // before we measure the baseline.
    create_topic(&client, &base, "force", 1).await?;
    produce(
        &client,
        &base,
        "force",
        (0..30)
            .map(|i| ProduceRecord {
                key: None,
                value: format!("v{}", i),
                partition: Some(0),
                sequence: None,
            })
            .collect(),
    )
    .await?;
    let before = describe(&client, &base, "force").await?;
    assert!(before.partitions[0].segment_count >= 2);

    // Enable aggressive retention via PUT, sleep past cutoff, then force a pass.
    client
        .put(format!("{}/topics/force/config", base))
        .json(&TopicConfigPatch {
            retention_ms: Some(1),
            cleanup_policy: Some(CleanupPolicyDto::Delete),
            ..Default::default()
        })
        .send()
        .await?
        .error_for_status()?;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let resp = client
        .post(format!("{}/admin/run-retention", base))
        .send()
        .await?;
    assert_eq!(resp.status().as_u16(), 204);

    let after = describe(&client, &base, "force").await?;
    assert!(
        after.partitions[0].segment_count < before.partitions[0].segment_count,
        "admin retention pass should have reaped sealed segments"
    );

    // Metrics counter should reflect the deletion.
    let body = client
        .get(format!("{}/metrics", base))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let line = body
        .lines()
        .find(|l| l.starts_with(r#"es_retention_segments_deleted_total{topic="force",partition="0"}"#))
        .expect("retention deleted counter missing");
    let deleted: u64 = line.rsplit(' ').next().unwrap().parse().unwrap();
    assert!(deleted > 0);

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_routing_is_stable() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot(&tmp, 1 << 20).await?;
    let client = Client::new();
    create_topic(&client, &base, "keyed", 4).await?;

    // Same key always lands on the same partition.
    let mut first_partition = None;
    for _ in 0..10 {
        let r = produce(
            &client,
            &base,
            "keyed",
            vec![ProduceRecord {
                key: Some("alpha".to_string()),
                value: "x".to_string(),
                partition: None,
                sequence: None,
            }],
        )
        .await?;
        let p = r.results[0].partition;
        match first_partition {
            None => first_partition = Some(p),
            Some(prev) => assert_eq!(prev, p, "key routing not stable"),
        }
    }

    handle.shutdown().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 3 — auth / ACL / rate-limits / bootstrap
// ---------------------------------------------------------------------------

async fn boot_auth(tmp: &TempDir) -> Result<(String, es_broker::BrokerHandle)> {
    let data_dir: PathBuf = tmp.path().to_path_buf();
    let mut cfg = Config::new(data_dir, ephemeral_bind(), 1 << 20);
    cfg.auth_mode = AuthMode::Required;
    cfg.segment_delete_grace = Duration::from_millis(50);
    let handle = spawn(cfg).await?;
    Ok((handle.base_url(), handle))
}

fn read_bootstrap_secret(tmp: &TempDir) -> Result<String> {
    let s = std::fs::read_to_string(tmp.path().join("bootstrap.key"))?;
    Ok(s.trim().to_string())
}

fn bearer(secret: &str) -> Client {
    let mut h = reqwest::header::HeaderMap::new();
    h.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", secret)).unwrap(),
    );
    Client::builder().default_headers(h).build().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_required_rejects_missing_token() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot_auth(&tmp).await?;
    let unauthed = Client::new();
    let resp = unauthed.get(format!("{}/topics", base)).send().await?;
    assert_eq!(resp.status().as_u16(), 401);

    // /healthz and /metrics stay public.
    assert_eq!(
        unauthed
            .get(format!("{}/healthz", base))
            .send()
            .await?
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        unauthed
            .get(format!("{}/metrics", base))
            .send()
            .await?
            .status()
            .as_u16(),
        200
    );

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_admin_key_works() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot_auth(&tmp).await?;
    let secret = read_bootstrap_secret(&tmp)?;
    let client = bearer(&secret);

    // Bootstrap key is admin "*" — can create topic + produce + consume.
    let resp = client
        .post(format!("{}/topics", base))
        .json(&CreateTopicRequest {
            name: "t".to_string(),
            partitions: 1,
            config: None,
        })
        .send()
        .await?;
    assert!(resp.status().is_success());

    let produce = client
        .post(format!("{}/topics/t/produce", base))
        .json(&ProduceRequest {
            records: vec![ProduceRecord {
                key: None,
                value: "hello".to_string(),
                partition: Some(0),
                sequence: None,
            }],
            producer_id: None,
        })
        .send()
        .await?;
    assert!(produce.status().is_success());

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acls_deny_write_without_grant() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot_auth(&tmp).await?;
    let admin_secret = read_bootstrap_secret(&tmp)?;
    let admin = bearer(&admin_secret);

    admin
        .post(format!("{}/topics", base))
        .json(&CreateTopicRequest {
            name: "orders".to_string(),
            partitions: 1,
            config: None,
        })
        .send()
        .await?
        .error_for_status()?;

    // Create a read-only key.
    let key_resp: CreateKeyResponse = admin
        .post(format!("{}/admin/keys", base))
        .json(&CreateKeyRequest {
            name: "reader".to_string(),
            acls: vec![AclRuleDto {
                action: AclActionDto::Read,
                topic_prefix: "orders".to_string(),
            }],
            produce_bytes_per_sec: None,
            consume_bytes_per_sec: None,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let reader = bearer(&key_resp.secret);

    // Read is allowed.
    let cons = reader
        .get(format!("{}/topics/orders/consume?partition=0&offset=0", base))
        .send()
        .await?;
    assert_eq!(cons.status().as_u16(), 200);

    // Write is forbidden.
    let prod = reader
        .post(format!("{}/topics/orders/produce", base))
        .json(&ProduceRequest {
            records: vec![ProduceRecord {
                key: None,
                value: "no".to_string(),
                partition: Some(0),
                sequence: None,
            }],
            producer_id: None,
        })
        .send()
        .await?;
    assert_eq!(prod.status().as_u16(), 403);

    // Creating a topic is forbidden too (admin only).
    let create = reader
        .post(format!("{}/topics", base))
        .json(&CreateTopicRequest {
            name: "x".to_string(),
            partitions: 1,
            config: None,
        })
        .send()
        .await?;
    assert_eq!(create.status().as_u16(), 403);

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn topic_prefix_acl_isolates_topics() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot_auth(&tmp).await?;
    let admin = bearer(&read_bootstrap_secret(&tmp)?);

    for name in &["orders.eu", "orders.us", "billing"] {
        admin
            .post(format!("{}/topics", base))
            .json(&CreateTopicRequest {
                name: name.to_string(),
                partitions: 1,
                config: None,
            })
            .send()
            .await?
            .error_for_status()?;
    }

    let resp: CreateKeyResponse = admin
        .post(format!("{}/admin/keys", base))
        .json(&CreateKeyRequest {
            name: "orders-writer".to_string(),
            acls: vec![AclRuleDto {
                action: AclActionDto::Write,
                topic_prefix: "orders.".to_string(),
            }],
            produce_bytes_per_sec: None,
            consume_bytes_per_sec: None,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let scoped = bearer(&resp.secret);

    for name in &["orders.eu", "orders.us"] {
        let r = scoped
            .post(format!("{}/topics/{}/produce", base, name))
            .json(&ProduceRequest {
                records: vec![ProduceRecord {
                    key: None,
                    value: "ok".to_string(),
                    partition: Some(0),
                    sequence: None,
                }],
                producer_id: None,
            })
            .send()
            .await?;
        assert!(r.status().is_success(), "write to {} should be allowed", name);
    }
    let r = scoped
        .post(format!("{}/topics/billing/produce", base))
        .json(&ProduceRequest {
            records: vec![ProduceRecord {
                key: None,
                value: "no".to_string(),
                partition: Some(0),
                sequence: None,
            }],
            producer_id: None,
        })
        .send()
        .await?;
    assert_eq!(r.status().as_u16(), 403, "write to billing should be denied");

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limit_returns_429_on_burst() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot_auth(&tmp).await?;
    let admin = bearer(&read_bootstrap_secret(&tmp)?);

    admin
        .post(format!("{}/topics", base))
        .json(&CreateTopicRequest {
            name: "rl".to_string(),
            partitions: 1,
            config: None,
        })
        .send()
        .await?
        .error_for_status()?;

    // Issue a key with a tiny produce-bytes budget.
    let resp: CreateKeyResponse = admin
        .post(format!("{}/admin/keys", base))
        .json(&CreateKeyRequest {
            name: "slow-writer".to_string(),
            acls: vec![AclRuleDto {
                action: AclActionDto::Write,
                topic_prefix: "rl".to_string(),
            }],
            produce_bytes_per_sec: Some(64), // 64 B/s; bursts of one ~40B request.
            consume_bytes_per_sec: None,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let writer = bearer(&resp.secret);

    let mut saw_429 = false;
    for _ in 0..20 {
        let r = writer
            .post(format!("{}/topics/rl/produce", base))
            .json(&ProduceRequest {
                records: vec![ProduceRecord {
                    key: Some("kkkkkkkk".to_string()),
                    value: "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv".to_string(),
                    partition: Some(0),
                    sequence: None,
                }],
                producer_id: None,
            })
            .send()
            .await?;
        if r.status().as_u16() == 429 {
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, "expected at least one 429 within the burst");

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keys_survive_broker_restart() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot_auth(&tmp).await?;
    let admin = bearer(&read_bootstrap_secret(&tmp)?);

    // Create a second key.
    let new_key: CreateKeyResponse = admin
        .post(format!("{}/admin/keys", base))
        .json(&CreateKeyRequest {
            name: "persistent".to_string(),
            acls: vec![AclRuleDto {
                action: AclActionDto::Read,
                topic_prefix: "*".to_string(),
            }],
            produce_bytes_per_sec: None,
            consume_bytes_per_sec: None,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let saved_secret = new_key.secret.clone();
    let saved_key_id = new_key.key.key_id.clone();

    handle.shutdown().await?;

    // Restart on the same data dir — bootstrap key NOT regenerated, prior key works.
    let (base2, handle2) = boot_auth(&tmp).await?;
    let prior = bearer(&saved_secret);

    // Auth must still succeed for the persisted key.
    let resp = prior.get(format!("{}/topics", base2)).send().await?;
    assert_eq!(resp.status().as_u16(), 200);

    // Revoke via admin and confirm 401 afterwards.
    let admin2 = bearer(&read_bootstrap_secret(&tmp)?);
    let rev = admin2
        .delete(format!("{}/admin/keys/{}", base2, saved_key_id))
        .send()
        .await?;
    assert_eq!(rev.status().as_u16(), 204);

    let after = prior.get(format!("{}/topics", base2)).send().await?;
    assert_eq!(after.status().as_u16(), 401);

    handle2.shutdown().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4 — idempotent producer + admin API
// ---------------------------------------------------------------------------

async fn produce_idempotent(
    client: &Client,
    base: &str,
    topic: &str,
    producer_id: &str,
    records: Vec<ProduceRecord>,
) -> Result<reqwest::Response> {
    Ok(client
        .post(format!("{}/topics/{}/produce", base, topic))
        .json(&ProduceRequest {
            records,
            producer_id: Some(producer_id.to_string()),
        })
        .send()
        .await?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idempotent_dedupes_on_replay() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot(&tmp, 1 << 20).await?;
    let client = Client::new();
    create_topic(&client, &base, "t", 1).await?;

    let make_rec = |seq: i64, val: &str| ProduceRecord {
        key: Some("k".to_string()),
        value: val.to_string(),
        partition: Some(0),
        sequence: Some(seq),
    };

    // First write: seq=0 → accepted at offset 0.
    let first = produce_idempotent(&client, &base, "t", "p1", vec![make_rec(0, "v0")]).await?;
    assert!(first.status().is_success());
    let first: ProduceResponse = first.json().await?;
    assert_eq!(first.results[0].offset, 0);
    assert!(!first.results[0].duplicate);

    // Replay seq=0 → must return offset 0 marked duplicate, no new append.
    let replay = produce_idempotent(&client, &base, "t", "p1", vec![make_rec(0, "v0-retry")])
        .await?;
    let replay: ProduceResponse = replay.json().await?;
    assert_eq!(replay.results[0].offset, 0);
    assert!(replay.results[0].duplicate);

    // Confirm only one record actually persisted.
    let desc = describe(&client, &base, "t").await?;
    assert_eq!(desc.partitions[0].end_offset, 1);

    // Advance to seq=1.
    let next = produce_idempotent(&client, &base, "t", "p1", vec![make_rec(1, "v1")]).await?;
    let next: ProduceResponse = next.json().await?;
    assert_eq!(next.results[0].offset, 1);
    assert!(!next.results[0].duplicate);

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idempotent_rejects_sequence_gap() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot(&tmp, 1 << 20).await?;
    let client = Client::new();
    create_topic(&client, &base, "t", 1).await?;

    let r = produce_idempotent(
        &client,
        &base,
        "t",
        "p1",
        vec![ProduceRecord {
            key: None,
            value: "v0".to_string(),
            partition: Some(0),
            sequence: Some(0),
        }],
    )
    .await?;
    assert!(r.status().is_success());

    // Skip seq=1 entirely — broker must reject with 400.
    let r = produce_idempotent(
        &client,
        &base,
        "t",
        "p1",
        vec![ProduceRecord {
            key: None,
            value: "v3".to_string(),
            partition: Some(0),
            sequence: Some(3),
        }],
    )
    .await?;
    assert_eq!(r.status().as_u16(), 400);

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn producer_state_survives_restart() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot(&tmp, 1 << 20).await?;
    let client = Client::new();
    create_topic(&client, &base, "t", 1).await?;

    produce_idempotent(
        &client,
        &base,
        "t",
        "p1",
        vec![
            ProduceRecord {
                key: None,
                value: "v0".to_string(),
                partition: Some(0),
                sequence: Some(0),
            },
            ProduceRecord {
                key: None,
                value: "v1".to_string(),
                partition: Some(0),
                sequence: Some(1),
            },
        ],
    )
    .await?
    .error_for_status()?;

    // Force a flush so the JSON file is committed before shutdown.
    handle.broker.producers.flush().await?;
    handle.shutdown().await?;

    // Restart and confirm state was restored: replay seq=1 → duplicate.
    let (base2, handle2) = boot(&tmp, 1 << 20).await?;
    let client = Client::new();
    let replay = produce_idempotent(
        &client,
        &base2,
        "t",
        "p1",
        vec![ProduceRecord {
            key: None,
            value: "v1-replay".to_string(),
            partition: Some(0),
            sequence: Some(1),
        }],
    )
    .await?;
    let body: ProduceResponse = replay.json().await?;
    assert!(body.results[0].duplicate, "post-restart replay should dedupe");
    assert_eq!(body.results[0].offset, 1);

    handle2.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_revoke_producer_resets_state() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot(&tmp, 1 << 20).await?;
    let client = Client::new();
    create_topic(&client, &base, "t", 1).await?;

    produce_idempotent(
        &client,
        &base,
        "t",
        "p1",
        vec![ProduceRecord {
            key: None,
            value: "v0".to_string(),
            partition: Some(0),
            sequence: Some(0),
        }],
    )
    .await?
    .error_for_status()?;

    let list: ListProducersResponse = client
        .get(format!("{}/admin/producers", base))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(list.producers.len(), 1);
    assert_eq!(list.producers[0].producer_id, "p1");

    let rev = client
        .delete(format!("{}/admin/producers/p1", base))
        .send()
        .await?;
    assert_eq!(rev.status().as_u16(), 204);

    // After revoke, seq=0 is accepted again as fresh state.
    let again = produce_idempotent(
        &client,
        &base,
        "t",
        "p1",
        vec![ProduceRecord {
            key: None,
            value: "v0-again".to_string(),
            partition: Some(0),
            sequence: Some(0),
        }],
    )
    .await?;
    let body: ProduceResponse = again.json().await?;
    assert!(!body.results[0].duplicate);
    // Was previously offset 0, now offset 1 (newly appended).
    assert_eq!(body.results[0].offset, 1);

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_reset_offsets_rewinds_groups() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot(&tmp, 1 << 20).await?;
    let client = Client::new();
    create_topic(&client, &base, "t", 1).await?;
    produce(
        &client,
        &base,
        "t",
        (0..10)
            .map(|i| ProduceRecord {
                key: None,
                value: format!("v{}", i),
                partition: Some(0),
                sequence: None,
            })
            .collect(),
    )
    .await?;

    // Commit two groups at different offsets.
    for (group, off) in &[("g1", 4), ("g2", 7)] {
        client
            .post(format!("{}/groups/{}/commit", base, group))
            .json(&CommitRequest {
                topic: "t".to_string(),
                partition: 0,
                offset: *off,
            })
            .send()
            .await?
            .error_for_status()?;
    }

    let resp: ResetOffsetsResponse = client
        .post(format!("{}/admin/reset-offsets", base))
        .json(&ResetOffsetsRequest {
            topic: "t".to_string(),
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(resp.groups_affected, 2);
    assert_eq!(resp.entries_reset, 2);

    // Both groups should now be at start_offset (=0 since nothing's been reaped).
    for group in &["g1", "g2"] {
        let g: GroupOffsetsResponse = client
            .get(format!("{}/groups/{}/offsets", base, group))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(*g.offsets.get("t").unwrap().get(&0).unwrap(), 0);
    }

    handle.shutdown().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 5 — binary protocol
// ---------------------------------------------------------------------------

use es_broker::binary::BinaryClient;
use es_protocol::wire::WireProduceRecord;

async fn boot_with_binary(
    tmp: &TempDir,
    auth: bool,
) -> Result<es_broker::BrokerHandle> {
    let mut cfg = Config::new(tmp.path().to_path_buf(), ephemeral_bind(), 1 << 20);
    cfg.bind_binary = Some("127.0.0.1:0".parse().unwrap());
    if auth {
        cfg.auth_mode = AuthMode::Required;
    }
    Ok(spawn(cfg).await?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_produce_consume_roundtrip() -> Result<()> {
    let tmp = TempDir::new()?;
    let handle = boot_with_binary(&tmp, false).await?;
    let http = Client::new();
    let base = handle.base_url();
    create_topic(&http, &base, "bin", 1).await?;

    let bin_addr = handle.binary_addr.unwrap();
    let mut client = BinaryClient::connect(bin_addr, "").await?;
    client.ping().await?;

    // Native bytes — values include 0x00, 0xFF, and non-UTF-8 sequences.
    let payloads: Vec<Vec<u8>> = vec![
        vec![0x00, 0x01, 0x02],
        b"hello".to_vec(),
        vec![0xFF, 0xC3, 0x28], // 0xC3 0x28 is invalid UTF-8
        vec![],                 // empty value
    ];
    let records: Vec<WireProduceRecord> = payloads
        .iter()
        .enumerate()
        .map(|(i, v)| WireProduceRecord {
            key: Some(format!("k{}", i).into_bytes()),
            value: v.clone(),
            partition: Some(0),
            sequence: None,
        })
        .collect();
    let results = client.produce("bin", None, records).await?;
    assert_eq!(results.len(), 4);
    for (i, r) in results.iter().enumerate() {
        assert_eq!(r.offset, i as u64);
        assert!(!r.duplicate);
    }

    // Consume back through the binary path and verify byte-exact roundtrip.
    let resp = client.consume("bin", 0, 0, 100, 1 << 20).await?;
    assert_eq!(resp.records.len(), 4);
    for (i, r) in resp.records.iter().enumerate() {
        assert_eq!(r.offset, i as u64);
        assert_eq!(r.value, payloads[i], "byte mismatch on record {}", i);
        assert_eq!(r.key.as_deref(), Some(format!("k{}", i).as_bytes()));
    }

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_handshake_requires_token_when_auth_on() -> Result<()> {
    let tmp = TempDir::new()?;
    let handle = boot_with_binary(&tmp, true).await?;
    let bin_addr = handle.binary_addr.unwrap();

    // No token → handshake fails.
    let err = BinaryClient::connect(bin_addr, "").await.err();
    assert!(err.is_some(), "expected handshake failure without token");

    // Bootstrap admin token works.
    let secret = read_bootstrap_secret(&tmp)?;
    let mut client = BinaryClient::connect(bin_addr, &secret).await?;
    client.ping().await?;

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_acl_denies_write_without_grant() -> Result<()> {
    let tmp = TempDir::new()?;
    let handle = boot_with_binary(&tmp, true).await?;
    let bin_addr = handle.binary_addr.unwrap();
    let admin_secret = read_bootstrap_secret(&tmp)?;
    let admin_http = bearer(&admin_secret);
    admin_http
        .post(format!("{}/topics", handle.base_url()))
        .json(&CreateTopicRequest {
            name: "secure".to_string(),
            partitions: 1,
            config: None,
        })
        .send()
        .await?
        .error_for_status()?;

    // Issue a read-only key, then attempt to produce over the binary protocol.
    let kr: CreateKeyResponse = admin_http
        .post(format!("{}/admin/keys", handle.base_url()))
        .json(&CreateKeyRequest {
            name: "reader".to_string(),
            acls: vec![AclRuleDto {
                action: AclActionDto::Read,
                topic_prefix: "secure".to_string(),
            }],
            produce_bytes_per_sec: None,
            consume_bytes_per_sec: None,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let mut reader = BinaryClient::connect(bin_addr, &kr.secret).await?;
    let err = reader
        .produce(
            "secure",
            None,
            vec![WireProduceRecord {
                key: None,
                value: b"nope".to_vec(),
                partition: Some(0),
                sequence: None,
            }],
        )
        .await;
    assert!(err.is_err(), "expected binary produce to be rejected");

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_concurrent_connections_stay_independent() -> Result<()> {
    let tmp = TempDir::new()?;
    let handle = boot_with_binary(&tmp, false).await?;
    let http = Client::new();
    let base = handle.base_url();
    create_topic(&http, &base, "many", 1).await?;

    let bin_addr = handle.binary_addr.unwrap();
    let mut tasks = Vec::new();
    for worker in 0..4u32 {
        let bin_addr = bin_addr;
        tasks.push(tokio::spawn(async move {
            let mut client = BinaryClient::connect(bin_addr, "").await.unwrap();
            let mut offsets = Vec::new();
            for i in 0..25u32 {
                let r = client
                    .produce(
                        "many",
                        None,
                        vec![WireProduceRecord {
                            key: Some(format!("w{}-k{}", worker, i).into_bytes()),
                            value: format!("w{}-v{}", worker, i).into_bytes(),
                            partition: Some(0),
                            sequence: None,
                        }],
                    )
                    .await
                    .unwrap();
                offsets.push(r[0].offset);
            }
            offsets
        }));
    }
    let mut all = Vec::new();
    for t in tasks {
        all.extend(t.await.unwrap());
    }
    all.sort();
    // 4 workers × 25 records = 100 unique offsets.
    assert_eq!(all.len(), 100);
    for i in 0..100 {
        assert_eq!(all[i], i as u64);
    }

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_gzip_roundtrip_preserves_bytes() -> Result<()> {
    use es_broker::binary::ClientOptions;
    let tmp = TempDir::new()?;
    let handle = boot_with_binary(&tmp, false).await?;
    let http = Client::new();
    let base = handle.base_url();
    create_topic(&http, &base, "gz", 1).await?;

    let bin_addr = handle.binary_addr.unwrap();
    let mut client =
        BinaryClient::connect_with(bin_addr, "", ClientOptions { gzip: true }).await?;
    assert!(client.gzip_enabled(), "server must accept gzip negotiation");

    // Big payload that benefits from gzip — repeating bytes compress well.
    let big_value: Vec<u8> = "lorem-ipsum-dolor-sit-amet-"
        .repeat(2_000)
        .into_bytes();

    let results = client
        .produce(
            "gz",
            None,
            vec![WireProduceRecord {
                key: Some(b"alpha".to_vec()),
                value: big_value.clone(),
                partition: Some(0),
                sequence: None,
            }],
        )
        .await?;
    assert_eq!(results[0].offset, 0);

    let resp = client.consume("gz", 0, 0, 10, 1 << 20).await?;
    assert_eq!(resp.records.len(), 1);
    assert_eq!(resp.records[0].value, big_value, "byte-exact after gzip");

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipelined_client_runs_many_concurrent_produces() -> Result<()> {
    use es_broker::binary::PipelinedClient;
    let tmp = TempDir::new()?;
    let handle = boot_with_binary(&tmp, false).await?;
    let http = Client::new();
    let base = handle.base_url();
    create_topic(&http, &base, "pipe", 1).await?;

    let bin_addr = handle.binary_addr.unwrap();
    let client = PipelinedClient::connect(bin_addr, "").await?;

    // Fire 50 produces in parallel on the same connection.
    let mut tasks = Vec::with_capacity(50);
    for i in 0..50u32 {
        let c = client.clone();
        tasks.push(tokio::spawn(async move {
            c.produce(
                "pipe",
                None,
                vec![WireProduceRecord {
                    key: Some(format!("k{}", i).into_bytes()),
                    value: format!("v{}", i).into_bytes(),
                    partition: Some(0),
                    sequence: None,
                }],
            )
            .await
        }));
    }

    let mut offsets = Vec::new();
    for t in tasks {
        let r = t.await??;
        offsets.push(r[0].offset);
    }
    offsets.sort();
    // All 50 records must land on distinct, contiguous offsets — the broker's
    // per-connection frame loop preserves ordering of incoming frames.
    assert_eq!(offsets.len(), 50);
    for i in 0..50 {
        assert_eq!(offsets[i], i as u64, "non-contiguous offsets after pipelining");
    }

    client.shutdown().await;
    handle.shutdown().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Consumer-group coordination
// ---------------------------------------------------------------------------

use es_protocol::{
    AssignmentResponse, HeartbeatRequest, HeartbeatResponse, JoinGroupRequest, JoinGroupResponse,
    LeaveGroupRequest, TopicPartitionDto,
};

async fn join(
    client: &Client,
    base: &str,
    group: &str,
    member_id: Option<&str>,
    topics: &[&str],
) -> Result<JoinGroupResponse> {
    Ok(client
        .post(format!("{}/groups/{}/join", base, group))
        .json(&JoinGroupRequest {
            member_id: member_id.map(|s| s.to_string()),
            topics: topics.iter().map(|s| s.to_string()).collect(),
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

async fn heartbeat(
    client: &Client,
    base: &str,
    group: &str,
    member_id: &str,
    generation: u64,
) -> Result<HeartbeatResponse> {
    Ok(client
        .post(format!("{}/groups/{}/heartbeat", base, group))
        .json(&HeartbeatRequest {
            member_id: member_id.to_string(),
            generation,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

async fn fetch_assignment(
    client: &Client,
    base: &str,
    group: &str,
    member_id: &str,
) -> Result<AssignmentResponse> {
    Ok(client
        .get(format!(
            "{}/groups/{}/assignment?member_id={}",
            base, group, member_id
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

async fn boot_coord_fast(tmp: &TempDir) -> Result<(String, es_broker::BrokerHandle)> {
    let mut cfg = Config::new(tmp.path().to_path_buf(), ephemeral_bind(), 1 << 20);
    cfg.coord_member_timeout = Duration::from_millis(400);
    cfg.coord_expire_interval = Duration::from_millis(100);
    let handle = spawn(cfg).await?;
    Ok((handle.base_url(), handle))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_members_split_two_partitions_one_each() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot_coord_fast(&tmp).await?;
    let client = Client::new();
    create_topic(&client, &base, "shared", 2).await?;

    let a = join(&client, &base, "g", None, &["shared"]).await?;
    let b = join(&client, &base, "g", None, &["shared"]).await?;

    // Generation must have advanced past 1 (it increments per join).
    assert!(b.generation > 1);

    // a's assignment is from generation 1 (stale). Re-fetch for the latest.
    let a_now = fetch_assignment(&client, &base, "g", &a.member_id).await?;
    let b_now = fetch_assignment(&client, &base, "g", &b.member_id).await?;
    assert_eq!(a_now.generation, b_now.generation);
    assert_eq!(a_now.assignment.len(), 1);
    assert_eq!(b_now.assignment.len(), 1);
    let combined: std::collections::BTreeSet<(String, u32)> = a_now
        .assignment
        .iter()
        .chain(b_now.assignment.iter())
        .map(|tp: &TopicPartitionDto| (tp.topic.clone(), tp.partition))
        .collect();
    assert_eq!(
        combined,
        std::collections::BTreeSet::from([
            ("shared".to_string(), 0),
            ("shared".to_string(), 1),
        ])
    );

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn member_leave_rebalances_remaining_members() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot_coord_fast(&tmp).await?;
    let client = Client::new();
    create_topic(&client, &base, "t", 4).await?;

    let a = join(&client, &base, "g", None, &["t"]).await?;
    let b = join(&client, &base, "g", None, &["t"]).await?;

    // Leaving an unknown member is a no-op (still 204).
    let resp = client
        .post(format!("{}/groups/g/leave", base))
        .json(&LeaveGroupRequest {
            member_id: "nonexistent".to_string(),
        })
        .send()
        .await?;
    assert_eq!(resp.status().as_u16(), 204);

    // Leave one of the real members; the other should now own all 4 partitions.
    client
        .post(format!("{}/groups/g/leave", base))
        .json(&LeaveGroupRequest {
            member_id: a.member_id.clone(),
        })
        .send()
        .await?
        .error_for_status()?;
    let b_assign = fetch_assignment(&client, &base, "g", &b.member_id).await?;
    assert_eq!(b_assign.assignment.len(), 4);

    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_member_is_evicted_and_remaining_rebalances() -> Result<()> {
    let tmp = TempDir::new()?;
    let (base, handle) = boot_coord_fast(&tmp).await?;
    let client = Client::new();
    create_topic(&client, &base, "t", 2).await?;

    let a = join(&client, &base, "g", None, &["t"]).await?;
    let b = join(&client, &base, "g", None, &["t"]).await?;

    // Keep a alive with heartbeats; let b go silent.
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(120)).await;
        let r = heartbeat(&client, &base, "g", &a.member_id, a.generation).await?;
        match r {
            HeartbeatResponse::Ok { .. } | HeartbeatResponse::RebalanceRequired { .. } => {}
            HeartbeatResponse::UnknownMember { .. } => {
                panic!("a evicted unexpectedly");
            }
        }
    }
    // ~720ms elapsed — past the 400ms member_timeout for b.
    let r = heartbeat(&client, &base, "g", &b.member_id, b.generation).await?;
    assert!(matches!(r, HeartbeatResponse::UnknownMember { .. }));

    // a should now own both partitions.
    let a_assign = fetch_assignment(&client, &base, "g", &a.member_id).await?;
    assert_eq!(a_assign.assignment.len(), 2);

    handle.shutdown().await?;
    Ok(())
}
