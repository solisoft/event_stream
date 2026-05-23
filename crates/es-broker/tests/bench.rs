//! Throughput micro-bench. Run with:
//!   cargo test --release --workspace --test bench -- --ignored --nocapture
//!
//! Boots a broker in-process, produces N records across BATCHES batches over
//! three protocol paths, prints elapsed time + MB/s. Not statistically rigorous;
//! designed to make the binary-protocol speedup obvious at a glance.

use std::net::SocketAddr;
use std::time::Instant;

use anyhow::Result;
use es_broker::binary::{BinaryClient, ClientOptions, PipelinedClient};
use es_broker::{BrokerHandle, Config, spawn};
use es_protocol::wire::WireProduceRecord;
use es_protocol::{CreateTopicRequest, ProduceRecord, ProduceRequest};
use reqwest::Client as HttpClient;
use tempfile::TempDir;

/// Total records per scenario.
const TOTAL_RECORDS: usize = 20_000;
/// Records per produce call. Realistic producers always batch.
const BATCH: usize = 200;
const VALUE_BYTES: usize = 256;

fn ephemeral() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

async fn boot(tmp: &TempDir) -> Result<BrokerHandle> {
    let mut cfg = Config::new(tmp.path().to_path_buf(), ephemeral(), 1 << 24);
    cfg.bind_binary = Some(ephemeral());
    // The bench is about protocol throughput, not disk fsync rate. Sync once
    // per batch so fsync isn't the dominant cost on this hardware.
    cfg.flush_every_records = BATCH as u32;
    Ok(spawn(cfg).await?)
}

async fn create_topic(http: &HttpClient, base: &str, name: &str) -> Result<()> {
    http.post(format!("{}/topics", base))
        .json(&CreateTopicRequest {
            name: name.to_string(),
            partitions: 1,
            config: None,
        })
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

fn payload_value() -> String {
    // Mostly-repeating to give gzip something to work with.
    "lorem-ipsum-dolor-sit-amet-".repeat(VALUE_BYTES / 27 + 1)[..VALUE_BYTES].to_string()
}

fn mb_per_sec(bytes: usize, elapsed_secs: f64) -> f64 {
    (bytes as f64 / 1_048_576.0) / elapsed_secs
}

async fn http_batched(base: &str, topic: &str) -> Result<(std::time::Duration, usize)> {
    let http = HttpClient::builder().tcp_keepalive(None).build()?;
    let value = payload_value();
    let total_bytes = TOTAL_RECORDS * value.len();
    let batches = TOTAL_RECORDS / BATCH;

    let start = Instant::now();
    for _ in 0..batches {
        let records: Vec<ProduceRecord> = (0..BATCH)
            .map(|_| ProduceRecord {
                key: None,
                value: value.clone(),
                partition: Some(0),
                sequence: None,
            })
            .collect();
        http.post(format!("{}/topics/{}/produce", base, topic))
            .json(&ProduceRequest {
                producer_id: None,
                records,
            })
            .send()
            .await?
            .error_for_status()?;
    }
    Ok((start.elapsed(), total_bytes))
}

async fn binary_batched(
    addr: SocketAddr,
    topic: &str,
    gzip: bool,
) -> Result<(std::time::Duration, usize)> {
    let mut client = BinaryClient::connect_with(addr, "", ClientOptions { gzip }).await?;
    let value_bytes = payload_value().into_bytes();
    let total_bytes = TOTAL_RECORDS * value_bytes.len();
    let batches = TOTAL_RECORDS / BATCH;

    let start = Instant::now();
    for _ in 0..batches {
        let records: Vec<WireProduceRecord> = (0..BATCH)
            .map(|_| WireProduceRecord {
                key: None,
                value: value_bytes.clone(),
                partition: Some(0),
                sequence: None,
            })
            .collect();
        client.produce(topic, None, records).await?;
    }
    Ok((start.elapsed(), total_bytes))
}

/// Pipelined: same single connection, but fire every batch concurrently and
/// let the broker process them as they arrive. The response stream is
/// multiplexed back to per-call `oneshot`s.
async fn binary_pipelined(
    addr: SocketAddr,
    topic: &str,
) -> Result<(std::time::Duration, usize)> {
    let client = PipelinedClient::connect(addr, "").await?;
    let value_bytes = payload_value().into_bytes();
    let total_bytes = TOTAL_RECORDS * value_bytes.len();
    let batches = TOTAL_RECORDS / BATCH;

    let start = Instant::now();
    let mut handles = Vec::with_capacity(batches);
    for _ in 0..batches {
        let c = client.clone();
        let value = value_bytes.clone();
        let topic = topic.to_string();
        handles.push(tokio::spawn(async move {
            let records: Vec<WireProduceRecord> = (0..BATCH)
                .map(|_| WireProduceRecord {
                    key: None,
                    value: value.clone(),
                    partition: Some(0),
                    sequence: None,
                })
                .collect();
            c.produce(&topic, None, records).await
        }));
    }
    for h in handles {
        h.await??;
    }
    let elapsed = start.elapsed();
    client.shutdown().await;
    Ok((elapsed, total_bytes))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bench_throughput() -> Result<()> {
    let tmp = TempDir::new()?;
    let handle = boot(&tmp).await?;
    let base = handle.base_url();
    let http = HttpClient::new();

    for name in &["http", "bin", "binz"] {
        create_topic(&http, &base, name).await?;
    }

    println!();
    println!(
        "=== throughput bench: {} records × {} bytes in batches of {} ({} MiB) ===",
        TOTAL_RECORDS,
        VALUE_BYTES,
        BATCH,
        (TOTAL_RECORDS * VALUE_BYTES) / 1_048_576
    );

    let (d, bytes) = http_batched(&base, "http").await?;
    println!(
        "HTTP / JSON         : {:>7.2}ms  {:>8.2} MB/s  ({:>7.2} k records/s)",
        d.as_secs_f64() * 1000.0,
        mb_per_sec(bytes, d.as_secs_f64()),
        (TOTAL_RECORDS as f64 / d.as_secs_f64()) / 1000.0
    );

    let (d, bytes) = binary_batched(handle.binary_addr.unwrap(), "bin", false).await?;
    println!(
        "binary / plain      : {:>7.2}ms  {:>8.2} MB/s  ({:>7.2} k records/s)",
        d.as_secs_f64() * 1000.0,
        mb_per_sec(bytes, d.as_secs_f64()),
        (TOTAL_RECORDS as f64 / d.as_secs_f64()) / 1000.0
    );

    let (d, bytes) = binary_batched(handle.binary_addr.unwrap(), "binz", true).await?;
    println!(
        "binary / gzip       : {:>7.2}ms  {:>8.2} MB/s  ({:>7.2} k records/s)",
        d.as_secs_f64() * 1000.0,
        mb_per_sec(bytes, d.as_secs_f64()),
        (TOTAL_RECORDS as f64 / d.as_secs_f64()) / 1000.0
    );

    // For pipelined we need a fresh topic — re-creating to keep offsets
    // independent of the warmup data.
    create_topic(&http, &base, "pipe").await?;
    let (d, bytes) = binary_pipelined(handle.binary_addr.unwrap(), "pipe").await?;
    println!(
        "binary / pipelined  : {:>7.2}ms  {:>8.2} MB/s  ({:>7.2} k records/s)",
        d.as_secs_f64() * 1000.0,
        mb_per_sec(bytes, d.as_secs_f64()),
        (TOTAL_RECORDS as f64 / d.as_secs_f64()) / 1000.0
    );

    handle.shutdown().await?;
    Ok(())
}
