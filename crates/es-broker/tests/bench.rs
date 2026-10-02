//! Throughput bench. Run with
//!
//! ```text
//! cargo test --release --test bench -- --ignored --nocapture
//! ```
//!
//! (on the build server: `rbuild --faithful`-equivalent settings, see AGENTS.md —
//! ThinLTO builds measure a few percent slow).
//!
//! Every scenario boots a fresh broker. "fsync=1" is the default durability:
//! nothing is acknowledged before it is on disk.

use std::net::SocketAddr;
use std::time::Instant;

use anyhow::Result;
use es_broker::binary::{BinaryClient, ClientOptions, PipelinedClient};
use es_broker::{spawn, Config};
use es_protocol::wire::WireProduceRecord;
use es_protocol::{CreateTopicRequest, ProduceRecord, ProduceRequest};
use reqwest::Client as HttpClient;
use tempfile::TempDir;

const VALUE_BYTES: usize = 256;

fn ephemeral() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

struct Scenario {
    flush_every: u32,
    raft: bool,
}

async fn boot(tmp: &TempDir, s: &Scenario) -> Result<es_broker::BrokerHandle> {
    let mut cfg = Config::new(tmp.path().to_path_buf(), ephemeral(), 1 << 26);
    cfg.bind_binary = Some(ephemeral());
    cfg.flush_every_records = s.flush_every;
    if s.raft {
        cfg.raft_node_id = Some(1);
        cfg.raft_bind = Some(ephemeral());
    }
    spawn(cfg).await
}

async fn create(http: &HttpClient, base: &str, name: &str, partitions: u32) -> Result<()> {
    http.post(format!("{}/topics", base))
        .json(&CreateTopicRequest {
            name: name.into(),
            partitions,
            config: None,
        })
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

fn value() -> Vec<u8> {
    "lorem-ipsum-".repeat(VALUE_BYTES / 11 + 1).as_bytes()[..VALUE_BYTES].to_vec()
}

fn report(label: &str, records: usize, secs: f64) {
    println!(
        "{:<58} {:>9.1} k rec/s {:>8.1} MB/s",
        label,
        records as f64 / secs / 1000.0,
        (records * VALUE_BYTES) as f64 / 1_048_576.0 / secs
    );
}

/// `conns` binary connections, each producing `batches` batches of `batch`.
async fn binary_produce(
    addr: SocketAddr,
    topic: &str,
    conns: usize,
    batches: usize,
    batch: usize,
) -> Result<f64> {
    let start = Instant::now();
    let mut tasks = Vec::new();
    for t in 0..conns {
        let topic = topic.to_string();
        tasks.push(tokio::spawn(async move {
            let mut c = BinaryClient::connect_with(addr, "", ClientOptions::default()).await?;
            let v = value();
            for b in 0..batches {
                let records: Vec<WireProduceRecord> = (0..batch)
                    .map(|i| WireProduceRecord {
                        key: Some(format!("k{}-{}-{}", t, b, i).into_bytes()),
                        value: v.clone(),
                        partition: None,
                        sequence: None,
                    })
                    .collect();
                c.produce(&topic, None, records).await?;
            }
            Ok::<_, anyhow::Error>(())
        }));
    }
    for t in tasks {
        t.await??;
    }
    Ok(start.elapsed().as_secs_f64())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn bench_throughput() -> Result<()> {
    let http = HttpClient::new();

    for (flush_every, label) in [(1u32, "fsync=1 (default)"), (1000, "fsync=1000")] {
        let s = Scenario {
            flush_every,
            raft: false,
        };
        for parts in [1u32, 4] {
            let tmp = TempDir::new()?;
            let h = boot(&tmp, &s).await?;
            create(&http, &h.base_url(), "t", parts).await?;
            let (conns, batches, batch) = (8, 25, 500);
            let secs = binary_produce(h.binary_addr.unwrap(), "t", conns, batches, batch).await?;
            report(
                &format!("binary produce  8 conns x 500/batch, {}p, {}", parts, label),
                conns * batches * batch,
                secs,
            );

            if parts == 1 && flush_every == 1 {
                // Read it all back over one connection.
                let mut c = BinaryClient::connect(h.binary_addr.unwrap(), "").await?;
                let start = Instant::now();
                let mut off = 0u64;
                let mut n = 0usize;
                loop {
                    let r = c.consume("t", 0, off, 100_000, 4 << 20).await?;
                    if r.records.is_empty() {
                        break;
                    }
                    n += r.records.len();
                    off = r.next_offset;
                }
                report(
                    "binary consume  1 conn, 4 MiB fetches",
                    n,
                    start.elapsed().as_secs_f64(),
                );
            }
            h.shutdown().await?;
        }
    }

    // Many small requests in flight on one connection: what group commit is for.
    {
        let tmp = TempDir::new()?;
        let h = boot(
            &tmp,
            &Scenario {
                flush_every: 1,
                raft: false,
            },
        )
        .await?;
        create(&http, &h.base_url(), "t", 1).await?;
        let c = PipelinedClient::connect(h.binary_addr.unwrap(), "").await?;
        let (inflight, per_task, batch) = (64, 40, 10);
        let start = Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..inflight {
            let c = c.clone();
            tasks.push(tokio::spawn(async move {
                let v = value();
                for _ in 0..per_task {
                    let records: Vec<WireProduceRecord> = (0..batch)
                        .map(|_| WireProduceRecord {
                            key: None,
                            value: v.clone(),
                            partition: Some(0),
                            sequence: None,
                        })
                        .collect();
                    c.produce("t", None, records).await?;
                }
                Ok::<_, anyhow::Error>(())
            }));
        }
        for t in tasks {
            t.await??;
        }
        report(
            "pipelined 1 conn, 64 in flight x 10/batch, 1p, fsync=1",
            inflight * per_task * batch,
            start.elapsed().as_secs_f64(),
        );
        c.shutdown().await;
        h.shutdown().await?;
    }

    // HTTP/JSON, 8 concurrent clients.
    {
        let tmp = TempDir::new()?;
        let h = boot(
            &tmp,
            &Scenario {
                flush_every: 1,
                raft: false,
            },
        )
        .await?;
        let base = h.base_url();
        create(&http, &base, "t", 4).await?;
        let (clients, batches, batch) = (8, 10, 500);
        let v = String::from_utf8(value())?;
        let start = Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..clients {
            let (http, base, v) = (http.clone(), base.clone(), v.clone());
            tasks.push(tokio::spawn(async move {
                for _ in 0..batches {
                    http.post(format!("{}/topics/t/produce", base))
                        .json(&ProduceRequest {
                            records: (0..batch)
                                .map(|_| ProduceRecord {
                                    key: None,
                                    value: v.clone(),
                                    partition: None,
                                    sequence: None,
                                })
                                .collect(),
                            producer_id: None,
                        })
                        .send()
                        .await?
                        .error_for_status()?;
                }
                Ok::<_, anyhow::Error>(())
            }));
        }
        for t in tasks {
            t.await??;
        }
        report(
            "http produce    8 clients x 500/batch, 4p, fsync=1",
            clients * batches * batch,
            start.elapsed().as_secs_f64(),
        );
        h.shutdown().await?;
    }

    // Single-node Raft partition: every record goes through the Raft log.
    {
        let tmp = TempDir::new()?;
        let h = boot(
            &tmp,
            &Scenario {
                flush_every: 1,
                raft: true,
            },
        )
        .await?;
        create(&http, &h.base_url(), "t", 1).await?;
        // Give the single-node group a moment to elect itself.
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let (conns, batches, batch) = (4, 10, 100);
        let secs = binary_produce(h.binary_addr.unwrap(), "t", conns, batches, batch).await?;
        report(
            "raft produce    4 conns x 100/batch, 1p (single node)",
            conns * batches * batch,
            secs,
        );
        h.shutdown().await?;
    }
    Ok(())
}
