use std::net::SocketAddr;
use std::time::Instant;

use anyhow::Result;
use es_broker::binary::{BinaryClient, ClientOptions};
use es_broker::{spawn, Config};
use es_protocol::wire::WireProduceRecord;
use es_protocol::CreateTopicRequest;
use reqwest::Client as HttpClient;
use tempfile::TempDir;

const TOTAL_RECORDS: usize = 200_000;
const BATCH: usize = 1000;
const VALUE_BYTES: usize = 256;
const CONCURRENCY: usize = 8;

fn ephemeral() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

async fn boot(tmp: &TempDir) -> Result<es_broker::BrokerHandle> {
    let mut cfg = Config::new(tmp.path().to_path_buf(), ephemeral(), 1 << 24);
    cfg.bind_binary = Some(ephemeral());
    cfg.flush_every_records = BATCH as u32;
    spawn(cfg).await
}

fn value() -> String {
    "lorem-ipsum-".repeat(VALUE_BYTES / 11 + 1)[..VALUE_BYTES].to_string()
}

fn mbps(bytes: usize, secs: f64) -> f64 {
    (bytes as f64 / 1_048_576.0) / secs
}

fn krecps(total: usize, secs: f64) -> f64 {
    (total as f64 / secs) / 1000.0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn bench_throughput() -> Result<()> {
    let tmp = TempDir::new()?;
    let handle = boot(&tmp).await?;
    let base = handle.base_url();
    let http = HttpClient::new();
    let bin_addr = handle.binary_addr.unwrap();
    let val = value();
    let val_bytes = val.as_bytes();

    // --- binary pipelined across partitions ---
    for npart in &[1u32, 4u32] {
        let name = format!("p{}", npart);
        http.post(format!("{}/topics", base))
            .json(&CreateTopicRequest {
                name: name.clone(),
                partitions: *npart,
                config: None,
            })
            .send()
            .await?
            .error_for_status()?;

        let batches_per_task = TOTAL_RECORDS / BATCH / CONCURRENCY;
        let start = Instant::now();
        let mut tasks = Vec::new();
        for t in 0..CONCURRENCY {
            let topic = name.clone();
            let v = val_bytes.to_vec();
            let addr = bin_addr;
            let _npart = *npart;
            tasks.push(tokio::spawn(async move {
                let mut client =
                    BinaryClient::connect_with(addr, "", ClientOptions { gzip: false }).await?;
                for b in 0..batches_per_task {
                    let records: Vec<WireProduceRecord> = (0..BATCH)
                        .map(|i| WireProduceRecord {
                            key: Some(
                                format!("k{}", t * batches_per_task * BATCH + b * BATCH + i)
                                    .into_bytes(),
                            ),
                            value: v.clone(),
                            partition: None,
                            sequence: None,
                        })
                        .collect();
                    client.produce(&topic, None, records).await?;
                }
                Ok::<_, anyhow::Error>(())
            }));
        }
        for t in tasks {
            t.await??;
        }
        let elapsed = start.elapsed().as_secs_f64();

        println!(
            "binary / {} conns / {}p : {:>8.2} MB/s  {:>8.2} k rec/s",
            CONCURRENCY,
            npart,
            mbps(TOTAL_RECORDS * VALUE_BYTES, elapsed),
            krecps(TOTAL_RECORDS, elapsed)
        );
    }

    handle.shutdown().await?;
    Ok(())
}
