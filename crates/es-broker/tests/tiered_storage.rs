use anyhow::Result;
use es_broker::{Config, spawn};
use tempfile::TempDir;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offload_segment_to_cold_storage() -> Result<()> {
    let tmp = TempDir::new()?;
    let cold = TempDir::new()?;

    let mut cfg = Config::new(
        tmp.path().to_path_buf(),
        "127.0.0.1:0".parse().unwrap(),
        256,
    );
    cfg.flush_every_records = 1;
    cfg.retention_check_interval = std::time::Duration::from_millis(100);
    cfg.segment_delete_grace = std::time::Duration::from_millis(0);
    cfg.cold_storage_dir = Some(cold.path().to_path_buf());
    let handle = spawn(cfg).await?;
    let base = handle.base_url();
    let client = reqwest::Client::new();

    client
        .post(format!("{}/topics", base))
        .json(&serde_json::json!({
            "name": "orders",
            "partitions": 1,
            "config": { "retention_ms": 1 }
        }))
        .send()
        .await?;

    for i in 0..50u32 {
        client
            .post(format!("{}/topics/orders/produce", base))
            .json(&serde_json::json!({
                "records": [{"key": format!("k{}", i), "value": format!("v{}", i)}]
            }))
            .send()
            .await?;
    }

    let _ = client
        .post(format!("{}/admin/run-retention", base))
        .send()
        .await?;

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let cold_dir = cold.path().join("orders").join("0");
    let cold_contents: Vec<_> = if cold_dir.exists() {
        std::fs::read_dir(&cold_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().into_string().unwrap_or_default())
            .filter(|n| n.ends_with(".log"))
            .collect()
    } else {
        Vec::new()
    };

    assert!(
        !cold_contents.is_empty(),
        "no segments offloaded to cold storage"
    );

    handle.shutdown().await?;
    Ok(())
}
