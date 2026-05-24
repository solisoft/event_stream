use anyhow::Result;
use es_broker::{spawn, Config};
use tempfile::TempDir;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schema_register_fetch_and_list() -> Result<()> {
    let tmp = TempDir::new()?;
    let mut cfg = Config::new(
        tmp.path().to_path_buf(),
        "127.0.0.1:0".parse().unwrap(),
        64 * 1024,
    );
    cfg.flush_every_records = 1;
    let handle = spawn(cfg).await?;
    let base = handle.base_url();
    let client = reqwest::Client::new();

    let schema_json = r#"{
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"}
        },
        "required": ["name"]
    }"#;
    let res = client
        .post(format!("{}/schemas", base))
        .json(&serde_json::json!({
            "subject": "user-value",
            "type": "json_schema",
            "schema": schema_json
        }))
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await?;
    assert_eq!(body["id"].as_u64().unwrap(), 1);

    let res = client.get(format!("{}/schemas/1", base)).send().await?;
    assert_eq!(res.status(), 200);

    let res = client.get(format!("{}/schemas", base)).send().await?;
    let list: Vec<serde_json::Value> = res.json().await?;
    assert_eq!(list.len(), 1);

    let res = client
        .get(format!("{}/subjects/user-value/versions/latest", base))
        .send()
        .await?;
    assert_eq!(res.status(), 200);

    // Backward-incompatible → 400.
    let res = client
        .post(format!("{}/schemas", base))
        .json(&serde_json::json!({
            "subject": "user-value",
            "type": "json_schema",
            "schema": r#"{"type":"object","properties":{"name":{"type":"string"}},"required":["name","email"]}"#
        }))
        .send()
        .await?;
    assert_eq!(res.status(), 400);

    // Compatible → 200.
    let res = client
        .post(format!("{}/schemas", base))
        .json(&serde_json::json!({
            "subject": "user-value",
            "type": "json_schema",
            "schema": r#"{"type":"object","properties":{"name":{"type":"string"},"age":{"type":"integer"},"email":{"type":"string"}},"required":["name"]}"#
        }))
        .send()
        .await?;
    assert_eq!(res.status(), 200);

    handle.shutdown().await?;
    Ok(())
}
