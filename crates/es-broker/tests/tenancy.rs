//! Regression tests for the second security pass: the DNS-rebinding guard,
//! consume quotas under concurrency, the group and producer-id namespaces,
//! ACL boundaries, and what a deleted topic leaves behind.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use es_broker::auth::AuthMode;
use es_broker::{spawn, Config};
use es_protocol::{
    AclActionDto, AclRuleDto, CommitRequest, ConsumeResponse, CreateKeyRequest, CreateKeyResponse,
    CreateTopicRequest, GroupOffsetsResponse, JoinGroupRequest, ProduceRecord, ProduceRequest,
    ProduceResponse,
};
use reqwest::{Client, StatusCode};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn ephemeral() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn bearer(secret: &str) -> Client {
    let mut h = reqwest::header::HeaderMap::new();
    h.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", secret)).unwrap(),
    );
    Client::builder().default_headers(h).build().unwrap()
}

struct Env {
    tmp: TempDir,
    handle: es_broker::BrokerHandle,
    base: String,
    admin: Client,
}

impl Env {
    async fn boot(auth: bool, tweak: impl FnOnce(&mut Config, PathBuf)) -> Result<Self> {
        let tmp = TempDir::new()?;
        let mut cfg = Config::new(tmp.path().join("data"), ephemeral(), 1 << 20);
        if auth {
            cfg.auth_mode = AuthMode::Required;
        }
        tweak(&mut cfg, tmp.path().to_path_buf());
        let handle = spawn(cfg).await?;
        let base = handle.base_url();
        let admin = if auth {
            let s = std::fs::read_to_string(tmp.path().join("data").join("bootstrap.key"))?;
            bearer(s.trim())
        } else {
            Client::new()
        };
        Ok(Self {
            tmp,
            handle,
            base,
            admin,
        })
    }

    async fn topic(&self, name: &str) -> Result<()> {
        self.admin
            .post(format!("{}/topics", self.base))
            .json(&CreateTopicRequest {
                name: name.into(),
                partitions: 1,
                config: None,
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn key(&self, acls: &[(AclActionDto, &str)], consume_bps: Option<u32>) -> Result<Client> {
        let resp: CreateKeyResponse = self
            .admin
            .post(format!("{}/admin/keys", self.base))
            .json(&CreateKeyRequest {
                name: "k".into(),
                acls: acls
                    .iter()
                    .map(|(a, p)| AclRuleDto {
                        action: *a,
                        topic_prefix: p.to_string(),
                    })
                    .collect(),
                produce_bytes_per_sec: None,
                consume_bytes_per_sec: consume_bps,
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(bearer(&resp.secret))
    }

    async fn produce(
        &self,
        c: &Client,
        topic: &str,
        values: Vec<String>,
        producer_id: Option<&str>,
    ) -> Result<reqwest::Response> {
        let records = values
            .into_iter()
            .enumerate()
            .map(|(i, value)| ProduceRecord {
                key: None,
                value,
                partition: Some(0),
                sequence: producer_id.map(|_| i as i64),
            })
            .collect();
        Ok(c.post(format!("{}/topics/{}/produce", self.base, topic))
            .json(&ProduceRequest {
                records,
                producer_id: producer_id.map(str::to_string),
            })
            .send()
            .await?)
    }
}

/// Send raw bytes, return the status line.
async fn raw_status_line(base: &str, request: &str) -> Result<String> {
    let addr = base.trim_start_matches("http://");
    let mut s = tokio::net::TcpStream::connect(addr).await?;
    s.write_all(request.as_bytes()).await?;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    Ok(text.lines().next().unwrap_or_default().to_string())
}

// Bonfire #703 ---------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebinding_names_that_merely_look_like_loopback_are_refused() -> Result<()> {
    let env = Env::boot(false, |_, _| {}).await?;
    let get = |host: &str| {
        Client::new()
            .get(format!("{}/topics", env.base))
            .header("Host", host)
            .send()
    };
    assert_eq!(
        get("127.rebind.attacker.com").await?.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get("127.0.0.1.attacker.com").await?.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(get("127.0.0.1").await?.status(), StatusCode::OK);
    assert_eq!(get("localhost").await?.status(), StatusCode::OK);
    env.handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_naming_no_host_is_refused_without_auth() -> Result<()> {
    let env = Env::boot(false, |_, _| {}).await?;
    let line = raw_status_line(&env.base, "GET /topics HTTP/1.0\r\n\r\n").await?;
    assert!(line.contains(" 403 "), "{line}");
    let line =
        raw_status_line(&env.base, "GET /topics HTTP/1.0\r\nHost: localhost\r\n\r\n").await?;
    assert!(line.contains(" 200 "), "{line}");
    env.handle.shutdown().await?;
    Ok(())
}

// Bonfire #709 ---------------------------------------------------------------

fn value_bytes(r: &ConsumeResponse) -> usize {
    r.records.iter().map(|r| r.value.len()).sum()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_consumes_share_one_quota() -> Result<()> {
    let env = Env::boot(true, |_, _| {}).await?;
    env.topic("q").await?;
    let values: Vec<String> = (0..100).map(|_| "x".repeat(100)).collect();
    env.produce(&env.admin, "q", values, None)
        .await?
        .error_for_status()?;
    let url = format!("{}/topics/q/consume?partition=0&offset=0", env.base);

    // One read asking for the default 1 MiB gets about a second of budget,
    // not every record.
    let reader = env.key(&[(AclActionDto::Read, "q")], Some(1000)).await?;
    let r: ConsumeResponse = reader
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(!r.records.is_empty(), "a read must make progress");
    assert!(value_bytes(&r) <= 1000, "read {} bytes", value_bytes(&r));

    // Concurrent reads share the budget: before, each of them passed the
    // credit check and read all 10,000 bytes.
    let reader = env.key(&[(AclActionDto::Read, "q")], Some(1000)).await?;
    let reads = (0..8).map(|_| {
        let c = reader.clone();
        let url = url.clone();
        async move {
            let resp = c.get(&url).send().await?;
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                return Ok::<usize, anyhow::Error>(0);
            }
            let r: ConsumeResponse = resp.error_for_status()?.json().await?;
            Ok(value_bytes(&r))
        }
    });
    let total: usize = futures::future::try_join_all(reads)
        .await?
        .into_iter()
        .sum();
    // One second of budget, plus what refills while the reads run.
    assert!(
        total <= 2000,
        "eight concurrent reads returned {total} bytes"
    );
    env.handle.shutdown().await?;
    Ok(())
}

// Bonfire #710 ---------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn group_and_producer_names_cannot_be_squatted() -> Result<()> {
    let env = Env::boot(true, |_, _| {}).await?;
    env.topic("shared").await?;
    let acme = env
        .key(
            &[
                (AclActionDto::Write, "shared"),
                (AclActionDto::Read, "acme"),
            ],
            None,
        )
        .await?;
    let beta = env
        .key(
            &[
                (AclActionDto::Write, "shared"),
                (AclActionDto::Read, "beta"),
            ],
            None,
        )
        .await?;
    let join = |c: &Client, group: &str| {
        c.post(format!("{}/groups/{}/join", env.base, group))
            .json(&JoinGroupRequest {
                member_id: None,
                topics: vec!["shared".into()],
            })
            .send()
    };

    // Beta cannot take a name in acme's namespace before acme uses it...
    assert_eq!(
        join(&beta, "acme.workers").await?.status(),
        StatusCode::FORBIDDEN
    );
    let r = beta
        .post(format!("{}/groups/acme.workers/commit", env.base))
        .json(&CommitRequest {
            topic: "shared".into(),
            partition: 0,
            offset: 0,
        })
        .send()
        .await?;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // ...so acme still can.
    assert!(join(&acme, "acme.workers").await?.status().is_success());
    assert!(join(&beta, "beta.workers").await?.status().is_success());

    // An existing foreign group and an unknown one answer alike.
    let offsets = |group: &str| {
        beta.get(format!("{}/groups/{}/offsets", env.base, group))
            .send()
    };
    let foreign = offsets("acme.workers").await?;
    let unknown = offsets("acme.nothing").await?;
    assert_eq!(foreign.status(), StatusCode::FORBIDDEN);
    assert_eq!(unknown.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        foreign.text().await?.replace("acme.workers", "X"),
        unknown.text().await?.replace("acme.nothing", "X")
    );

    // Producer ids: the same namespace.
    let one = || vec!["v".to_string()];
    assert_eq!(
        env.produce(&beta, "shared", one(), Some("acme.p"))
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(env
        .produce(&acme, "shared", one(), Some("acme.p"))
        .await?
        .status()
        .is_success());
    assert!(env
        .produce(&beta, "shared", one(), Some("beta.p"))
        .await?
        .status()
        .is_success());
    env.handle.shutdown().await?;
    Ok(())
}

// Bonfire #717 ---------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_dots_are_acl_boundaries_and_subjects_follow_their_topic() -> Result<()> {
    let env = Env::boot(true, |_, _| {}).await?;
    for t in ["acme", "acme.eu", "acme-corp"] {
        env.topic(t).await?;
    }
    let k = env.key(&[(AclActionDto::Write, "acme")], None).await?;
    let one = || vec!["v".to_string()];
    assert!(env
        .produce(&k, "acme", one(), None)
        .await?
        .status()
        .is_success());
    assert!(env
        .produce(&k, "acme.eu", one(), None)
        .await?
        .status()
        .is_success());
    assert_eq!(
        env.produce(&k, "acme-corp", one(), None).await?.status(),
        StatusCode::FORBIDDEN
    );

    for subject in ["acme-value", "acme-key", "acme-corp-value"] {
        env.admin
            .post(format!("{}/schemas", env.base))
            .json(&serde_json::json!({
                "subject": subject,
                "type": "json_schema",
                "schema": r#"{"type":"object"}"#
            }))
            .send()
            .await?
            .error_for_status()?;
    }
    let list: Vec<serde_json::Value> = k
        .get(format!("{}/schemas", env.base))
        .send()
        .await?
        .json()
        .await?;
    let mut subjects: Vec<&str> = list.iter().filter_map(|s| s["subject"].as_str()).collect();
    subjects.sort();
    assert_eq!(subjects, vec!["acme-key", "acme-value"]);
    let latest = |s: &str| {
        k.get(format!("{}/subjects/{}/versions/latest", env.base, s))
            .send()
    };
    assert_eq!(latest("acme-value").await?.status(), StatusCode::OK);
    assert_eq!(
        latest("acme-corp-value").await?.status(),
        StatusCode::NOT_FOUND
    );
    env.handle.shutdown().await?;
    Ok(())
}

// Bonfire #718 ---------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recreated_topic_inherits_nothing_from_the_deleted_one() -> Result<()> {
    let env = Env::boot(false, |c, root| {
        c.cold_storage_dir = Some(root.join("cold"))
    })
    .await?;
    env.topic("t").await?;
    env.topic("kept").await?;
    let values = |n: usize| (0..n).map(|i| format!("v{i}")).collect::<Vec<_>>();
    env.produce(&env.admin, "t", values(4), Some("p"))
        .await?
        .error_for_status()?;
    for topic in ["t", "kept"] {
        env.admin
            .post(format!("{}/groups/g/commit", env.base))
            .json(&CommitRequest {
                topic: topic.into(),
                partition: 0,
                offset: 3,
            })
            .send()
            .await?
            .error_for_status()?;
    }
    // A cold segment, as an offload would have left it.
    let cold = env.tmp.path().join("cold").join("t").join("0");
    std::fs::create_dir_all(&cold)?;
    std::fs::write(cold.join(format!("{:020}.log", 0)), b"old")?;

    env.admin
        .delete(format!("{}/topics/t", env.base))
        .send()
        .await?
        .error_for_status()?;
    assert!(!env.tmp.path().join("cold").join("t").exists());
    env.topic("t").await?;

    let offsets: GroupOffsetsResponse = env
        .admin
        .get(format!("{}/groups/g/offsets", env.base))
        .send()
        .await?
        .json()
        .await?;
    assert!(!offsets.offsets.contains_key("t"), "{:?}", offsets.offsets);
    assert!(offsets.offsets.contains_key("kept"));

    // The producer starting again from sequence 0 is written, not answered
    // with an offset of the deleted log.
    let r: ProduceResponse = env
        .produce(&env.admin, "t", values(1), Some("p"))
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(!r.results[0].duplicate);
    assert_eq!(r.results[0].offset, 0);

    let tiered: serde_json::Value = env
        .admin
        .get(format!("{}/admin/tiered/t/0", env.base))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(tiered["segments"], serde_json::json!([]));
    env.handle.shutdown().await?;
    Ok(())
}
