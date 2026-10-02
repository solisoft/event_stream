//! Regression tests for the security audit: each test pins one hole shut.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use es_broker::auth::AuthMode;
use es_broker::binary::{BinaryClient, ClientOptions, ClientTls};
use es_broker::{spawn, Config};
use es_protocol::wire::WireProduceRecord;
use es_protocol::{
    AclActionDto, AclRuleDto, CommitRequest, CreateKeyRequest, CreateKeyResponse,
    CreateTopicRequest, JoinGroupRequest, ProduceRecord, ProduceRequest,
};
use reqwest::{Client, StatusCode};
use tempfile::TempDir;

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
    _tmp: TempDir,
    handle: es_broker::BrokerHandle,
    base: String,
    admin: Client,
}

impl Env {
    async fn boot(auth: bool, tweak: impl FnOnce(&mut Config)) -> Result<Self> {
        let tmp = TempDir::new()?;
        let mut cfg = Config::new(tmp.path().to_path_buf(), ephemeral(), 1 << 20);
        cfg.bind_binary = Some(ephemeral());
        if auth {
            cfg.auth_mode = AuthMode::Required;
        }
        tweak(&mut cfg);
        let handle = spawn(cfg).await?;
        let base = handle.base_url();
        let admin = if auth {
            let s = std::fs::read_to_string(tmp.path().join("bootstrap.key"))?;
            bearer(s.trim())
        } else {
            Client::new()
        };
        Ok(Self {
            _tmp: tmp,
            handle,
            base,
            admin,
        })
    }

    async fn topic(&self, name: &str, partitions: u32) -> Result<()> {
        self.admin
            .post(format!("{}/topics", self.base))
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

    async fn key(&self, acls: &[(AclActionDto, &str)], consume_bps: Option<u32>) -> Result<String> {
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
        Ok(resp.secret)
    }
}

fn record(value: &str) -> ProduceRecord {
    ProduceRecord {
        key: None,
        value: value.into(),
        partition: Some(0),
        sequence: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_cors_headers_unless_configured() -> Result<()> {
    let env = Env::boot(false, |_| {}).await?;
    let resp = Client::new()
        .request(reqwest::Method::OPTIONS, format!("{}/topics", env.base))
        .header("Origin", "https://evil.example")
        .header("Access-Control-Request-Method", "DELETE")
        .send()
        .await?;
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "a preflight from an arbitrary origin must not be approved"
    );
    env.handle.shutdown().await?;

    let env = Env::boot(false, |c| {
        c.cors_allowed_origins = vec!["https://ui.example".into()]
    })
    .await?;
    let resp = Client::new()
        .get(format!("{}/topics", env.base))
        .header("Origin", "https://ui.example")
        .send()
        .await?;
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap().to_string()),
        Some("https://ui.example".to_string())
    );
    env.handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_rebinding_host_is_refused_without_auth() -> Result<()> {
    let env = Env::boot(false, |_| {}).await?;
    let resp = Client::new()
        .get(format!("{}/topics", env.base))
        .header("Host", "attacker.example")
        .send()
        .await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    env.handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_public_bind_is_refused() -> Result<()> {
    let tmp = TempDir::new()?;
    let cfg = Config::new(tmp.path().to_path_buf(), "0.0.0.0:0".parse()?, 1 << 20);
    let err = spawn(cfg).await.err().expect("must refuse");
    assert!(err.to_string().contains("without authentication"), "{err}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_cert_without_key_is_refused() -> Result<()> {
    let tmp = TempDir::new()?;
    let mut cfg = Config::new(tmp.path().to_path_buf(), ephemeral(), 1 << 20);
    cfg.tls_cert_path = Some(PathBuf::from("tests/fixtures/tls/cert.pem"));
    assert!(spawn(cfg).await.is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_without_grants_cannot_join_or_take_over_a_group() -> Result<()> {
    let env = Env::boot(true, |_| {}).await?;
    env.topic("t", 4).await?;
    let a = bearer(&env.key(&[(AclActionDto::Read, "t")], None).await?);
    let b = bearer(&env.key(&[(AclActionDto::Read, "t")], None).await?);
    let nobody = bearer(&env.key(&[(AclActionDto::Read, "other")], None).await?);

    let join = |c: &Client, topics: Vec<String>, member: &str| {
        c.post(format!("{}/groups/g/join", env.base))
            .json(&JoinGroupRequest {
                member_id: Some(member.into()),
                topics,
            })
            .send()
    };
    assert!(join(&a, vec!["t".into()], "m1")
        .await?
        .status()
        .is_success());
    // An empty subscription no longer passes the read check vacuously.
    assert_eq!(
        join(&nobody, vec![], "x").await?.status(),
        StatusCode::BAD_REQUEST
    );
    // Another key cannot join, nor reuse a member id.
    assert_eq!(
        join(&b, vec!["t".into()], "m2").await?.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        join(&b, vec!["t".into()], "m1").await?.status(),
        StatusCode::FORBIDDEN
    );
    // Nor commit the group's offsets.
    let r = b
        .post(format!("{}/groups/g/commit", env.base))
        .json(&CommitRequest {
            topic: "t".into(),
            partition: 0,
            offset: 0,
        })
        .send()
        .await?;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    env.handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commits_must_name_a_real_partition() -> Result<()> {
    let env = Env::boot(false, |_| {}).await?;
    env.topic("t", 1).await?;
    let commit = |topic: &str, partition: u32| {
        env.admin
            .post(format!("{}/groups/g/commit", env.base))
            .json(&CommitRequest {
                topic: topic.into(),
                partition,
                offset: 1,
            })
            .send()
    };
    assert_eq!(commit("nope", 0).await?.status(), StatusCode::NOT_FOUND);
    assert_eq!(commit("t", 7).await?.status(), StatusCode::BAD_REQUEST);
    assert_eq!(commit("t", 0).await?.status(), StatusCode::NO_CONTENT);
    env.handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_producer_id_belongs_to_one_key() -> Result<()> {
    let env = Env::boot(true, |_| {}).await?;
    env.topic("t", 1).await?;
    let a = bearer(&env.key(&[(AclActionDto::Write, "t")], None).await?);
    let b = bearer(&env.key(&[(AclActionDto::Write, "t")], None).await?);
    let send = |c: &Client, seq: i64| {
        c.post(format!("{}/topics/t/produce", env.base))
            .json(&ProduceRequest {
                records: vec![ProduceRecord {
                    sequence: Some(seq),
                    ..record("v")
                }],
                producer_id: Some("shared".into()),
            })
            .send()
    };
    assert!(send(&a, 0).await?.status().is_success());
    // B advancing A's sequence used to make A's next record a "duplicate".
    assert_eq!(send(&b, 1).await?.status(), StatusCode::FORBIDDEN);
    assert!(send(&a, 1).await?.status().is_success());
    env.handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consume_quota_is_enforced() -> Result<()> {
    let env = Env::boot(true, |_| {}).await?;
    env.topic("q", 1).await?;
    let big = "x".repeat(4000);
    env.admin
        .post(format!("{}/topics/q/produce", env.base))
        .json(&ProduceRequest {
            records: (0..5).map(|_| record(&big)).collect(),
            producer_id: None,
        })
        .send()
        .await?
        .error_for_status()?;
    let reader = bearer(&env.key(&[(AclActionDto::Read, "q")], Some(1000)).await?);
    let url = format!("{}/topics/q/consume?partition=0&offset=0", env.base);
    assert!(reader.get(&url).send().await?.status().is_success());
    let second = reader.get(&url).send().await?;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(second.headers().get("retry-after").is_some());
    env.handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_records_are_refused_on_both_protocols() -> Result<()> {
    let env = Env::boot(false, |c| c.max_record_bytes = 1024).await?;
    env.topic("t", 1).await?;
    let r = env
        .admin
        .post(format!("{}/topics/t/produce", env.base))
        .json(&ProduceRequest {
            records: vec![record(&"y".repeat(2000))],
            producer_id: None,
        })
        .send()
        .await?;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    let mut bin = BinaryClient::connect(env.handle.binary_addr.unwrap(), "").await?;
    let err = bin
        .produce(
            "t",
            None,
            vec![WireProduceRecord {
                key: None,
                value: vec![0; 2000],
                partition: Some(0),
                sequence: None,
            }],
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("limit"), "{err}");
    env.handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_only_show_what_the_key_can_read() -> Result<()> {
    let env = Env::boot(true, |_| {}).await?;
    env.topic("mine", 1).await?;
    env.topic("theirs", 1).await?;
    let k = bearer(&env.key(&[(AclActionDto::Read, "mine")], None).await?);
    let body = k
        .get(format!("{}/metrics", env.base))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    assert!(body.contains(r#"topic="mine""#));
    assert!(!body.contains(r#"topic="theirs""#));
    env.handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acl_prefixes_respect_name_boundaries() -> Result<()> {
    let env = Env::boot(true, |_| {}).await?;
    env.topic("orders", 1).await?;
    env.topic("ordersecret", 1).await?;
    let k = bearer(&env.key(&[(AclActionDto::Write, "orders")], None).await?);
    let send = |t: &str| {
        k.post(format!("{}/topics/{}/produce", env.base, t))
            .json(&ProduceRequest {
                records: vec![record("v")],
                producer_id: None,
            })
            .send()
    };
    assert!(send("orders").await?.status().is_success());
    assert_eq!(send("ordersecret").await?.status(), StatusCode::FORBIDDEN);
    // An empty prefix (formerly "everything, and admin too") is refused.
    let r = env
        .admin
        .post(format!("{}/admin/keys", env.base))
        .json(&CreateKeyRequest {
            name: "x".into(),
            acls: vec![AclRuleDto {
                action: AclActionDto::Admin,
                topic_prefix: "".into(),
            }],
            produce_bytes_per_sec: None,
            consume_bytes_per_sec: None,
        })
        .send()
        .await?;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    env.handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_a_key_closes_its_open_binary_connections() -> Result<()> {
    let env = Env::boot(true, |_| {}).await?;
    env.topic("t", 1).await?;
    let secret = env.key(&[(AclActionDto::Write, "t")], None).await?;
    let mut bin = BinaryClient::connect(env.handle.binary_addr.unwrap(), &secret).await?;
    let rec = || {
        vec![WireProduceRecord {
            key: None,
            value: b"v".to_vec(),
            partition: Some(0),
            sequence: None,
        }]
    };
    bin.produce("t", None, rec()).await?;

    let keys: es_protocol::ListKeysResponse = env
        .admin
        .get(format!("{}/admin/keys", env.base))
        .send()
        .await?
        .json()
        .await?;
    let id = keys
        .keys
        .iter()
        .find(|k| k.name == "k")
        .unwrap()
        .key_id
        .clone();
    env.admin
        .delete(format!("{}/admin/keys/{}", env.base, id))
        .send()
        .await?
        .error_for_status()?;

    assert!(
        bin.produce("t", None, rec()).await.is_err(),
        "a revoked key must stop working on connections it already holds"
    );
    env.handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forbidden_gzip_frames_are_refused_before_they_are_inflated() -> Result<()> {
    let env = Env::boot(true, |_| {}).await?;
    env.topic("allowed", 1).await?;
    env.topic("secret", 1).await?;
    let secret = env.key(&[(AclActionDto::Read, "allowed")], None).await?;
    let mut bin = BinaryClient::connect_with(
        env.handle.binary_addr.unwrap(),
        &secret,
        ClientOptions {
            gzip: true,
            ..Default::default()
        },
    )
    .await?;
    // 32 MiB of zeros compresses to a few tens of KiB.
    let started = std::time::Instant::now();
    let err = bin
        .produce(
            "secret",
            None,
            vec![WireProduceRecord {
                key: None,
                value: vec![0; 32 << 20],
                partition: Some(0),
                sequence: None,
            }],
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("forbidden"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(10));
    env.handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_listener_uses_tls_when_configured() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = Env::boot(false, |c| {
        c.tls_cert_path = Some(PathBuf::from("tests/fixtures/tls/cert.pem"));
        c.tls_key_path = Some(PathBuf::from("tests/fixtures/tls/key.pem"));
    })
    .await?;
    let addr = env.handle.binary_addr.unwrap();

    // Plaintext is no longer accepted on a TLS-configured broker.
    assert!(BinaryClient::connect(addr, "").await.is_err());

    use rustls_pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pki_types::CertificateDer::pem_file_iter("tests/fixtures/tls/ca.pem")? {
        roots.add(c?)?;
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tls = ClientTls {
        config: Arc::new(cfg),
        server_name: "localhost".into(),
    };
    let mut bin = BinaryClient::connect_with(
        addr,
        "",
        ClientOptions {
            gzip: false,
            tls: Some(tls),
        },
    )
    .await?;
    bin.ping().await?;
    env.handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn internal_errors_do_not_leak_paths() -> Result<()> {
    let env = Env::boot(false, |_| {}).await?;
    let r = env
        .admin
        .get(format!("{}/schemas/999", env.base))
        .send()
        .await?;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let body = r.text().await?;
    assert!(
        !body.contains('/'),
        "error bodies must not carry paths: {body}"
    );
    env.handle.shutdown().await?;
    Ok(())
}
