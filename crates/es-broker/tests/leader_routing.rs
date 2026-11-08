//! Leader routing (Bonfire #730): a produce sent to a Raft follower is
//! forwarded to the partition's leader, once, as the original caller.
//!
//! Each test runs three full brokers on loopback. Ports are reserved up front
//! — every broker must know its peers' Raft and API addresses before it
//! starts — and released just before the broker binds them.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use es_broker::auth::{AuthMode, KeyStore};
use es_broker::binary::{BinaryClient, PipelinedClient};
use es_broker::raft_partition::Leadership;
use es_broker::{spawn, BrokerHandle, Config};
use es_protocol::wire::WireProduceRecord;
use es_protocol::{
    AclActionDto, AclRuleDto, ConsumeResponse, CreateKeyRequest, CreateKeyResponse,
    CreateTopicRequest, ProduceRecord, ProduceRequest, ProduceResponse,
};
use reqwest::{Client, StatusCode};
use tempfile::TempDir;

const TLS_CERT: &str = "tests/fixtures/tls/cert.pem";
const TLS_KEY: &str = "tests/fixtures/tls/key.pem";
const TLS_CA: &str = "tests/fixtures/tls/ca.pem";

/// A loopback address nothing listens on once this returns.
///
/// Taken below the ephemeral range (32768+ on Linux, 49152+ on macOS), and
/// never twice in this process: a port the OS handed out with `:0` and that
/// was released could be handed out again — to another test's listener or an
/// outgoing connection — before the broker meant to have it binds it.
fn free_addr() -> SocketAddr {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let _ = NEXT.compare_exchange(
        0,
        20_000 + (std::process::id() % 1_000) as u16 * 10,
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
    loop {
        let port = NEXT.fetch_add(1, Ordering::Relaxed);
        assert!(port < 32_000, "ran out of test ports");
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        if std::net::TcpListener::bind(addr).is_ok() {
            return addr;
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum PeerApis {
    /// Each peer's real API address.
    Real,
    /// Addresses nothing listens on: every leader is unreachable.
    Dead,
}

struct Opts {
    auth: bool,
    tls: bool,
    apis: PeerApis,
}

struct Node {
    id: u32,
    handle: BrokerHandle,
    base: String,
}

struct Cluster {
    nodes: Vec<Node>,
    _dirs: Vec<TempDir>,
    /// Sends requests as the admin (or anonymously, without auth).
    admin: Client,
    /// Per-name key secrets, valid on every broker.
    keys: BTreeMap<&'static str, String>,
}

fn client(token: Option<&str>, tls: bool) -> Client {
    let mut b = Client::builder();
    if let Some(t) = token {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {t}").parse().unwrap(),
        );
        b = b.default_headers(h);
    }
    if tls {
        let pem = std::fs::read(TLS_CA).unwrap();
        b = b
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(&pem).unwrap());
    }
    b.build().unwrap()
}

fn key_request(name: &str, acls: &[(AclActionDto, &str)]) -> CreateKeyRequest {
    CreateKeyRequest {
        name: name.into(),
        acls: acls
            .iter()
            .map(|(a, p)| AclRuleDto {
                action: *a,
                topic_prefix: p.to_string(),
            })
            .collect(),
        produce_bytes_per_sec: None,
        consume_bytes_per_sec: None,
    }
}

impl Cluster {
    async fn boot(opts: Opts) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ids = [1u32, 2, 3];
        let raft: BTreeMap<u32, SocketAddr> = ids.iter().map(|i| (*i, free_addr())).collect();
        let http: BTreeMap<u32, SocketAddr> = ids.iter().map(|i| (*i, free_addr())).collect();
        let dirs: Vec<TempDir> = ids.iter().map(|_| TempDir::new().unwrap()).collect();

        // The same keys on every broker: the leader authenticates a forwarded
        // produce with its own key store.
        let mut keys = BTreeMap::new();
        if opts.auth {
            let (store, bootstrap) = KeyStore::open(dirs[0].path().to_path_buf(), true)?;
            keys.insert(
                "admin",
                bootstrap.expect("a fresh store has a bootstrap key"),
            );
            let w = key_request(
                "writer",
                &[
                    (AclActionDto::Write, "orders"),
                    (AclActionDto::Read, "orders"),
                ],
            );
            keys.insert("writer", store.create_key(&w)?.1);
            let r = key_request("reader", &[(AclActionDto::Read, "orders")]);
            keys.insert("reader", store.create_key(&r)?.1);
            drop(store);
            for d in &dirs[1..] {
                std::fs::copy(
                    dirs[0].path().join("api_keys.json"),
                    d.path().join("api_keys.json"),
                )?;
            }
        }

        let scheme = if opts.tls { "https" } else { "http" };
        let mut nodes = Vec::new();
        for (i, id) in ids.iter().enumerate() {
            let mut cfg = Config::new(dirs[i].path().to_path_buf(), http[id], 1 << 20);
            cfg.bind_binary = Some("127.0.0.1:0".parse()?);
            if opts.auth {
                cfg.auth_mode = AuthMode::Required;
            }
            if opts.tls {
                cfg.tls_cert_path = Some(PathBuf::from(TLS_CERT));
                cfg.tls_key_path = Some(PathBuf::from(TLS_KEY));
                cfg.raft_peer_api_ca = Some(PathBuf::from(TLS_CA));
            }
            cfg.raft_node_id = Some(*id);
            cfg.raft_bind = Some(raft[id]);
            for p in ids.iter().filter(|p| *p != id) {
                cfg.raft_peer_addrs.insert(*p, raft[p]);
                let api = match opts.apis {
                    PeerApis::Real => http[p],
                    PeerApis::Dead => free_addr(),
                };
                // `localhost`: the name the test certificate carries.
                cfg.raft_peer_apis
                    .insert(*p, format!("{scheme}://localhost:{}", api.port()));
            }
            let handle = spawn(cfg).await?;
            let base = format!("{scheme}://localhost:{}", handle.port());
            nodes.push(Node {
                id: *id,
                handle,
                base,
            });
        }
        let admin = client(keys.get("admin").map(String::as_str), opts.tls);
        Ok(Self {
            nodes,
            _dirs: dirs,
            admin,
            keys,
        })
    }

    /// Create `name` on every broker: topics are per broker, and each one's
    /// partitions join the Raft group of the same name.
    async fn topic(&self, name: &str, partitions: u32) -> Result<()> {
        for n in &self.nodes {
            self.admin
                .post(format!("{}/topics", n.base))
                .json(&CreateTopicRequest {
                    name: name.into(),
                    partitions,
                    config: None,
                })
                .send()
                .await?
                .error_for_status()?;
        }
        Ok(())
    }

    /// Poll until one broker leads `topic`/`partition` and every other one
    /// knows it. Returns the leader's index in `nodes`.
    async fn await_leader(&self, topic: &str, partition: usize) -> Result<usize> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let mut seen = Vec::new();
            for n in &self.nodes {
                let t = n.handle.broker.topic(topic).expect("topic exists");
                seen.push(t.partitions[partition].leadership().await);
            }
            let leaders: Vec<usize> = (0..seen.len())
                .filter(|i| seen[*i] == Leadership::Local)
                .collect();
            if let [l] = leaders[..] {
                let id = self.nodes[l].id;
                if seen
                    .iter()
                    .enumerate()
                    .all(|(i, s)| i == l || *s == Leadership::Remote(Some(id)))
                {
                    return Ok(l);
                }
            }
            if Instant::now() > deadline {
                bail!("no settled leader for {topic}/{partition}: {seen:?}");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn follower_of(&self, leader: usize) -> usize {
        (leader + 1) % self.nodes.len()
    }

    fn end_offset(&self, node: usize, topic: &str, partition: usize) -> u64 {
        let t = self.nodes[node].handle.broker.topic(topic).unwrap();
        t.partitions[partition].end_offset()
    }

    async fn shutdown(self) -> Result<()> {
        for n in self.nodes {
            n.handle.shutdown().await?;
        }
        Ok(())
    }
}

fn rec(value: &str, partition: u32, sequence: Option<i64>) -> ProduceRecord {
    ProduceRecord {
        key: None,
        value: value.into(),
        partition: Some(partition),
        sequence,
    }
}

async fn produce(
    c: &Client,
    base: &str,
    topic: &str,
    records: Vec<ProduceRecord>,
    producer_id: Option<&str>,
) -> Result<reqwest::Response> {
    Ok(c.post(format!("{base}/topics/{topic}/produce"))
        .json(&ProduceRequest {
            records,
            producer_id: producer_id.map(str::to_string),
        })
        .send()
        .await?)
}

async fn values_on(c: &Client, base: &str, topic: &str, partition: u32) -> Result<Vec<String>> {
    let r: ConsumeResponse = c
        .get(format!(
            "{base}/topics/{topic}/consume?partition={partition}&offset=0"
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(r.records.into_iter().map(|r| r.value).collect())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_produce_to_a_follower_lands_on_the_leader() -> Result<()> {
    let c = Cluster::boot(Opts {
        auth: false,
        tls: false,
        apis: PeerApis::Real,
    })
    .await?;
    c.topic("orders", 1).await?;
    let leader = c.await_leader("orders", 0).await?;
    let follower = c.follower_of(leader);
    let fbase = &c.nodes[follower].base;
    let lbase = &c.nodes[leader].base;

    let recs = vec![rec("a", 0, None), rec("b", 0, None), rec("c", 0, None)];
    let resp = produce(&c.admin, fbase, "orders", recs, None).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let got: ProduceResponse = resp.json().await?;
    let offsets: Vec<u64> = got.results.iter().map(|r| r.offset).collect();
    assert_eq!(offsets, vec![0, 1, 2], "the leader's offsets come back");

    // The leader wrote them, in order: its next record follows them.
    let resp = produce(&c.admin, lbase, "orders", vec![rec("d", 0, None)], None).await?;
    let got: ProduceResponse = resp.error_for_status()?.json().await?;
    assert_eq!(got.results[0].offset, 3);
    assert_eq!(
        values_on(&c.admin, lbase, "orders", 0).await?,
        vec!["a", "b", "c", "d"]
    );

    // Idempotence holds through the hop: the leader dedupes a retry.
    let idem = || vec![rec("e", 0, Some(0)), rec("f", 0, Some(1))];
    let first: ProduceResponse = produce(&c.admin, fbase, "orders", idem(), Some("p1"))
        .await?
        .error_for_status()?
        .json()
        .await?;
    let again: ProduceResponse = produce(&c.admin, fbase, "orders", idem(), Some("p1"))
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(first.results[0].offset, 4);
    assert!(!first.results[0].duplicate);
    for (a, b) in first.results.iter().zip(&again.results) {
        assert_eq!(a.offset, b.offset);
        assert!(b.duplicate, "a retry through the follower is a duplicate");
    }
    assert_eq!(c.end_offset(leader, "orders", 0), 6);

    c.shutdown().await
}

/// Partitions elect independently, so one request can address partitions led
/// by different brokers: each part goes to its own leader, and the answers
/// come back in the order the records were sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_spanning_leaders_is_split_between_them() -> Result<()> {
    let c = Cluster::boot(Opts {
        auth: false,
        tls: false,
        apis: PeerApis::Real,
    })
    .await?;
    c.topic("orders", 3).await?;
    let mut leaders = Vec::new();
    for p in 0..3 {
        leaders.push(c.await_leader("orders", p).await?);
    }
    // Whichever broker is asked, at least the partitions it does not lead
    // are forwarded.
    let base = &c.nodes[0].base;
    let recs = vec![
        rec("p2-a", 2, None),
        rec("p0-a", 0, None),
        rec("p1-a", 1, None),
        rec("p2-b", 2, None),
    ];
    let got: ProduceResponse = produce(&c.admin, base, "orders", recs, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    let placed: Vec<(u32, u64)> = got
        .results
        .iter()
        .map(|r| (r.partition, r.offset))
        .collect();
    assert_eq!(placed, vec![(2, 0), (0, 0), (1, 0), (2, 1)]);
    for (p, want) in [
        (0, vec!["p0-a"]),
        (1, vec!["p1-a"]),
        (2, vec!["p2-a", "p2-b"]),
    ] {
        let lbase = &c.nodes[leaders[p as usize]].base;
        assert_eq!(values_on(&c.admin, lbase, "orders", p).await?, want);
    }
    c.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_binary_produce_to_a_follower_is_forwarded() -> Result<()> {
    let c = Cluster::boot(Opts {
        auth: false,
        tls: false,
        apis: PeerApis::Real,
    })
    .await?;
    c.topic("orders", 1).await?;
    let leader = c.await_leader("orders", 0).await?;
    let follower = c.follower_of(leader);
    let faddr = c.nodes[follower].handle.binary_addr.unwrap();
    let laddr = c.nodes[leader].handle.binary_addr.unwrap();

    // Not UTF-8: binary records cross the HTTP hop byte for byte.
    let raw = |v: &[u8]| WireProduceRecord {
        key: Some(vec![0xff, 0x00]),
        value: v.to_vec(),
        partition: Some(0),
        sequence: None,
    };
    let mut bin = BinaryClient::connect(faddr, "").await?;
    let res = bin
        .produce("orders", None, vec![raw(&[0xfe, 0x01]), raw(&[0x80])])
        .await?;
    assert_eq!(res.iter().map(|r| r.offset).collect::<Vec<_>>(), vec![0, 1]);

    // A pipelined client keeps its order through the hop.
    let pipe = PipelinedClient::connect(faddr, "").await?;
    let sends = (0..8u8).map(|i| {
        let pipe = &pipe;
        async move { pipe.produce("orders", None, vec![raw(&[i])]).await }
    });
    let answers = futures::future::try_join_all(sends).await?;
    let offsets: Vec<u64> = answers.iter().map(|r| r[0].offset).collect();
    assert_eq!(offsets, (2..10).collect::<Vec<u64>>());
    pipe.shutdown().await;

    let mut lbin = BinaryClient::connect(laddr, "").await?;
    let back = lbin.consume("orders", 0, 0, 100, 1 << 20).await?;
    assert_eq!(back.records.len(), 10);
    assert_eq!(back.records[0].key.as_deref(), Some(&[0xff, 0x00][..]));
    assert_eq!(back.records[0].value, vec![0xfe, 0x01]);
    assert_eq!(back.records[1].value, vec![0x80]);
    for (i, r) in back.records[2..].iter().enumerate() {
        assert_eq!(
            r.value,
            vec![i as u8],
            "pipelined produces kept their order"
        );
    }
    c.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forwarded_produce_is_never_forwarded_again() -> Result<()> {
    let c = Cluster::boot(Opts {
        auth: false,
        tls: false,
        apis: PeerApis::Real,
    })
    .await?;
    c.topic("orders", 1).await?;
    let leader = c.await_leader("orders", 0).await?;
    let follower = c.follower_of(leader);

    // What a follower sends on, arriving at a broker that does not lead.
    let resp = c
        .admin
        .post(format!("{}/topics/orders/produce", c.nodes[follower].base))
        .header("x-es-forwarded", "1")
        .json(&ProduceRequest {
            records: vec![rec("x", 0, None)],
            producer_id: None,
        })
        .send()
        .await?;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(resp.headers().contains_key(reqwest::header::RETRY_AFTER));
    let body = resp.text().await?;
    assert!(body.contains("not leader"), "{body}");
    assert!(body.contains("not forwarded again"), "{body}");
    let leader_id = c.nodes[leader].id;
    assert!(body.contains(&format!("node {leader_id}")), "{body}");
    for n in 0..3 {
        assert_eq!(c.end_offset(n, "orders", 0), 0, "nothing was written");
    }

    // On the leader the header changes nothing: the produce is written.
    let resp = c
        .admin
        .post(format!("{}/topics/orders/produce", c.nodes[leader].base))
        .header("x-es-forwarded", "1")
        .json(&ProduceRequest {
            records: vec![rec("x", 0, None)],
            producer_id: None,
        })
        .send()
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    c.shutdown().await
}

/// With TLS on, forwarding goes over https and carries the caller's key; the
/// leader checks that key itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credentials_are_checked_again_on_the_leader() -> Result<()> {
    let c = Cluster::boot(Opts {
        auth: true,
        tls: true,
        apis: PeerApis::Real,
    })
    .await?;
    c.topic("orders", 1).await?;
    let leader = c.await_leader("orders", 0).await?;
    let follower = c.follower_of(leader);
    let fbase = &c.nodes[follower].base;
    let lbase = &c.nodes[leader].base;
    let writer = client(Some(&c.keys["writer"]), true);
    let reader = client(Some(&c.keys["reader"]), true);

    // A key with write access: forwarded, written by the leader.
    let resp = produce(&writer, fbase, "orders", vec![rec("ok", 0, None)], None).await?;
    assert_eq!(resp.status(), StatusCode::OK, "{}", resp.text().await?);
    assert_eq!(c.end_offset(leader, "orders", 0), 1);

    // A key without it is refused when sent to a follower.
    let resp = produce(&reader, fbase, "orders", vec![rec("no", 0, None)], None).await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // The forwarded marker grants nothing on the leader either.
    let resp = reader
        .post(format!("{lbase}/topics/orders/produce"))
        .header("x-es-forwarded", "1")
        .json(&ProduceRequest {
            records: vec![rec("no", 0, None)],
            producer_id: None,
        })
        .send()
        .await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // A key only the follower knows: the follower lets it through, the
    // leader does not. Nothing the follower vouches for counts.
    let local: CreateKeyResponse = c
        .admin
        .post(format!("{fbase}/admin/keys"))
        .json(&key_request("local", &[(AclActionDto::Write, "orders")]))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let local = client(Some(&local.secret), true);
    let resp = produce(&local, fbase, "orders", vec![rec("no", 0, None)], None).await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = resp.text().await?;
    assert!(body.contains("did not accept this key"), "{body}");

    assert_eq!(
        c.end_offset(leader, "orders", 0),
        1,
        "only the writer's record"
    );
    c.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_leader_is_a_retryable_error() -> Result<()> {
    let c = Cluster::boot(Opts {
        auth: false,
        tls: false,
        apis: PeerApis::Dead,
    })
    .await?;
    c.topic("orders", 1).await?;
    let leader = c.await_leader("orders", 0).await?;
    let follower = c.follower_of(leader);
    let leader_id = c.nodes[leader].id;

    let started = Instant::now();
    let resp = produce(
        &c.admin,
        &c.nodes[follower].base,
        "orders",
        vec![rec("x", 0, None)],
        None,
    )
    .await?;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(resp.headers().contains_key(reqwest::header::RETRY_AFTER));
    let body = resp.text().await?;
    assert!(body.contains("not leader"), "{body}");
    assert!(body.contains(&format!("node {leader_id}")), "{body}");
    assert!(started.elapsed() < Duration::from_secs(10), "fails fast");

    // The binary protocol answers the same, as an error frame.
    let faddr = c.nodes[follower].handle.binary_addr.unwrap();
    let mut bin = BinaryClient::connect(faddr, "").await?;
    let err = bin
        .produce(
            "orders",
            None,
            vec![WireProduceRecord {
                key: None,
                value: b"x".to_vec(),
                partition: Some(0),
                sequence: None,
            }],
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not leader"), "{err}");

    for n in 0..3 {
        assert_eq!(c.end_offset(n, "orders", 0), 0, "nothing was written");
    }
    c.shutdown().await
}
