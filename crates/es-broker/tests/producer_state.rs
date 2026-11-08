//! Idempotent-producer state travels through Raft (Bonfire #770).
//!
//! Before, a producer's sequence windows lived only on the broker that
//! accepted its writes. After a leadership change the new leader knew none of
//! them, and a retry of a write the old leader had committed was appended a
//! second time. Every wait here polls a condition; none sleeps a fixed time
//! and hopes.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use es_broker::auth::{AuthMode, KeyStore};
use es_broker::partition::AppendRecord;
use es_broker::producers::DedupeOutcome;
use es_broker::raft::{SharedSecret, Timing};
use es_broker::raft_partition::{
    Leadership, ProducerRetry, ProducerWrite, RaftPartition, RaftPartitionConfig,
    RaftTransportConfig,
};
use es_broker::{spawn, BrokerHandle, Config};
use es_protocol::{
    AclActionDto, AclRuleDto, CreateKeyRequest, CreateTopicRequest, ProduceRecord, ProduceRequest,
    ProduceResponse,
};
use reqwest::{Client, StatusCode};
use tempfile::TempDir;

/// A loopback address nothing listens on once this returns. Below the
/// ephemeral range and never twice in this process (see leader_routing.rs).
fn free_addr() -> SocketAddr {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let _ = NEXT.compare_exchange(
        0,
        // Another thousand ports than leader_routing.rs uses, so the two test
        // binaries do not reach for the same ones when run side by side.
        21_000 + (std::process::id() % 1_000) as u16 * 10,
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

/// Poll `cond` until it holds, for at most `secs`.
async fn eventually<F, Fut>(what: &str, secs: u64, mut cond: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !cond().await {
        if Instant::now() > deadline {
            bail!("timed out waiting for {what}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

// ---------- full brokers ----------

struct Node {
    id: u32,
    handle: BrokerHandle,
    base: String,
}

/// Three brokers on loopback; a stopped one leaves `None` behind.
struct Cluster {
    nodes: Vec<Option<Node>>,
    _dirs: Vec<TempDir>,
    admin: Client,
    keys: BTreeMap<&'static str, String>,
}

fn client(token: Option<&str>) -> Client {
    let mut b = Client::builder();
    if let Some(t) = token {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {t}").parse().unwrap(),
        );
        b = b.default_headers(h);
    }
    b.build().unwrap()
}

fn writer_key(name: &str) -> CreateKeyRequest {
    CreateKeyRequest {
        name: name.into(),
        acls: [AclActionDto::Write, AclActionDto::Read]
            .into_iter()
            .map(|action| AclRuleDto {
                action,
                topic_prefix: "orders".into(),
            })
            .collect(),
        produce_bytes_per_sec: None,
        consume_bytes_per_sec: None,
    }
}

impl Cluster {
    /// With `auth`, two keys with the same grants, `first` and `second`:
    /// each may claim the producer ids under `orders`.
    async fn boot(auth: bool) -> Result<Self> {
        let ids = [1u32, 2, 3];
        let raft: BTreeMap<u32, SocketAddr> = ids.iter().map(|i| (*i, free_addr())).collect();
        let http: BTreeMap<u32, SocketAddr> = ids.iter().map(|i| (*i, free_addr())).collect();
        let dirs: Vec<TempDir> = ids.iter().map(|_| TempDir::new().unwrap()).collect();

        let mut keys = BTreeMap::new();
        if auth {
            let (store, bootstrap) = KeyStore::open(dirs[0].path().to_path_buf(), true)?;
            keys.insert(
                "admin",
                bootstrap.expect("a fresh store has a bootstrap key"),
            );
            keys.insert("first", store.create_key(&writer_key("first"))?.1);
            keys.insert("second", store.create_key(&writer_key("second"))?.1);
            drop(store);
            for d in &dirs[1..] {
                std::fs::copy(
                    dirs[0].path().join("api_keys.json"),
                    d.path().join("api_keys.json"),
                )?;
            }
        }

        let mut nodes = Vec::new();
        for (i, id) in ids.iter().enumerate() {
            let mut cfg = Config::new(dirs[i].path().to_path_buf(), http[id], 1 << 20);
            if auth {
                cfg.auth_mode = AuthMode::Required;
            }
            cfg.raft_node_id = Some(*id);
            cfg.raft_bind = Some(raft[id]);
            for p in ids.iter().filter(|p| *p != id) {
                cfg.raft_peer_addrs.insert(*p, raft[p]);
                cfg.raft_peer_apis
                    .insert(*p, format!("http://127.0.0.1:{}", http[p].port()));
            }
            let handle = spawn(cfg).await?;
            let base = format!("http://127.0.0.1:{}", handle.port());
            nodes.push(Some(Node {
                id: *id,
                handle,
                base,
            }));
        }
        let admin = client(keys.get("admin").map(String::as_str));
        Ok(Self {
            nodes,
            _dirs: dirs,
            admin,
            keys,
        })
    }

    fn node(&self, i: usize) -> &Node {
        self.nodes[i].as_ref().expect("a running broker")
    }

    fn live(&self) -> impl Iterator<Item = (usize, &Node)> {
        self.nodes
            .iter()
            .enumerate()
            .filter_map(|(i, n)| n.as_ref().map(|n| (i, n)))
    }

    async fn topic(&self, name: &str) -> Result<()> {
        for (_, n) in self.live() {
            self.admin
                .post(format!("{}/topics", n.base))
                .json(&CreateTopicRequest {
                    name: name.into(),
                    partitions: 1,
                    config: None,
                })
                .send()
                .await?
                .error_for_status()?;
        }
        Ok(())
    }

    /// Poll until one running broker leads `topic`/0 and every other running
    /// one knows it. Returns its index.
    async fn await_leader(&self, topic: &str) -> Result<usize> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let mut seen = Vec::new();
            for (i, n) in self.live() {
                let t = n.handle.broker.topic(topic).expect("topic exists");
                seen.push((i, n.id, t.partitions[0].leadership().await));
            }
            let leaders: Vec<_> = seen
                .iter()
                .filter(|(_, _, l)| *l == Leadership::Local)
                .collect();
            if let [(l, id, _)] = leaders[..] {
                if seen
                    .iter()
                    .all(|(i, _, s)| i == l || *s == Leadership::Remote(Some(*id)))
                {
                    return Ok(*l);
                }
            }
            if Instant::now() > deadline {
                bail!("no settled leader for {topic}/0");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The raft partition `topic`/0 on broker `i`.
    fn partition(&self, i: usize, topic: &str) -> Arc<RaftPartition> {
        let t = self.node(i).handle.broker.topic(topic).unwrap();
        t.partitions[0].as_raft().expect("a raft partition").clone()
    }

    /// Wait until the leader replicates producer state: it has heard from
    /// every follower that they understand it. Before that, a write would
    /// keep the leader's own window, as with a 0.3.0 follower.
    async fn await_replicated(&self, leader: usize, topic: &str) -> Result<()> {
        let rp = self.partition(leader, topic);
        eventually("the followers to advertise producer state", 10, || {
            let rp = rp.clone();
            async move {
                rp.producer_state("probe", Duration::from_secs(1))
                    .await
                    .is_ok_and(|v| v.replicated)
            }
        })
        .await
    }

    async fn await_end_offset(&self, topic: &str, want: u64) -> Result<()> {
        for (i, _) in self.live() {
            let rp = self.partition(i, topic);
            eventually("every replica to apply the writes", 10, || {
                let rp = rp.clone();
                async move { rp.partition().end_offset() >= want }
            })
            .await?;
        }
        Ok(())
    }

    async fn stop(&mut self, i: usize) -> Result<()> {
        let n = self.nodes[i].take().expect("a running broker");
        n.handle.shutdown().await
    }

    async fn shutdown(mut self) -> Result<()> {
        for i in 0..self.nodes.len() {
            if self.nodes[i].is_some() {
                self.stop(i).await?;
            }
        }
        Ok(())
    }
}

fn rec(value: &str, sequence: i64) -> ProduceRecord {
    ProduceRecord {
        key: None,
        value: value.into(),
        partition: Some(0),
        sequence: Some(sequence),
    }
}

async fn produce(
    c: &Client,
    base: &str,
    records: Vec<ProduceRecord>,
    producer_id: &str,
) -> Result<reqwest::Response> {
    Ok(c.post(format!("{base}/topics/orders/produce"))
        .json(&ProduceRequest {
            records,
            producer_id: Some(producer_id.to_string()),
        })
        .send()
        .await?)
}

async fn produced(
    c: &Client,
    base: &str,
    records: Vec<ProduceRecord>,
    producer_id: &str,
) -> Result<Vec<(u64, bool)>> {
    let resp = produce(c, base, records, producer_id).await?;
    let status = resp.status();
    if status != StatusCode::OK {
        bail!("{status}: {}", resp.text().await?);
    }
    let r: ProduceResponse = resp.json().await?;
    Ok(r.results.iter().map(|r| (r.offset, r.duplicate)).collect())
}

/// The regression: a retry of a write the old leader committed reaches the
/// new leader, directly and through a follower, and is answered as a
/// duplicate rather than written again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_after_the_leader_changes_is_a_duplicate() -> Result<()> {
    let mut c = Cluster::boot(false).await?;
    c.topic("orders").await?;
    let old = c.await_leader("orders").await?;
    c.await_replicated(old, "orders").await?;

    let batch = || vec![rec("a", 0), rec("b", 1)];
    let first = produced(&c.admin, &c.node(old).base, batch(), "orders.svc").await?;
    assert_eq!(first, vec![(0, false), (1, false)]);
    c.await_end_offset("orders", 2).await?;

    c.stop(old).await?;
    let new = c.await_leader("orders").await?;
    let follower = c.live().map(|(i, _)| i).find(|i| *i != new).unwrap();

    let direct = produced(&c.admin, &c.node(new).base, batch(), "orders.svc").await?;
    assert_eq!(
        direct,
        vec![(0, true), (1, true)],
        "retried on the new leader"
    );
    let forwarded = produced(&c.admin, &c.node(follower).base, batch(), "orders.svc").await?;
    assert_eq!(
        forwarded,
        vec![(0, true), (1, true)],
        "retried through a follower"
    );

    // The producer carries on where it left off, and a gap is still one.
    let next = produced(
        &c.admin,
        &c.node(follower).base,
        vec![rec("c", 2)],
        "orders.svc",
    )
    .await?;
    assert_eq!(next, vec![(2, false)]);
    let gap = produce(&c.admin, &c.node(new).base, vec![rec("x", 9)], "orders.svc").await?;
    assert_eq!(gap.status(), StatusCode::BAD_REQUEST);
    assert!(gap.text().await?.contains("expected 3"));

    c.await_end_offset("orders", 3).await?;
    for (i, _) in c.live() {
        assert_eq!(c.partition(i, "orders").partition().end_offset(), 3);
    }
    c.shutdown().await
}

/// Retries of one sequence sent all at once, to the leader and through both
/// followers, are written once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_retries_are_written_once() -> Result<()> {
    let c = Cluster::boot(false).await?;
    c.topic("orders").await?;
    let leader = c.await_leader("orders").await?;
    c.await_replicated(leader, "orders").await?;

    let sends = (0..9).map(|i| {
        let base = c.node(i % 3).base.clone();
        let admin = c.admin.clone();
        async move { produced(&admin, &base, vec![rec("once", 0)], "orders.svc").await }
    });
    let answers = futures::future::try_join_all(sends).await?;
    let written = answers.iter().filter(|a| !a[0].1).count();
    assert_eq!(written, 1, "{answers:?}");
    assert!(answers.iter().all(|a| a[0].0 == 0), "{answers:?}");
    assert_eq!(c.partition(leader, "orders").partition().end_offset(), 1);
    c.shutdown().await
}

/// The key that first used a producer id keeps it on the next leader, which
/// never saw the claim: another key is refused there, the owner is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_producer_id_keeps_its_owner_across_a_leader_change() -> Result<()> {
    let mut c = Cluster::boot(true).await?;
    c.topic("orders").await?;
    let old = c.await_leader("orders").await?;
    c.await_replicated(old, "orders").await?;
    let first = client(Some(&c.keys["first"]));
    let second = client(Some(&c.keys["second"]));

    let got = produced(&first, &c.node(old).base, vec![rec("a", 0)], "orders.svc").await?;
    assert_eq!(got, vec![(0, false)]);
    c.await_end_offset("orders", 1).await?;

    c.stop(old).await?;
    let new = c.await_leader("orders").await?;
    let follower = c.live().map(|(i, _)| i).find(|i| *i != new).unwrap();

    for base in [&c.node(new).base, &c.node(follower).base] {
        let resp = produce(&second, base, vec![rec("b", 1)], "orders.svc").await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(resp.text().await?.contains("not available to this key"));
    }
    let retry = produced(&first, &c.node(new).base, vec![rec("a", 0)], "orders.svc").await?;
    assert_eq!(retry, vec![(0, true)]);
    let next = produced(
        &first,
        &c.node(follower).base,
        vec![rec("b", 1)],
        "orders.svc",
    )
    .await?;
    assert_eq!(next, vec![(1, false)]);
    c.shutdown().await
}

// ---------- raft partitions on their own ----------

fn timing() -> Timing {
    Timing {
        election_min: Duration::from_millis(200),
        election_max: Duration::from_millis(400),
        heartbeat: Duration::from_millis(30),
    }
}

fn config(id: u32, peers: Vec<u32>, dir: &TempDir, snapshot_after: u32) -> RaftPartitionConfig {
    RaftPartitionConfig {
        node_id: id,
        peers,
        raft_store_path: dir.path().join("raft").join("0"),
        timing: timing(),
        snapshot_after_applies: snapshot_after,
        joining: false,
    }
}

/// Replica `id` of a three-node group over TCP.
async fn open_node(
    id: u32,
    addrs: &[SocketAddr],
    dir: &TempDir,
    snapshot_after: u32,
) -> Result<Arc<RaftPartition>> {
    let peers: Vec<u32> = (1..=addrs.len() as u32).filter(|p| *p != id).collect();
    let rp = RaftPartition::open(
        dir.path().join("p0"),
        0,
        1 << 20,
        1,
        config(id, peers.clone(), dir, snapshot_after),
    )?;
    rp.connect_transport(RaftTransportConfig {
        bind: addrs[id as usize - 1],
        peer_addrs: peers.iter().map(|p| (*p, addrs[*p as usize - 1])).collect(),
        shared_secret: Some(SharedSecret::new("test-cluster-secret-of-32-bytes!")?),
    })
    .await?;
    Ok(rp)
}

async fn leader_of(nodes: &[&Arc<RaftPartition>]) -> Result<Arc<RaftPartition>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        for n in nodes {
            if n.leadership().await == Leadership::Local {
                return Ok((*n).clone());
            }
        }
        if Instant::now() > deadline {
            bail!("no leader elected");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn await_replicated(rp: &Arc<RaftPartition>) -> Result<()> {
    eventually("producer state to be replicated", 10, || async {
        rp.producer_state("probe", Duration::from_secs(1))
            .await
            .is_ok_and(|v| v.replicated)
    })
    .await
}

fn write_of(producer_id: &str, seq: i64, checked: Option<i64>) -> ProducerWrite {
    ProducerWrite {
        producer_id: producer_id.into(),
        owner: "k".into(),
        first_sequence: seq,
        checked_last_seen: checked,
    }
}

fn record(seq: i64) -> Vec<AppendRecord> {
    vec![AppendRecord::new(None, format!("v{seq}").into_bytes())]
}

/// Check `seq` as the produce path does, and write it if it is new.
async fn write(rp: &RaftPartition, producer_id: &str, seq: i64) -> Result<u64> {
    let view = rp
        .producer_state(producer_id, Duration::from_secs(5))
        .await?;
    let checked = view.window.as_ref().map(|w| w.last_seen());
    if let Some(w) = &view.window {
        assert_eq!(w.check(seq), DedupeOutcome::Accept);
    }
    let offs = rp
        .append_batch_as(record(seq), write_of(producer_id, seq, checked))
        .await?;
    Ok(offs[0])
}

/// A retry that arrives while the first copy of its write is in the
/// leader's log but not committed is held back, not checked against a window
/// that does not have it yet, and the write lands once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_in_flight_holds_back_its_retry() -> Result<()> {
    let addrs: Vec<SocketAddr> = (0..3).map(|_| free_addr()).collect();
    let dirs: Vec<TempDir> = (0..3).map(|_| TempDir::new().unwrap()).collect();
    let mut nodes = Vec::new();
    for id in 1..=3 {
        nodes.push(Some(
            open_node(id, &addrs, &dirs[id as usize - 1], 0).await?,
        ));
    }
    let all: Vec<&Arc<RaftPartition>> = nodes.iter().flatten().collect();
    let leader = leader_of(&all).await?;
    await_replicated(&leader).await?;
    assert_eq!(write(&leader, "p", 0).await?, 0);

    // Without its followers the leader can append but not commit.
    for slot in nodes.iter_mut() {
        if !Arc::ptr_eq(slot.as_ref().unwrap(), &leader) {
            slot.take().unwrap().shutdown().await;
        }
    }
    let first = tokio::spawn({
        let leader = leader.clone();
        async move {
            leader
                .append_batch_as(record(1), write_of("p", 1, Some(0)))
                .await
        }
    });
    // Its retry is not decided while the first copy is in flight...
    eventually("the first copy to be in the log", 5, || async {
        matches!(
            leader.producer_state("p", Duration::from_millis(50)).await,
            Err(e) if e.is::<ProducerRetry>()
        )
    })
    .await?;
    // ...and cannot be proposed on the strength of the window from before.
    let retry = leader
        .append_batch_as(record(1), write_of("p", 1, Some(0)))
        .await
        .unwrap_err();
    assert!(retry.is::<ProducerRetry>(), "{retry:#}");

    // One follower back: the first copy commits, and the retry is now a
    // duplicate of it.
    let back = (1..=3u32)
        .find(|id| nodes[*id as usize - 1].is_none())
        .unwrap();
    nodes[back as usize - 1] = Some(open_node(back, &addrs, &dirs[back as usize - 1], 0).await?);
    let offs = first.await??;
    assert_eq!(offs, vec![1]);
    let view = leader.producer_state("p", Duration::from_secs(5)).await?;
    let w = view.window.unwrap();
    assert_eq!(w.check(1), DedupeOutcome::Duplicate { prev_offset: 1 });
    assert_eq!(leader.partition().end_offset(), 2, "written once");

    for n in nodes.into_iter().flatten() {
        n.shutdown().await;
    }
    Ok(())
}

/// A replica that falls behind the leader's compacted log gets the producer
/// windows with the snapshot, and finds them again after a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lagging_follower_gets_the_windows_with_the_snapshot() -> Result<()> {
    let addrs: Vec<SocketAddr> = (0..3).map(|_| free_addr()).collect();
    let dirs: Vec<TempDir> = (0..3).map(|_| TempDir::new().unwrap()).collect();
    let mut nodes = Vec::new();
    for id in 1..=3 {
        nodes.push(open_node(id, &addrs, &dirs[id as usize - 1], 20).await?);
    }
    let leader = leader_of(&nodes.iter().collect::<Vec<_>>()).await?;
    await_replicated(&leader).await?;
    write(&leader, "p", 0).await?;

    // A follower stops; the leader goes on, and compacts what it missed.
    let lag = nodes.iter().position(|n| !Arc::ptr_eq(n, &leader)).unwrap();
    let lag_id = lag as u32 + 1;
    nodes.remove(lag).shutdown().await;
    for seq in 1..60 {
        write(&leader, "p", seq).await?;
    }
    eventually("the leader to compact its log", 10, || async {
        leader.raft_state().lock().await.log.base_index > 10
    })
    .await?;

    let late = open_node(lag_id, &addrs, &dirs[lag], 20).await?;
    eventually("the late replica to catch up", 20, || async {
        late.partition().end_offset() >= 60
    })
    .await?;
    let windows = |rp: &RaftPartition| {
        rp.producer_windows()
            .into_iter()
            .collect::<BTreeMap<_, _>>()
    };
    eventually("the late replica to apply the last write", 10, || async {
        windows(&late).get("p").is_some_and(|w| w.last_seen() == 59)
    })
    .await?;
    // Sequence 5 was only ever in entries the late replica never received:
    // it can only know it from the snapshot.
    assert_eq!(
        windows(&late)["p"].check(5),
        DedupeOutcome::Duplicate { prev_offset: 5 }
    );

    // Restarted, it has them before it has applied anything.
    late.shutdown().await;
    let late = open_node(lag_id, &addrs, &dirs[lag], 20).await?;
    assert_eq!(
        windows(&late).get("p").map(|w| w.check(5)),
        Some(DedupeOutcome::Duplicate { prev_offset: 5 }),
        "restored from the snapshot"
    );
    eventually("the restarted replica to replay its log", 10, || async {
        windows(&late).get("p").is_some_and(|w| w.last_seen() == 59)
    })
    .await?;

    late.shutdown().await;
    for n in nodes {
        n.shutdown().await;
    }
    Ok(())
}

/// A single-node partition rebuilds its windows from its snapshot plus the
/// log after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn windows_are_rebuilt_from_snapshot_and_log_after_a_restart() -> Result<()> {
    let dir = TempDir::new()?;
    let open = || {
        RaftPartition::open(
            dir.path().join("p0"),
            0,
            1 << 20,
            1,
            config(1, Vec::new(), &dir, 5),
        )
    };
    let rp = open()?;
    leader_of(&[&rp]).await?;
    for seq in 0..12 {
        assert_eq!(write(&rp, "p", seq).await?, seq as u64);
    }
    let base = rp.raft_state().lock().await.log.base_index;
    assert!(base > 0, "snapshotted");
    assert!(
        base < rp.raft_state().lock().await.log.last_index(),
        "with entries after the snapshot"
    );
    rp.shutdown().await;

    let rp = open()?;
    leader_of(&[&rp]).await?;
    let view = rp.producer_state("p", Duration::from_secs(5)).await?;
    assert!(view.replicated);
    assert_eq!(view.owner.as_deref(), Some("k"));
    let w = view.window.unwrap();
    assert_eq!(w.last_seen(), 11, "the log after the snapshot is replayed");
    assert_eq!(w.check(3), DedupeOutcome::Duplicate { prev_offset: 3 });
    assert_eq!(write(&rp, "p", 12).await?, 12);
    rp.shutdown().await;
    Ok(())
}
