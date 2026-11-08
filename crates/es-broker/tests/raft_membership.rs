//! Bonfire #731: adding and removing brokers at runtime, through
//! `/admin/raft/members`, on real brokers talking over real Raft ports.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Result;
use es_broker::raft::transport::dialer_handshake;
use es_broker::{spawn, BrokerHandle, Config};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::net::TcpStream;

struct Node {
    id: u32,
    raft: SocketAddr,
    base: String,
    handle: BrokerHandle,
    _dir: TempDir,
}

/// A loopback port nothing listens on yet. Peers must know each other's
/// Raft address before any of them binds.
fn free_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

async fn start(id: u32, raft: SocketAddr, peers: &[(u32, SocketAddr)], join: bool) -> Result<Node> {
    let dir = TempDir::new()?;
    let mut cfg = Config::new(
        dir.path().to_path_buf(),
        "127.0.0.1:0".parse().unwrap(),
        1 << 20,
    );
    cfg.raft_node_id = Some(id);
    cfg.raft_bind = Some(raft);
    cfg.raft_peer_addrs = peers.iter().copied().collect::<BTreeMap<_, _>>();
    cfg.raft_join = join;
    let handle = spawn(cfg).await?;
    Ok(Node {
        id,
        raft,
        base: handle.base_url(),
        handle,
        _dir: dir,
    })
}

/// Brokers `1..=n`, each listing the others.
async fn cluster(n: u32) -> Result<Vec<Node>> {
    let addrs: Vec<(u32, SocketAddr)> = (1..=n).map(|id| (id, free_addr())).collect();
    let mut nodes = Vec::new();
    for (id, addr) in &addrs {
        let peers: Vec<_> = addrs.iter().copied().filter(|(p, _)| p != id).collect();
        nodes.push(start(*id, *addr, &peers, false).await?);
    }
    Ok(nodes)
}

async fn create_topic(c: &Client, node: &Node) -> Result<()> {
    let r = c
        .post(format!("{}/topics", node.base))
        .json(&json!({"name": "t", "partitions": 1}))
        .send()
        .await?;
    anyhow::ensure!(r.status().is_success(), "create topic: {}", r.status());
    Ok(())
}

async fn get(c: &Client, url: String) -> Result<Value> {
    Ok(c.get(url).send().await?.error_for_status()?.json().await?)
}

/// The id of the broker that leads partition 0 of `t`, as that broker says.
async fn leader(c: &Client, nodes: &[&Node], within: Duration) -> Result<u32> {
    let give_up = Instant::now() + within;
    while Instant::now() < give_up {
        for n in nodes {
            let status = get(c, format!("{}/raft", n.base)).await?;
            let role = &status["partitions"][0]["role"];
            if role == "leader" {
                return Ok(n.id);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("no leader within {within:?}")
}

fn node<'a>(nodes: &[&'a Node], id: u32) -> &'a Node {
    nodes
        .iter()
        .find(|n| n.id == id)
        .copied()
        .expect("a known node")
}

async fn produce(c: &Client, node: &Node, values: &[&str]) -> Result<()> {
    let records: Vec<Value> = values.iter().map(|v| json!({"value": v})).collect();
    let r = c
        .post(format!("{}/topics/t/produce", node.base))
        .json(&json!({"records": records}))
        .send()
        .await?;
    anyhow::ensure!(r.status().is_success(), "produce: {}", r.text().await?);
    Ok(())
}

fn end_offset(node: &Node) -> u64 {
    node.handle.broker.topic("t").unwrap().partitions[0].end_offset()
}

async fn wait_for(mut f: impl FnMut() -> bool, within: Duration) -> bool {
    let give_up = Instant::now() + within;
    while Instant::now() < give_up {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

fn statuses(report: &Value) -> Vec<String> {
    report["partitions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["status"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_is_added_and_replicated_to() -> Result<()> {
    let c = Client::new();
    let nodes = cluster(3).await?;
    for n in &nodes {
        create_topic(&c, n).await?;
    }
    let all: Vec<&Node> = nodes.iter().collect();
    let l = node(&all, leader(&c, &all, Duration::from_secs(10)).await?);
    produce(&c, l, &["a", "b", "c"]).await?;

    // Broker 4 joins: it knows the members, and waits to be added.
    let four = start(
        4,
        free_addr(),
        &[(1, nodes[0].raft), (2, nodes[1].raft), (3, nodes[2].raft)],
        true,
    )
    .await?;
    create_topic(&c, &four).await?;

    let report: Value = c
        .post(format!("{}/admin/raft/members", l.base))
        .json(&json!({"id": 4, "addr": four.raft.to_string()}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(report["complete"], true, "{report}");
    assert_eq!(statuses(&report), vec!["committed"]);

    produce(&c, l, &["d", "e"]).await?;
    assert!(
        wait_for(|| end_offset(&four) == 5, Duration::from_secs(10)).await,
        "the added broker holds every record, old and new: end offset {}",
        end_offset(&four)
    );

    let members = get(&c, format!("{}/admin/raft/members", four.base)).await?;
    assert_eq!(
        members["partitions"][0]["voters"],
        json!([1, 2, 3, 4]),
        "{members}"
    );
    let members = get(&c, format!("{}/admin/raft/members", l.base)).await?;
    assert!(
        members["peers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == 4),
        "the leader's transport follows: {members}"
    );

    // Asking again is not a second change.
    let again: Value = c
        .post(format!("{}/admin/raft/members", l.base))
        .json(&json!({"id": 4, "addr": four.raft.to_string()}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(statuses(&again), vec!["already"]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_follower_can_no_longer_connect() -> Result<()> {
    let c = Client::new();
    let nodes = cluster(3).await?;
    for n in &nodes {
        create_topic(&c, n).await?;
    }
    let all: Vec<&Node> = nodes.iter().collect();
    let l = node(&all, leader(&c, &all, Duration::from_secs(10)).await?);
    let f = nodes.iter().find(|n| n.id != l.id).unwrap();

    let report: Value = c
        .delete(format!("{}/admin/raft/members/{}", l.base, f.id))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(report["complete"], true, "{report}");

    // The leader learns the removal committed as it happens; its transport
    // follows a moment later.
    let give_up = Instant::now() + Duration::from_secs(5);
    loop {
        let members = get(&c, format!("{}/admin/raft/members", l.base)).await?;
        if !members["peers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == f.id)
        {
            break;
        }
        anyhow::ensure!(Instant::now() < give_up, "still connected: {members}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    // The removed broker is refused at the leader's Raft port.
    let mut sock = TcpStream::connect(l.raft).await?;
    assert!(
        dialer_handshake(&mut sock, f.id, l.id, b"").await.is_err(),
        "a removed member must not be able to connect"
    );
    // And the two that remain still commit writes.
    produce(&c, l, &["after"]).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_leader_steps_down_and_the_rest_elect_another() -> Result<()> {
    let c = Client::new();
    let nodes = cluster(3).await?;
    for n in &nodes {
        create_topic(&c, n).await?;
    }
    let all: Vec<&Node> = nodes.iter().collect();
    let old = node(&all, leader(&c, &all, Duration::from_secs(10)).await?);

    let report: Value = c
        .delete(format!("{}/admin/raft/members/{}", old.base, old.id))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(statuses(&report), vec!["committed"], "{report}");

    let rest: Vec<&Node> = nodes.iter().filter(|n| n.id != old.id).collect();
    let new = node(&rest, leader(&c, &rest, Duration::from_secs(10)).await?);
    assert_ne!(new.id, old.id);
    let status = get(&c, format!("{}/raft", old.base)).await?;
    assert_ne!(status["partitions"][0]["role"], "leader", "{status}");
    produce(&c, new, &["after"]).await?;
    let members = get(&c, format!("{}/admin/raft/members", new.base)).await?;
    assert!(
        !members["partitions"][0]["voters"]
            .as_array()
            .unwrap()
            .contains(&json!(old.id)),
        "{members}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_change_is_refused_while_the_first_is_uncommitted() -> Result<()> {
    let c = Client::new();
    // A cluster of one, adding a broker that does not exist: the new
    // configuration needs two votes and can never commit.
    let one = start(1, free_addr(), &[], false).await?;
    create_topic(&c, &one).await?;
    leader(&c, &[&one], Duration::from_secs(10)).await?;

    let first: Value = c
        .post(format!("{}/admin/raft/members", one.base))
        .json(&json!({"id": 2, "addr": free_addr().to_string()}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(first["complete"], false, "{first}");
    assert_eq!(statuses(&first), vec!["pending"]);

    let second = c
        .post(format!("{}/admin/raft/members", one.base))
        .json(&json!({"id": 3, "addr": free_addr().to_string()}))
        .send()
        .await?;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let undo = c
        .delete(format!("{}/admin/raft/members/2", one.base))
        .send()
        .await?;
    assert_eq!(
        undo.status(),
        StatusCode::CONFLICT,
        "a removal is a change too"
    );

    let members = get(&c, format!("{}/admin/raft/members", one.base)).await?;
    assert_eq!(
        members["partitions"][0]["change_pending"], true,
        "{members}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn membership_changes_are_refused_with_bad_input() -> Result<()> {
    let c = Client::new();
    let one = start(1, free_addr(), &[], false).await?;
    let no_topics = c
        .post(format!("{}/admin/raft/members", one.base))
        .json(&json!({"id": 2, "addr": "127.0.0.1:7000"}))
        .send()
        .await?;
    assert_eq!(no_topics.status(), StatusCode::BAD_REQUEST);
    create_topic(&c, &one).await?;
    for body in [
        json!({"id": 0, "addr": "127.0.0.1:7000"}),
        json!({"id": 2, "addr": "broker-2:7000"}),
    ] {
        let r = c
            .post(format!("{}/admin/raft/members", one.base))
            .json(&body)
            .send()
            .await?;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{body}");
    }
    Ok(())
}
