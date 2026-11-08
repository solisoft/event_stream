//! The blocking client against a real broker, plain and over TLS.
//!
//! The broker runs on tokio in the test; the client is called from
//! `spawn_blocking`, as it would be from any thread that is not async.

use std::path::{Path, PathBuf};
use std::time::Duration;

use es_broker::auth::AuthMode;
use es_broker::{spawn, BrokerHandle, Config};
use es_client::{Client, Error, Options, Tls, WireConsumeRequest, WireProduceRecord};
use es_protocol::wire::HandshakeStatus;
use es_protocol::CreateTopicRequest;
use tempfile::TempDir;

struct Env {
    _tmp: TempDir,
    handle: BrokerHandle,
    token: String,
}

async fn boot(auth: bool, tls: bool) -> Env {
    let tmp = TempDir::new().unwrap();
    let mut cfg = Config::new(
        tmp.path().to_path_buf(),
        "127.0.0.1:0".parse().unwrap(),
        1 << 20,
    );
    cfg.bind_binary = Some("127.0.0.1:0".parse().unwrap());
    if auth {
        cfg.auth_mode = AuthMode::Required;
    }
    if tls {
        cfg.tls_cert_path = Some(fixture("cert.pem"));
        cfg.tls_key_path = Some(fixture("key.pem"));
    }
    let handle = spawn(cfg).await.unwrap();
    let token = if auth {
        std::fs::read_to_string(tmp.path().join("bootstrap.key"))
            .unwrap()
            .trim()
            .to_string()
    } else {
        String::new()
    };
    Env {
        _tmp: tmp,
        handle,
        token,
    }
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../es-broker/tests/fixtures/tls")
        .join(name)
}

async fn create_topic(env: &Env, name: &str, partitions: u32) {
    let mut http = reqwest::Client::builder();
    if env.handle.scheme == "https" {
        let ca = std::fs::read(fixture("ca.pem")).unwrap();
        http = http.add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap());
    }
    let mut req = http
        .build()
        .unwrap()
        .post(format!(
            "{}/topics",
            env.handle.base_url().replace("127.0.0.1", "localhost")
        ))
        .json(&CreateTopicRequest {
            name: name.into(),
            partitions,
            config: None,
        });
    if !env.token.is_empty() {
        req = req.bearer_auth(&env.token);
    }
    let resp = req.send().await.unwrap();
    assert!(
        resp.status().is_success(),
        "create topic: {}",
        resp.status()
    );
}

fn record(key: &[u8], value: &[u8]) -> WireProduceRecord {
    WireProduceRecord {
        key: Some(key.to_vec()),
        value: value.to_vec(),
        partition: Some(0),
        sequence: None,
    }
}

fn consume_all(client: &mut Client, topic: &str) -> es_client::WireConsumeResponse {
    client
        .consume(&WireConsumeRequest {
            topic: topic.into(),
            partition: 0,
            offset: 0,
            max_records: 100,
            max_bytes: 1 << 20,
        })
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bytes_go_in_and_come_out_unchanged_with_and_without_gzip() {
    let env = boot(false, false).await;
    create_topic(&env, "bin", 1).await;
    let addr = env.handle.binary_addr.unwrap();

    tokio::task::spawn_blocking(move || {
        for gzip in [false, true] {
            let mut client = Client::connect(
                addr,
                &Options {
                    gzip,
                    ..Options::default()
                },
            )
            .unwrap();
            assert_eq!(client.gzip_enabled(), gzip);
            client.ping().unwrap();
            // Non-UTF-8 and empty values, and one large enough to compress.
            let big = vec![b'z'; 4096];
            let values: [&[u8]; 3] = [&[0x00, 0xFF, 0xC3, 0x28], b"", &big];
            let results = client
                .produce(
                    "bin",
                    None,
                    values.iter().map(|v| record(b"k", v)).collect(),
                )
                .unwrap();
            assert_eq!(results.len(), 3);
            assert!(results.windows(2).all(|w| w[1].offset == w[0].offset + 1));
        }
        let mut client = Client::connect(addr, &Options::default()).unwrap();
        let page = consume_all(&mut client, "bin");
        assert_eq!(page.records.len(), 6);
        assert_eq!(page.records[0].value, vec![0x00, 0xFF, 0xC3, 0x28]);
        assert_eq!(page.records[4].value, Vec::<u8>::new());
        assert_eq!(page.records[5].value.len(), 4096);
        assert_eq!(page.records[0].key.as_deref(), Some(&b"k"[..]));
        assert_eq!(page.next_offset, 6);
        assert_eq!(page.high_watermark, 6);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_error_leaves_the_connection_usable() {
    let env = boot(false, false).await;
    let addr = env.handle.binary_addr.unwrap();
    tokio::task::spawn_blocking(move || {
        let mut client = Client::connect(addr, &Options::default()).unwrap();
        let err = client
            .produce("missing", None, vec![record(b"k", b"v")])
            .unwrap_err();
        assert!(matches!(err, Error::Server(_)), "{err:?}");
        assert!(err.connection_usable());
        assert!(err.to_string().contains("missing"), "{err}");
        client.ping().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retry_under_a_producer_id_is_a_duplicate() {
    let env = boot(false, false).await;
    create_topic(&env, "idem", 1).await;
    let addr = env.handle.binary_addr.unwrap();
    tokio::task::spawn_blocking(move || {
        let mut client = Client::connect(addr, &Options::default()).unwrap();
        let sequenced = |seq| WireProduceRecord {
            sequence: Some(seq),
            ..record(b"k", b"v")
        };
        let first = client
            .produce("idem", Some("p1"), vec![sequenced(0)])
            .unwrap();
        let again = client
            .produce("idem", Some("p1"), vec![sequenced(0)])
            .unwrap();
        assert!(!first[0].duplicate);
        assert!(again[0].duplicate);
        assert_eq!(again[0].offset, first[0].offset);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_token_is_checked_at_the_handshake() {
    let env = boot(true, false).await;
    let addr = env.handle.binary_addr.unwrap();
    let token = env.token.clone();
    tokio::task::spawn_blocking(move || {
        let refused = Client::connect(addr, &Options::default()).err().unwrap();
        assert!(
            matches!(
                refused,
                Error::Handshake {
                    status: Some(HandshakeStatus::AuthRequired | HandshakeStatus::AuthFailed),
                    ..
                }
            ),
            "{refused:?}"
        );
        let wrong = Client::connect(
            addr,
            &Options {
                token: "esk_wrong".into(),
                ..Options::default()
            },
        )
        .err()
        .unwrap();
        assert!(matches!(wrong, Error::Handshake { .. }), "{wrong:?}");
        let mut client = Client::connect(
            addr,
            &Options {
                token,
                ..Options::default()
            },
        )
        .unwrap();
        client.ping().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_http_port_is_named_as_the_mistake() {
    let env = boot(false, false).await;
    let http = env.handle.addr;
    tokio::task::spawn_blocking(move || {
        let err = Client::connect(
            http,
            &Options {
                connect_timeout: Duration::from_secs(2),
                ..Options::default()
            },
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("HTTP port"), "{err}");
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_connection_is_seen_before_it_is_used() {
    let env = boot(false, false).await;
    let addr = env.handle.binary_addr.unwrap();
    let mut client = tokio::task::spawn_blocking(move || {
        let mut client = Client::connect(addr, &Options::default()).unwrap();
        client.ping().unwrap();
        assert!(!client.is_closed());
        // Still usable after the probe.
        client.ping().unwrap();
        client
    })
    .await
    .unwrap();

    env.handle.shutdown().await.unwrap();
    tokio::task::spawn_blocking(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !client.is_closed() {
            assert!(std::time::Instant::now() < deadline, "never saw the close");
            std::thread::sleep(Duration::from_millis(20));
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn over_tls_and_idle_is_not_closed() {
    let env = boot(false, true).await;
    create_topic(&env, "secure", 1).await;
    let addr = env.handle.binary_addr.unwrap();
    tokio::task::spawn_blocking(move || {
        let plain = Client::connect(
            addr,
            &Options {
                connect_timeout: Duration::from_secs(2),
                ..Options::default()
            },
        );
        assert!(plain.is_err(), "a TLS listener must refuse plaintext");

        let tls = Tls::from_ca_file(&fixture("ca.pem"), "localhost").unwrap();
        let mut client = Client::connect(
            addr,
            &Options {
                tls: Some(tls),
                gzip: true,
                ..Options::default()
            },
        )
        .unwrap();
        client
            .produce("secure", None, vec![record(b"k", b"v")])
            .unwrap();
        // Session tickets may arrive after the handshake: idle is not closed.
        std::thread::sleep(Duration::from_millis(100));
        assert!(!client.is_closed());
        assert_eq!(consume_all(&mut client, "secure").records[0].value, b"v");
    })
    .await
    .unwrap();
}
