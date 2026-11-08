//! Leader routing: a follower forwards a produce to the partition's leader.
//!
//! Only the leader of a partition's Raft group can propose a write. A produce
//! that reaches a follower is sent on to the leader's HTTP API, once, and the
//! leader's answer is returned to the client as if the follower had written
//! the records itself.
//!
//! # Why HTTP, for both protocols
//!
//! Every broker serves HTTP; the binary listener is optional. HTTP carries the
//! caller's credential with each request, where the binary protocol
//! authenticates a whole connection at its handshake — forwarding binary as
//! binary would need a connection per leader *and per caller key*. Keys and
//! values are sent base64-encoded (`?encoding=base64`), so binary records
//! survive the hop byte for byte.
//!
//! # Nothing is trusted on the leader's side
//!
//! The leader authenticates and authorizes the forwarded request as it would
//! the client's own: same key, same ACLs, same producer-id ownership, same
//! quota. The [`FORWARDED_HEADER`] grants nothing; it only tells the leader not
//! to forward again, so a request makes at most one hop even while two brokers
//! disagree about who leads.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine as _;
use es_protocol::{ApiError, ProduceRecord, ProduceRequest, ProduceResponse};

use crate::config::Config;
use crate::dataplane::{DataError, IncomingRecord, Produced};

/// Marks a produce a follower has already forwarded. A broker that receives
/// one and does not lead the partition answers "not leader" instead of
/// forwarding it again.
pub const FORWARDED_HEADER: &str = "x-es-forwarded";

/// Longest a forwarded produce may take, from connecting to the leader to its
/// last response byte. Above the leader's own commit timeout (10 s), so a
/// leader that cannot commit gets to say so before the follower gives up.
pub const FORWARD_TIMEOUT: Duration = Duration::from_secs(15);
/// Connecting to a leader that is down fails fast: the client is better off
/// retrying, by which time another broker may lead.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// A leader's answer is a few dozen bytes per record. Anything far beyond
/// that is not a produce response.
const RESPONSE_BYTES_PER_RECORD: usize = 128;
const RESPONSE_BYTES_BASE: usize = 64 * 1024;

pub struct Forwarder {
    client: reqwest::Client,
    /// Peer node id → base URL of its HTTP API.
    peers: BTreeMap<u32, String>,
    /// Largest body sent to a leader: what its HTTP listener accepts, the
    /// cluster being configured alike.
    max_body: usize,
}

impl Forwarder {
    /// `None` on a broker with no peer API addresses: nothing to forward to.
    pub fn from_config(config: &Config) -> Result<Option<Self>> {
        if config.raft_peer_apis.is_empty() {
            return Ok(None);
        }
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(FORWARD_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            // A redirect would carry the caller's key to wherever it points.
            .redirect(reqwest::redirect::Policy::none())
            // Cluster traffic: an HTTP(S)_PROXY meant for the outside world
            // must not see the caller's key either.
            .no_proxy();
        if let Some(ca) = &config.raft_peer_api_ca {
            let pem = std::fs::read(ca).with_context(|| format!("read {ca:?}"))?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .with_context(|| format!("parse certificates in {ca:?}"))?;
            if certs.is_empty() {
                anyhow::bail!("--raft-peer-api-ca {ca:?} holds no certificate");
            }
            builder = builder.tls_built_in_root_certs(false);
            for c in certs {
                builder = builder.add_root_certificate(c);
            }
        }
        let client = builder
            .build()
            .context("build the leader-forwarding client")?;
        Ok(Some(Self {
            client,
            peers: config.raft_peer_apis.clone(),
            max_body: config.max_request_body_bytes,
        }))
    }

    /// The API address configured for `node`, if any.
    pub fn address(&self, node: u32) -> Option<&str> {
        self.peers.get(&node).map(String::as_str)
    }

    /// Send `records` to `leader` as one produce request, authenticated with
    /// `credential` (the caller's own), and return its results in order.
    /// Every record names its partition, so the leader routes it where this
    /// broker did.
    pub async fn produce(
        &self,
        leader: u32,
        topic: &str,
        credential: Option<&str>,
        records: Vec<IncomingRecord>,
        producer_id: Option<&str>,
    ) -> Result<Vec<Produced>, DataError> {
        let base = self.address(leader).ok_or_else(|| {
            DataError::Unavailable(format!(
                "not leader (hint: node {leader}, which has no --raft-peer-api address); send \
                 the produce to node {leader}"
            ))
        })?;
        let count = records.len();
        let b64 = base64::engine::general_purpose::STANDARD;
        let body = ProduceRequest {
            records: records
                .into_iter()
                .map(|r| ProduceRecord {
                    key: r.key.map(|k| b64.encode(k)),
                    value: b64.encode(r.value),
                    partition: r.partition,
                    sequence: r.sequence,
                })
                .collect(),
            producer_id: producer_id.map(str::to_string),
        };
        let body = serde_json::to_vec(&body).map_err(|e| DataError::Internal(e.into()))?;
        if body.len() > self.max_body {
            return Err(DataError::BadRequest(format!(
                "this produce is {} bytes once encoded for forwarding to the leader, node \
                 {leader} at {base}; the limit is {}. Send it to the leader directly, or in \
                 smaller batches",
                body.len(),
                self.max_body
            )));
        }

        let mut req = self
            .client
            .post(format!("{base}/topics/{topic}/produce?encoding=base64"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(FORWARDED_HEADER, "1")
            .body(body);
        if let Some(c) = credential {
            req = req.bearer_auth(c);
        }
        let unreachable = |e: &dyn std::fmt::Display| {
            DataError::Unavailable(format!(
                "not leader (hint: node {leader} at {base}); forwarding to it failed: {e}. \
                 Retry, or send the produce to the leader"
            ))
        };
        let mut resp = req.send().await.map_err(|e| unreachable(&e))?;
        let status = resp.status();
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<f64>().ok());

        let cap = RESPONSE_BYTES_BASE + count * RESPONSE_BYTES_PER_RECORD;
        let mut bytes = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| unreachable(&e))? {
            if bytes.len() + chunk.len() > cap {
                return Err(DataError::Internal(anyhow::anyhow!(
                    "leader node {leader} sent a produce response over {cap} bytes"
                )));
            }
            bytes.extend_from_slice(&chunk);
        }

        if status.is_success() {
            let parsed: ProduceResponse = serde_json::from_slice(&bytes).map_err(|e| {
                DataError::Internal(anyhow::anyhow!(
                    "leader node {leader} sent an unreadable produce response: {e}"
                ))
            })?;
            if parsed.results.len() != count {
                return Err(DataError::Internal(anyhow::anyhow!(
                    "leader node {leader} answered {} results for {count} records",
                    parsed.results.len()
                )));
            }
            return Ok(parsed
                .results
                .into_iter()
                .map(|r| Produced {
                    partition: r.partition,
                    offset: r.offset,
                    duplicate: r.duplicate,
                })
                .collect());
        }

        // The leader's message is already one it shows its own clients.
        let msg = serde_json::from_slice::<ApiError>(&bytes)
            .map(|e| e.error)
            .unwrap_or_else(|_| String::from_utf8_lossy(&bytes).into_owned());
        Err(match status.as_u16() {
            401 => DataError::Forbidden(format!(
                "the leader, node {leader}, did not accept this key ({msg}); API keys must be \
                 the same on every broker"
            )),
            403 => DataError::Forbidden(msg),
            404 => DataError::NotFound(msg),
            400 | 413 => DataError::BadRequest(msg),
            429 => DataError::RateLimited(retry_after.unwrap_or(1.0)),
            503 => DataError::Unavailable(msg),
            _ => DataError::Internal(anyhow::anyhow!(
                "leader node {leader} answered {status} to a forwarded produce: {msg}"
            )),
        })
    }
}
