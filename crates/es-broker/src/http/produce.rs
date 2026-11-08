use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use base64::Engine as _;
use serde::Deserialize;

use es_protocol::{ProduceRequest, ProduceResponse, ProduceResult};

use crate::auth::AuthMode;
use crate::broker::Broker;
use crate::dataplane::{self, IncomingRecord, Origin};
use crate::forward::FORWARDED_HEADER;

use super::auth_ext::{extract_bearer, AuthedKey};
use super::error::{AppError, AppResult};

#[derive(Debug, Deserialize)]
pub struct ProduceQuery {
    /// `base64` when keys and values are base64-encoded — the only way to
    /// send bytes that are not UTF-8 over HTTP. `utf8` (the default) takes
    /// them as they are.
    #[serde(default)]
    pub encoding: Option<String>,
}

pub async fn produce(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(topic_name): Path<String>,
    Query(q): Query<ProduceQuery>,
    headers: HeaderMap,
    Json(req): Json<ProduceRequest>,
) -> AppResult<Json<ProduceResponse>> {
    let base64 = match q.encoding.as_deref() {
        None | Some("utf8") => false,
        Some("base64") => true,
        Some(other) => {
            return Err(AppError::bad_request(format!(
                "unknown encoding '{}' (use 'utf8' or 'base64')",
                other
            )))
        }
    };
    let decode = |field: &str, i: usize, s: String| -> AppResult<Vec<u8>> {
        if !base64 {
            return Ok(s.into_bytes());
        }
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| AppError::bad_request(format!("record {i} {field} is not base64: {e}")))
    };
    let mut records = Vec::with_capacity(req.records.len());
    for (i, r) in req.records.into_iter().enumerate() {
        records.push(IncomingRecord {
            key: r.key.map(|k| decode("key", i, k)).transpose()?,
            value: decode("value", i, r.value)?,
            partition: r.partition,
            sequence: r.sequence,
        });
    }
    // The credential goes on to the leader if a partition is led elsewhere,
    // and the leader checks it again. The header only stops a second hop.
    let credential = match broker.config.auth_mode {
        AuthMode::Required => Some(extract_bearer(&headers)?),
        AuthMode::Disabled => None,
    };
    let origin = Origin {
        credential: credential.as_deref(),
        forwarded: headers.contains_key(FORWARDED_HEADER),
    };
    let produced = dataplane::produce(
        &broker,
        &key,
        &topic_name,
        records,
        req.producer_id.as_deref(),
        origin,
    )
    .await?;
    Ok(Json(ProduceResponse {
        results: produced
            .into_iter()
            .map(|p| ProduceResult {
                partition: p.partition,
                offset: p.offset,
                duplicate: p.duplicate,
            })
            .collect(),
    }))
}
