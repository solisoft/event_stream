use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};

use es_protocol::{ProduceRequest, ProduceResponse, ProduceResult};

use crate::broker::Broker;
use crate::dataplane::{self, IncomingRecord};

use super::auth_ext::AuthedKey;
use super::error::AppResult;

pub async fn produce(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(topic_name): Path<String>,
    Json(req): Json<ProduceRequest>,
) -> AppResult<Json<ProduceResponse>> {
    let records = req
        .records
        .into_iter()
        .map(|r| IncomingRecord {
            key: r.key.map(String::into_bytes),
            value: r.value.into_bytes(),
            partition: r.partition,
            sequence: r.sequence,
        })
        .collect();
    let produced = dataplane::produce(
        &broker,
        &key,
        &topic_name,
        records,
        req.producer_id.as_deref(),
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
