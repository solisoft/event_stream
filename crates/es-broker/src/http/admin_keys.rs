use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use es_protocol::{ApiKeyDto, CreateKeyRequest, CreateKeyResponse, ListKeysResponse};

use crate::broker::Broker;

use super::auth_ext::AuthedKey;
use super::error::{AppError, AppResult};

pub async fn create(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Json(req): Json<CreateKeyRequest>,
) -> AppResult<(StatusCode, Json<CreateKeyResponse>)> {
    if !key.is_admin() {
        return Err(AppError::forbidden("admin grant required to create keys"));
    }
    let (new_key, secret) = broker.keys.create_key(&req)?;
    Ok((
        StatusCode::CREATED,
        Json(CreateKeyResponse {
            key: new_key.to_dto(),
            secret,
        }),
    ))
}

pub async fn list(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
) -> AppResult<Json<ListKeysResponse>> {
    if !key.is_admin() {
        return Err(AppError::forbidden("admin grant required to list keys"));
    }
    let keys: Vec<ApiKeyDto> = broker.keys.list().iter().map(|k| k.to_dto()).collect();
    Ok(Json(ListKeysResponse { keys }))
}

pub async fn revoke(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(key_id): Path<String>,
) -> AppResult<StatusCode> {
    if !key.is_admin() {
        return Err(AppError::forbidden("admin grant required to revoke keys"));
    }
    broker.keys.revoke(&key_id)?;
    Ok(StatusCode::NO_CONTENT)
}
