use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};

use crate::auth::AclAction;
use crate::broker::Broker;
use crate::schema::SchemaEntry;

use super::auth_ext::AuthedKey;
use super::error::{AppError, AppResult};

#[derive(Debug, Deserialize)]
pub struct RegisterSchemaRequest {
    pub subject: String,
    #[serde(rename = "type")]
    pub schema_type: Option<String>,
    pub schema: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterSchemaResponse {
    pub id: u32,
}

#[derive(Debug, Serialize)]
pub struct SchemaResponse {
    pub id: u32,
    pub subject: String,
    #[serde(rename = "type")]
    pub schema_type: String,
    pub schema: String,
    pub created_at_ms: i64,
}

impl From<&SchemaEntry> for SchemaResponse {
    fn from(e: &SchemaEntry) -> Self {
        Self {
            id: e.id,
            subject: e.subject.clone(),
            schema_type: e.schema_type.clone(),
            schema: e.schema.clone(),
            created_at_ms: e.created_at_ms,
        }
    }
}

pub async fn register(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Json(req): Json<RegisterSchemaRequest>,
) -> AppResult<Json<RegisterSchemaResponse>> {
    if !key.can(AclAction::Admin, "*") {
        return Err(AppError::forbidden("admin access required"));
    }
    let stype = req.schema_type.unwrap_or_else(|| "json_schema".to_string());
    let entry = broker
        .schemas
        .register(req.subject, stype, req.schema)
        .map_err(|e| AppError::bad_request(format!("{}", e)))?;
    Ok(Json(RegisterSchemaResponse { id: entry.id }))
}

pub async fn get(
    State(broker): State<Arc<Broker>>,
    Path(id): Path<u32>,
) -> AppResult<Json<SchemaResponse>> {
    let entry = broker
        .schemas
        .get(id)
        .ok_or_else(|| AppError::not_found(format!("schema {} not found", id)))?;
    Ok(Json(SchemaResponse::from(entry.as_ref())))
}

pub async fn list(
    State(broker): State<Arc<Broker>>,
) -> Json<Vec<SchemaResponse>> {
    let schemas: Vec<SchemaResponse> = broker
        .schemas
        .list()
        .iter()
        .map(|e| SchemaResponse::from(e.as_ref()))
        .collect();
    Json(schemas)
}

pub async fn latest_version(
    State(broker): State<Arc<Broker>>,
    Path(subject): Path<String>,
) -> AppResult<Json<SchemaResponse>> {
    let entry = broker
        .schemas
        .latest_version(&subject)
        .ok_or_else(|| AppError::not_found(format!("no schema for subject '{}'", subject)))?;
    Ok(Json(SchemaResponse::from(entry.as_ref())))
}
