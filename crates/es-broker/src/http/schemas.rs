use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::auth::{AclAction, ApiKey};
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
    if !key.is_admin() {
        return Err(AppError::forbidden("admin access required"));
    }
    let stype = req.schema_type.unwrap_or_else(|| "json_schema".to_string());
    let entry = broker
        .schemas
        .register(req.subject, stype, req.schema)
        .map_err(|e| AppError::bad_request(format!("{}", e)))?;
    Ok(Json(RegisterSchemaResponse { id: entry.id }))
}

// Subjects follow the `<topic>-value` / `<topic>-key` convention, so the
// same ACL that grants reading a topic grants reading its schemas. That used
// to fall out of `-` being an ACL boundary; now that only `.` is one, the
// suffix is stripped here, explicitly. Every key used to be able to read
// every tenant's schemas. A schema the caller may not read is reported as not
// found, so ids do not reveal what exists.

/// The name a subject's ACL is checked against: its topic for
/// `<topic>-value` / `<topic>-key`, the subject itself otherwise.
fn subject_acl_name(subject: &str) -> &str {
    subject
        .strip_suffix("-value")
        .or_else(|| subject.strip_suffix("-key"))
        .filter(|t| !t.is_empty())
        .unwrap_or(subject)
}

fn can_read_subject(key: &ApiKey, subject: &str) -> bool {
    key.can(AclAction::Read, subject_acl_name(subject))
}

pub async fn get(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(id): Path<u32>,
) -> AppResult<Json<SchemaResponse>> {
    let entry = broker
        .schemas
        .get(id)
        .filter(|e| can_read_subject(&key, &e.subject))
        .ok_or_else(|| AppError::not_found(format!("schema {} not found", id)))?;
    Ok(Json(SchemaResponse::from(entry.as_ref())))
}

pub async fn list(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
) -> Json<Vec<SchemaResponse>> {
    let schemas: Vec<SchemaResponse> = broker
        .schemas
        .list()
        .iter()
        .filter(|e| can_read_subject(&key, &e.subject))
        .map(|e| SchemaResponse::from(e.as_ref()))
        .collect();
    Json(schemas)
}

pub async fn latest_version(
    State(broker): State<Arc<Broker>>,
    AuthedKey(key): AuthedKey,
    Path(subject): Path<String>,
) -> AppResult<Json<SchemaResponse>> {
    let entry = broker
        .schemas
        .latest_version(&subject)
        .filter(|_| can_read_subject(&key, &subject))
        .ok_or_else(|| AppError::not_found(format!("no schema for subject '{}'", subject)))?;
    Ok(Json(SchemaResponse::from(entry.as_ref())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AclRule;

    fn reader(prefix: &str) -> ApiKey {
        ApiKey {
            key_id: "k".into(),
            name: "k".into(),
            acls: vec![AclRule {
                action: AclAction::Read,
                topic_prefix: prefix.into(),
            }],
            produce_bytes_per_sec: None,
            consume_bytes_per_sec: None,
            created_at_ms: 0,
            disabled: false,
        }
    }

    #[test]
    fn subjects_authorize_against_their_topic() {
        let k = reader("orders");
        assert!(can_read_subject(&k, "orders-value"));
        assert!(can_read_subject(&k, "orders-key"));
        assert!(can_read_subject(&k, "orders.eu-value"));
        assert!(can_read_subject(&k, "orders"));
        // Another tenant's topic that begins with the same word.
        assert!(!can_read_subject(&k, "orders-archive-value"));
        assert!(!can_read_subject(&k, "orderssecret-value"));
        assert!(!can_read_subject(&k, "-value"));
    }
}
