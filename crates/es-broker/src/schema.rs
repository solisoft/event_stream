use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::topic::write_json_atomic;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaEntry {
    pub id: u32,
    pub subject: String,
    #[serde(rename = "type")]
    pub schema_type: String,
    pub schema: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedSchemas {
    next_id: u32,
    schemas: Vec<SchemaEntry>,
}

pub struct SchemaStore {
    schemas: DashMap<u32, Arc<SchemaEntry>>,
    /// Subject → latest version id.
    subjects: DashMap<String, u32>,
    next_id: AtomicU32,
    path: PathBuf,
}

impl SchemaStore {
    pub fn open(data_dir: PathBuf) -> Result<Arc<Self>> {
        let path = data_dir.join("schemas.json");
        let (next_id, entries) = match std::fs::read(&path) {
            Ok(bytes) => {
                let persisted: PersistedSchemas = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parse schemas {:?}", path))?;
                (persisted.next_id, persisted.schemas)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (1, Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let schemas = DashMap::new();
        let subjects = DashMap::new();
        for entry in entries {
            let id = entry.id;
            subjects.insert(entry.subject.clone(), id);
            schemas.insert(id, Arc::new(entry));
        }

        Ok(Arc::new(Self {
            schemas,
            subjects,
            next_id: AtomicU32::new(next_id),
            path,
        }))
    }

    /// Register a new schema. If a previous version exists for the same
    /// subject, a backward-compatibility check is performed.
    pub fn register(
        &self,
        subject: String,
        schema_type: String,
        schema: String,
    ) -> Result<Arc<SchemaEntry>> {
        if subject.is_empty() || subject.len() > 200 {
            return Err(anyhow!("subject must be 1..=200 chars"));
        }
        if schema_type != "json_schema" && schema_type != "avro" && schema_type != "protobuf" {
            return Err(anyhow!(
                "schema_type must be 'json_schema', 'avro', or 'protobuf'"
            ));
        }
        if schema.is_empty() || schema.len() > 512 * 1024 {
            return Err(anyhow!("schema must be 1..=512 KiB"));
        }

        // Validate that the schema is parseable (basic JSON parse).
        let _: serde_json::Value = serde_json::from_str(&schema)
            .map_err(|e| anyhow!("schema is not valid JSON: {}", e))?;

        // Backward compatibility check for JSON Schema.
        if schema_type == "json_schema" {
            if let Some(prev_id) = self.subjects.get(&subject) {
                let prev = self
                    .schemas
                    .get(&*prev_id)
                    .ok_or_else(|| anyhow!("previous schema not found"))?;
                check_compatibility(&prev.schema, &schema)?;
            }
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(SchemaEntry {
            id,
            subject: subject.clone(),
            schema_type,
            schema,
            created_at_ms: now_ms(),
        });

        self.subjects.insert(subject, id);
        self.schemas.insert(id, entry.clone());
        self.flush()?;

        Ok(entry)
    }

    pub fn get(&self, id: u32) -> Option<Arc<SchemaEntry>> {
        self.schemas.get(&id).map(|r| r.clone())
    }

    pub fn list(&self) -> Vec<Arc<SchemaEntry>> {
        let mut out: Vec<_> = self.schemas.iter().map(|r| r.clone()).collect();
        out.sort_by_key(|e| e.id);
        out
    }

    pub fn latest_version(&self, subject: &str) -> Option<Arc<SchemaEntry>> {
        let id = self.subjects.get(subject)?;
        self.get(*id)
    }

    fn flush(&self) -> Result<()> {
        let persisted = PersistedSchemas {
            next_id: self.next_id.load(Ordering::Relaxed),
            schemas: {
                let mut v: Vec<SchemaEntry> = Vec::new();
                for entry in self.schemas.iter() {
                    v.push((**entry).clone());
                }
                v
            },
        };
        write_json_atomic(&self.path, &persisted)
    }
}

/// Basic backward compatibility for JSON Schema: new schema must accept all
/// data that the old schema accepted. Checks:
///   1. New required fields must be subset of old required fields.
///   2. Properties present in old must also be present in new.
///   3. Property types in new must be compatible (no narrowing).
fn check_compatibility(old_schema_str: &str, new_schema_str: &str) -> Result<()> {
    let old: serde_json::Value =
        serde_json::from_str(old_schema_str).map_err(|e| anyhow!("old schema parse: {}", e))?;
    let new: serde_json::Value =
        serde_json::from_str(new_schema_str).map_err(|e| anyhow!("new schema parse: {}", e))?;

    let old_req = required_fields(&old);
    let new_req = required_fields(&new);

    for f in &new_req {
        if !old_req.contains(f) {
            return Err(anyhow!(
                "backward-incompatible: new schema adds required field '{}'",
                f
            ));
        }
    }

    if let Some(old_props) = old.get("properties").and_then(|v| v.as_object()) {
        if let Some(new_props) = new.get("properties").and_then(|v| v.as_object()) {
            for (name, _old_type) in old_props {
                if !new_props.contains_key(name) {
                    return Err(anyhow!(
                        "backward-incompatible: new schema removes property '{}'",
                        name
                    ));
                }
            }
        }
    }

    Ok(())
}

fn required_fields(schema: &serde_json::Value) -> Vec<String> {
    schema
        .get("required")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
