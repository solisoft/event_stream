use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::topic::write_json_atomic;
use es_protocol::{AclActionDto, AclRuleDto, ApiKeyDto, CreateKeyRequest};

/// Whether the auth middleware enforces or passes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Disabled,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclAction {
    Read,
    Write,
    Admin,
}

impl AclAction {
    pub fn from_dto(d: AclActionDto) -> Self {
        match d {
            AclActionDto::Read => Self::Read,
            AclActionDto::Write => Self::Write,
            AclActionDto::Admin => Self::Admin,
        }
    }
    pub fn to_dto(self) -> AclActionDto {
        match self {
            Self::Read => AclActionDto::Read,
            Self::Write => AclActionDto::Write,
            Self::Admin => AclActionDto::Admin,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "admin" => Ok(Self::Admin),
            other => Err(anyhow!("unknown acl action '{}'", other)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AclRule {
    pub action: AclAction,
    pub topic_prefix: String,
}

impl AclRule {
    fn matches(&self, action: AclAction, topic: &str) -> bool {
        let action_ok = match (self.action, action) {
            (AclAction::Admin, _) => true,
            (a, b) if a == b => true,
            // A Write grant implies Read on the same prefix.
            (AclAction::Write, AclAction::Read) => true,
            _ => false,
        };
        if !action_ok {
            return false;
        }
        // "*" matches every topic.
        self.topic_prefix == "*" || topic.starts_with(&self.topic_prefix)
    }
}

#[derive(Clone, Debug)]
pub struct ApiKey {
    pub key_id: String,
    pub name: String,
    pub acls: Vec<AclRule>,
    pub produce_bytes_per_sec: Option<u32>,
    pub consume_bytes_per_sec: Option<u32>,
    pub created_at_ms: i64,
    pub disabled: bool,
}

impl ApiKey {
    pub fn to_dto(&self) -> ApiKeyDto {
        ApiKeyDto {
            key_id: self.key_id.clone(),
            name: self.name.clone(),
            acls: self
                .acls
                .iter()
                .map(|a| AclRuleDto {
                    action: a.action.to_dto(),
                    topic_prefix: a.topic_prefix.clone(),
                })
                .collect(),
            produce_bytes_per_sec: self.produce_bytes_per_sec,
            consume_bytes_per_sec: self.consume_bytes_per_sec,
            created_at_ms: self.created_at_ms,
            disabled: self.disabled,
        }
    }

    /// Returns true if any ACL rule grants `action` on `topic`. Admin always passes.
    pub fn can(&self, action: AclAction, topic: &str) -> bool {
        if self.disabled {
            return false;
        }
        self.acls.iter().any(|r| r.matches(action, topic))
    }

    /// Convenience: any admin grant means "broker-wide ops".
    pub fn is_admin(&self) -> bool {
        if self.disabled {
            return false;
        }
        self.acls.iter().any(|r| {
            r.action == AclAction::Admin && (r.topic_prefix == "*" || r.topic_prefix.is_empty())
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedAcl {
    action: String,
    topic_prefix: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedKey {
    key_id: String,
    name: String,
    secret_sha256_hex: String,
    acls: Vec<PersistedAcl>,
    #[serde(default)]
    produce_bytes_per_sec: Option<u32>,
    #[serde(default)]
    consume_bytes_per_sec: Option<u32>,
    created_at_ms: i64,
    #[serde(default)]
    disabled: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedKeyStore {
    keys: Vec<PersistedKey>,
}

type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

struct KeyLimiters {
    produce: Option<Arc<Limiter>>,
    consume: Option<Arc<Limiter>>,
}

pub struct KeyStore {
    file_path: PathBuf,
    keys: DashMap<String, Arc<ApiKey>>,
    by_hash: DashMap<[u8; 32], String>,
    limiters: DashMap<String, KeyLimiters>,
}

impl KeyStore {
    /// Load the keystore from disk. If `auth_required` is true and the store is
    /// empty, generate a bootstrap admin key and write it to
    /// `<dir>/bootstrap.key` (plain text, deletable after first use).
    pub fn open(dir: PathBuf, auth_required: bool) -> Result<(Arc<Self>, Option<String>)> {
        std::fs::create_dir_all(&dir).with_context(|| format!("create dir {:?}", dir))?;
        let file_path = dir.join("api_keys.json");
        let store = Self {
            file_path: file_path.clone(),
            keys: DashMap::new(),
            by_hash: DashMap::new(),
            limiters: DashMap::new(),
        };
        let persisted: PersistedKeyStore = match std::fs::read(&file_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parse keystore {:?}", file_path))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PersistedKeyStore::default(),
            Err(e) => return Err(e.into()),
        };

        for pk in persisted.keys {
            let key_id = pk.key_id.clone();
            let mut hash_buf = [0u8; 32];
            hex::decode_into(&pk.secret_sha256_hex, &mut hash_buf)
                .with_context(|| format!("bad secret_sha256_hex on key {}", pk.key_id))?;
            let acls = pk
                .acls
                .iter()
                .map(|a| {
                    Ok(AclRule {
                        action: AclAction::from_str(&a.action)?,
                        topic_prefix: a.topic_prefix.clone(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let api_key = Arc::new(ApiKey {
                key_id: pk.key_id.clone(),
                name: pk.name,
                acls,
                produce_bytes_per_sec: pk.produce_bytes_per_sec,
                consume_bytes_per_sec: pk.consume_bytes_per_sec,
                created_at_ms: pk.created_at_ms,
                disabled: pk.disabled,
            });
            store
                .limiters
                .insert(key_id.clone(), make_limiters(&api_key));
            store.by_hash.insert(hash_buf, key_id.clone());
            store.keys.insert(key_id, api_key);
        }

        let store = Arc::new(store);

        let mut bootstrap_secret: Option<String> = None;
        if auth_required && store.keys.is_empty() {
            let req = CreateKeyRequest {
                name: "bootstrap-admin".to_string(),
                acls: vec![AclRuleDto {
                    action: AclActionDto::Admin,
                    topic_prefix: "*".to_string(),
                }],
                produce_bytes_per_sec: None,
                consume_bytes_per_sec: None,
            };
            let (_key, secret) = store.create_key(&req)?;
            let path = dir.join("bootstrap.key");
            std::fs::write(&path, &secret)
                .with_context(|| format!("write bootstrap key to {:?}", path))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            tracing::warn!(
                bootstrap_key_path = ?path,
                "auth required + empty store: generated bootstrap admin key (secret written to file, rotate after first use)"
            );
            bootstrap_secret = Some(secret);
        }

        Ok((store, bootstrap_secret))
    }

    fn persist(&self) -> Result<()> {
        let snapshot: Vec<PersistedKey> = self
            .keys
            .iter()
            .map(|kv| {
                let k = kv.value();
                // Find the hash that maps to this key_id (reverse lookup).
                let hash_hex = self
                    .by_hash
                    .iter()
                    .find(|h| h.value() == &k.key_id)
                    .map(|h| hex_encode(h.key()))
                    .unwrap_or_default();
                PersistedKey {
                    key_id: k.key_id.clone(),
                    name: k.name.clone(),
                    secret_sha256_hex: hash_hex,
                    acls: k
                        .acls
                        .iter()
                        .map(|a| PersistedAcl {
                            action: a.action.as_str().to_string(),
                            topic_prefix: a.topic_prefix.clone(),
                        })
                        .collect(),
                    produce_bytes_per_sec: k.produce_bytes_per_sec,
                    consume_bytes_per_sec: k.consume_bytes_per_sec,
                    created_at_ms: k.created_at_ms,
                    disabled: k.disabled,
                }
            })
            .collect();
        let wrapper = PersistedKeyStore { keys: snapshot };
        write_json_atomic(&self.file_path, &wrapper)?;
        Ok(())
    }

    pub fn create_key(&self, req: &CreateKeyRequest) -> Result<(Arc<ApiKey>, String)> {
        if req.name.is_empty() {
            return Err(anyhow!("name must be non-empty"));
        }
        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        let secret = format!(
            "esk_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_bytes)
        );
        let hash = sha256(secret.as_bytes());
        // Short key_id derived from the hash so admins can refer to the key
        // without quoting the secret.
        let key_id = format!("key_{}", hex_encode(&hash[..6]));

        let acls = req
            .acls
            .iter()
            .map(|a| AclRule {
                action: AclAction::from_dto(a.action),
                topic_prefix: a.topic_prefix.clone(),
            })
            .collect::<Vec<_>>();
        let api_key = Arc::new(ApiKey {
            key_id: key_id.clone(),
            name: req.name.clone(),
            acls,
            produce_bytes_per_sec: req.produce_bytes_per_sec,
            consume_bytes_per_sec: req.consume_bytes_per_sec,
            created_at_ms: now_ms(),
            disabled: false,
        });
        self.limiters
            .insert(key_id.clone(), make_limiters(&api_key));
        self.by_hash.insert(hash, key_id.clone());
        self.keys.insert(key_id, api_key.clone());
        self.persist()?;
        Ok((api_key, secret))
    }

    pub fn list(&self) -> Vec<Arc<ApiKey>> {
        let mut out: Vec<Arc<ApiKey>> = self.keys.iter().map(|kv| kv.value().clone()).collect();
        out.sort_by_key(|a| a.created_at_ms);
        out
    }

    pub fn revoke(&self, key_id: &str) -> Result<()> {
        let key = match self.keys.get(key_id) {
            Some(k) => k.value().clone(),
            None => return Err(anyhow!("key '{}' not found", key_id)),
        };
        let new_key = Arc::new(ApiKey {
            disabled: true,
            ..(*key).clone()
        });
        self.keys.insert(key_id.to_string(), new_key);
        self.persist()?;
        Ok(())
    }

    /// Look up an `ApiKey` by its plaintext secret. Returns `None` if the secret
    /// is unknown or the matching key is disabled.
    pub fn authenticate(&self, secret: &str) -> Option<Arc<ApiKey>> {
        let hash = sha256(secret.as_bytes());
        let key_id = self.by_hash.get(&hash)?.value().clone();
        let key = self.keys.get(&key_id)?.value().clone();
        if key.disabled {
            return None;
        }
        Some(key)
    }

    /// Pre-check whether `n_bytes` would fit in the produce rate-limit budget
    /// for this key. Returns Ok if allowed (and consumes the tokens), Err with
    /// a retry hint in seconds if denied.
    pub fn check_produce(&self, key_id: &str, n_bytes: u32) -> Result<(), f64> {
        check_against(
            self.limiters
                .get(key_id)
                .and_then(|l| l.value().produce.clone()),
            n_bytes,
        )
    }

    pub fn check_consume(&self, key_id: &str, n_bytes: u32) -> Result<(), f64> {
        check_against(
            self.limiters
                .get(key_id)
                .and_then(|l| l.value().consume.clone()),
            n_bytes,
        )
    }
}

fn check_against(limiter: Option<Arc<Limiter>>, n: u32) -> Result<(), f64> {
    let Some(limiter) = limiter else {
        return Ok(());
    };
    let weight = match NonZeroU32::new(n.max(1)) {
        Some(w) => w,
        None => return Ok(()),
    };
    match limiter.check_n(weight) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(neg)) => {
            // `neg` is a NotUntil; convert to a wait duration.
            let wait = neg.wait_time_from(governor::clock::Clock::now(&DefaultClock::default()));
            Err(wait.as_secs_f64())
        }
        Err(_insufficient_quota) => {
            // The request was larger than the bucket capacity. Reject outright.
            Err(1.0)
        }
    }
}

fn make_limiters(key: &ApiKey) -> KeyLimiters {
    KeyLimiters {
        produce: key
            .produce_bytes_per_sec
            .and_then(NonZeroU32::new)
            .map(|n| Arc::new(RateLimiter::direct(Quota::per_second(n)))),
        consume: key
            .consume_bytes_per_sec
            .and_then(NonZeroU32::new)
            .map(|n| Arc::new(RateLimiter::direct(Quota::per_second(n)))),
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// Tiny inline hex decoder so we don't pull in another dep.
mod hex {
    use anyhow::{anyhow, Result};
    pub fn decode_into(hex: &str, out: &mut [u8]) -> Result<()> {
        if hex.len() != out.len() * 2 {
            return Err(anyhow!(
                "hex length {} mismatched output {}",
                hex.len(),
                out.len() * 2
            ));
        }
        let bytes = hex.as_bytes();
        for i in 0..out.len() {
            out[i] = (nyb(bytes[i * 2])? << 4) | nyb(bytes[i * 2 + 1])?;
        }
        Ok(())
    }
    fn nyb(b: u8) -> Result<u8> {
        Ok(match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(anyhow!("bad hex nibble {:#x}", b)),
        })
    }
}
