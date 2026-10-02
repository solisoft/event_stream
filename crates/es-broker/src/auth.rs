use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use dashmap::DashMap;
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

/// Characters that separate the components of a hierarchical topic name.
const NAME_SEPARATORS: [char; 3] = ['.', '-', '_'];

impl AclRule {
    fn matches(&self, action: AclAction, topic: &str) -> bool {
        let action_ok = match (self.action, action) {
            (AclAction::Admin, _) => true,
            (a, b) if a == b => true,
            // A Write grant implies Read on the same prefix.
            (AclAction::Write, AclAction::Read) => true,
            _ => false,
        };
        action_ok && prefix_matches(&self.topic_prefix, topic)
    }
}

/// Whether an ACL prefix covers `topic`.
///
/// `*` covers everything. Otherwise the prefix covers the topic of that exact
/// name and the topics below it — where "below" starts at a name separator
/// (`.`, `-`, `_`). A plain `starts_with` let a grant on `orders` cover
/// `ordersarchive` and every other tenant whose name happened to begin with
/// the same letters. A prefix that itself ends in a separator (`orders.`)
/// covers exactly the names that start with it.
pub fn prefix_matches(prefix: &str, topic: &str) -> bool {
    if prefix == "*" {
        return true;
    }
    if prefix.is_empty() || !topic.starts_with(prefix) {
        return false;
    }
    if topic.len() == prefix.len() || prefix.ends_with(NAME_SEPARATORS) {
        return true;
    }
    topic[prefix.len()..].starts_with(NAME_SEPARATORS)
}

/// Validate an ACL prefix supplied by an admin. An empty prefix used to match
/// every topic *and* make `is_admin` true — an easy way to mint a super-admin
/// by accident. Global grants are spelled `*`.
fn validate_prefix(prefix: &str) -> Result<()> {
    if prefix == "*" {
        return Ok(());
    }
    if prefix.is_empty() || prefix.len() > 200 {
        return Err(anyhow!(
            "topic_prefix must be '*' or 1..=200 characters (an empty prefix is not allowed)"
        ));
    }
    if !prefix
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(anyhow!(
            "topic_prefix may only contain ASCII alphanumerics, '_', '-', '.' (or be '*')"
        ));
    }
    Ok(())
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

    /// A global admin grant (`admin` on `*`): broker-wide operations.
    pub fn is_admin(&self) -> bool {
        if self.disabled {
            return false;
        }
        self.acls
            .iter()
            .any(|r| r.action == AclAction::Admin && r.topic_prefix == "*")
    }
}

/// The principal every request runs as when auth is disabled. Built once:
/// constructing it per request cost an `Arc` and four allocations each time.
pub static ANONYMOUS_ADMIN: LazyLock<Arc<ApiKey>> = LazyLock::new(|| {
    Arc::new(ApiKey {
        key_id: "anonymous".to_string(),
        name: "anonymous (auth disabled)".to_string(),
        acls: vec![AclRule {
            action: AclAction::Admin,
            topic_prefix: "*".to_string(),
        }],
        produce_bytes_per_sec: None,
        consume_bytes_per_sec: None,
        created_at_ms: 0,
        disabled: false,
    })
});

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

/// A byte-rate token bucket holding at most one second of budget.
///
/// Unlike `governor`'s GCRA it can go into debt: consume quotas are charged
/// *after* the read, when the size is known, and the next read is refused
/// until the debt is repaid. With `governor` a denied post-charge consumed
/// nothing and the next call was not refused either, so consume quotas never
/// limited anything.
struct Bucket {
    rate: f64,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(rate: u32) -> Self {
        Self {
            rate: rate as f64,
            tokens: rate as f64,
            last: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.rate);
    }

    /// Take `n` now if the budget has it. A request larger than a whole
    /// second of budget can never fit and is refused outright.
    fn try_take(&mut self, n: u64) -> Result<(), f64> {
        self.refill();
        let n = n as f64;
        if n > self.rate {
            return Err(1.0);
        }
        if n <= self.tokens {
            self.tokens -= n;
            Ok(())
        } else {
            Err((n - self.tokens) / self.rate)
        }
    }

    /// Refuse while in debt.
    fn check_credit(&mut self) -> Result<(), f64> {
        self.refill();
        if self.tokens > 0.0 {
            Ok(())
        } else {
            Err((-self.tokens + 1.0) / self.rate)
        }
    }

    /// Charge `n`, going into debt if need be (bounded at ten seconds' worth).
    fn charge(&mut self, n: u64) {
        self.refill();
        self.tokens = (self.tokens - n as f64).max(-10.0 * self.rate);
    }
}

struct KeyLimiters {
    produce: Option<Mutex<Bucket>>,
    consume: Option<Mutex<Bucket>>,
}

pub struct KeyStore {
    file_path: PathBuf,
    keys: DashMap<String, Arc<ApiKey>>,
    by_hash: DashMap<[u8; 32], String>,
    limiters: DashMap<String, KeyLimiters>,
    /// Serializes `persist`: the snapshot is taken under it, so the last
    /// writer always writes the newest state. Without it a create and a revoke
    /// racing could persist in the wrong order and bring a revoked key back
    /// after a restart.
    persist_lock: Mutex<()>,
    /// Bumped on every revocation, so long-lived connections can tell cheaply
    /// that they must re-check their key.
    revocations: AtomicU64,
}

impl KeyStore {
    /// Load the keystore from disk. If `auth_required` is true and the store is
    /// empty, generate a bootstrap admin key and write it to
    /// `<dir>/bootstrap.key` (plain text, deletable after first use).
    pub fn open(dir: PathBuf, auth_required: bool) -> Result<(Arc<Self>, Option<String>)> {
        crate::fsutil::create_dir_all_private(&dir)
            .with_context(|| format!("create dir {:?}", dir))?;
        let file_path = dir.join("api_keys.json");
        let store = Self {
            file_path: file_path.clone(),
            keys: DashMap::new(),
            by_hash: DashMap::new(),
            limiters: DashMap::new(),
            persist_lock: Mutex::new(()),
            revocations: AtomicU64::new(0),
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
                    // An empty prefix used to mean "everything"; keep keys
                    // issued that way working under the explicit spelling.
                    let topic_prefix = if a.topic_prefix.is_empty() {
                        tracing::warn!(key = %pk.key_id, "ACL with an empty topic prefix loaded as '*'");
                        "*".to_string()
                    } else {
                        a.topic_prefix.clone()
                    };
                    Ok(AclRule {
                        action: AclAction::from_str(&a.action)?,
                        topic_prefix,
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
            // Born 0600 (O_EXCL + mode). Writing first and chmod-ing after left
            // the admin secret readable under the umask in between — and the
            // chmod's error was ignored.
            let _ = std::fs::remove_file(&path);
            {
                use std::io::Write;
                let mut f = crate::fsutil::create_new_private(&path)
                    .with_context(|| format!("create bootstrap key file {:?}", path))?;
                f.write_all(secret.as_bytes())
                    .with_context(|| format!("write bootstrap key to {:?}", path))?;
                f.sync_all()?;
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
        let _guard = self.persist_lock.lock().unwrap_or_else(|e| e.into_inner());
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
        if req.name.is_empty() || req.name.len() > 200 {
            return Err(anyhow!("name must be 1..=200 characters"));
        }
        if req.acls.len() > 100 {
            return Err(anyhow!("a key may carry at most 100 ACL rules"));
        }
        for a in &req.acls {
            validate_prefix(&a.topic_prefix)?;
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
        self.revocations.fetch_add(1, Ordering::AcqRel);
        self.persist()?;
        Ok(())
    }

    /// Current revocation generation. A connection that authenticated at
    /// generation `g` must re-check its key once this moves past `g`.
    pub fn revocation_epoch(&self) -> u64 {
        self.revocations.load(Ordering::Acquire)
    }

    /// The current state of a key, if it is still enabled.
    pub fn get_enabled(&self, key_id: &str) -> Option<Arc<ApiKey>> {
        let k = self.keys.get(key_id)?.value().clone();
        (!k.disabled).then_some(k)
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

    /// Take `n_bytes` from the produce budget before the write. Err carries a
    /// retry hint in seconds.
    pub fn check_produce(&self, key_id: &str, n_bytes: u64) -> Result<(), f64> {
        match self.limiters.get(key_id) {
            Some(l) => match &l.produce {
                Some(b) => b
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .try_take(n_bytes),
                None => Ok(()),
            },
            None => Ok(()),
        }
    }

    /// Before a read: refuse while the consume budget is in debt.
    pub fn check_consume(&self, key_id: &str) -> Result<(), f64> {
        match self.limiters.get(key_id) {
            Some(l) => match &l.consume {
                Some(b) => b.lock().unwrap_or_else(|e| e.into_inner()).check_credit(),
                None => Ok(()),
            },
            None => Ok(()),
        }
    }

    /// After a read: charge what was actually returned.
    pub fn charge_consume(&self, key_id: &str, n_bytes: u64) {
        if let Some(l) = self.limiters.get(key_id) {
            if let Some(b) = &l.consume {
                b.lock().unwrap_or_else(|e| e.into_inner()).charge(n_bytes);
            }
        }
    }
}

fn make_limiters(key: &ApiKey) -> KeyLimiters {
    KeyLimiters {
        produce: key
            .produce_bytes_per_sec
            .filter(|n| *n > 0)
            .map(|n| Mutex::new(Bucket::new(n))),
        consume: key
            .consume_bytes_per_sec
            .filter(|n| *n > 0)
            .map(|n| Mutex::new(Bucket::new(n))),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_match_at_name_boundaries_only() {
        assert!(prefix_matches("*", "anything"));
        assert!(prefix_matches("orders", "orders"));
        assert!(prefix_matches("orders", "orders.eu"));
        assert!(prefix_matches("orders", "orders-archive"));
        assert!(prefix_matches("orders.", "orders.eu"));
        assert!(!prefix_matches("orders", "ordersarchive"));
        assert!(!prefix_matches("orders.", "orders"));
        assert!(!prefix_matches("", "orders"));
    }

    #[test]
    fn empty_and_odd_prefixes_are_refused_at_creation() {
        assert!(validate_prefix("").is_err());
        assert!(validate_prefix("a/b").is_err());
        assert!(validate_prefix("*").is_ok());
        assert!(validate_prefix("orders.").is_ok());
    }

    #[test]
    fn consume_debt_blocks_the_next_read() {
        let mut b = Bucket::new(100);
        assert!(b.check_credit().is_ok());
        b.charge(1000);
        assert!(
            b.check_credit().is_err(),
            "a debt must refuse the next read"
        );
    }

    #[test]
    fn produce_bucket_refuses_oversized_and_overdrawn_requests() {
        let mut b = Bucket::new(64);
        assert!(b.try_take(1000).is_err());
        assert!(b.try_take(40).is_ok());
        assert!(b.try_take(40).is_err());
    }

    #[test]
    fn bootstrap_key_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let (_s, secret) = KeyStore::open(dir.path().to_path_buf(), true).unwrap();
        assert!(secret.is_some());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("bootstrap.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
