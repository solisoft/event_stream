//! Idempotent-producer state.
//!
//! A producer that sends `producer_id` + per-record `sequence` gets each record
//! written at most once per (topic, partition): a retried record is answered
//! with the offset it was first written at instead of being written again.
//!
//! * **Ownership.** A producer id belongs to the API key that first used it.
//!   Another key presenting the same id is refused — otherwise a co-tenant
//!   could advance someone else's sequence and have their next real record
//!   acknowledged as a "duplicate" and silently dropped.
//! * **Atomicity.** The caller holds the producer's lock from the sequence
//!   check through the append to recording the offset, so two concurrent
//!   retries cannot both be accepted.
//! * **Window.** The last [`WINDOW`] sequences per partition are remembered, so
//!   a retried batch is recognised record by record, not only its last record.
//! * **Durability.** Accepted sequences are appended to a journal and fsynced
//!   before the produce is acknowledged; `producers.json` is a periodic
//!   compaction of it. State is no longer up to two seconds behind the data
//!   it describes after a crash.
//! * **Bounds.** Producers idle for [`PRODUCER_EXPIRY`] are forgotten, and each
//!   key may hold at most [`MAX_PRODUCERS_PER_KEY`].

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use es_protocol::{ProducerPartitionStateDto, ProducerStateDto};

/// Outcome of a sequence check.
#[derive(Debug, PartialEq, Eq)]
pub enum DedupeOutcome {
    /// Record is new; append it, then [`ProducerState::record`] its offset.
    Accept,
    /// A retry of a record already written at `prev_offset`.
    Duplicate { prev_offset: u64 },
    /// Below the remembered window: too old to tell whether it was written.
    SequenceTooLow { last_seen: i64 },
    /// Skips ahead of the next expected value; the producer must resend the
    /// missing records first.
    Gap { expected: i64, got: i64 },
}

/// Sequences remembered per (producer, partition).
pub const WINDOW: usize = 128;
/// Upper bound on distinct producers tracked, across all keys.
const MAX_PRODUCERS: usize = 100_000;
/// Upper bound on producers owned by one key: one tenant cannot fill the
/// global table and lock every other tenant out of idempotent produce.
pub const MAX_PRODUCERS_PER_KEY: usize = 10_000;
/// A producer not seen for this long is forgotten (Kafka's default for
/// transactional ids is the same seven days).
pub const PRODUCER_EXPIRY: Duration = Duration::from_secs(7 * 24 * 3600);

#[derive(Debug, Clone, Default)]
struct PartitionWindow {
    last_seen: i64,
    last_offset: u64,
    recent: VecDeque<(i64, u64)>,
}

/// One producer's state. Lock it (via [`ProducerRegistry::admit`]) for the
/// whole check-append-record sequence of a request.
#[derive(Debug, Default)]
pub struct ProducerState {
    owner: String,
    last_used_ms: i64,
    partitions: BTreeMap<(String, u32), PartitionWindow>,
}

impl ProducerState {
    pub fn check(&self, topic: &str, partition: u32, sequence: i64) -> DedupeOutcome {
        let Some(w) = self.partitions.get(&(topic.to_string(), partition)) else {
            // First record from this producer on this partition. Any starting
            // sequence is accepted: a client may resume after its own restart.
            return DedupeOutcome::Accept;
        };
        if sequence == w.last_seen.saturating_add(1) {
            return DedupeOutcome::Accept;
        }
        if sequence > w.last_seen {
            return DedupeOutcome::Gap {
                expected: w.last_seen.saturating_add(1),
                got: sequence,
            };
        }
        if let Some((_, off)) = w.recent.iter().find(|(s, _)| *s == sequence) {
            return DedupeOutcome::Duplicate { prev_offset: *off };
        }
        if sequence == w.last_seen {
            return DedupeOutcome::Duplicate {
                prev_offset: w.last_offset,
            };
        }
        DedupeOutcome::SequenceTooLow {
            last_seen: w.last_seen,
        }
    }

    pub fn record(&mut self, topic: &str, partition: u32, sequence: i64, offset: u64) {
        let w = self
            .partitions
            .entry((topic.to_string(), partition))
            .or_default();
        if w.recent.is_empty() || sequence > w.last_seen {
            w.last_seen = sequence;
            w.last_offset = offset;
        }
        w.recent.push_back((sequence, offset));
        while w.recent.len() > WINDOW {
            w.recent.pop_front();
        }
        self.last_used_ms = now_ms();
    }

    pub fn touch(&mut self) {
        self.last_used_ms = now_ms();
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedPartition {
    topic: String,
    partition: u32,
    last_seen_sequence: i64,
    last_offset: u64,
    #[serde(default)]
    recent: Vec<(i64, u64)>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedProducer {
    producer_id: String,
    #[serde(default)]
    owner: String,
    #[serde(default)]
    last_used_ms: i64,
    partitions: Vec<PersistedPartition>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedRegistry {
    producers: Vec<PersistedProducer>,
}

/// One journal line: an accepted sequence.
#[derive(Debug, Serialize, Deserialize)]
struct JournalEntry {
    p: String,
    o: String,
    t: String,
    n: u32,
    s: i64,
    f: u64,
}

/// Why a producer id was refused.
#[derive(Debug)]
pub enum AdmitError {
    Invalid(String),
    /// Owned by another key.
    Forbidden(String),
    Limit(String),
}

impl std::fmt::Display for AdmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) | Self::Forbidden(m) | Self::Limit(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for AdmitError {}

type Slot = Arc<Mutex<ProducerState>>;

pub struct ProducerRegistry {
    file_path: PathBuf,
    journal_path: PathBuf,
    state: DashMap<String, Slot>,
    per_owner: DashMap<String, usize>,
    journal: std::sync::Mutex<Option<std::fs::File>>,
    /// Serializes flushes (and revocations) against each other.
    flush_lock: Mutex<()>,
    dirty: AtomicBool,
}

impl ProducerRegistry {
    pub fn open(dir: PathBuf) -> Result<Arc<Self>> {
        crate::fsutil::create_dir_all_private(&dir)
            .with_context(|| format!("create dir {:?}", dir))?;
        let file_path = dir.join("producers.json");
        let journal_path = dir.join("producers.journal");
        let reg = Self {
            file_path: file_path.clone(),
            journal_path: journal_path.clone(),
            state: DashMap::new(),
            per_owner: DashMap::new(),
            journal: std::sync::Mutex::new(None),
            flush_lock: Mutex::new(()),
            dirty: AtomicBool::new(false),
        };
        match std::fs::read(&file_path) {
            Ok(bytes) => {
                let persisted: PersistedRegistry = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parse {:?}", file_path))?;
                for p in persisted.producers {
                    let mut st = ProducerState {
                        owner: p.owner,
                        last_used_ms: if p.last_used_ms == 0 {
                            now_ms()
                        } else {
                            p.last_used_ms
                        },
                        partitions: BTreeMap::new(),
                    };
                    for q in p.partitions {
                        st.partitions.insert(
                            (q.topic, q.partition),
                            PartitionWindow {
                                last_seen: q.last_seen_sequence,
                                last_offset: q.last_offset,
                                recent: q.recent.into_iter().collect(),
                            },
                        );
                    }
                    *reg.per_owner.entry(st.owner.clone()).or_insert(0) += 1;
                    reg.state.insert(p.producer_id, Arc::new(Mutex::new(st)));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        // Replay journals newer than the snapshot: a rotated one left by a
        // flush that crashed mid-way, then the live one.
        for path in [rotated(&journal_path), journal_path.clone()] {
            reg.replay(&path)?;
        }
        Ok(Arc::new(reg))
    }

    fn replay(&self, path: &Path) -> Result<()> {
        let f = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let mut n = 0usize;
        for line in std::io::BufReader::new(f).lines() {
            let Ok(line) = line else { break };
            // A torn last line is the only kind there can be.
            let Ok(e) = serde_json::from_str::<JournalEntry>(&line) else {
                break;
            };
            let slot = self.state.entry(e.p.clone()).or_insert_with(|| {
                *self.per_owner.entry(e.o.clone()).or_insert(0) += 1;
                Arc::new(Mutex::new(ProducerState {
                    owner: e.o.clone(),
                    last_used_ms: now_ms(),
                    partitions: BTreeMap::new(),
                }))
            });
            slot.try_lock()
                .expect("no contention during open")
                .record(&e.t, e.n, e.s, e.f);
            n += 1;
        }
        if n > 0 {
            self.dirty.store(true, Ordering::Release);
            tracing::info!(journal = ?path, entries = n, "replayed producer journal");
        }
        Ok(())
    }

    /// Validate `producer_id`, check it belongs to `owner` (claiming it if it
    /// is new), and return its state locked for the caller's request.
    pub async fn admit(
        &self,
        producer_id: &str,
        owner: &str,
    ) -> Result<OwnedMutexGuard<ProducerState>, AdmitError> {
        if producer_id.is_empty() || producer_id.len() > 200 {
            return Err(AdmitError::Invalid(
                "producer_id length must be 1..=200".into(),
            ));
        }
        if !producer_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(AdmitError::Invalid(
                "producer_id may only contain ASCII alphanumerics, '_', '-', '.'".into(),
            ));
        }
        let slot = match self.state.get(producer_id).map(|s| s.clone()) {
            Some(s) => s,
            None => {
                if self.state.len() >= MAX_PRODUCERS {
                    return Err(AdmitError::Limit(format!(
                        "producer limit reached ({})",
                        MAX_PRODUCERS
                    )));
                }
                if self.per_owner.get(owner).map(|c| *c).unwrap_or(0) >= MAX_PRODUCERS_PER_KEY {
                    return Err(AdmitError::Limit(format!(
                        "this key already owns {} producer ids",
                        MAX_PRODUCERS_PER_KEY
                    )));
                }
                let mut created = false;
                let slot = self
                    .state
                    .entry(producer_id.to_string())
                    .or_insert_with(|| {
                        created = true;
                        Arc::new(Mutex::new(ProducerState {
                            owner: owner.to_string(),
                            last_used_ms: now_ms(),
                            partitions: BTreeMap::new(),
                        }))
                    })
                    .clone();
                if created {
                    *self.per_owner.entry(owner.to_string()).or_insert(0) += 1;
                }
                slot
            }
        };
        let mut guard = slot.lock_owned().await;
        if guard.owner.is_empty() {
            // State persisted before ownership existed: first key to use it
            // after the upgrade claims it.
            guard.owner = owner.to_string();
            *self.per_owner.entry(owner.to_string()).or_insert(0) += 1;
        }
        if guard.owner != owner {
            return Err(AdmitError::Forbidden(format!(
                "producer_id '{}' belongs to another key",
                producer_id
            )));
        }
        guard.touch();
        Ok(guard)
    }

    /// Durably record sequences accepted by a request, before it is
    /// acknowledged. Blocking; call from a blocking thread.
    pub fn journal(
        &self,
        producer_id: &str,
        owner: &str,
        entries: &[(String, u32, i64, u64)],
    ) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut buf = Vec::new();
        for (t, n, s, f) in entries {
            serde_json::to_writer(
                &mut buf,
                &JournalEntry {
                    p: producer_id.to_string(),
                    o: owner.to_string(),
                    t: t.clone(),
                    n: *n,
                    s: *s,
                    f: *f,
                },
            )?;
            buf.push(b'\n');
        }
        let mut guard = self.journal.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = Some(crate::fsutil::open_append_private(&self.journal_path)?);
        }
        let f = guard.as_mut().unwrap();
        f.write_all(&buf)?;
        f.sync_data()?;
        self.dirty.store(true, Ordering::Release);
        Ok(())
    }

    pub async fn list(&self) -> Vec<ProducerStateDto> {
        let mut out: Vec<ProducerStateDto> = Vec::with_capacity(self.state.len());
        let slots: Vec<(String, Slot)> = self
            .state
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().clone()))
            .collect();
        for (id, slot) in slots {
            let guard = slot.lock().await;
            let partitions = guard
                .partitions
                .iter()
                .map(|((topic, partition), st)| ProducerPartitionStateDto {
                    topic: topic.clone(),
                    partition: *partition,
                    last_seen_sequence: st.last_seen,
                    last_offset: st.last_offset,
                })
                .collect();
            out.push(ProducerStateDto {
                producer_id: id,
                partitions,
            });
        }
        out.sort_by(|a, b| a.producer_id.cmp(&b.producer_id));
        out
    }

    pub async fn revoke(&self, producer_id: &str) -> Result<()> {
        let Some((_, slot)) = self.state.remove(producer_id) else {
            return Err(anyhow!("producer '{}' not found", producer_id));
        };
        let owner = slot.lock().await.owner.clone();
        if let Some(mut c) = self.per_owner.get_mut(&owner) {
            *c = c.saturating_sub(1);
        }
        self.dirty.store(true, Ordering::Release);
        // Immediately: a revoked producer replayed from the journal on the
        // next boot would come back.
        self.flush().await
    }

    /// Forget producers idle longer than `max_idle`.
    pub async fn expire(&self, max_idle: Duration) -> usize {
        let cutoff = now_ms().saturating_sub(max_idle.as_millis() as i64);
        let slots: Vec<(String, Slot)> = self
            .state
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().clone()))
            .collect();
        let mut removed = 0;
        for (id, slot) in slots {
            let g = slot.lock().await;
            if g.last_used_ms < cutoff {
                let owner = g.owner.clone();
                drop(g);
                if self.state.remove(&id).is_some() {
                    removed += 1;
                    if let Some(mut c) = self.per_owner.get_mut(&owner) {
                        *c = c.saturating_sub(1);
                    }
                }
            }
        }
        if removed > 0 {
            self.dirty.store(true, Ordering::Release);
        }
        removed
    }

    /// Compact the journal into `producers.json`.
    ///
    /// The live journal is rotated aside first, so records journaled while
    /// the snapshot is being taken land in a fresh file. Every entry in the
    /// rotated journal was applied to memory before it was written, hence
    /// before the snapshot: once the snapshot is durable the rotated journal
    /// is redundant.
    pub async fn flush(&self) -> Result<()> {
        let _guard = self.flush_lock.lock().await;
        self.dirty.store(false, Ordering::Release);
        {
            let mut j = self.journal.lock().unwrap_or_else(|e| e.into_inner());
            *j = None;
            if self.journal_path.exists() {
                std::fs::rename(&self.journal_path, rotated(&self.journal_path))?;
            }
        }
        let slots: Vec<(String, Slot)> = self
            .state
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().clone()))
            .collect();
        let mut producers = Vec::with_capacity(slots.len());
        for (id, slot) in slots {
            let g = slot.lock().await;
            producers.push(PersistedProducer {
                producer_id: id,
                owner: g.owner.clone(),
                last_used_ms: g.last_used_ms,
                partitions: g
                    .partitions
                    .iter()
                    .map(|((t, p), w)| PersistedPartition {
                        topic: t.clone(),
                        partition: *p,
                        last_seen_sequence: w.last_seen,
                        last_offset: w.last_offset,
                        recent: w.recent.iter().copied().collect(),
                    })
                    .collect(),
            });
        }
        producers.sort_by(|a, b| a.producer_id.cmp(&b.producer_id));
        let bytes = serde_json::to_vec(&PersistedRegistry { producers })?;
        let path = self.file_path.clone();
        let old = rotated(&self.journal_path);
        tokio::task::spawn_blocking(move || -> Result<()> {
            crate::fsutil::write_atomic(&path, &bytes)?;
            let _ = std::fs::remove_file(&old);
            Ok(())
        })
        .await
        .map_err(|e| anyhow!("producer flush task: {e}"))??;
        Ok(())
    }
}

fn rotated(journal: &Path) -> PathBuf {
    journal.with_extension("journal.old")
}

/// Spawn a background task that periodically compacts producer state and
/// expires idle producers.
pub fn spawn_flusher(
    registry: Arc<ProducerRegistry>,
    interval: Duration,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut since_expiry = Duration::ZERO;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(interval) => {}
            }
            since_expiry += interval;
            if since_expiry >= Duration::from_secs(60) {
                since_expiry = Duration::ZERO;
                let n = registry.expire(PRODUCER_EXPIRY).await;
                if n > 0 {
                    tracing::info!(expired = n, "producers: idle producer ids forgotten");
                }
            }
            if registry.dirty.load(Ordering::Acquire) {
                if let Err(e) = registry.flush().await {
                    tracing::warn!(error = %e, "producers flusher: flush failed");
                }
            }
        }
        if registry.dirty.load(Ordering::Acquire) {
            let _ = registry.flush().await;
        }
        tracing::info!("producers flusher: stopped");
    })
}

fn now_ms() -> i64 {
    crate::partition::now_ms()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn another_key_cannot_use_a_producer_id() {
        let dir = tempfile::tempdir().unwrap();
        let reg = ProducerRegistry::open(dir.path().to_path_buf()).unwrap();
        drop(reg.admit("p1", "key_a").await.unwrap());
        assert!(matches!(
            reg.admit("p1", "key_b").await,
            Err(AdmitError::Forbidden(_))
        ));
    }

    #[test]
    fn window_recognises_a_retried_batch() {
        let mut st = ProducerState::default();
        for s in 0..10 {
            assert_eq!(st.check("t", 0, s), DedupeOutcome::Accept);
            st.record("t", 0, s, 100 + s as u64);
        }
        assert_eq!(
            st.check("t", 0, 3),
            DedupeOutcome::Duplicate { prev_offset: 103 }
        );
        assert_eq!(st.check("t", 0, 10), DedupeOutcome::Accept);
        assert!(matches!(st.check("t", 0, 12), DedupeOutcome::Gap { .. }));
    }

    #[tokio::test]
    async fn journaled_state_survives_without_a_flush() {
        let dir = tempfile::tempdir().unwrap();
        {
            let reg = ProducerRegistry::open(dir.path().to_path_buf()).unwrap();
            let mut g = reg.admit("p1", "k").await.unwrap();
            g.record("t", 0, 5, 42);
            drop(g);
            reg.journal("p1", "k", &[("t".into(), 0, 5, 42)]).unwrap();
            // No flush: simulates a crash before the periodic compaction.
        }
        let reg = ProducerRegistry::open(dir.path().to_path_buf()).unwrap();
        let g = reg.admit("p1", "k").await.unwrap();
        assert_eq!(
            g.check("t", 0, 5),
            DedupeOutcome::Duplicate { prev_offset: 42 }
        );
    }

    #[tokio::test]
    async fn flush_compacts_the_journal() {
        let dir = tempfile::tempdir().unwrap();
        let reg = ProducerRegistry::open(dir.path().to_path_buf()).unwrap();
        let mut g = reg.admit("p1", "k").await.unwrap();
        g.record("t", 0, 1, 7);
        drop(g);
        reg.journal("p1", "k", &[("t".into(), 0, 1, 7)]).unwrap();
        reg.flush().await.unwrap();
        assert!(!dir.path().join("producers.journal").exists());
        drop(reg);
        let reg = ProducerRegistry::open(dir.path().to_path_buf()).unwrap();
        let g = reg.admit("p1", "k").await.unwrap();
        assert_eq!(
            g.check("t", 0, 1),
            DedupeOutcome::Duplicate { prev_offset: 7 }
        );
    }
}
