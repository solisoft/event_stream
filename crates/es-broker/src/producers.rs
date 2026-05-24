use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::topic::write_json_atomic;
use es_protocol::{ProducerPartitionStateDto, ProducerStateDto};

/// Outcome of `check_and_advance`.
#[derive(Debug)]
pub enum DedupeOutcome {
    /// Record is new; the broker should append it. The caller fills in the
    /// real offset after the append via [`ProducerRegistry::record_offset`].
    Accept,
    /// Exact replay of the most-recently-accepted record. Caller should not
    /// re-append; respond with `prev_offset` and `duplicate = true`.
    Duplicate { prev_offset: u64 },
    /// Sequence is below the last seen value but not equal to it. Likely a
    /// rebased producer or replay of an older window — the broker rejects to
    /// avoid silently dropping new data.
    SequenceTooLow { last_seen: i64 },
    /// Sequence skips ahead of the next expected value. The broker rejects so
    /// the producer can resend the missing records.
    Gap { expected: i64, got: i64 },
    /// Producer state was missing/lost (e.g., across a restart) and the very
    /// first sequence we see is not 0. The caller must decide policy; by
    /// default we accept any starting sequence as the new baseline. Returned
    /// only when `strict` mode is on.
    NeedsInit,
}

#[derive(Debug, Clone)]
struct PartitionState {
    last_seen_sequence: i64,
    last_offset: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedPartition {
    topic: String,
    partition: u32,
    last_seen_sequence: i64,
    last_offset: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedProducer {
    producer_id: String,
    partitions: Vec<PersistedPartition>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedRegistry {
    producers: Vec<PersistedProducer>,
}

#[allow(clippy::type_complexity)]
pub struct ProducerRegistry {
    file_path: PathBuf,
    /// `producer_id` -> `(topic, partition) -> PartitionState`.
    state: DashMap<String, Arc<Mutex<BTreeMap<(String, u32), PartitionState>>>>,
    dirty: AtomicBool,
}

impl ProducerRegistry {
    pub fn open(dir: PathBuf) -> Result<Arc<Self>> {
        std::fs::create_dir_all(&dir).with_context(|| format!("create dir {:?}", dir))?;
        let file_path = dir.join("producers.json");
        let store = Self {
            file_path: file_path.clone(),
            state: DashMap::new(),
            dirty: AtomicBool::new(false),
        };
        if let Ok(bytes) = std::fs::read(&file_path) {
            let persisted: PersistedRegistry = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse {:?}", file_path))?;
            for p in persisted.producers {
                let mut parts: BTreeMap<(String, u32), PartitionState> = BTreeMap::new();
                for q in p.partitions {
                    parts.insert(
                        (q.topic, q.partition),
                        PartitionState {
                            last_seen_sequence: q.last_seen_sequence,
                            last_offset: q.last_offset,
                        },
                    );
                }
                store
                    .state
                    .insert(p.producer_id, Arc::new(Mutex::new(parts)));
            }
        }
        Ok(Arc::new(store))
    }

    fn slot(
        &self,
        producer_id: &str,
    ) -> Arc<Mutex<BTreeMap<(String, u32), PartitionState>>> {
        if let Some(slot) = self.state.get(producer_id) {
            return slot.clone();
        }
        let new_slot = Arc::new(Mutex::new(BTreeMap::new()));
        self.state
            .entry(producer_id.to_string())
            .or_insert(new_slot)
            .clone()
    }

    /// Single-record decision. Holds the per-producer mutex only while the
    /// decision is being made — append happens outside the lock so a slow disk
    /// doesn't serialize unrelated producers.
    pub async fn check_and_advance(
        &self,
        producer_id: &str,
        topic: &str,
        partition: u32,
        sequence: i64,
    ) -> DedupeOutcome {
        let slot = self.slot(producer_id);
        let mut guard = slot.lock().await;
        let key = (topic.to_string(), partition);
        match guard.get(&key) {
            None => {
                // First record we see from this producer on this partition.
                // We don't insist sequence==0 — clients may resume from a known
                // sequence after a client-side restart.
                guard.insert(
                    key,
                    PartitionState {
                        last_seen_sequence: sequence - 1,
                        last_offset: 0,
                    },
                );
                DedupeOutcome::Accept
            }
            Some(ps) => {
                if sequence == ps.last_seen_sequence {
                    DedupeOutcome::Duplicate {
                        prev_offset: ps.last_offset,
                    }
                } else if sequence == ps.last_seen_sequence + 1 {
                    DedupeOutcome::Accept
                } else if sequence < ps.last_seen_sequence {
                    DedupeOutcome::SequenceTooLow {
                        last_seen: ps.last_seen_sequence,
                    }
                } else {
                    DedupeOutcome::Gap {
                        expected: ps.last_seen_sequence + 1,
                        got: sequence,
                    }
                }
            }
        }
    }

    /// After a successful append, commit the new sequence + offset under the
    /// producer's lock. Must be called for every record where `check_and_advance`
    /// returned `Accept`.
    pub async fn record_offset(
        &self,
        producer_id: &str,
        topic: &str,
        partition: u32,
        sequence: i64,
        offset: u64,
    ) {
        let slot = self.slot(producer_id);
        let mut guard = slot.lock().await;
        let key = (topic.to_string(), partition);
        let entry = guard.entry(key).or_insert(PartitionState {
            last_seen_sequence: -1,
            last_offset: 0,
        });
        entry.last_seen_sequence = sequence;
        entry.last_offset = offset;
        self.dirty.store(true, Ordering::Release);
    }

    pub async fn list(&self) -> Vec<ProducerStateDto> {
        let mut out: Vec<ProducerStateDto> = Vec::with_capacity(self.state.len());
        // Snapshot the keys first so we don't hold the DashMap shard across awaits.
        let ids: Vec<String> = self.state.iter().map(|kv| kv.key().clone()).collect();
        for id in ids {
            let slot = self.slot(&id);
            let guard = slot.lock().await;
            let partitions = guard
                .iter()
                .map(|((topic, partition), st)| ProducerPartitionStateDto {
                    topic: topic.clone(),
                    partition: *partition,
                    last_seen_sequence: st.last_seen_sequence,
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
        if self.state.remove(producer_id).is_none() {
            return Err(anyhow!("producer '{}' not found", producer_id));
        }
        self.dirty.store(true, Ordering::Release);
        self.flush().await?;
        Ok(())
    }

    pub async fn flush(&self) -> Result<()> {
        let snapshot = self.list().await;
        let persisted = PersistedRegistry {
            producers: snapshot
                .into_iter()
                .map(|p| PersistedProducer {
                    producer_id: p.producer_id,
                    partitions: p
                        .partitions
                        .into_iter()
                        .map(|pp| PersistedPartition {
                            topic: pp.topic,
                            partition: pp.partition,
                            last_seen_sequence: pp.last_seen_sequence,
                            last_offset: pp.last_offset,
                        })
                        .collect(),
                })
                .collect(),
        };
        write_json_atomic(&self.file_path, &persisted)?;
        self.dirty.store(false, Ordering::Release);
        Ok(())
    }
}

/// Spawn a background task that periodically flushes producer state when dirty.
pub fn spawn_flusher(
    registry: Arc<ProducerRegistry>,
    interval: Duration,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(interval) => {}
            }
            if registry.dirty.load(Ordering::Acquire) {
                if let Err(e) = registry.flush().await {
                    tracing::warn!(error = %e, "producers flusher: flush failed");
                }
            }
        }
        // Final flush on shutdown.
        if registry.dirty.load(Ordering::Acquire) {
            let _ = registry.flush().await;
        }
        tracing::info!("producers flusher: stopped");
    })
}
