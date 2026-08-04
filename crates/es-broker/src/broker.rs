use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::auth::{AuthMode, KeyStore};
use crate::config::Config;
use crate::coord::GroupCoordinator;
use crate::groups::GroupStore;
use crate::producers::ProducerRegistry;
use crate::raft::RaftHub;
use crate::schema::SchemaStore;
use crate::tiered_storage::TieredStore;
use crate::topic::{Topic, TopicConfig};
use es_protocol::TopicConfigPatch;

/// How long a dropped Raft peer connection waits before redialing.
const RAFT_RECONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(2);

pub struct Broker {
    pub config: Arc<Config>,
    pub topics: DashMap<String, Arc<Topic>>,
    pub groups: GroupStore,
    pub keys: Arc<KeyStore>,
    pub producers: Arc<ProducerRegistry>,
    pub coordinator: Arc<GroupCoordinator>,
    pub schemas: Arc<SchemaStore>,
    pub tiered_store: Option<Arc<dyn TieredStore>>,
    pub shutdown: CancellationToken,
    background: Mutex<Vec<JoinHandle<()>>>,
    /// The shared Raft transport, once `start_raft` has bound it. `None` on a
    /// broker that is not a cluster member.
    raft_hub: Mutex<Option<Arc<RaftHub>>>,
}

impl Broker {
    pub fn open(config: Config) -> Result<Arc<Self>> {
        let config = Arc::new(config);
        let topics_root = topics_root(&config.data_dir);
        let groups_root = groups_root(&config.data_dir);
        std::fs::create_dir_all(&topics_root)
            .with_context(|| format!("create dir {:?}", topics_root))?;

        let topics = DashMap::new();
        for entry in std::fs::read_dir(&topics_root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue,
            };
            let topic = Topic::open(&topics_root, &name, &config)
                .with_context(|| format!("open topic {}", name))?;
            topics.insert(name, topic);
        }

        let groups = GroupStore::open(groups_root)?;
        let auth_required = config.auth_mode == AuthMode::Required;
        let (keys, _bootstrap_secret) = KeyStore::open(config.data_dir.clone(), auth_required)?;
        let producers = ProducerRegistry::open(config.data_dir.clone())?;
        let coordinator = Arc::new(GroupCoordinator::new(config.coord_member_timeout));
        let schemas = SchemaStore::open(config.data_dir.clone())?;
        let tiered_store: Option<Arc<dyn TieredStore>> =
            config.cold_storage_dir.as_ref().map(|dir| {
                let store: Arc<dyn TieredStore> =
                    Arc::new(crate::tiered_storage::LocalTieredStore::new(dir.clone()));
                store
            });

        Ok(Arc::new(Self {
            config,
            topics,
            groups,
            keys,
            producers,
            coordinator,
            schemas,
            tiered_store,
            shutdown: CancellationToken::new(),
            background: Mutex::new(Vec::new()),
            raft_hub: Mutex::new(None),
        }))
    }

    /// Bind the Raft transport and route every Raft-backed partition over it.
    ///
    /// A no-op on a broker that is not a cluster member. When it *is* one, a
    /// failure here is fatal to startup rather than a warning: a cluster member
    /// whose transport never came up serves reads and accepts writes from its
    /// own copy, reports healthy, and diverges silently.
    pub async fn start_raft(&self) -> Result<()> {
        self.config.validate_raft()?;
        let (node_id, bind) = match (self.config.raft_node_id, self.config.raft_bind) {
            (Some(id), Some(bind)) => (id, bind),
            _ => return Ok(()),
        };

        let hub = RaftHub::bind(
            node_id,
            bind,
            self.config.raft_peer_addrs.clone(),
            RAFT_RECONNECT_BACKOFF,
            self.config.raft_shared_secret.clone(),
        )
        .await
        .with_context(|| format!("bind the raft transport on {bind}"))?;

        for entry in self.topics.iter() {
            entry.value().attach_raft(&hub)?;
        }
        tracing::info!(
            node = node_id,
            bind = %hub.local_addr(),
            peers = self.config.raft_peer_addrs.len(),
            groups = hub.registered_groups(),
            "raft transport up"
        );
        *self.raft_hub.lock().unwrap() = Some(hub);
        Ok(())
    }

    fn raft_hub(&self) -> Option<Arc<RaftHub>> {
        self.raft_hub.lock().unwrap().clone()
    }

    /// Spawn the retention reaper, the compactor, and the producer-state flusher.
    /// Idempotent — calling twice is a programming error and panics.
    pub fn start_background(self: &Arc<Self>) {
        let mut guard = self.background.lock().unwrap();
        assert!(guard.is_empty(), "background tasks already started");
        let reaper = crate::retention::spawn_reaper(
            self,
            self.config.retention_check_interval,
            self.config.segment_delete_grace,
            self.shutdown.clone(),
        );
        let compactor = crate::compaction::spawn_compactor(
            self,
            self.config.compaction_check_interval,
            self.config.segment_delete_grace,
            self.shutdown.clone(),
        );
        let flusher = crate::producers::spawn_flusher(
            self.producers.clone(),
            self.config.producer_flush_interval,
            self.shutdown.clone(),
        );
        let coord_expire = spawn_coord_expire(self.clone(), self.config.coord_expire_interval);
        guard.push(reaper);
        guard.push(compactor);
        guard.push(flusher);
        guard.push(coord_expire);
    }

    pub async fn shutdown_background(&self) {
        self.shutdown.cancel();
        let handles: Vec<JoinHandle<()>> = {
            let mut guard = self.background.lock().unwrap();
            std::mem::take(&mut *guard)
        };
        for h in handles {
            let _ = h.await;
        }
    }

    pub fn create_topic(
        &self,
        name: &str,
        partitions: u32,
        patch: Option<&TopicConfigPatch>,
    ) -> Result<Arc<Topic>> {
        if self.topics.contains_key(name) {
            return Err(anyhow!("topic '{}' already exists", name));
        }
        let topic = Topic::create(
            &topics_root(&self.config.data_dir),
            name,
            partitions,
            &self.config,
            patch,
        )?;
        // Topics are created while the broker is running, so a new one has to
        // join the transport now. Doing it at startup only would leave every
        // topic created after boot unreplicated.
        if let Some(hub) = self.raft_hub() {
            if let Err(e) = topic.attach_raft(&hub) {
                // Undo the creation rather than keep a topic that accepts
                // writes it will never replicate.
                topic.detach_raft(&hub);
                let _ = std::fs::remove_dir_all(topics_root(&self.config.data_dir).join(name));
                return Err(e);
            }
        }
        self.topics.insert(name.to_string(), topic.clone());
        Ok(topic)
    }

    pub fn update_topic_config(
        &self,
        name: &str,
        patch: &TopicConfigPatch,
    ) -> Result<Arc<TopicConfig>> {
        let topic = self
            .topic(name)
            .ok_or_else(|| anyhow!("topic '{}' not found", name))?;
        topic.update_config(patch, &self.config)
    }

    pub fn topic(&self, name: &str) -> Option<Arc<Topic>> {
        self.topics.get(name).map(|r| r.clone())
    }

    pub fn list_topics(&self) -> Vec<String> {
        let mut names: Vec<String> = self.topics.iter().map(|kv| kv.key().clone()).collect();
        names.sort();
        names
    }

    pub fn delete_topic(&self, name: &str) -> Result<Arc<Topic>> {
        let topic = self
            .topic(name)
            .ok_or_else(|| anyhow!("topic '{}' not found", name))?;
        self.topics.remove(name);
        if let Some(hub) = self.raft_hub() {
            topic.detach_raft(&hub);
        }
        if let Err(e) = std::fs::remove_dir_all(topics_root(&self.config.data_dir).join(name)) {
            tracing::warn!(topic = %name, error = %e, "failed to clean up topic directory");
        }
        // The Raft state directory too. Leaving it behind would give a topic
        // later recreated under this name a log whose term and index run ahead
        // of its empty partition, and the apply loop would replay the deleted
        // topic's entries into it.
        let raft_dir = self.config.data_dir.join("raft").join(name);
        if raft_dir.exists() {
            if let Err(e) = std::fs::remove_dir_all(&raft_dir) {
                tracing::warn!(topic = %name, error = %e, "failed to clean up raft state directory");
            }
        }
        Ok(topic)
    }
}

pub fn topics_root(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("topics")
}

pub fn groups_root(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("groups")
}

fn spawn_coord_expire(broker: Arc<Broker>, interval: std::time::Duration) -> JoinHandle<()> {
    let cancel = broker.shutdown.clone();
    let weak = Arc::downgrade(&broker);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(interval) => {}
            }
            let Some(b) = weak.upgrade() else {
                break;
            };
            b.coordinator.expire_stale(&b).await;
        }
        tracing::info!("coord: expire task stopped");
    })
}
