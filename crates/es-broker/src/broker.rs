use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use dashmap::DashMap;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::auth::{AuthMode, KeyStore};
use crate::config::Config;
use crate::coord::GroupCoordinator;
use crate::groups::GroupStore;
use crate::producers::ProducerRegistry;
use crate::schema::SchemaStore;
use crate::tiered_storage::TieredStore;
use crate::topic::{Topic, TopicConfig};
use es_protocol::TopicConfigPatch;

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
        }))
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
            let Some(b) = weak.upgrade() else { break; };
            b.coordinator.expire_stale(&b).await;
        }
        tracing::info!("coord: expire task stopped");
    })
}
