use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

/// Pluggable cold-storage backend for offloading sealed segments.
pub trait TieredStore: Send + Sync {
    /// Copy a sealed segment (log + index) to cold storage. Returns bytes stored.
    fn offload(
        &self,
        topic: &str,
        partition_id: u32,
        base_offset: u64,
        log_path: &Path,
        index_path: &Path,
    ) -> Result<u64>;

    /// Fetch a remote segment back to a local directory. The caller passes
    /// the destination directory (typically the partition dir); the method
    /// creates `<base_offset>.log` and `<base_offset>.index` there.
    fn retrieve(
        &self,
        topic: &str,
        partition_id: u32,
        base_offset: u64,
        dest_dir: &Path,
    ) -> Result<()>;

    /// List remote segment base offsets for a partition.
    fn list_remote(&self, topic: &str, partition_id: u32) -> Result<Vec<u64>>;

    /// Delete a remote segment.
    fn delete_remote(&self, topic: &str, partition_id: u32, base_offset: u64) -> Result<()>;
}

/// Local-directory cold storage. Segments are copied to
/// `<root>/<topic>/<partition>/<base_offset>.{log,index}`.
pub struct LocalTieredStore {
    root: PathBuf,
}

impl LocalTieredStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn segment_dir(&self, topic: &str, partition_id: u32) -> PathBuf {
        self.root.join(topic).join(partition_id.to_string())
    }

    fn log_name(base_offset: u64) -> String {
        format!("{:020}.log", base_offset)
    }

    fn index_name(base_offset: u64) -> String {
        format!("{:020}.index", base_offset)
    }
}

impl TieredStore for LocalTieredStore {
    fn offload(
        &self,
        topic: &str,
        partition_id: u32,
        base_offset: u64,
        log_path: &Path,
        index_path: &Path,
    ) -> Result<u64> {
        let dir = self.segment_dir(topic, partition_id);
        fs::create_dir_all(&dir).with_context(|| format!("create cold dir {:?}", dir))?;

        let dest_log = dir.join(Self::log_name(base_offset));
        let dest_idx = dir.join(Self::index_name(base_offset));

        let log_size = fs::copy(log_path, &dest_log)
            .with_context(|| format!("offload log {:?} → {:?}", log_path, dest_log))?;
        fs::copy(index_path, &dest_idx)
            .with_context(|| format!("offload index {:?} → {:?}", index_path, dest_idx))?;
        let idx_size = fs::metadata(&dest_idx).map(|m| m.len()).unwrap_or(0);

        Ok(log_size + idx_size)
    }

    fn retrieve(
        &self,
        topic: &str,
        partition_id: u32,
        base_offset: u64,
        dest_dir: &Path,
    ) -> Result<()> {
        let dir = self.segment_dir(topic, partition_id);
        let src_log = dir.join(Self::log_name(base_offset));
        let src_idx = dir.join(Self::index_name(base_offset));

        if !src_log.exists() {
            return Err(anyhow!(
                "remote segment {}/{}@{} not found",
                topic,
                partition_id,
                base_offset
            ));
        }
        fs::copy(&src_log, dest_dir.join(Self::log_name(base_offset)))
            .with_context(|| format!("retrieve log {:?}", src_log))?;
        if src_idx.exists() {
            fs::copy(&src_idx, dest_dir.join(Self::index_name(base_offset)))
                .with_context(|| format!("retrieve index {:?}", src_idx))?;
        }
        Ok(())
    }

    fn list_remote(&self, topic: &str, partition_id: u32) -> Result<Vec<u64>> {
        let dir = self.segment_dir(topic, partition_id);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut offsets = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name().into_string().unwrap_or_default();
            if name.ends_with(".log") {
                if let Ok(off) = name.trim_end_matches(".log").parse::<u64>() {
                    offsets.push(off);
                }
            }
        }
        offsets.sort_unstable();
        Ok(offsets)
    }

    fn delete_remote(&self, topic: &str, partition_id: u32, base_offset: u64) -> Result<()> {
        let dir = self.segment_dir(topic, partition_id);
        let _ = fs::remove_file(dir.join(Self::log_name(base_offset)));
        let _ = fs::remove_file(dir.join(Self::index_name(base_offset)));
        Ok(())
    }
}
