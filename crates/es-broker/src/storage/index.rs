use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

pub const INDEX_ENTRY_LEN: usize = 16; // u64 rel_offset + u64 file_pos

/// In-memory sparse index for one segment.
///
/// Entries are sorted by `relative_offset` (ascending). For "basic" mode we
/// write one entry per record — still tiny and makes lookups exact.
#[derive(Debug, Default)]
pub struct SparseIndex {
    entries: Vec<(u64, u64)>,
}

impl SparseIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, relative_offset: u64, file_position: u64) {
        self.entries.push((relative_offset, file_position));
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Largest entry with `relative_offset <= target`. Returns `None` if the index
    /// is empty or every entry is greater than `target`.
    pub fn floor(&self, target: u64) -> Option<(u64, u64)> {
        if self.entries.is_empty() {
            return None;
        }
        match self.entries.binary_search_by_key(&target, |(o, _)| *o) {
            Ok(i) => Some(self.entries[i]),
            Err(0) => None,
            Err(i) => Some(self.entries[i - 1]),
        }
    }

    pub fn write_entry(file: &mut File, relative_offset: u64, file_position: u64) -> io::Result<()> {
        let mut buf = [0u8; INDEX_ENTRY_LEN];
        buf[0..8].copy_from_slice(&relative_offset.to_be_bytes());
        buf[8..16].copy_from_slice(&file_position.to_be_bytes());
        file.write_all(&buf)
    }

    pub fn write_all_to(path: &Path, entries: &[(u64, u64)]) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        let mut buf = Vec::with_capacity(entries.len() * INDEX_ENTRY_LEN);
        for (rel, pos) in entries {
            buf.extend_from_slice(&rel.to_be_bytes());
            buf.extend_from_slice(&pos.to_be_bytes());
        }
        file.write_all(&buf)?;
        file.sync_all()?;
        Ok(())
    }

    pub fn load_from(path: &Path) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        if buf.len() % INDEX_ENTRY_LEN != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "index file size is not a multiple of entry size",
            ));
        }
        let mut entries = Vec::with_capacity(buf.len() / INDEX_ENTRY_LEN);
        for chunk in buf.chunks_exact(INDEX_ENTRY_LEN) {
            let rel = u64::from_be_bytes(chunk[0..8].try_into().unwrap());
            let pos = u64::from_be_bytes(chunk[8..16].try_into().unwrap());
            entries.push((rel, pos));
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[(u64, u64)] {
        &self.entries
    }

    pub fn from_entries(entries: Vec<(u64, u64)>) -> Self {
        Self { entries }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_basic() {
        let idx = SparseIndex::from_entries(vec![(0, 0), (10, 100), (20, 200)]);
        assert_eq!(idx.floor(0), Some((0, 0)));
        assert_eq!(idx.floor(5), Some((0, 0)));
        assert_eq!(idx.floor(10), Some((10, 100)));
        assert_eq!(idx.floor(15), Some((10, 100)));
        assert_eq!(idx.floor(25), Some((20, 200)));
    }

    #[test]
    fn floor_empty_or_before() {
        let empty = SparseIndex::default();
        assert_eq!(empty.floor(7), None);
        let idx = SparseIndex::from_entries(vec![(10, 100)]);
        assert_eq!(idx.floor(5), None);
    }
}
