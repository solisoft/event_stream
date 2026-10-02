//! Filesystem helpers shared by every on-disk structure the broker owns.
//!
//! Two properties the call sites kept getting individually wrong:
//!
//!   * **Privacy.** Segments, offsets, API-key hashes and producer state are
//!     tenant data. Created under the default umask they come out world-readable
//!     (0644 / 0755). Everything created through here is 0600 / 0700.
//!   * **Durability of names, not just bytes.** `fsync` on a file makes its
//!     contents durable; a newly created or renamed *entry* is only durable once
//!     the parent directory has been synced too. Without that a crash can bring
//!     back the previous version of a file that was "atomically" replaced.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Mode for every file the broker creates.
pub const FILE_MODE: u32 = 0o600;
/// Mode for every directory the broker creates.
pub const DIR_MODE: u32 = 0o700;

/// `create_dir_all`, but directories that did not exist are created 0700.
pub fn create_dir_all_private(path: &Path) -> io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(DIR_MODE);
    }
    b.create(path)
}

fn private_options() -> OpenOptions {
    let mut o = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(FILE_MODE);
    }
    o
}

/// Open (creating if needed, 0600) a file for appending.
pub fn open_append_private(path: &Path) -> io::Result<File> {
    private_options()
        .create(true)
        .append(true)
        .read(true)
        .open(path)
}

/// Create (or truncate) a file for writing, 0600.
pub fn create_private(path: &Path) -> io::Result<File> {
    private_options()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
}

/// Create a file that must not already exist, 0600. `O_EXCL` means the mode is
/// the one the file is born with — there is no window where it exists with the
/// umask's permissions.
pub fn create_new_private(path: &Path) -> io::Result<File> {
    private_options().create_new(true).write(true).open(path)
}

/// Make the directory entry for something inside `dir` durable.
pub fn fsync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

fn parent_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// A temp name no other writer can be using at the same moment.
///
/// The old scheme was `<name>.json.tmp`: two concurrent writers of the same file
/// opened the same temp path, interleaved their bytes, and one of them renamed
/// a corrupt file into place — which for `api_keys.json` meant a broker that
/// refused to start.
fn unique_tmp(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push(format!(".{}.{}.tmp", std::process::id(), n));
    parent_of(path).join(name)
}

/// Replace `path` with `bytes` atomically and durably: unique temp file (0600),
/// fsync, rename, fsync the directory.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = unique_tmp(path);
    let result = (|| {
        let mut f = create_private(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        fsync_dir(&parent_of(path))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Whether a file name is a leftover of [`write_atomic`] (a crash between the
/// write and the rename). Safe to delete on startup.
pub fn is_atomic_tmp_leftover(name: &str) -> bool {
    name.ends_with(".tmp") && name.matches('.').count() >= 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_replaces_and_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.json");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, FILE_MODE);
        }
        // No temp files left behind.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, vec!["x.json".to_string()]);
    }

    #[test]
    fn concurrent_writers_never_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let p = std::sync::Arc::new(dir.path().join("k.json"));
        let mut hs = Vec::new();
        for t in 0..8u8 {
            let p = p.clone();
            hs.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    let body = vec![b'a' + t; 4096];
                    write_atomic(&p, &body).unwrap();
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        let got = std::fs::read(&*p).unwrap();
        assert_eq!(got.len(), 4096);
        assert!(got.iter().all(|b| *b == got[0]), "interleaved writes");
    }

    #[test]
    fn tmp_leftovers_are_recognised() {
        assert!(is_atomic_tmp_leftover("api_keys.json.123.4.tmp"));
        assert!(!is_atomic_tmp_leftover("api_keys.json"));
    }
}
