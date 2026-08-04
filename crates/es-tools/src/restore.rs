use std::fs::{self, File};
use std::io::BufReader;
use std::path::PathBuf;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;

#[derive(Debug, serde::Deserialize)]
struct Manifest {
    #[allow(dead_code)]
    version: u32,
    #[allow(dead_code)]
    created_at_ms: u64,
    #[allow(dead_code)]
    broker_version: String,
    #[allow(dead_code)]
    topics: Vec<String>,
    #[allow(dead_code)]
    includes_keys: bool,
    #[allow(dead_code)]
    file_count: usize,
    #[allow(dead_code)]
    total_bytes: u64,
}

pub fn restore(input: &str, data_dir: &str, force: bool) -> Result<()> {
    let data_dir = PathBuf::from(data_dir);

    // Check if data-dir already has content
    if data_dir.exists() {
        let has_content = fs::read_dir(&data_dir)
            .map(|mut rd| rd.next().is_some())
            .unwrap_or(false);
        if has_content && !force {
            return Err(anyhow::anyhow!(
                "data-dir '{}' already exists and is not empty. Use --force to overwrite.",
                data_dir.display()
            ));
        }
        if has_content && force {
            eprintln!(
                "warning: removing existing data directory '{}' (--force)",
                data_dir.display()
            );
            fs::remove_dir_all(&data_dir)
                .with_context(|| format!("remove existing data-dir {:?}", data_dir))?;
        }
    }

    fs::create_dir_all(&data_dir).with_context(|| format!("create data-dir {:?}", data_dir))?;

    // Open archive
    let file = File::open(input).with_context(|| format!("open archive '{}'", input))?;
    let decoder = GzDecoder::new(BufReader::new(file));
    let mut archive = tar::Archive::new(decoder);

    let mut manifest: Option<Manifest> = None;
    let mut files_restored: usize = 0;
    let mut bytes_restored: u64 = 0;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        let path_str = path.to_string_lossy();

        // Read manifest first
        if path_str == "manifest.json" {
            manifest = Some(
                serde_json::from_reader(&mut entry)
                    .with_context(|| "parse manifest.json".to_string())?,
            );
            if let Some(ref m) = manifest {
                if m.version > 1 {
                    return Err(anyhow::anyhow!(
                        "unsupported backup version {} (this tool supports version 1)",
                        m.version
                    ));
                }
                eprintln!(
                    "restoring backup v{} from {} ({} topic(s), {} file(s), {:.1} MiB)",
                    m.version,
                    humantime_ms(m.created_at_ms),
                    m.topics.len(),
                    m.file_count,
                    m.total_bytes as f64 / (1024.0 * 1024.0),
                );
            }
            continue;
        }

        // Security: only extract regular files and directories. The broker only
        // ever stores plain files/dirs, so a symlink or hardlink entry is always
        // malicious — extracting one lets a later entry's parent resolve outside
        // the data dir (symlink traversal).
        let entry_type = entry.header().entry_type();
        if !(entry_type.is_file() || entry_type.is_dir()) {
            eprintln!(
                "warning: skipping non-regular entry '{}' (type {:?})",
                path_str, entry_type
            );
            continue;
        }

        // Security: refuse paths that could escape the data directory. We reject
        // absolute paths and any `..` component *before* joining — canonicalize()
        // can't be trusted here because the freshly-created data-dir means the
        // destination doesn't exist yet, and `Path::starts_with` compares
        // components literally (so `data/../../etc` "starts with" `data`).
        if !is_safe_relative_path(&path) {
            eprintln!(
                "warning: skipping entry with unsafe path '{}' (absolute or escapes data-dir)",
                path_str
            );
            continue;
        }

        let dest = data_dir.join(&path);

        // Create parent directories
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create dir {:?}", parent))?;
        }

        if entry_type.is_dir() {
            fs::create_dir_all(&dest).with_context(|| format!("create dir {:?}", dest))?;
            continue;
        }

        // Unpack entry
        let size = entry.size();
        entry
            .unpack(&dest)
            .with_context(|| format!("unpack {:?}", dest))?;

        files_restored += 1;
        bytes_restored += size;
    }

    if manifest.is_none() {
        return Err(anyhow::anyhow!(
            "archive '{}' does not contain a manifest.json — is this a valid es backup?",
            input
        ));
    }

    eprintln!(
        "restore complete: {} file(s) ({:.1} MiB) written to '{}'",
        files_restored,
        bytes_restored as f64 / (1024.0 * 1024.0),
        data_dir.display(),
    );

    Ok(())
}

/// True when `path` is a safe *relative* path that cannot escape the extraction
/// root: no absolute/root/prefix components and no `..` parent references.
fn is_safe_relative_path(path: &std::path::Path) -> bool {
    use std::path::Component;
    let mut saw_component = false;
    for c in path.components() {
        match c {
            Component::Normal(_) => saw_component = true,
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    saw_component
}

fn humantime_ms(ms: u64) -> String {
    // Simple RFC 3339-ish formatting
    let secs = (ms / 1000) as i64;
    let nanos = ((ms % 1000) * 1_000_000) as u32;
    if let Ok(dt) = time_from_unix(secs, nanos) {
        return dt;
    }
    format!("{} ms", ms)
}

fn time_from_unix(secs: i64, nanos: u32) -> Result<String, ()> {
    // Basic manual conversion: seconds since epoch to YYYY-MM-DD HH:MM:SS
    let days_since_epoch = secs / 86400;
    let secs_of_day = secs % 86400;

    // Gregorian calendar calculation
    let (y, m, d) = civil_from_days(days_since_epoch).ok_or(())?;
    let h = secs_of_day / 3600;
    let min = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;

    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y,
        m,
        d,
        h,
        min,
        s,
        nanos / 1_000_000
    ))
}

/// Convert days since Unix epoch to Gregorian (year, month, day).
/// Based on Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> Option<(i64, u32, u32)> {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    Some((y, m, d))
}

#[cfg(test)]
mod tests {
    use super::is_safe_relative_path;
    use std::path::Path;

    #[test]
    fn accepts_normal_relative_paths() {
        assert!(is_safe_relative_path(Path::new("topics/foo/0/000.log")));
        assert!(is_safe_relative_path(Path::new("manifest.json")));
        assert!(is_safe_relative_path(Path::new("./topics/foo")));
    }

    #[test]
    fn rejects_traversal_and_absolute_paths() {
        // Parent-dir traversal (zip-slip) must be rejected.
        assert!(!is_safe_relative_path(Path::new("../../etc/cron.d/pwn")));
        assert!(!is_safe_relative_path(Path::new(
            "topics/../../../etc/passwd"
        )));
        // Absolute paths must be rejected.
        assert!(!is_safe_relative_path(Path::new("/etc/passwd")));
        // Empty path is not a valid extraction target.
        assert!(!is_safe_relative_path(Path::new("")));
    }
}
