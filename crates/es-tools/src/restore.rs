use std::fs::{self, File};
use std::io::BufReader;
use std::io::Read;
use std::path::{Path, PathBuf};

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

/// Restore `input` into `data_dir`.
///
/// The archive is extracted into a staging directory next to `data_dir` and
/// validated there — manifest first and supported, every path on the
/// allow-list, sizes within what the manifest declared — before the existing
/// data is touched. Only then is the old directory moved aside (never deleted:
/// its new name is printed) and the staging directory renamed into place.
///
/// The old order deleted the data directory first and opened the archive
/// second, so a typo in `--input` or a truncated archive destroyed live data.
pub fn restore(input: &str, data_dir: &str, force: bool) -> Result<()> {
    let data_dir = PathBuf::from(data_dir);
    let has_content = data_dir.exists()
        && fs::read_dir(&data_dir)
            .map(|mut rd| rd.next().is_some())
            .unwrap_or(false);
    if has_content && !force {
        return Err(anyhow::anyhow!(
            "data-dir '{}' already exists and is not empty. Use --force to replace it (the \
             current contents are kept under a new name).",
            data_dir.display()
        ));
    }

    // Open the archive before anything else exists.
    let file = File::open(input).with_context(|| format!("open archive '{}'", input))?;

    let parent = match data_dir.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let base = data_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "data".into());
    let staging = parent.join(format!(".{}.restore-{}", base, std::process::id()));
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    create_private_dir(&staging)?;

    let extracted = extract(file, input, &staging);
    let (manifest, files_restored, bytes_restored) = match extracted {
        Ok(v) => v,
        Err(e) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
    };

    if has_content {
        let aside = parent.join(format!(
            "{}.pre-restore-{}",
            base,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        ));
        fs::rename(&data_dir, &aside)
            .with_context(|| format!("move existing data-dir aside to {:?}", aside))?;
        eprintln!(
            "existing data directory moved to '{}' (delete it once the restore is verified)",
            aside.display()
        );
    } else if data_dir.exists() {
        fs::remove_dir(&data_dir).ok();
    }
    fs::rename(&staging, &data_dir)
        .with_context(|| format!("move restored data into {:?}", data_dir))?;

    eprintln!(
        "restore complete: {} file(s) ({:.1} MiB) from a v{} backup written to '{}'",
        files_restored,
        bytes_restored as f64 / (1024.0 * 1024.0),
        manifest.version,
        data_dir.display(),
    );
    Ok(())
}

/// Slack allowed over the manifest's declared byte total: files grow between
/// the manifest being written and being copied when dumping a live broker.
const SIZE_SLACK_BYTES: u64 = 64 * 1024 * 1024;

fn extract(file: File, input: &str, staging: &Path) -> Result<(Manifest, usize, u64)> {
    let decoder = GzDecoder::new(BufReader::new(file));
    let mut archive = tar::Archive::new(decoder);

    let mut manifest: Option<Manifest> = None;
    let mut files_restored: usize = 0;
    let mut bytes_restored: u64 = 0;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        let path_str = path.to_string_lossy().into_owned();

        // The manifest comes first (dump writes it first), so everything
        // after it can be checked against what it declares.
        let Some(m) = manifest.as_ref() else {
            if path_str != "manifest.json" {
                return Err(anyhow::anyhow!(
                    "archive '{}' does not start with manifest.json — is this an es backup?",
                    input
                ));
            }
            if entry.size() > 1024 * 1024 {
                return Err(anyhow::anyhow!("manifest.json is implausibly large"));
            }
            let m: Manifest = serde_json::from_reader(&mut entry)
                .with_context(|| "parse manifest.json".to_string())?;
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
            manifest = Some(m);
            continue;
        };

        // Security: only regular files and directories. The broker only ever
        // stores plain files/dirs, so a symlink or hardlink entry is always
        // malicious — extracting one lets a later entry's parent resolve
        // outside the data dir.
        let entry_type = entry.header().entry_type();
        if !(entry_type.is_file() || entry_type.is_dir()) {
            eprintln!(
                "warning: skipping non-regular entry '{}' (type {:?})",
                path_str, entry_type
            );
            continue;
        }

        // Security: refuse paths that could escape the data directory, then
        // refuse anything that is not part of a broker's layout: an archive
        // that plants `bootstrap.key` or an unrequested `api_keys.json` is
        // not restoring data, it is installing credentials.
        if !is_safe_relative_path(&path) {
            eprintln!(
                "warning: skipping entry with unsafe path '{}' (absolute or escapes data-dir)",
                path_str
            );
            continue;
        }
        if !is_allowed(&path, entry_type.is_dir(), m.includes_keys) {
            eprintln!(
                "warning: skipping '{}': not part of a broker data directory",
                path_str
            );
            continue;
        }

        let dest = staging.join(&path);
        if entry_type.is_dir() {
            create_private_dir(&dest)?;
            continue;
        }
        if let Some(parent) = dest.parent() {
            create_private_dir(parent)?;
        }

        let size = entry.size();
        bytes_restored += size;
        if bytes_restored > m.total_bytes + SIZE_SLACK_BYTES {
            return Err(anyhow::anyhow!(
                "archive holds more data than its manifest declares ({} bytes); refusing to \
                 continue",
                m.total_bytes
            ));
        }
        // Written 0600 regardless of the mode recorded in the archive (which
        // can say 0777).
        let mut out = {
            let mut o = fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            o.open(&dest)
                .with_context(|| format!("create {:?}", dest))?
        };
        let copied = std::io::copy(&mut (&mut entry).take(size), &mut out)
            .with_context(|| format!("unpack {:?}", dest))?;
        if copied != size {
            return Err(anyhow::anyhow!("archive truncated inside '{}'", path_str));
        }
        out.sync_all()?;
        files_restored += 1;
    }

    let m = manifest.ok_or_else(|| {
        anyhow::anyhow!(
            "archive '{}' does not contain a manifest.json — is this a valid es backup?",
            input
        )
    })?;
    // The manifest counts itself.
    if files_restored + 1 < m.file_count {
        eprintln!(
            "warning: manifest lists {} file(s), {} restored (segments deleted during the dump \
             are expected to be missing)",
            m.file_count,
            files_restored + 1
        );
    }
    Ok((m, files_restored, bytes_restored))
}

fn create_private_dir(p: &Path) -> Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(p).with_context(|| format!("create dir {:?}", p))
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Whether `path` is something a broker data directory contains.
fn is_allowed(path: &Path, is_dir: bool, includes_keys: bool) -> bool {
    let parts: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    let p: Vec<&str> = parts.iter().map(|s| s.as_str()).collect();
    let segment_file = |f: &str| {
        let (stem, ext) = match f.rsplit_once('.') {
            Some(v) => v,
            None => return false,
        };
        (ext == "log" || ext == "index")
            && stem.len() == 20
            && stem.bytes().all(|b| b.is_ascii_digit())
    };
    if is_dir {
        return match p.as_slice() {
            ["topics"] | ["groups"] => true,
            ["topics", t] => valid_name(t),
            ["topics", t, n] => valid_name(t) && n.parse::<u32>().is_ok(),
            _ => false,
        };
    }
    match p.as_slice() {
        ["schemas.json"]
        | ["producers.json"]
        | ["producers.journal"]
        | ["producers.journal.old"] => true,
        ["api_keys.json"] => includes_keys,
        ["groups", g] => g.strip_suffix(".json").map(valid_name).unwrap_or(false),
        ["topics", t, "topic.json"] => valid_name(t),
        ["topics", t, n, f] => valid_name(t) && n.parse::<u32>().is_ok() && segment_file(f),
        _ => false,
    }
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
    fn only_the_broker_layout_is_allowed() {
        use super::is_allowed;
        assert!(is_allowed(
            Path::new("topics/orders/0/00000000000000000000.log"),
            false,
            false
        ));
        assert!(is_allowed(
            Path::new("topics/orders/topic.json"),
            false,
            false
        ));
        assert!(is_allowed(Path::new("groups/g1.json"), false, false));
        assert!(!is_allowed(Path::new("bootstrap.key"), false, true));
        assert!(!is_allowed(Path::new("api_keys.json"), false, false));
        assert!(is_allowed(Path::new("api_keys.json"), false, true));
        assert!(!is_allowed(
            Path::new("topics/orders/0/evil.sh"),
            false,
            false
        ));
        assert!(!is_allowed(Path::new(".ssh/authorized_keys"), false, false));
    }

    #[test]
    fn dump_then_restore_roundtrips_and_stays_private() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("topics/t/0")).unwrap();
        std::fs::create_dir_all(src.join("groups")).unwrap();
        std::fs::write(src.join("topics/t/topic.json"), br#"{"partitions":1}"#).unwrap();
        std::fs::write(src.join("topics/t/0/00000000000000000000.log"), b"").unwrap();
        std::fs::write(src.join("topics/t/0/00000000000000000000.index"), b"").unwrap();
        std::fs::write(src.join("groups/g.json"), b"{}").unwrap();
        std::fs::write(src.join("api_keys.json"), b"{\"keys\":[]}").unwrap();
        std::fs::write(src.join("bootstrap.key"), b"esk_secret").unwrap();
        let out = dir.path().join("b.tar.gz");
        crate::dump::dump(
            src.to_str().unwrap(),
            out.to_str().unwrap(),
            None,
            true,
            false,
        )
        .unwrap();

        let dst = dir.path().join("dst");
        super::restore(out.to_str().unwrap(), dst.to_str().unwrap(), false).unwrap();
        assert!(dst.join("topics/t/0/00000000000000000000.log").exists());
        assert!(dst.join("groups/g.json").exists());
        assert!(
            dst.join("api_keys.json").exists(),
            "--include-keys must back up api_keys.json"
        );
        assert!(
            !dst.join("bootstrap.key").exists(),
            "a plaintext secret is never backed up"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dst.join("groups/g.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn a_bad_archive_leaves_existing_data_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("schemas.json"), b"precious").unwrap();
        let bogus = dir.path().join("bogus.tar.gz");
        std::fs::write(&bogus, b"not an archive").unwrap();
        assert!(super::restore(bogus.to_str().unwrap(), data.to_str().unwrap(), true).is_err());
        assert!(super::restore("/does/not/exist.tar.gz", data.to_str().unwrap(), true).is_err());
        assert_eq!(
            std::fs::read(data.join("schemas.json")).unwrap(),
            b"precious"
        );
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
