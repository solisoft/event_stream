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

/// Most partitions one topic may have. Mirrors `es_broker::topic::MAX_PARTITIONS`
/// (this crate does not link the broker): a restored topic.json above it would
/// be refused by the broker at startup.
const MAX_PARTITIONS: u32 = 10_000;

/// Default for `--max-bytes`: the most archive payload a restore unpacks.
pub const DEFAULT_MAX_BYTES: u64 = 1 << 40;
/// Default for `--max-entries`: the most archive entries a restore reads.
pub const DEFAULT_MAX_ENTRIES: u64 = 1_000_000;

/// What the operator allows a restore to do. The archive's own manifest is
/// never an authority on any of it (Bonfire #711): whoever wrote the archive
/// wrote the manifest too.
#[derive(Debug, Clone)]
pub struct RestoreOptions {
    /// Replace a non-empty data directory (moved aside, never deleted).
    pub force: bool,
    /// Restore `api_keys.json`. Without it a key file in the archive is
    /// skipped, whatever the manifest claims.
    pub with_keys: bool,
    /// Ceiling on the bytes of every entry read, restored or skipped.
    pub max_bytes: u64,
    /// Ceiling on the number of entries read, directories and empty files
    /// included.
    pub max_entries: u64,
}

impl Default for RestoreOptions {
    fn default() -> Self {
        Self {
            force: false,
            with_keys: false,
            max_bytes: DEFAULT_MAX_BYTES,
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

/// Restore `input` into `data_dir`.
///
/// The archive is extracted into a staging directory next to `data_dir` and
/// validated there — manifest first and supported, every path on the
/// allow-list, sizes within what the manifest declared and what `opts`
/// allow, every topic.json one the broker will open — before the existing
/// data is touched. Only then is the old directory moved aside (never deleted:
/// its new name is printed) and the staging directory renamed into place.
///
/// The old order deleted the data directory first and opened the archive
/// second, so a typo in `--input` or a truncated archive destroyed live data.
pub fn restore(input: &str, data_dir: &str, opts: &RestoreOptions) -> Result<()> {
    let data_dir = PathBuf::from(data_dir);
    let has_content = data_dir.exists()
        && fs::read_dir(&data_dir)
            .map(|mut rd| rd.next().is_some())
            .unwrap_or(false);
    if has_content && !opts.force {
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
    let staging = create_staging_dir(&parent, &base)?;

    let extracted =
        extract(file, input, &staging, opts).and_then(|v| validate_topics(&staging).map(|_| v));
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

/// A topic.json is a few hundred bytes; anything near this is not one.
const MAX_TOPIC_META_BYTES: u64 = 1024 * 1024;

fn extract(
    file: File,
    input: &str,
    staging: &Path,
    opts: &RestoreOptions,
) -> Result<(Manifest, usize, u64)> {
    let decoder = GzDecoder::new(BufReader::new(file));
    let mut archive = tar::Archive::new(decoder);

    let mut manifest: Option<Manifest> = None;
    let mut files_restored: usize = 0;
    let mut bytes_restored: u64 = 0;
    // Every entry counts, restored or skipped, directory or empty file: the
    // tar stream is decompressed in full either way.
    let mut entries_read: u64 = 0;
    let mut bytes_read: u64 = 0;

    for entry in archive.entries()? {
        let mut entry = entry?;
        entries_read += 1;
        if entries_read > opts.max_entries {
            return Err(anyhow::anyhow!(
                "archive has more than {} entries (--max-entries); refusing to continue",
                opts.max_entries
            ));
        }
        bytes_read = bytes_read
            .checked_add(entry.size())
            .filter(|b| *b <= opts.max_bytes)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "archive holds more than {} bytes (--max-bytes); refusing to continue",
                    opts.max_bytes
                )
            })?;
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
        if is_key_file(&path) && !opts.with_keys {
            eprintln!(
                "warning: skipping '{}': API keys are restored only with --with-keys{}",
                path_str,
                if m.includes_keys {
                    " (the archive says it includes them)"
                } else {
                    ""
                }
            );
            continue;
        }
        if !is_allowed(&path, entry_type.is_dir(), opts.with_keys) {
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
        if path_str.ends_with("topic.json") && size > MAX_TOPIC_META_BYTES {
            return Err(anyhow::anyhow!("'{}' is implausibly large", path_str));
        }
        bytes_restored = bytes_restored.saturating_add(size);
        if bytes_restored > m.total_bytes.saturating_add(SIZE_SLACK_BYTES) {
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

/// Create the staging directory `.<base>.restore-<random>` in `parent`.
///
/// One `mkdir`, mode 0700, that fails if the name exists — never a recursive
/// create, which follows a symlink planted at a predictable name (the old
/// suffix was the pid) and would extract into wherever it points (Bonfire
/// #719). The result is checked with `symlink_metadata` before use.
fn create_staging_dir(parent: &Path, base: &str) -> Result<PathBuf> {
    let mut last_err = None;
    for _ in 0..8 {
        let staging = parent.join(format!(".{}.restore-{:016x}", base, random_u64()));
        let mut b = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        match b.create(&staging) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => {
                return Err(e).with_context(|| format!("create staging dir {:?}", staging));
            }
        }
        let meta = fs::symlink_metadata(&staging)
            .with_context(|| format!("stat staging dir {:?}", staging))?;
        if !meta.file_type().is_dir() {
            return Err(anyhow::anyhow!(
                "staging dir {:?} is not a plain directory",
                staging
            ));
        }
        return Ok(staging);
    }
    Err(anyhow::anyhow!(
        "could not create a staging dir in {:?}: {}",
        parent,
        last_err.map(|e| e.to_string()).unwrap_or_default()
    ))
}

/// 64 unpredictable bits without a `rand` dependency: std seeds every
/// `RandomState` from the OS generator.
fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u32(std::process::id());
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    h.finish()
}

fn is_key_file(path: &Path) -> bool {
    let mut normal = path.components().filter_map(|c| match c {
        std::path::Component::Normal(s) => Some(s),
        _ => None,
    });
    matches!((normal.next(), normal.next()), (Some(f), None) if f == "api_keys.json")
}

/// The subset of the broker's topic.json a restore checks.
#[derive(Debug, serde::Deserialize)]
struct TopicMeta {
    partitions: u32,
    #[serde(default)]
    config: TopicMetaConfig,
}

#[derive(Debug, Default, serde::Deserialize)]
struct TopicMetaConfig {
    #[serde(default)]
    cleanup_policy: Option<String>,
    #[serde(default)]
    segment_bytes: Option<u64>,
}

/// Every restored topic must be one the broker can open: a topic.json that
/// parses, a partition count within 1..=MAX_PARTITIONS, a config the broker
/// accepts, and no partition directory beyond the count. A bad one used to be
/// restored as is and the broker then refused to start (Bonfire #711).
fn validate_topics(staging: &Path) -> Result<()> {
    let topics = staging.join("topics");
    let rd = match fs::read_dir(&topics) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context("read restored topics"),
    };
    for entry in rd {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !valid_name(&name) {
            return Err(anyhow::anyhow!(
                "restored topic '{}' has an invalid name",
                name
            ));
        }
        let dir = entry.path();
        let bytes = fs::read(dir.join("topic.json"))
            .with_context(|| format!("topic '{}' has no topic.json", name))?;
        let meta = parse_topic_meta(&bytes).with_context(|| format!("topic '{}'", name))?;
        for p in fs::read_dir(&dir)? {
            let p = p?;
            if !p.file_type()?.is_dir() {
                continue;
            }
            let id: u32 = p
                .file_name()
                .to_string_lossy()
                .parse()
                .map_err(|_| anyhow::anyhow!("topic '{}': stray directory", name))?;
            if id >= meta.partitions {
                return Err(anyhow::anyhow!(
                    "topic '{}': partition {} beyond its {} partition(s)",
                    name,
                    id,
                    meta.partitions
                ));
            }
        }
    }
    Ok(())
}

fn parse_topic_meta(bytes: &[u8]) -> Result<TopicMeta> {
    let meta: TopicMeta = serde_json::from_slice(bytes).context("parse topic.json")?;
    if meta.partitions == 0 || meta.partitions > MAX_PARTITIONS {
        return Err(anyhow::anyhow!(
            "topic.json: partitions must be between 1 and {} (found {})",
            MAX_PARTITIONS,
            meta.partitions
        ));
    }
    if let Some(sb) = meta.config.segment_bytes {
        if !(128..=(1u64 << 40)).contains(&sb) {
            return Err(anyhow::anyhow!(
                "topic.json: segment_bytes must be between 128 bytes and 1 TiB"
            ));
        }
    }
    if let Some(cp) = meta.config.cleanup_policy.as_deref() {
        if !matches!(cp, "delete" | "compact" | "compact,delete") {
            return Err(anyhow::anyhow!(
                "topic.json: unknown cleanup_policy '{}'",
                cp
            ));
        }
    }
    Ok(meta)
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
        let opts = super::RestoreOptions {
            with_keys: true,
            ..Default::default()
        };
        super::restore(out.to_str().unwrap(), dst.to_str().unwrap(), &opts).unwrap();
        assert!(dst.join("topics/t/0/00000000000000000000.log").exists());
        assert!(dst.join("groups/g.json").exists());
        assert!(
            dst.join("api_keys.json").exists(),
            "--include-keys and --with-keys must round-trip api_keys.json"
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
        let force = super::RestoreOptions {
            force: true,
            ..Default::default()
        };
        assert!(super::restore(bogus.to_str().unwrap(), data.to_str().unwrap(), &force).is_err());
        assert!(super::restore("/does/not/exist.tar.gz", data.to_str().unwrap(), &force).is_err());
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

    use super::RestoreOptions;

    const SEG: &str = "00000000000000000000";

    /// Write a gzipped tar of `entries` (path, contents; `None` = directory)
    /// after a manifest with the given `includes_keys` and `total_bytes`.
    fn archive(
        dir: &Path,
        includes_keys: bool,
        total_bytes: u64,
        entries: &[(&str, Option<&[u8]>)],
    ) -> std::path::PathBuf {
        let out = dir.join("crafted.tar.gz");
        let f = std::fs::File::create(&out).unwrap();
        let gz = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
        let mut tar = tar::Builder::new(gz);
        let manifest = serde_json::json!({
            "version": 1, "created_at_ms": 0, "broker_version": "test",
            "topics": [], "includes_keys": includes_keys,
            "file_count": entries.len() + 1, "total_bytes": total_bytes,
        })
        .to_string();
        let mut add = |path: &str, data: Option<&[u8]>| {
            let mut h = tar::Header::new_gnu();
            match data {
                Some(d) => {
                    h.set_entry_type(tar::EntryType::Regular);
                    h.set_size(d.len() as u64);
                    h.set_mode(0o644);
                    h.set_cksum();
                    tar.append_data(&mut h, path, d).unwrap();
                }
                None => {
                    h.set_entry_type(tar::EntryType::Directory);
                    h.set_size(0);
                    h.set_mode(0o755);
                    h.set_cksum();
                    tar.append_data(&mut h, path, &[][..]).unwrap();
                }
            }
        };
        add("manifest.json", Some(manifest.as_bytes()));
        for (p, d) in entries {
            add(p, *d);
        }
        tar.into_inner().unwrap().finish().unwrap();
        out
    }

    fn topic(partitions: &str) -> Vec<(String, Option<Vec<u8>>)> {
        vec![
            ("topics".into(), None),
            ("topics/t".into(), None),
            (
                "topics/t/topic.json".into(),
                Some(format!(r#"{{"partitions":{partitions}}}"#).into_bytes()),
            ),
            ("topics/t/0".into(), None),
            (format!("topics/t/0/{SEG}.log"), Some(Vec::new())),
        ]
    }

    fn run(
        entries: &[(String, Option<Vec<u8>>)],
        includes_keys: bool,
        total_bytes: u64,
        opts: &RestoreOptions,
    ) -> (tempfile::TempDir, anyhow::Result<()>) {
        let dir = tempfile::tempdir().unwrap();
        let e: Vec<(&str, Option<&[u8]>)> = entries
            .iter()
            .map(|(p, d)| (p.as_str(), d.as_deref()))
            .collect();
        let a = archive(dir.path(), includes_keys, total_bytes, &e);
        let dst = dir.path().join("dst");
        let r = super::restore(a.to_str().unwrap(), dst.to_str().unwrap(), opts);
        (dir, r)
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".restore-"))
            .collect()
    }

    /// Bonfire #711: the manifest is written by whoever wrote the archive.
    /// Saying `includes_keys: true` no longer installs credentials; only the
    /// operator's --with-keys does.
    #[test]
    fn keys_are_restored_only_with_the_flag() {
        let mut e = topic("1");
        e.push(("api_keys.json".into(), Some(b"{\"keys\":[]}".to_vec())));

        let (dir, r) = run(&e, true, 1 << 20, &RestoreOptions::default());
        r.unwrap();
        assert!(!dir.path().join("dst/api_keys.json").exists());
        assert!(dir.path().join("dst/topics/t/topic.json").exists());

        let with = RestoreOptions {
            with_keys: true,
            ..Default::default()
        };
        let (dir, r) = run(&e, false, 1 << 20, &with);
        r.unwrap();
        assert!(dir.path().join("dst/api_keys.json").exists());
    }

    #[test]
    fn entry_and_byte_ceilings_hold_whatever_the_manifest_says() {
        let mut e = topic("1");
        for i in 0..20 {
            e.push((format!("groups/g{i}.json"), Some(Vec::new())));
        }
        // Directories and empty files count toward --max-entries.
        let opts = RestoreOptions {
            max_entries: 10,
            ..Default::default()
        };
        let (dir, r) = run(&e, false, u64::MAX, &opts);
        assert!(format!("{:#}", r.unwrap_err()).contains("--max-entries"));
        assert!(!dir.path().join("dst").exists());
        assert!(leftovers(dir.path()).is_empty(), "staging removed");

        // A manifest total near u64::MAX cannot raise the CLI ceiling, nor
        // wrap the running count.
        let mut e = topic("1");
        e.push(("schemas.json".into(), Some(vec![b' '; 4096])));
        let opts = RestoreOptions {
            max_bytes: 1024,
            ..Default::default()
        };
        let (dir, r) = run(&e, false, u64::MAX, &opts);
        assert!(format!("{:#}", r.unwrap_err()).contains("--max-bytes"));
        assert!(!dir.path().join("dst").exists());

        let (_dir, r) = run(&e, false, u64::MAX, &RestoreOptions::default());
        r.unwrap();
    }

    #[test]
    fn a_topic_the_broker_could_not_open_is_refused() {
        for bad in ["4294967295", "0", "10001", "\"x\""] {
            let (dir, r) = run(&topic(bad), false, 1 << 20, &RestoreOptions::default());
            assert!(r.is_err(), "partitions {bad} accepted");
            assert!(!dir.path().join("dst").exists());
            assert!(leftovers(dir.path()).is_empty());
        }
        // A partition directory beyond the declared count.
        let mut e = topic("1");
        e.push(("topics/t/3".into(), None));
        let (_dir, r) = run(&e, false, 1 << 20, &RestoreOptions::default());
        assert!(format!("{:#}", r.unwrap_err()).contains("beyond"));
        // A topic without its topic.json.
        let e: Vec<(String, Option<Vec<u8>>)> = topic("1")
            .into_iter()
            .filter(|(p, _)| !p.ends_with("topic.json"))
            .collect();
        let (_dir, r) = run(&e, false, 1 << 20, &RestoreOptions::default());
        assert!(r.is_err());
        // Config the broker rejects.
        let mut e = topic("1");
        e[2].1 = Some(br#"{"partitions":1,"config":{"segment_bytes":1}}"#.to_vec());
        let (_dir, r) = run(&e, false, 1 << 20, &RestoreOptions::default());
        assert!(r.is_err());
    }

    /// Bonfire #719: the staging directory is unpredictable, private, created
    /// by a single non-recursive mkdir, and never an existing path.
    #[test]
    fn staging_dir_is_fresh_private_and_unpredictable() {
        let dir = tempfile::tempdir().unwrap();
        let a = super::create_staging_dir(dir.path(), "data").unwrap();
        let b = super::create_staging_dir(dir.path(), "data").unwrap();
        assert_ne!(a, b);
        let name = a.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with(".data.restore-"));
        assert!(!name.ends_with(&std::process::id().to_string()));
        let meta = std::fs::symlink_metadata(&a).unwrap();
        assert!(meta.file_type().is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        }
        // A parent that does not exist is not created on the way.
        assert!(super::create_staging_dir(&dir.path().join("missing/x"), "data").is_err());
        assert!(!dir.path().join("missing").exists());
    }
}
