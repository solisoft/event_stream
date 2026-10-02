use std::collections::BTreeSet;
use std::fs::{self, File};
#[cfg(test)]
use std::io::Write;
use std::io::{self, BufWriter, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct Manifest {
    version: u32,
    created_at_ms: u64,
    broker_version: String,
    topics: Vec<String>,
    includes_keys: bool,
    file_count: usize,
    total_bytes: u64,
}

/// Segment log file name for a given base offset.
#[allow(dead_code)]
fn segment_log_name(base_offset: u64) -> String {
    format!("{:020}.log", base_offset)
}

/// Segment index file name for a given base offset.
fn segment_index_name(base_offset: u64) -> String {
    format!("{:020}.index", base_offset)
}

pub fn dump(
    data_dir: &str,
    output: &str,
    topic_filter: Option<&[&str]>,
    include_keys: bool,
    verify: bool,
) -> Result<()> {
    let data_dir = PathBuf::from(data_dir);
    if !data_dir.is_dir() {
        return Err(anyhow::anyhow!(
            "data-dir '{}' does not exist or is not a directory",
            data_dir.display()
        ));
    }

    let filter_set: Option<BTreeSet<&str>> = topic_filter.map(|v| v.iter().copied().collect());
    let entries = discover_files(&data_dir, filter_set.as_ref(), include_keys)?;

    if entries.log_files.is_empty() && entries.metadata_files.is_empty() {
        eprintln!(
            "warning: data-dir '{}' contains no backup-eligible files",
            data_dir.display()
        );
    }

    // Calculate total size
    let mut total_bytes: u64 = 0;
    for log in &entries.log_files {
        if let Ok(meta) = fs::metadata(&log.path) {
            total_bytes += meta.len();
        }
        if let Ok(meta) = fs::metadata(&log.index_path) {
            total_bytes += meta.len();
        }
    }
    for meta_file in &entries.metadata_files {
        if let Ok(meta) = fs::metadata(meta_file) {
            total_bytes += meta.len();
        }
    }

    let manifest = Manifest {
        version: 1,
        created_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        broker_version: env!("CARGO_PKG_VERSION").to_string(),
        topics: entries.topics.iter().cloned().collect(),
        includes_keys: include_keys,
        file_count: entries.log_files.len() * 2 + entries.metadata_files.len() + 1, // +1 for manifest
        total_bytes,
    };

    // The archive holds every tenant's data (and with --include-keys, key
    // hashes): created 0600, not under the umask.
    let out_file = {
        let mut o = fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        o.open(output)
            .with_context(|| format!("create output file '{}'", output))?
    };
    let encoder = GzEncoder::new(BufWriter::new(out_file), Compression::default());
    let mut tar = tar::Builder::new(encoder);

    // Write manifest
    {
        let manifest_json = serde_json::to_vec_pretty(&manifest)?;
        let mut header = tar::Header::new_gnu();
        header.set_path("manifest.json")?;
        header.set_size(manifest_json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "manifest.json", &manifest_json[..])?;
    }

    // Write metadata files
    for meta_path in &entries.metadata_files {
        let rel = meta_path
            .strip_prefix(&data_dir)
            .unwrap_or(meta_path)
            .to_string_lossy()
            .replace('\\', "/");
        add_file_to_tar(&mut tar, meta_path, &rel)?;
    }
    eprintln!(
        "note: segments of a running broker are copied up to the length each had when it was \
         opened; files are not captured at one instant. Stop the broker for a point-in-time backup."
    );

    // Write segment log + index files
    for log_entry in &entries.log_files {
        let rel_log = log_entry
            .path
            .strip_prefix(&data_dir)
            .unwrap_or(&log_entry.path)
            .to_string_lossy()
            .replace('\\', "/");
        let rel_index = log_entry
            .index_path
            .strip_prefix(&data_dir)
            .unwrap_or(&log_entry.index_path)
            .to_string_lossy()
            .replace('\\', "/");

        if verify {
            verify_segment(&log_entry.path)?;
        }

        if !add_file_to_tar(&mut tar, &log_entry.path, &rel_log)? {
            continue;
        }
        if log_entry.index_path.exists() {
            add_file_to_tar(&mut tar, &log_entry.index_path, &rel_index)?;
        }
    }

    let encoder = tar.into_inner()?;
    encoder.finish()?;

    let output_size = fs::metadata(output).map(|m| m.len()).unwrap_or(0);
    eprintln!(
        "backup created: {} ({:.1} MiB, {} segment(s) across {} topic(s))",
        output,
        output_size as f64 / (1024.0 * 1024.0),
        entries.log_files.len(),
        entries.topics.len(),
    );

    Ok(())
}

#[derive(Debug)]
struct LogEntry {
    path: PathBuf,
    index_path: PathBuf,
}

#[derive(Debug)]
struct DiscoveredFiles {
    topics: BTreeSet<String>,
    log_files: Vec<LogEntry>,
    metadata_files: Vec<PathBuf>,
}

fn discover_files(
    data_dir: &Path,
    topic_filter: Option<&BTreeSet<&str>>,
    include_keys: bool,
) -> Result<DiscoveredFiles> {
    let topics_root = data_dir.join("topics");
    let groups_root = data_dir.join("groups");

    let mut topics_set = BTreeSet::new();
    let mut log_files = Vec::new();
    let mut metadata_files = Vec::new();

    // Discover topics and segments
    if topics_root.is_dir() {
        for topic_entry in fs::read_dir(&topics_root)
            .with_context(|| format!("read topics dir {:?}", topics_root))?
        {
            let topic_entry = topic_entry?;
            let topic_path = topic_entry.path();
            if !topic_path.is_dir() {
                continue;
            }
            let topic_name = topic_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();

            if let Some(filter) = topic_filter {
                if !filter.contains(topic_name.as_str()) {
                    continue;
                }
            }
            topics_set.insert(topic_name);

            // topic.json
            let topic_json = topic_path.join("topic.json");
            if topic_json.exists() {
                metadata_files.push(topic_json);
            }

            // Partition directories
            for part_entry in fs::read_dir(&topic_path)? {
                let part_entry = part_entry?;
                let part_path = part_entry.path();
                if !part_path.is_dir() {
                    continue;
                }
                let part_name = part_path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                // Skip non-numeric directory names (not a partition)
                if part_name.parse::<u32>().is_err() {
                    continue;
                }

                // Find .log files
                let mut log_offsets = Vec::new();
                for file_entry in fs::read_dir(&part_path)? {
                    let file_entry = file_entry?;
                    let file_name = file_entry.file_name().to_string_lossy().into_owned();
                    if file_name.ends_with(".log") && !file_name.contains(".compact.tmp.") {
                        let stem = file_name.trim_end_matches(".log");
                        if let Ok(off) = stem.parse::<u64>() {
                            log_offsets.push((off, file_entry.path()));
                        }
                    }
                }
                log_offsets.sort_by_key(|(o, _)| *o);

                for (off, log_path) in log_offsets {
                    let index_path = part_path.join(segment_index_name(off));
                    log_files.push(LogEntry {
                        path: log_path,
                        index_path,
                    });
                }
            }
        }
    }

    // Group offsets
    if groups_root.is_dir() {
        for entry in fs::read_dir(&groups_root)
            .with_context(|| format!("read groups dir {:?}", groups_root))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                metadata_files.push(path);
            }
        }
    }

    // Schema store
    let schemas_path = data_dir.join("schemas.json");
    if schemas_path.exists() {
        metadata_files.push(schemas_path);
    }

    // Producer registry: the compacted state and the journal of what was
    // accepted since (both are needed to restore it exactly).
    for name in [
        "producers.json",
        "producers.journal.old",
        "producers.journal",
    ] {
        let p = data_dir.join(name);
        if p.exists() {
            metadata_files.push(p);
        }
    }

    // Auth keys (only if --include-keys). The broker's file is
    // `api_keys.json`; the tool looked for `keys.json`, found nothing, and
    // still wrote `includes_keys: true` into the manifest. `bootstrap.key`
    // (a plaintext secret) is never included.
    if include_keys {
        let keys_path = data_dir.join("api_keys.json");
        if keys_path.exists() {
            metadata_files.push(keys_path);
        } else {
            eprintln!("warning: --include-keys given but no api_keys.json in the data dir");
        }
    }

    Ok(DiscoveredFiles {
        topics: topics_set,
        log_files,
        metadata_files,
    })
}

/// A reader that yields exactly `len` bytes: the file's bytes up to `len`,
/// zero-padded if the file turned out shorter.
///
/// The tar header carries a size; tar copies whatever the reader yields. A
/// segment that grew between `metadata()` and the copy (the broker is
/// appending) wrote more bytes than its header declared and every following
/// entry became unreadable.
struct Exactly<R> {
    inner: io::Take<R>,
    pad: u64,
}

impl<R: Read> Read for Exactly<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 || buf.is_empty() {
            return Ok(n);
        }
        let remaining = self.inner.limit() + self.pad;
        if remaining == 0 {
            return Ok(0);
        }
        // The file ended early: account for what is missing, then pad.
        if self.inner.limit() > 0 {
            self.pad += self.inner.limit();
            self.inner.set_limit(0);
        }
        let k = (self.pad as usize).min(buf.len());
        buf[..k].fill(0);
        self.pad -= k as u64;
        Ok(k)
    }
}

/// Add one file. Returns `false` (and warns) if it vanished before it could
/// be opened — retention or compaction removed it mid-dump.
fn add_file_to_tar<W: io::Write>(
    tar: &mut tar::Builder<W>,
    src_path: &Path,
    archive_path: &str,
) -> Result<bool> {
    let file = match File::open(src_path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            eprintln!(
                "warning: {:?} disappeared during the dump; skipped",
                src_path
            );
            return Ok(false);
        }
        Err(e) => return Err(e).with_context(|| format!("open {:?}", src_path)),
    };
    let meta = file
        .metadata()
        .with_context(|| format!("metadata {:?}", src_path))?;
    let len = meta.len();

    let mut header = tar::Header::new_gnu();
    header.set_path(archive_path)?;
    header.set_size(len);
    header.set_mode(0o600);
    header.set_mtime(
        meta.modified()
            .ok()
            .and_then(timestamp_from_systime)
            .unwrap_or(0),
    );
    header.set_cksum();
    let reader = Exactly {
        inner: file.take(len),
        pad: 0,
    };
    tar.append_data(&mut header, archive_path, reader)?;

    Ok(true)
}

fn timestamp_from_systime(t: SystemTime) -> Option<u64> {
    t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

/// Verify a segment log file by reading every record and checking CRC.
fn verify_segment(path: &Path) -> Result<()> {
    let mut file =
        File::open(path).with_context(|| format!("open segment {:?} for verification", path))?;
    let file_size = file.metadata()?.len();
    let mut records = 0u64;
    loop {
        let pos = file.stream_position()?;
        if pos >= file_size {
            break;
        }
        match read_record(&mut file) {
            Ok(_) => records += 1,
            Err(e) if e.to_string().contains("eof") || pos >= file_size => break,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "segment {:?} corrupted at byte {}: {}",
                    path,
                    pos,
                    e
                ));
            }
        }
    }
    eprintln!(
        "  verified {:?}: {} record(s) ok",
        path.file_name().unwrap_or_default(),
        records
    );
    Ok(())
}

// ——— minimal record reader (duplicated from es-broker to avoid pulling in axum/tokio) ———

const HEADER_LEN: usize = 8 + 8 + 4;
const VALUE_LEN_FIELD: usize = 4;
const CRC_LEN: usize = 4;
const RECORD_LEN_FIELD: usize = 4;
const MAX_RECORD_BODY_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Record {
    offset: u64,
    _timestamp_ms: i64,
    _key: Option<Vec<u8>>,
    _value: Vec<u8>,
}

#[derive(Debug)]
enum RecordErr {
    Eof,
    Truncated { at: u64 },
    CrcMismatch { at: u64, stored: u32, computed: u32 },
    Invalid { at: u64, reason: &'static str },
    Io(io::Error),
}

impl std::fmt::Display for RecordErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eof => write!(f, "eof"),
            Self::Truncated { at } => write!(f, "truncated record at byte {}", at),
            Self::CrcMismatch {
                at,
                stored,
                computed,
            } => {
                write!(
                    f,
                    "crc mismatch at byte {}: stored={:#010x} computed={:#010x}",
                    at, stored, computed
                )
            }
            Self::Invalid { at, reason } => write!(f, "invalid record at byte {}: {}", at, reason),
            Self::Io(e) => write!(f, "io: {}", e),
        }
    }
}

impl From<io::Error> for RecordErr {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

fn read_record<R: Read + Seek>(reader: &mut R) -> Result<Record, RecordErr> {
    let at = reader.stream_position()?;

    let mut len_buf = [0u8; RECORD_LEN_FIELD];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(RecordErr::Eof);
        }
        Err(e) => return Err(e.into()),
    }
    let body_len = u32::from_be_bytes(len_buf) as usize;

    if body_len < HEADER_LEN + VALUE_LEN_FIELD + CRC_LEN {
        return Err(RecordErr::Invalid {
            at,
            reason: "body_len below minimum",
        });
    }
    // Same cap as the broker: a corrupt length must not become a 4 GiB
    // allocation.
    if body_len > MAX_RECORD_BODY_BYTES {
        return Err(RecordErr::Invalid {
            at,
            reason: "body_len exceeds maximum",
        });
    }

    let mut body = vec![0u8; body_len];
    if let Err(e) = reader.read_exact(&mut body) {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            reader.seek(SeekFrom::Start(at))?;
            return Err(RecordErr::Truncated { at });
        }
        return Err(e.into());
    }

    let mut p = 0usize;
    let offset = u64::from_be_bytes(body[p..p + 8].try_into().unwrap());
    p += 8;
    let timestamp_ms = i64::from_be_bytes(body[p..p + 8].try_into().unwrap());
    p += 8;
    let key_len = i32::from_be_bytes(body[p..p + 4].try_into().unwrap());
    p += 4;

    let key = if key_len < 0 {
        if key_len != -1 {
            return Err(RecordErr::Invalid {
                at,
                reason: "key_len negative != -1",
            });
        }
        None
    } else {
        let kl = key_len as usize;
        if p + kl > body.len() {
            return Err(RecordErr::Truncated { at });
        }
        let k = body[p..p + kl].to_vec();
        p += kl;
        Some(k)
    };

    if p + VALUE_LEN_FIELD > body.len() {
        return Err(RecordErr::Truncated { at });
    }
    let value_len = u32::from_be_bytes(body[p..p + 4].try_into().unwrap()) as usize;
    p += 4;
    if p + value_len + CRC_LEN != body.len() {
        return Err(RecordErr::Invalid {
            at,
            reason: "value_len does not match remaining body",
        });
    }
    let value = body[p..p + value_len].to_vec();
    p += value_len;

    let stored_crc = u32::from_be_bytes(body[p..p + 4].try_into().unwrap());
    let computed_crc = crc32fast::hash(&body[..p]);
    if stored_crc != computed_crc {
        return Err(RecordErr::CrcMismatch {
            at,
            stored: stored_crc,
            computed: computed_crc,
        });
    }

    Ok(Record {
        offset,
        _timestamp_ms: timestamp_ms,
        _key: key,
        _value: value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_truncates_and_pads() {
        let mut long = Exactly {
            inner: (&b"abcdef"[..]).take(3),
            pad: 0,
        };
        let mut out = Vec::new();
        long.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"abc");

        let mut short = Exactly {
            inner: (&b"ab"[..]).take(5),
            pad: 0,
        };
        let mut out = Vec::new();
        short.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"ab\0\0\0");
    }

    #[test]
    fn a_growing_file_does_not_corrupt_the_archive() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("a.log");
        std::fs::write(&src, vec![1u8; 1000]).unwrap();
        let mut buf = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut buf);
            // Size captured at open...
            let file = File::open(&src).unwrap();
            let len = file.metadata().unwrap().len();
            // ...then the broker appends.
            std::fs::OpenOptions::new()
                .append(true)
                .open(&src)
                .unwrap()
                .write_all(&[2u8; 700])
                .unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_path("a.log").unwrap();
            header.set_size(len);
            header.set_cksum();
            tar.append_data(
                &mut header,
                "a.log",
                Exactly {
                    inner: file.take(len),
                    pad: 0,
                },
            )
            .unwrap();
            add_file_to_tar(&mut tar, &src, "b.log").unwrap();
            tar.finish().unwrap();
        }
        let mut ar = tar::Archive::new(&buf[..]);
        let names: Vec<String> = ar
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["a.log", "b.log"]);
    }
}
