use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    response::IntoResponse,
};

use crate::broker::Broker;

/// Prometheus text-exposition handler.
///
/// Format: `metric{label="v"} value\n`. Labels are escaped per the Prometheus spec
/// (only `"`, `\`, and `\n` need handling — topic/group names pass `validate_name`
/// which already restricts the alphabet, but we escape defensively).
pub async fn metrics(State(broker): State<Arc<Broker>>) -> impl IntoResponse {
    let body = render_metrics(&broker).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4"),
    );
    (headers, body)
}

async fn render_metrics(broker: &Arc<Broker>) -> String {
    let mut out = String::with_capacity(4096);

    out.push_str("# HELP es_partition_start_offset Earliest offset retained in the partition.\n");
    out.push_str("# TYPE es_partition_start_offset gauge\n");
    let topic_names = broker.list_topics();
    for name in &topic_names {
        let Some(topic) = broker.topic(name) else { continue };
        for p in &topic.partitions {
            writeln!(
                out,
                r#"es_partition_start_offset{{topic="{}",partition="{}"}} {}"#,
                esc(name),
                p.id,
                p.start_offset()
            )
            .ok();
        }
    }

    out.push_str("# HELP es_partition_end_offset High watermark (offset of the next record to be produced).\n");
    out.push_str("# TYPE es_partition_end_offset gauge\n");
    for name in &topic_names {
        let Some(topic) = broker.topic(name) else { continue };
        for p in &topic.partitions {
            writeln!(
                out,
                r#"es_partition_end_offset{{topic="{}",partition="{}"}} {}"#,
                esc(name),
                p.id,
                p.end_offset()
            )
            .ok();
        }
    }

    out.push_str("# HELP es_partition_size_bytes On-disk size of the partition across all segments.\n");
    out.push_str("# TYPE es_partition_size_bytes gauge\n");
    for name in &topic_names {
        let Some(topic) = broker.topic(name) else { continue };
        for p in &topic.partitions {
            writeln!(
                out,
                r#"es_partition_size_bytes{{topic="{}",partition="{}"}} {}"#,
                esc(name),
                p.id,
                p.total_size_bytes()
            )
            .ok();
        }
    }

    out.push_str("# HELP es_partition_segment_count Number of segments currently in the partition.\n");
    out.push_str("# TYPE es_partition_segment_count gauge\n");
    for name in &topic_names {
        let Some(topic) = broker.topic(name) else { continue };
        for p in &topic.partitions {
            writeln!(
                out,
                r#"es_partition_segment_count{{topic="{}",partition="{}"}} {}"#,
                esc(name),
                p.id,
                p.segment_count()
            )
            .ok();
        }
    }

    // Topic-level counters.
    out.push_str("# HELP es_topic_records_produced_total Records appended via produce.\n");
    out.push_str("# TYPE es_topic_records_produced_total counter\n");
    for name in &topic_names {
        let Some(topic) = broker.topic(name) else { continue };
        writeln!(
            out,
            r#"es_topic_records_produced_total{{topic="{}"}} {}"#,
            esc(name),
            topic.records_produced_total.load(Ordering::Relaxed)
        )
        .ok();
    }
    out.push_str("# HELP es_topic_bytes_produced_total Bytes of key+value appended via produce.\n");
    out.push_str("# TYPE es_topic_bytes_produced_total counter\n");
    for name in &topic_names {
        let Some(topic) = broker.topic(name) else { continue };
        writeln!(
            out,
            r#"es_topic_bytes_produced_total{{topic="{}"}} {}"#,
            esc(name),
            topic.bytes_produced_total.load(Ordering::Relaxed)
        )
        .ok();
    }
    out.push_str("# HELP es_topic_records_consumed_total Records served via consume.\n");
    out.push_str("# TYPE es_topic_records_consumed_total counter\n");
    for name in &topic_names {
        let Some(topic) = broker.topic(name) else { continue };
        writeln!(
            out,
            r#"es_topic_records_consumed_total{{topic="{}"}} {}"#,
            esc(name),
            topic.records_consumed_total.load(Ordering::Relaxed)
        )
        .ok();
    }
    out.push_str("# HELP es_topic_bytes_consumed_total Bytes of key+value served via consume.\n");
    out.push_str("# TYPE es_topic_bytes_consumed_total counter\n");
    for name in &topic_names {
        let Some(topic) = broker.topic(name) else { continue };
        writeln!(
            out,
            r#"es_topic_bytes_consumed_total{{topic="{}"}} {}"#,
            esc(name),
            topic.bytes_consumed_total.load(Ordering::Relaxed)
        )
        .ok();
    }

    // Retention / compaction.
    out.push_str("# HELP es_retention_segments_deleted_total Segments deleted by the reaper.\n");
    out.push_str("# TYPE es_retention_segments_deleted_total counter\n");
    for name in &topic_names {
        let Some(topic) = broker.topic(name) else { continue };
        for p in &topic.partitions {
            writeln!(
                out,
                r#"es_retention_segments_deleted_total{{topic="{}",partition="{}"}} {}"#,
                esc(name),
                p.id,
                p.retention_segments_deleted_total.load(Ordering::Relaxed)
            )
            .ok();
        }
    }
    out.push_str("# HELP es_retention_bytes_reclaimed_total Bytes reclaimed by the reaper.\n");
    out.push_str("# TYPE es_retention_bytes_reclaimed_total counter\n");
    for name in &topic_names {
        let Some(topic) = broker.topic(name) else { continue };
        for p in &topic.partitions {
            writeln!(
                out,
                r#"es_retention_bytes_reclaimed_total{{topic="{}",partition="{}"}} {}"#,
                esc(name),
                p.id,
                p.retention_bytes_reclaimed_total.load(Ordering::Relaxed)
            )
            .ok();
        }
    }
    out.push_str("# HELP es_compaction_runs_total Compaction passes completed.\n");
    out.push_str("# TYPE es_compaction_runs_total counter\n");
    for name in &topic_names {
        let Some(topic) = broker.topic(name) else { continue };
        for p in &topic.partitions {
            writeln!(
                out,
                r#"es_compaction_runs_total{{topic="{}",partition="{}"}} {}"#,
                esc(name),
                p.id,
                p.compaction_runs_total.load(Ordering::Relaxed)
            )
            .ok();
        }
    }
    out.push_str("# HELP es_compaction_records_dropped_total Records discarded by compaction (dupes + expired tombstones).\n");
    out.push_str("# TYPE es_compaction_records_dropped_total counter\n");
    for name in &topic_names {
        let Some(topic) = broker.topic(name) else { continue };
        for p in &topic.partitions {
            writeln!(
                out,
                r#"es_compaction_records_dropped_total{{topic="{}",partition="{}"}} {}"#,
                esc(name),
                p.id,
                p.compaction_records_dropped_total.load(Ordering::Relaxed)
            )
            .ok();
        }
    }

    // Group offsets + lag. Snapshot one group at a time to avoid holding many locks.
    out.push_str("# HELP es_group_committed_offset Last committed offset for the (group, topic, partition).\n");
    out.push_str("# TYPE es_group_committed_offset gauge\n");
    out.push_str("# HELP es_group_lag Records between the committed offset and the partition's high watermark.\n");
    out.push_str("# TYPE es_group_lag gauge\n");
    let group_names: Vec<String> = broker
        .groups
        .iter_group_names()
        .into_iter()
        .collect();
    for g in &group_names {
        let snapshot = broker.groups.snapshot(g).await;
        for (topic_name, parts) in snapshot {
            let Some(topic) = broker.topic(&topic_name) else { continue };
            for (pid, committed) in parts {
                let p = match topic.partitions.get(pid as usize) {
                    Some(p) => p,
                    None => continue,
                };
                let hwm = p.end_offset();
                writeln!(
                    out,
                    r#"es_group_committed_offset{{group="{}",topic="{}",partition="{}"}} {}"#,
                    esc(g),
                    esc(&topic_name),
                    pid,
                    committed
                )
                .ok();
                let lag = hwm.saturating_sub(committed);
                writeln!(
                    out,
                    r#"es_group_lag{{group="{}",topic="{}",partition="{}"}} {}"#,
                    esc(g),
                    esc(&topic_name),
                    pid,
                    lag
                )
                .ok();
            }
        }
    }

    out
}

fn esc(s: &str) -> String {
    // Prometheus label-value escaping: backslash, double quote, newline.
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}
