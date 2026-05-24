use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use es_protocol::{
    AclActionDto, AclRuleDto, AssignmentResponse, CleanupPolicyDto, CommitRequest, ConsumeResponse,
    CreateKeyRequest, CreateKeyResponse, CreateTopicRequest, DescribeTopicResponse,
    GroupOffsetsResponse, HeartbeatRequest, HeartbeatResponse, JoinGroupRequest, JoinGroupResponse,
    LeaveGroupRequest, ListKeysResponse, ListProducersResponse, ListTopicsResponse, ProduceRecord,
    ProduceRequest, ProduceResponse, ResetOffsetsRequest, ResetOffsetsResponse, TopicConfigDto,
    TopicConfigPatch, TopicSummary,
};

#[derive(Parser, Debug)]
#[command(name = "es", about = "CLI for the es event-streaming broker")]
struct Cli {
    #[arg(long, env = "ES_BROKER", default_value = "http://127.0.0.1:9000")]
    broker: String,

    /// Bearer token sent on every request when auth is enabled on the broker.
    /// May be set via the `ES_AUTH` environment variable.
    #[arg(long, env = "ES_AUTH")]
    auth: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    Topic {
        #[command(subcommand)]
        sub: TopicCmd,
    },
    Produce {
        #[arg(long)]
        topic: String,
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        partition: Option<u32>,
        #[arg(long, conflicts_with = "from_file")]
        value: Option<String>,
        #[arg(long)]
        from_file: Option<PathBuf>,
        /// Enable idempotent producer semantics under this producer id.
        #[arg(long)]
        producer_id: Option<String>,
        /// Sequence for the first record. When --from-file is used, sequences
        /// auto-increment from this value.
        #[arg(long)]
        sequence: Option<i64>,
    },
    Consume {
        #[arg(long)]
        topic: String,
        #[arg(long, requires = "offset")]
        partition: Option<u32>,
        #[arg(long)]
        offset: Option<u64>,
        #[arg(long, conflicts_with = "offset")]
        group: Option<String>,
        #[arg(long, default_value_t = 100)]
        max: usize,
    },
    Commit {
        #[arg(long)]
        group: String,
        #[arg(long)]
        topic: String,
        #[arg(long)]
        partition: u32,
        #[arg(long)]
        offset: u64,
    },
    Group {
        #[command(subcommand)]
        sub: GroupCmd,
    },
    Key {
        #[command(subcommand)]
        sub: KeyCmd,
    },
    Producer {
        #[command(subcommand)]
        sub: ProducerCmd,
    },
    /// Reset every consumer group's committed offset on the given topic
    /// to that partition's current start_offset.
    ResetOffsets {
        #[arg(long)]
        topic: String,
    },
    Schema {
        #[command(subcommand)]
        sub: SchemaCmd,
    },
    Tiered {
        #[command(subcommand)]
        sub: TieredCmd,
    },
}

#[derive(Subcommand, Debug)]
enum TopicCmd {
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, default_value_t = 1)]
        partitions: u32,
        #[arg(long)]
        retention_ms: Option<u64>,
        #[arg(long)]
        retention_bytes: Option<u64>,
        #[arg(long, value_enum)]
        cleanup_policy: Option<CleanupPolicyArg>,
        #[arg(long)]
        segment_bytes: Option<u64>,
        #[arg(long)]
        tombstone_retention_ms: Option<u64>,
    },
    Alter {
        #[arg(long)]
        name: String,
        #[arg(long)]
        retention_ms: Option<u64>,
        #[arg(long)]
        retention_bytes: Option<u64>,
        #[arg(long, value_enum)]
        cleanup_policy: Option<CleanupPolicyArg>,
        #[arg(long)]
        segment_bytes: Option<u64>,
        #[arg(long)]
        tombstone_retention_ms: Option<u64>,
    },
    List,
    Describe {
        #[arg(long)]
        name: String,
    },
    ShowConfig {
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum GroupCmd {
    Show {
        #[arg(long)]
        name: String,
    },
    /// Join a consumer group. Prints the assigned partitions + member_id you
    /// will use for subsequent heartbeats.
    Join {
        #[arg(long)]
        name: String,
        /// Topic names to subscribe to. Repeat for multiple topics.
        #[arg(long = "topic")]
        topics: Vec<String>,
        /// Optional — coordinator picks one if omitted.
        #[arg(long)]
        member_id: Option<String>,
    },
    /// Send a heartbeat from a member to the coordinator.
    Heartbeat {
        #[arg(long)]
        name: String,
        #[arg(long)]
        member_id: String,
        #[arg(long)]
        generation: u64,
    },
    /// Leave the group.
    Leave {
        #[arg(long)]
        name: String,
        #[arg(long)]
        member_id: String,
    },
    /// Fetch the current assignment for a member.
    Assignment {
        #[arg(long)]
        name: String,
        #[arg(long)]
        member_id: String,
    },
}

#[derive(Subcommand, Debug)]
enum ProducerCmd {
    List,
    Revoke {
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum KeyCmd {
    /// Create a new API key. Prints the secret exactly once.
    Create {
        #[arg(long)]
        name: String,
        /// ACL rules in the form `action:topic_prefix`, e.g. `write:orders.` or `admin:*`.
        /// Pass multiple times for several rules. Action is one of read|write|admin.
        #[arg(long = "acl", value_name = "ACTION:PREFIX")]
        acls: Vec<String>,
        #[arg(long)]
        produce_bytes_per_sec: Option<u32>,
        #[arg(long)]
        consume_bytes_per_sec: Option<u32>,
    },
    List,
    Revoke {
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum SchemaCmd {
    /// Register a new schema. Returns the schema ID.
    Register {
        #[arg(long)]
        subject: String,
        /// Schema type: json_schema, avro, or protobuf.
        #[arg(long, default_value = "json_schema")]
        r#type: String,
        /// Path to a JSON file containing the schema definition, or inline JSON.
        #[arg(long)]
        schema: String,
    },
    /// Get a schema by ID.
    Get {
        #[arg(long)]
        id: u32,
    },
    /// List all registered schemas.
    List,
    /// Get the latest schema version for a subject.
    Latest {
        #[arg(long)]
        subject: String,
    },
}

#[derive(Subcommand, Debug)]
enum TieredCmd {
    /// List remote segments for a topic partition.
    List {
        #[arg(long)]
        topic: String,
        #[arg(long)]
        partition: u32,
    },
}

fn parse_acl_rule(s: &str) -> Result<AclRuleDto> {
    let (action_str, prefix) = s
        .split_once(':')
        .ok_or_else(|| anyhow!("--acl must be `action:prefix` (got '{}')", s))?;
    let action = match action_str {
        "read" => AclActionDto::Read,
        "write" => AclActionDto::Write,
        "admin" => AclActionDto::Admin,
        other => return Err(anyhow!("unknown acl action '{}' (read|write|admin)", other)),
    };
    Ok(AclRuleDto {
        action,
        topic_prefix: prefix.to_string(),
    })
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CleanupPolicyArg {
    Delete,
    Compact,
    #[value(name = "compact,delete")]
    CompactDelete,
}

impl CleanupPolicyArg {
    fn to_dto(self) -> CleanupPolicyDto {
        match self {
            Self::Delete => CleanupPolicyDto::Delete,
            Self::Compact => CleanupPolicyDto::Compact,
            Self::CompactDelete => CleanupPolicyDto::CompactDelete,
        }
    }
}

fn build_patch(
    retention_ms: Option<u64>,
    retention_bytes: Option<u64>,
    cleanup_policy: Option<CleanupPolicyArg>,
    segment_bytes: Option<u64>,
    tombstone_retention_ms: Option<u64>,
) -> TopicConfigPatch {
    TopicConfigPatch {
        retention_ms,
        retention_bytes,
        cleanup_policy: cleanup_policy.map(|c| c.to_dto()),
        segment_bytes,
        tombstone_retention_ms,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = build_client(cli.auth.as_deref())?;
    let base = cli.broker.trim_end_matches('/').to_string();
    match cli.cmd {
        Cmd::Topic { sub } => match sub {
            TopicCmd::Create {
                name,
                partitions,
                retention_ms,
                retention_bytes,
                cleanup_policy,
                segment_bytes,
                tombstone_retention_ms,
            } => {
                let patch = build_patch(
                    retention_ms,
                    retention_bytes,
                    cleanup_policy,
                    segment_bytes,
                    tombstone_retention_ms,
                );
                let any_set = patch.retention_ms.is_some()
                    || patch.retention_bytes.is_some()
                    || patch.cleanup_policy.is_some()
                    || patch.segment_bytes.is_some()
                    || patch.tombstone_retention_ms.is_some();
                let body = CreateTopicRequest {
                    name,
                    partitions,
                    config: if any_set { Some(patch) } else { None },
                };
                let resp: TopicSummary =
                    post_json(&client, &format!("{}/topics", base), &body).await?;
                println!(
                    "created topic '{}' with {} partition(s)",
                    resp.name, resp.partitions
                );
            }
            TopicCmd::Alter {
                name,
                retention_ms,
                retention_bytes,
                cleanup_policy,
                segment_bytes,
                tombstone_retention_ms,
            } => {
                let patch = build_patch(
                    retention_ms,
                    retention_bytes,
                    cleanup_policy,
                    segment_bytes,
                    tombstone_retention_ms,
                );
                let resp: TopicConfigDto =
                    put_json(&client, &format!("{}/topics/{}/config", base, name), &patch).await?;
                println!("updated topic '{}' config:", name);
                print_config(&resp);
            }
            TopicCmd::List => {
                let resp: ListTopicsResponse =
                    get_json(&client, &format!("{}/topics", base)).await?;
                if resp.topics.is_empty() {
                    println!("(no topics)");
                } else {
                    for t in resp.topics {
                        println!("{}", t);
                    }
                }
            }
            TopicCmd::Describe { name } => {
                let resp: DescribeTopicResponse =
                    get_json(&client, &format!("{}/topics/{}", base, name)).await?;
                println!("topic {}", resp.name);
                print_config(&resp.config);
                for p in resp.partitions {
                    println!(
                        "  partition {}  start={:>6}  end={:>6}  segments={}  size={}B",
                        p.id, p.start_offset, p.end_offset, p.segment_count, p.size_bytes
                    );
                }
            }
            TopicCmd::ShowConfig { name } => {
                let resp: TopicConfigDto =
                    get_json(&client, &format!("{}/topics/{}/config", base, name)).await?;
                print_config(&resp);
            }
        },
        Cmd::Produce {
            topic,
            key,
            partition,
            value,
            from_file,
            producer_id,
            sequence,
        } => {
            if producer_id.is_some() && sequence.is_none() {
                return Err(anyhow!("--producer-id requires --sequence"));
            }
            let mut next_seq = sequence;
            let records: Vec<ProduceRecord> = if let Some(v) = value {
                vec![ProduceRecord {
                    key: key.clone(),
                    value: v,
                    partition,
                    sequence: next_seq,
                }]
            } else if let Some(path) = from_file {
                let file =
                    std::fs::File::open(&path).with_context(|| format!("open {:?}", path))?;
                BufReader::new(file)
                    .lines()
                    .map_while(|l| l.ok())
                    .filter(|l| !l.is_empty())
                    .map(|v| {
                        let seq = next_seq;
                        if let Some(s) = next_seq.as_mut() {
                            *s += 1;
                        }
                        ProduceRecord {
                            key: key.clone(),
                            value: v,
                            partition,
                            sequence: seq,
                        }
                    })
                    .collect()
            } else {
                return Err(anyhow!("provide --value or --from-file"));
            };

            let body = ProduceRequest {
                records,
                producer_id,
            };
            let resp: ProduceResponse = post_json(
                &client,
                &format!("{}/topics/{}/produce", base, topic),
                &body,
            )
            .await?;
            for r in resp.results {
                let marker = if r.duplicate { " (duplicate)" } else { "" };
                println!("partition={} offset={}{}", r.partition, r.offset, marker);
            }
        }
        Cmd::Consume {
            topic,
            partition,
            offset,
            group,
            max,
        } => {
            let url = if let Some(g) = group {
                let p = partition.ok_or_else(|| anyhow!("--group requires --partition"))?;
                format!(
                    "{}/groups/{}/consume?topic={}&partition={}&max_records={}",
                    base, g, topic, p, max
                )
            } else {
                let p = partition.ok_or_else(|| anyhow!("--partition is required"))?;
                let o = offset.ok_or_else(|| anyhow!("--offset is required"))?;
                format!(
                    "{}/topics/{}/consume?partition={}&offset={}&max_records={}",
                    base, topic, p, o, max
                )
            };
            let resp: ConsumeResponse = get_json(&client, &url).await?;
            for r in &resp.records {
                println!(
                    "p={} off={} ts={} key={:?} value={}",
                    r.partition, r.offset, r.timestamp_ms, r.key, r.value
                );
            }
            println!(
                "-- next_offset={} high_watermark={} ({} record(s))",
                resp.next_offset,
                resp.high_watermark,
                resp.records.len()
            );
        }
        Cmd::Commit {
            group,
            topic,
            partition,
            offset,
        } => {
            let body = CommitRequest {
                topic,
                partition,
                offset,
            };
            let resp = client
                .post(format!("{}/groups/{}/commit", base, group))
                .json(&body)
                .send()
                .await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(anyhow!("commit failed: {} {}", status, body));
            }
            println!("committed");
        }
        Cmd::Group { sub } => match sub {
            GroupCmd::Show { name } => {
                let resp: GroupOffsetsResponse =
                    get_json(&client, &format!("{}/groups/{}/offsets", base, name)).await?;
                if resp.offsets.is_empty() {
                    println!("(no committed offsets for group '{}')", name);
                } else {
                    for (topic, parts) in resp.offsets {
                        println!("topic {}", topic);
                        for (pid, off) in parts {
                            println!("  partition {} -> offset {}", pid, off);
                        }
                    }
                }
            }
            GroupCmd::Join {
                name,
                topics,
                member_id,
            } => {
                let body = JoinGroupRequest { member_id, topics };
                let resp: JoinGroupResponse =
                    post_json(&client, &format!("{}/groups/{}/join", base, name), &body).await?;
                println!("member_id:  {}", resp.member_id);
                println!("generation: {}", resp.generation);
                if resp.assignment.is_empty() {
                    println!("assignment: (none)");
                } else {
                    println!("assignment:");
                    for tp in resp.assignment {
                        println!("  {}/{}", tp.topic, tp.partition);
                    }
                }
            }
            GroupCmd::Heartbeat {
                name,
                member_id,
                generation,
            } => {
                let body = HeartbeatRequest {
                    member_id,
                    generation,
                };
                let resp: HeartbeatResponse = post_json(
                    &client,
                    &format!("{}/groups/{}/heartbeat", base, name),
                    &body,
                )
                .await?;
                match resp {
                    HeartbeatResponse::Ok { generation } => {
                        println!("ok (generation {})", generation)
                    }
                    HeartbeatResponse::RebalanceRequired { current_generation } => {
                        println!(
                            "rebalance required (current_generation {})",
                            current_generation
                        )
                    }
                    HeartbeatResponse::UnknownMember { current_generation } => println!(
                        "unknown member (current_generation {}); rejoin required",
                        current_generation
                    ),
                }
            }
            GroupCmd::Leave { name, member_id } => {
                let body = LeaveGroupRequest { member_id };
                let resp = client
                    .post(format!("{}/groups/{}/leave", base, name))
                    .json(&body)
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(anyhow!("leave failed: {} {}", status, body));
                }
                println!("left");
            }
            GroupCmd::Assignment { name, member_id } => {
                let resp: AssignmentResponse = get_json(
                    &client,
                    &format!(
                        "{}/groups/{}/assignment?member_id={}",
                        base, name, member_id
                    ),
                )
                .await?;
                println!("generation: {}", resp.generation);
                if resp.assignment.is_empty() {
                    println!("(no partitions assigned)");
                } else {
                    for tp in resp.assignment {
                        println!("  {}/{}", tp.topic, tp.partition);
                    }
                }
            }
        },
        Cmd::Key { sub } => match sub {
            KeyCmd::Create {
                name,
                acls,
                produce_bytes_per_sec,
                consume_bytes_per_sec,
            } => {
                let parsed_acls: Result<Vec<_>> = acls.iter().map(|s| parse_acl_rule(s)).collect();
                let parsed_acls = parsed_acls?;
                let body = CreateKeyRequest {
                    name,
                    acls: parsed_acls,
                    produce_bytes_per_sec,
                    consume_bytes_per_sec,
                };
                let resp: CreateKeyResponse =
                    post_json(&client, &format!("{}/admin/keys", base), &body).await?;
                println!("key_id: {}", resp.key.key_id);
                println!("name:   {}", resp.key.name);
                for a in &resp.key.acls {
                    let act = match a.action {
                        AclActionDto::Read => "read",
                        AclActionDto::Write => "write",
                        AclActionDto::Admin => "admin",
                    };
                    println!("acl:    {}:{}", act, a.topic_prefix);
                }
                println!();
                println!("SECRET (shown once, save it now):");
                println!("  {}", resp.secret);
            }
            KeyCmd::List => {
                let resp: ListKeysResponse =
                    get_json(&client, &format!("{}/admin/keys", base)).await?;
                if resp.keys.is_empty() {
                    println!("(no keys)");
                } else {
                    for k in resp.keys {
                        let suffix = if k.disabled { " [revoked]" } else { "" };
                        println!("{}  {}{}", k.key_id, k.name, suffix);
                        for a in &k.acls {
                            let act = match a.action {
                                AclActionDto::Read => "read",
                                AclActionDto::Write => "write",
                                AclActionDto::Admin => "admin",
                            };
                            println!("  acl: {}:{}", act, a.topic_prefix);
                        }
                    }
                }
            }
            KeyCmd::Revoke { id } => {
                let resp = client
                    .delete(format!("{}/admin/keys/{}", base, id))
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(anyhow!("revoke failed: {} {}", status, body));
                }
                println!("revoked {}", id);
            }
        },
        Cmd::Producer { sub } => match sub {
            ProducerCmd::List => {
                let resp: ListProducersResponse =
                    get_json(&client, &format!("{}/admin/producers", base)).await?;
                if resp.producers.is_empty() {
                    println!("(no registered producers)");
                } else {
                    for p in resp.producers {
                        println!("producer {}", p.producer_id);
                        for q in p.partitions {
                            println!(
                                "  topic={} partition={} last_seq={} last_offset={}",
                                q.topic, q.partition, q.last_seen_sequence, q.last_offset
                            );
                        }
                    }
                }
            }
            ProducerCmd::Revoke { id } => {
                let resp = client
                    .delete(format!("{}/admin/producers/{}", base, id))
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(anyhow!("revoke failed: {} {}", status, body));
                }
                println!("revoked producer {}", id);
            }
        },
        Cmd::ResetOffsets { topic } => {
            let body = ResetOffsetsRequest { topic };
            let resp: ResetOffsetsResponse =
                post_json(&client, &format!("{}/admin/reset-offsets", base), &body).await?;
            println!(
                "reset {} entries across {} group(s)",
                resp.entries_reset, resp.groups_affected
            );
        }
        Cmd::Schema { sub } => match sub {
            SchemaCmd::Register {
                subject,
                r#type,
                schema,
            } => {
                let schema_str = if schema.starts_with('{') || schema.starts_with('[') {
                    schema
                } else {
                    std::fs::read_to_string(&schema)
                        .with_context(|| format!("read schema file {}", schema))?
                };
                let body = serde_json::json!({
                    "subject": subject,
                    "type": r#type,
                    "schema": schema_str,
                });
                let resp: serde_json::Value =
                    post_json(&client, &format!("{}/schemas", base), &body).await?;
                println!("id: {}", resp["id"]);
            }
            SchemaCmd::Get { id } => {
                let resp: serde_json::Value =
                    get_json(&client, &format!("{}/schemas/{}", base, id)).await?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            SchemaCmd::List => {
                let resp: serde_json::Value =
                    get_json(&client, &format!("{}/schemas", base)).await?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            SchemaCmd::Latest { subject } => {
                let resp: serde_json::Value = get_json(
                    &client,
                    &format!("{}/subjects/{}/versions/latest", base, subject),
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
        },
        Cmd::Tiered { sub } => match sub {
            TieredCmd::List { topic, partition } => {
                let resp: serde_json::Value = get_json(
                    &client,
                    &format!("{}/admin/tiered/{}/{}", base, topic, partition),
                )
                .await?;
                if let Some(segments) = resp["segments"].as_array() {
                    for s in segments {
                        println!("{}", s);
                    }
                } else {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                }
            }
        },
    }
    Ok(())
}

fn print_config(c: &TopicConfigDto) {
    let policy = match c.cleanup_policy {
        CleanupPolicyDto::Delete => "delete",
        CleanupPolicyDto::Compact => "compact",
        CleanupPolicyDto::CompactDelete => "compact,delete",
    };
    println!("  config:");
    println!("    cleanup_policy         = {}", policy);
    println!("    segment_bytes          = {}", c.segment_bytes);
    println!("    tombstone_retention_ms = {}", c.tombstone_retention_ms);
    match c.retention_ms {
        Some(v) => println!("    retention_ms           = {}", v),
        None => println!("    retention_ms           = (unset, infinite)"),
    }
    match c.retention_bytes {
        Some(v) => println!("    retention_bytes        = {}", v),
        None => println!("    retention_bytes        = (unset, infinite)"),
    }
}

fn build_client(auth: Option<&str>) -> Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(token) = auth {
        let value = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))
            .map_err(|e| anyhow!("invalid auth token: {}", e))?;
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .map_err(|e| anyhow!("reqwest client build failed: {}", e))
}

async fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T> {
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("GET {} failed: {} {}", url, status, body));
    }
    Ok(resp.json().await?)
}

async fn post_json<B: serde::Serialize, T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    body: &B,
) -> Result<T> {
    let resp = client.post(url).json(body).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        return Err(anyhow!("POST {} failed: {} {}", url, status, txt));
    }
    Ok(resp.json().await?)
}

async fn put_json<B: serde::Serialize, T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    body: &B,
) -> Result<T> {
    let resp = client.put(url).json(body).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        return Err(anyhow!("PUT {} failed: {} {}", url, status, txt));
    }
    Ok(resp.json().await?)
}
