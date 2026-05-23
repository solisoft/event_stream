pub mod wire;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CleanupPolicyDto {
    #[serde(rename = "delete")]
    Delete,
    #[serde(rename = "compact")]
    Compact,
    #[serde(rename = "compact,delete")]
    CompactDelete,
}

/// Patch shape used by both create-topic and update-config. All fields are optional;
/// `None` means "use the broker default" (on create) or "preserve the current value"
/// (on update).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TopicConfigPatch {
    #[serde(default)]
    pub retention_ms: Option<u64>,
    #[serde(default)]
    pub retention_bytes: Option<u64>,
    #[serde(default)]
    pub cleanup_policy: Option<CleanupPolicyDto>,
    #[serde(default)]
    pub segment_bytes: Option<u64>,
    #[serde(default)]
    pub tombstone_retention_ms: Option<u64>,
}

/// Fully resolved topic config (no `None` for `cleanup_policy`, `segment_bytes`,
/// or `tombstone_retention_ms`). Returned by `GET /topics/:name/config` and
/// embedded in describe responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicConfigDto {
    #[serde(default)]
    pub retention_ms: Option<u64>,
    #[serde(default)]
    pub retention_bytes: Option<u64>,
    pub cleanup_policy: CleanupPolicyDto,
    pub segment_bytes: u64,
    pub tombstone_retention_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTopicRequest {
    pub name: String,
    #[serde(default = "default_partitions")]
    pub partitions: u32,
    #[serde(default)]
    pub config: Option<TopicConfigPatch>,
}

fn default_partitions() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicSummary {
    pub name: String,
    pub partitions: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListTopicsResponse {
    pub topics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionInfo {
    pub id: u32,
    pub start_offset: u64,
    pub end_offset: u64,
    pub segment_count: u32,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescribeTopicResponse {
    pub name: String,
    pub partitions: Vec<PartitionInfo>,
    pub config: TopicConfigDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProduceRecord {
    #[serde(default)]
    pub key: Option<String>,
    pub value: String,
    #[serde(default)]
    pub partition: Option<u32>,
    /// Monotonically increasing sequence within `(producer_id, topic, partition)`.
    /// Required when the enclosing request carries a `producer_id`; ignored otherwise.
    #[serde(default)]
    pub sequence: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProduceRequest {
    pub records: Vec<ProduceRecord>,
    /// Opt-in idempotency: when set, the broker dedupes records by
    /// `(producer_id, topic, partition, sequence)` and rejects sequence gaps.
    #[serde(default)]
    pub producer_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProduceResult {
    pub partition: u32,
    pub offset: u64,
    /// True when the broker recognized this record as a retry of a previously
    /// acknowledged record and returned the original offset without re-appending.
    #[serde(default, skip_serializing_if = "is_false")]
    pub duplicate: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProducerStateDto {
    pub producer_id: String,
    /// One entry per `(topic, partition)` known to this producer.
    pub partitions: Vec<ProducerPartitionStateDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProducerPartitionStateDto {
    pub topic: String,
    pub partition: u32,
    pub last_seen_sequence: i64,
    pub last_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListProducersResponse {
    pub producers: Vec<ProducerStateDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetOffsetsRequest {
    /// Resets every group's committed offset on this topic to the partition's
    /// current start_offset. Useful after a destructive cleanup.
    pub topic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetOffsetsResponse {
    pub groups_affected: u32,
    pub entries_reset: u32,
}

// --- consumer-group coordination ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinGroupRequest {
    /// May be omitted on first join; the coordinator assigns one.
    #[serde(default)]
    pub member_id: Option<String>,
    /// Topics the member wants to consume. Must already exist.
    pub topics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinGroupResponse {
    pub member_id: String,
    pub generation: u64,
    /// Partitions assigned to *this* member as `(topic, partition)` pairs.
    pub assignment: Vec<TopicPartitionDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub member_id: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum HeartbeatResponse {
    Ok { generation: u64 },
    RebalanceRequired { current_generation: u64 },
    UnknownMember { current_generation: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaveGroupRequest {
    pub member_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignmentResponse {
    pub generation: u64,
    pub assignment: Vec<TopicPartitionDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicPartitionDto {
    pub topic: String,
    pub partition: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProduceResponse {
    pub results: Vec<ProduceResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordDto {
    pub partition: u32,
    pub offset: u64,
    pub timestamp_ms: i64,
    #[serde(default)]
    pub key: Option<String>,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumeResponse {
    pub records: Vec<RecordDto>,
    pub next_offset: u64,
    pub high_watermark: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRequest {
    pub topic: String,
    pub partition: u32,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupOffsetsResponse {
    pub offsets: std::collections::BTreeMap<String, std::collections::BTreeMap<u32, u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AclActionDto {
    Read,
    Write,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRuleDto {
    pub action: AclActionDto,
    pub topic_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    pub acls: Vec<AclRuleDto>,
    #[serde(default)]
    pub produce_bytes_per_sec: Option<u32>,
    #[serde(default)]
    pub consume_bytes_per_sec: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyDto {
    pub key_id: String,
    pub name: String,
    pub acls: Vec<AclRuleDto>,
    pub produce_bytes_per_sec: Option<u32>,
    pub consume_bytes_per_sec: Option<u32>,
    pub created_at_ms: i64,
    pub disabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateKeyResponse {
    pub key: ApiKeyDto,
    /// Secret bearer token. Returned exactly once on creation and never again.
    pub secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListKeysResponse {
    pub keys: Vec<ApiKeyDto>,
}
