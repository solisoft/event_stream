//! Raft consensus — **step 1 of N**: leader election only.
//!
//! What works today:
//!   * Term + voted-for state machine (`state::RaftState`)
//!   * Randomized election timeouts + leader heartbeat
//!   * Three-way role transitions: Follower → Candidate → Leader
//!   * Per-peer TCP transport with persistent connections and reconnect
//!
//! What's deliberately deferred to later steps:
//!   * Log replication (`AppendEntries.entries` is always empty)
//!   * Persistent `current_term` + `voted_for` (in-memory only — a real broker
//!     must `fsync` these before responding to RPCs to keep election safety
//!     across restarts)
//!   * Snapshots / log truncation
//!   * Membership changes (joint consensus)
//!   * Linearizable client reads (read-index or leases)
//!   * Integration with the partition log so writes go through Raft
//!
//! Treat this as the *scaffolding* — the wire types, state machine, and
//! transport are designed so step 2 can add log replication without
//! reshaping anything.

pub mod log;
pub mod messages;
pub mod node;
pub mod state;
pub mod transport;

pub use log::{JsonStore, Log, MemStore, PersistedRaft, PersistedSnapshot, RaftStore};
pub use messages::{LogEntry, LogIndex, Message, NodeId, Term};
pub use node::{spawn_node, spawn_node_with_store, NodeHandle, Outbound, ProposeReply, Timing};
pub use state::{Action, RaftState, Role};
pub use transport::{spawn_transport, Transport};
