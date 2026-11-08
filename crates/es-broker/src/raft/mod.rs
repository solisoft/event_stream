//! Raft consensus: leader election, log replication, snapshots, and a TCP
//! transport shared by every replicated partition on a broker.
//!
//! * `state` — the pure state machine (no I/O, no clock).
//! * `node` — the driver: timers, persistence-before-send, snapshot transfer.
//! * `log` — the in-memory log and the durable, append-only store.
//! * `transport` — one authenticated connection per peer, many groups over it.
//! * `secret` — the cluster's shared secret: long enough, never printed.
//! * `tls` — per-broker identity: mTLS certificates that name the node id.
//! * `membership` — single-server configuration changes and their log entries.
//!
//! Membership changes are single-server (one voter added or removed at a
//! time, in effect when appended), proposed through `/admin/raft/members`, and
//! the transport follows them: an added broker is dialed and accepted, a
//! removed one disconnected and refused, without a restart. Joint consensus
//! (several voters at once) is not implemented.
//!
//! Not implemented: linearizable reads (reads are served from whatever the
//! replica has applied).

pub mod log;
pub mod membership;
pub mod messages;
pub mod node;
pub mod secret;
pub mod state;
pub mod tls;
pub mod transport;

pub use log::{
    FileStore, JsonStore, Log, MemStore, PersistOp, PersistedRaft, PersistedSnapshot, RaftStore,
};
pub use membership::{MemberChange, Membership};
pub use messages::{LogEntry, LogIndex, Message, NodeId, Term};
pub use node::{
    spawn_node, spawn_node_with_options, spawn_node_with_store, NodeHandle, NodeOptions, Outbound,
    ProposeReply, SnapshotSender, SnapshotTransfer, Timing,
};
pub use secret::SharedSecret;
pub use state::{Action, RaftState, Role};
pub use tls::RaftTls;
pub use transport::{group_key, spawn_transport, HubOptions, RaftHub, Transport};
