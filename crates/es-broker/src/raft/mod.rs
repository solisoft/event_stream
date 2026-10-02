//! Raft consensus: leader election, log replication, snapshots, and a TCP
//! transport shared by every replicated partition on a broker.
//!
//! * `state` — the pure state machine (no I/O, no clock).
//! * `node` — the driver: timers, persistence-before-send, snapshot transfer.
//! * `log` — the in-memory log and the durable, append-only store.
//! * `transport` — one authenticated connection per peer, many groups over it.
//!
//! Not implemented: joint-consensus membership changes (config entries are
//! applied, but there is no safe reconfiguration protocol on top of them) and
//! linearizable reads (reads are served from whatever the replica has applied).

pub mod log;
pub mod messages;
pub mod node;
pub mod state;
pub mod transport;

pub use log::{
    FileStore, JsonStore, Log, MemStore, PersistOp, PersistedRaft, PersistedSnapshot, RaftStore,
};
pub use messages::{LogEntry, LogIndex, Message, NodeId, Term};
pub use node::{
    spawn_node, spawn_node_with_options, spawn_node_with_store, NodeHandle, NodeOptions, Outbound,
    ProposeReply, SnapshotSender, SnapshotTransfer, Timing,
};
pub use state::{Action, RaftState, Role};
pub use transport::{group_key, spawn_transport, RaftHub, Transport};
