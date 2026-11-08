//! Raft consensus: leader election, log replication, snapshots, and a TCP
//! transport shared by every replicated partition on a broker.
//!
//! * `state` — the pure state machine (no I/O, no clock).
//! * `node` — the driver: timers, persistence-before-send, snapshot transfer.
//! * `log` — the in-memory log and the durable, append-only store.
//! * `transport` — one authenticated connection per peer, many groups over it.
//! * `secret` — the cluster's shared secret: long enough, never printed.
//!
//! Not implemented: joint-consensus membership changes (config entries are
//! applied, but there is no safe reconfiguration protocol on top of them) and
//! linearizable reads (reads are served from whatever the replica has applied).
//! Nothing outside tests proposes a config entry: the membership is the
//! configured one, and removing a member means restarting the others without
//! it — which is also what takes away its access to their raft ports.

pub mod log;
pub mod messages;
pub mod node;
pub mod secret;
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
pub use secret::SharedSecret;
pub use state::{Action, RaftState, Role};
pub use transport::{group_key, spawn_transport, RaftHub, Transport};
