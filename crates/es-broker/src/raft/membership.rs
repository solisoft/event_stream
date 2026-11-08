//! Who votes in a Raft group, where they listen, and how a change to that is
//! written into the log.
//!
//! # Single-server changes (Raft dissertation §4.1)
//!
//! A change adds or removes **one** voter. Any majority of the old
//! configuration and any majority of the new one then share a member, so the
//! two can never elect separate leaders, and no joint consensus is needed. Two
//! rules make that hold:
//!
//! * a configuration takes effect on a server as soon as its entry is in that
//!   server's log — appended, not committed — and is undone if the entry is
//!   truncated away;
//! * a leader proposes the next change only once the previous one is
//!   committed, and only once it has committed an entry of its own term (the
//!   fix to §4.1 published after the dissertation: without it, a change
//!   proposed by a new leader could overlap one left uncommitted by its
//!   predecessor).
//!
//! # Entry format
//!
//! ```text
//!   CONFIG_MAGIC [4] | add_count u32 | add ids u32… | remove_count u32 | remove ids u32…
//!   [ "ADR1" | addr_len u16 | addr utf-8 ]        the added node's Raft address
//! ```
//!
//! The first part is the format 0.2 already decoded; the address trails it, so
//! a 0.2 node reading a 0.3 entry still sees a well-formed change. The address
//! is what lets every member's transport dial a node added after it started.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::messages::NodeId;

pub(crate) const CONFIG_MAGIC: [u8; 4] = [0xEE, 0xEE, 0xEE, 0xEE];
const ADDR_TAG: [u8; 4] = *b"ADR1";
/// Longest Raft address an entry may carry: a bracketed IPv6 address with a
/// port is under 50 bytes.
const MAX_ADDR_LEN: usize = 256;

/// The voters of one Raft group, with the Raft address of each when known.
///
/// An empty address means "the one this broker was started with": members
/// named by `--raft-peer` are not repeated in the log.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    pub voters: BTreeMap<NodeId, String>,
}

impl Membership {
    pub fn new(ids: impl IntoIterator<Item = NodeId>) -> Self {
        Self {
            voters: ids.into_iter().map(|id| (id, String::new())).collect(),
        }
    }

    pub fn contains(&self, id: NodeId) -> bool {
        self.voters.contains_key(&id)
    }

    pub fn ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.voters.keys().copied()
    }

    pub fn len(&self) -> usize {
        self.voters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.voters.is_empty()
    }

    pub(crate) fn apply(&mut self, change: &ConfigChange) {
        for id in &change.remove {
            self.voters.remove(id);
        }
        for id in &change.add {
            let addr = match (&change.addr, change.add.len()) {
                (Some(a), 1) => a.clone(),
                _ => String::new(),
            };
            let slot = self.voters.entry(*id).or_default();
            if !addr.is_empty() {
                *slot = addr;
            }
        }
    }

    /// `count u32 | (id u32 | addr_len u16 | addr)…`
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.voters.len() as u32).to_be_bytes());
        for (id, addr) in &self.voters {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&(addr.len() as u16).to_be_bytes());
            out.extend_from_slice(addr.as_bytes());
        }
    }

    /// Decode what [`Self::encode`] wrote, from the front of `bytes`: what a
    /// 0.3.0 node does with whatever trails an InstallSnapshot.
    #[cfg(test)]
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        Self::decode_prefix(bytes).map(|(m, _)| m)
    }

    /// [`Self::decode`], also returning how many bytes the membership took:
    /// fields added after it start there.
    pub(crate) fn decode_prefix(bytes: &[u8]) -> Option<(Self, usize)> {
        let mut pos = 0usize;
        let n = take_u32(bytes, &mut pos)? as usize;
        let mut voters = BTreeMap::new();
        // Bounded by the bytes present, not by the count a peer claims.
        if n > bytes.len() / 6 {
            return None;
        }
        for _ in 0..n {
            let id = take_u32(bytes, &mut pos)?;
            let len = take_u16(bytes, &mut pos)? as usize;
            if len > MAX_ADDR_LEN {
                return None;
            }
            let addr = std::str::from_utf8(bytes.get(pos..pos.checked_add(len)?)?).ok()?;
            pos += len;
            voters.insert(id, addr.to_string());
        }
        Some((Self { voters }, pos))
    }
}

/// A requested change to a group's voters: one server at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberChange {
    /// Add `id`, reachable for Raft at `addr` (`host:port`).
    Add {
        id: NodeId,
        addr: String,
    },
    Remove {
        id: NodeId,
    },
}

impl MemberChange {
    pub fn node(&self) -> NodeId {
        match self {
            Self::Add { id, .. } | Self::Remove { id } => *id,
        }
    }
}

/// A config entry as decoded: the 0.2 format allowed several ids each way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigChange {
    pub add: Vec<NodeId>,
    pub remove: Vec<NodeId>,
    pub addr: Option<String>,
}

/// The 0.2 multi-id format, without addresses. Kept for tests and for
/// reading old logs; new changes are written by [`encode_member_change`].
pub fn encode_config_change(add: Vec<NodeId>, remove: Vec<NodeId>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&CONFIG_MAGIC);
    out.extend_from_slice(&(add.len() as u32).to_be_bytes());
    for id in &add {
        out.extend_from_slice(&id.to_be_bytes());
    }
    out.extend_from_slice(&(remove.len() as u32).to_be_bytes());
    for id in &remove {
        out.extend_from_slice(&id.to_be_bytes());
    }
    out
}

/// One single-server change, in the format above.
pub fn encode_member_change(change: &MemberChange) -> Vec<u8> {
    match change {
        MemberChange::Add { id, addr } => {
            let mut out = encode_config_change(vec![*id], Vec::new());
            out.extend_from_slice(&ADDR_TAG);
            out.extend_from_slice(&(addr.len() as u16).to_be_bytes());
            out.extend_from_slice(addr.as_bytes());
            out
        }
        MemberChange::Remove { id } => encode_config_change(Vec::new(), vec![*id]),
    }
}

fn take_u32(payload: &[u8], pos: &mut usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let slice = payload.get(*pos..end)?;
    *pos = end;
    Some(u32::from_be_bytes(slice.try_into().ok()?))
}

fn take_u16(payload: &[u8], pos: &mut usize) -> Option<u16> {
    let end = pos.checked_add(2)?;
    let slice = payload.get(*pos..end)?;
    *pos = end;
    Some(u16::from_be_bytes(slice.try_into().ok()?))
}

pub(crate) fn decode_config_change(payload: &[u8]) -> Option<ConfigChange> {
    if payload.len() < 8 || payload[..4] != CONFIG_MAGIC {
        return None;
    }
    // Bounds-checked: a truncated or lying length yields `None` instead of a
    // panic, and capacities are bounded by the bytes actually remaining so a
    // huge declared count cannot drive a giant allocation.
    fn take_ids(payload: &[u8], pos: &mut usize) -> Option<Vec<NodeId>> {
        let len = take_u32(payload, pos)? as usize;
        let remaining_ids = payload.len().saturating_sub(*pos) / 4;
        let mut out = Vec::with_capacity(len.min(remaining_ids));
        for _ in 0..len {
            out.push(take_u32(payload, pos)?);
        }
        Some(out)
    }
    let mut pos = 4usize;
    let add = take_ids(payload, &mut pos)?;
    let remove = take_ids(payload, &mut pos)?;
    let addr = if payload.get(pos..pos + 4) == Some(&ADDR_TAG[..]) {
        pos += 4;
        let len = take_u16(payload, &mut pos)? as usize;
        if len > MAX_ADDR_LEN {
            return None;
        }
        let bytes = payload.get(pos..pos.checked_add(len)?)?;
        Some(std::str::from_utf8(bytes).ok()?.to_string())
    } else {
        None
    };
    Some(ConfigChange { add, remove, addr })
}

pub fn is_config_entry(payload: &[u8]) -> bool {
    payload.len() >= 4 && payload[..4] == CONFIG_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_config_change_rejects_truncated_payload() {
        let mut payload = CONFIG_MAGIC.to_vec();
        payload.extend_from_slice(&1u32.to_be_bytes());
        assert!(decode_config_change(&payload).is_none());
        let mut huge = CONFIG_MAGIC.to_vec();
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_config_change(&huge).is_none());
    }

    #[test]
    fn a_member_change_round_trips_with_its_address() {
        let add = encode_member_change(&MemberChange::Add {
            id: 4,
            addr: "10.0.0.4:6000".into(),
        });
        assert!(is_config_entry(&add));
        let c = decode_config_change(&add).unwrap();
        assert_eq!(c.add, vec![4]);
        assert!(c.remove.is_empty());
        assert_eq!(c.addr.as_deref(), Some("10.0.0.4:6000"));

        let rm = decode_config_change(&encode_member_change(&MemberChange::Remove { id: 2 }));
        assert_eq!(rm.unwrap().remove, vec![2]);
    }

    /// What a 0.2 node reads from a 0.3 entry: the address trails the part it
    /// decodes, which stays a valid change on its own.
    #[test]
    fn a_0_2_reader_sees_a_well_formed_change() {
        let add = encode_member_change(&MemberChange::Add {
            id: 4,
            addr: "10.0.0.4:6000".into(),
        });
        let legacy_len = 4 + 4 + 4 + 4;
        let c = decode_config_change(&add[..legacy_len]).unwrap();
        assert_eq!((c.add, c.remove, c.addr), (vec![4], vec![], None));
    }

    #[test]
    fn membership_encodes_and_refuses_lies() {
        let mut m = Membership::new([1, 2]);
        m.voters.insert(4, "10.0.0.4:6000".into());
        let mut out = Vec::new();
        m.encode(&mut out);
        assert_eq!(Membership::decode(&out), Some(m));
        assert!(Membership::decode(&u32::MAX.to_be_bytes()).is_none());
        assert!(Membership::decode(&out[..out.len() - 1]).is_none());
    }
}
