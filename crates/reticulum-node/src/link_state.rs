use alloc::collections::BTreeMap;
use reticulum_core::{identity::PublicIdentity, link::LinkEphemeral};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus {
    Pending,
    Handshake,
    Active,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkId(pub [u8; 16]);

#[derive(Debug, Clone)]
pub(crate) struct LinkEntry {
    pub status: LinkStatus,
    pub initiator: bool,
    pub ephemeral: LinkEphemeral,
    pub peer_x25519_pub: Option<[u8; 32]>,
    pub destination_public: Option<PublicIdentity>,
    pub derived_key: Option<[u8; 64]>,
    pub interface: u16,
    pub last_activity: u64,
    pub last_keepalive: u64,
}

#[derive(Debug, Default)]
pub(crate) struct LinkRegistry {
    entries: BTreeMap<LinkId, LinkEntry>,
}

impl LinkRegistry {
    pub fn insert(&mut self, id: [u8; 16], entry: LinkEntry) {
        self.entries.insert(LinkId(id), entry);
    }

    pub fn get(&self, id: &[u8; 16]) -> Option<&LinkEntry> {
        self.entries.get(&LinkId(*id))
    }

    pub fn get_mut(&mut self, id: &[u8; 16]) -> Option<&mut LinkEntry> {
        self.entries.get_mut(&LinkId(*id))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&LinkId, &mut LinkEntry)> {
        self.entries.iter_mut()
    }
}
