use alloc::collections::BTreeMap;
use reticulum_core::identity::PublicIdentity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathEntry {
    pub interface: u16,
    pub next_hop_transport_id: Option<[u8; 16]>,
    pub hops: u8,
    pub expires_at: u64,
    pub timestamp: u64,
    pub public: PublicIdentity,
    /// Latest advertised ratchet public key, when present.
    pub ratchet: Option<[u8; 32]>,
}

#[derive(Debug, Default)]
pub struct PathTable {
    entries: BTreeMap<[u8; 16], PathEntry>,
}

impl PathTable {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, dest_hash: [u8; 16], entry: PathEntry) -> bool {
        let replace = match self.entries.get(&dest_hash) {
            None => true,
            Some(current) if entry.hops < current.hops => true,
            Some(current) => entry.hops == current.hops && entry.timestamp > current.timestamp,
        };
        if replace {
            self.entries.insert(dest_hash, entry);
        }
        replace
    }

    /// Applies the deterministic route preference used for valid announces.
    pub fn update(&mut self, dest_hash: [u8; 16], entry: PathEntry, now: u64) -> bool {
        let replace = match self.entries.get(&dest_hash) {
            None => true,
            Some(current) if current.expires_at <= now => true,
            Some(current) if entry.hops < current.hops => true,
            Some(current) => entry.hops == current.hops && entry.timestamp > current.timestamp,
        };
        if replace {
            self.entries.insert(dest_hash, entry);
        }
        replace
    }

    pub fn prune(&mut self, now: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.expires_at > now);
        before - self.entries.len()
    }

    pub fn get(&self, dest_hash: &[u8; 16]) -> Option<&PathEntry> {
        self.entries.get(dest_hash)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn snapshot(&self) -> alloc::vec::Vec<([u8; 16], PathEntry)> {
        self.entries
            .iter()
            .map(|(destination, entry)| (*destination, entry.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::identity::Identity;

    fn entry(identity: &Identity, hops: u8, timestamp: u64, expires_at: u64) -> PathEntry {
        PathEntry {
            interface: u16::from(hops),
            next_hop_transport_id: Some([hops; 16]),
            hops,
            expires_at,
            timestamp,
            public: identity.public(),
            ratchet: None,
        }
    }

    #[test]
    fn insert_and_get() {
        let id = Identity::from_private_bytes(&[1u8; 32], &[2u8; 32]);
        let mut table = PathTable::new();
        let dest_hash = [9u8; 16];
        table.insert(
            dest_hash,
            PathEntry {
                interface: 3,
                next_hop_transport_id: Some([9u8; 16]),
                hops: 0,
                expires_at: 100,
                timestamp: 1,
                public: id.public(),
                ratchet: None,
            },
        );
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(&dest_hash).unwrap().interface, 3);
        assert!(table.get(&[0u8; 16]).is_none());
    }

    #[test]
    fn prefers_fewer_hops_then_newer_equal_hop_announce() {
        let id = Identity::from_private_bytes(&[1u8; 32], &[2u8; 32]);
        let destination = [7u8; 16];
        let mut table = PathTable::new();

        assert!(table.insert(destination, entry(&id, 4, 20, 100)));
        assert!(!table.insert(destination, entry(&id, 5, 30, 100)));
        assert!(table.insert(destination, entry(&id, 3, 10, 100)));
        assert!(!table.insert(destination, entry(&id, 3, 9, 100)));
        assert!(table.insert(destination, entry(&id, 3, 11, 100)));
        assert_eq!(table.get(&destination).unwrap().timestamp, 11);
    }

    #[test]
    fn expired_route_is_replaced_and_pruned_by_injected_time() {
        let id = Identity::from_private_bytes(&[1u8; 32], &[2u8; 32]);
        let destination = [7u8; 16];
        let mut table = PathTable::new();
        table.insert(destination, entry(&id, 1, 10, 20));

        assert!(table.update(destination, entry(&id, 9, 5, 50), 20));
        assert_eq!(table.get(&destination).unwrap().hops, 9);
        assert_eq!(table.prune(49), 0);
        assert_eq!(table.prune(50), 1);
        assert!(table.is_empty());
    }
}
