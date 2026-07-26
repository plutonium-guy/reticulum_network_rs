use alloc::collections::BTreeMap;
use reticulum_core::identity::PublicIdentity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathEntry {
    pub interface: u16,
    pub hops: u8,
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

    pub fn insert(&mut self, dest_hash: [u8; 16], entry: PathEntry) {
        self.entries.insert(dest_hash, entry);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::identity::Identity;

    #[test]
    fn insert_and_get() {
        let id = Identity::from_private_bytes(&[1u8; 32], &[2u8; 32]);
        let mut table = PathTable::new();
        let dest_hash = [9u8; 16];
        table.insert(
            dest_hash,
            PathEntry {
                interface: 3,
                hops: 0,
                public: id.public(),
                ratchet: None,
            },
        );
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(&dest_hash).unwrap().interface, 3);
        assert!(table.get(&[0u8; 16]).is_none());
    }
}
