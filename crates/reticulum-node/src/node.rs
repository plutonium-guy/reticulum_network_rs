use alloc::{collections::VecDeque, vec::Vec};
use reticulum_core::{
    announce::Announce,
    destination::{destination_hash, name_hash},
    identity::Identity,
    packet::Packet,
};

use crate::{path_table::PathTable, rng::EntropySource};

#[derive(Debug)]
struct LocalDestination {
    name_hash: [u8; 10],
    dest_hash: [u8; 16],
}

pub struct Node {
    identity: Identity,
    locals: Vec<LocalDestination>,
    paths: PathTable,
    outbound: VecDeque<(u16, Vec<u8>)>,
}

impl Node {
    pub fn new(identity: Identity) -> Node {
        Node {
            identity,
            locals: Vec::new(),
            paths: PathTable::new(),
            outbound: VecDeque::new(),
        }
    }

    pub fn register_single_destination(&mut self, app_name: &str, aspects: &[&str]) -> [u8; 16] {
        let name_hash = name_hash(app_name, aspects);
        let dest_hash = destination_hash(&name_hash, &self.identity.hash());
        self.locals.push(LocalDestination {
            name_hash,
            dest_hash,
        });
        dest_hash
    }

    pub fn send_announce<R: EntropySource>(
        &mut self,
        dest_hash: &[u8; 16],
        app_data: &[u8],
        rng: &mut R,
        interface: u16,
    ) {
        let Some(local) = self
            .locals
            .iter()
            .find(|local| &local.dest_hash == dest_hash)
        else {
            return;
        };
        let mut random_hash = [0u8; 10];
        rng.fill(&mut random_hash);
        let announce = Announce::build(
            &self.identity,
            dest_hash,
            &local.name_hash,
            &random_hash,
            app_data,
        );
        let packet = Packet::announce(dest_hash, announce.to_payload());
        self.outbound.push_back((interface, packet.encode()));
    }

    pub fn poll_outbound(&mut self) -> Option<(u16, Vec<u8>)> {
        self.outbound.pop_front()
    }

    pub fn local_destinations(&self) -> impl Iterator<Item = [u8; 16]> + '_ {
        self.locals.iter().map(|local| local.dest_hash)
    }

    pub fn knows_path(&self, dest_hash: &[u8; 16]) -> bool {
        self.paths.get(dest_hash).is_some()
    }
}
