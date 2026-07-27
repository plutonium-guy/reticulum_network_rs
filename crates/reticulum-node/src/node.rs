use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use reticulum_core::{
    announce::Announce,
    destination::{destination_hash, name_hash},
    identity::{Identity, PublicIdentity},
    link::{
        LinkEphemeral, build_link_proof, derive_link_key, link_id_from_request,
        link_request_payload, parse_link_request, verify_link_proof,
    },
    packet::{
        ANNOUNCE, BROADCAST, DATA, HEADER_1, HEADER_2, KEEPALIVE, LINK, LINKCLOSE, LINKREQUEST,
        LRPROOF, LRRTT, PATH_RESPONSE, PLAIN, PROOF, Packet, TRANSPORT,
    },
    token,
};

const PATH_EXPIRY_SECS: u64 = 604_800;
const PATHFINDER_MAX_HOPS: u8 = 128;
const PACKET_HASH_TTL_SECS: u64 = 60;
const LINK_KEEPALIVE_SECS: u64 = 360;
const LINK_STALE_SECS: u64 = 720;

use crate::{
    Event, NodeError,
    clock::{Clock, NoClock},
    link_state::{LinkEntry, LinkRegistry, LinkStatus},
    path_table::{PathEntry, PathTable},
    rng::EntropySource,
};

#[derive(Debug)]
struct LocalDestination {
    name_hash: [u8; 10],
    dest_hash: [u8; 16],
}

pub struct Node<C: Clock = NoClock> {
    identity: Identity,
    clock: C,
    locals: Vec<LocalDestination>,
    paths: PathTable,
    interfaces: Vec<u16>,
    transport_enabled: bool,
    seen_announces: BTreeMap<([u8; 16], [u8; 10]), u64>,
    seen_path_requests: BTreeMap<([u8; 16], [u8; 16]), u64>,
    seen_packets: BTreeMap<[u8; 16], u64>,
    cached_announces: BTreeMap<[u8; 16], Packet>,
    outbound: VecDeque<(u16, Vec<u8>)>,
    links: LinkRegistry,
    pending_events: VecDeque<Event>,
}

impl Node<NoClock> {
    pub fn new(identity: Identity) -> Node {
        Self::with_clock(identity, NoClock)
    }
}

impl<C: Clock> Node<C> {
    pub fn with_clock(identity: Identity, clock: C) -> Self {
        Node {
            identity,
            clock,
            locals: Vec::new(),
            paths: PathTable::new(),
            interfaces: Vec::new(),
            transport_enabled: false,
            seen_announces: BTreeMap::new(),
            seen_path_requests: BTreeMap::new(),
            seen_packets: BTreeMap::new(),
            cached_announces: BTreeMap::new(),
            outbound: VecDeque::new(),
            links: LinkRegistry::default(),
            pending_events: VecDeque::new(),
        }
    }

    pub fn now_secs(&self) -> u64 {
        self.clock.now_secs()
    }

    pub fn clock(&self) -> &C {
        &self.clock
    }

    pub fn enable_transport(&mut self, enabled: bool) {
        self.transport_enabled = enabled;
    }

    pub fn register_interface(&mut self, interface: u16) {
        if !self.interfaces.contains(&interface) {
            self.interfaces.push(interface);
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
        self.cached_announces.insert(*dest_hash, packet.clone());
        self.outbound.push_back((interface, packet.encode()));
    }

    pub fn request_path<R: EntropySource>(&mut self, dest_hash: &[u8; 16], rng: &mut R) {
        let mut tag = [0u8; 16];
        rng.fill(&mut tag);
        let transport_id = self.transport_enabled.then(|| self.identity.hash());
        let packet = Packet::path_request(dest_hash, transport_id.as_ref(), &tag).encode();
        for interface in &self.interfaces {
            self.outbound.push_back((*interface, packet.clone()));
        }
    }

    pub fn poll_outbound(&mut self) -> Option<(u16, Vec<u8>)> {
        self.outbound.pop_front()
    }

    pub fn send_message<R: EntropySource>(
        &mut self,
        dest_hash: &[u8; 16],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<(), NodeError> {
        self.paths.prune(self.clock.now_secs());
        let (interface, next_hop_transport_id, hops, public) = self
            .paths
            .get(dest_hash)
            .map(|entry| {
                (
                    entry.interface,
                    entry.next_hop_transport_id,
                    entry.hops,
                    entry.public.clone(),
                )
            })
            .ok_or(NodeError::Unknown)?;

        let mut ephemeral = [0u8; 32];
        let mut iv = [0u8; 16];
        rng.fill(&mut ephemeral);
        rng.fill(&mut iv);
        let ciphertext = token::encrypt(&public, plaintext, &ephemeral, &iv);
        let mut packet = Packet::data_single(dest_hash, ciphertext);
        if hops > 1 {
            let Some(next_hop_transport_id) = next_hop_transport_id else {
                return Err(NodeError::Unknown);
            };
            packet.header_type = HEADER_2;
            packet.propagation = TRANSPORT;
            packet.transport_id = Some(next_hop_transport_id);
        }
        self.outbound.push_back((interface, packet.encode()));
        Ok(())
    }

    pub fn establish_link<R: EntropySource>(
        &mut self,
        dest_hash: &[u8; 16],
        rng: &mut R,
    ) -> Result<[u8; 16], NodeError> {
        self.paths.prune(self.clock.now_secs());
        let (interface, next_hop_transport_id, hops, destination_public) = self
            .paths
            .get(dest_hash)
            .map(|entry| {
                (
                    entry.interface,
                    entry.next_hop_transport_id,
                    entry.hops,
                    entry.public.clone(),
                )
            })
            .ok_or(NodeError::Unknown)?;
        let ephemeral = LinkEphemeral::generate(rng);
        let mut packet = Packet::link_request(dest_hash, link_request_payload(&ephemeral));
        let link_id = link_id_from_request(&packet);
        if hops > 1 {
            packet.header_type = HEADER_2;
            packet.propagation = TRANSPORT;
            packet.transport_id = next_hop_transport_id;
            if packet.transport_id.is_none() {
                return Err(NodeError::Unknown);
            }
        }
        let now = self.clock.now_secs();
        self.links.insert(
            link_id,
            LinkEntry {
                status: LinkStatus::Pending,
                initiator: true,
                ephemeral,
                peer_x25519_pub: None,
                destination_public: Some(destination_public),
                derived_key: None,
                interface,
                last_activity: now,
                last_keepalive: now,
            },
        );
        self.outbound.push_back((interface, packet.encode()));
        Ok(link_id)
    }

    pub fn link_send<R: EntropySource>(
        &mut self,
        link_id: &[u8; 16],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<(), NodeError> {
        let (key, interface) = self
            .links
            .get(link_id)
            .filter(|link| link.status == LinkStatus::Active)
            .and_then(|link| link.derived_key.map(|key| (key, link.interface)))
            .ok_or(NodeError::Unknown)?;
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        let ciphertext = token::seal_with_key(&key, plaintext, &iv);
        self.outbound
            .push_back((interface, Packet::link_data(link_id, ciphertext).encode()));
        if let Some(link) = self.links.get_mut(link_id) {
            link.last_activity = self.clock.now_secs();
        }
        Ok(())
    }

    pub fn close_link(&mut self, link_id: &[u8; 16]) {
        if let Some(link) = self.links.get_mut(link_id)
            && link.status != LinkStatus::Closed
        {
            link.status = LinkStatus::Closed;
            self.pending_events
                .push_back(Event::LinkClosed { link_id: *link_id });
        }
    }

    pub fn tick(&mut self) -> Vec<Event> {
        let now = self.clock.now_secs();
        let mut keepalives = Vec::new();
        let mut closed = Vec::new();
        for (id, link) in self.links.iter_mut() {
            if link.status != LinkStatus::Active {
                continue;
            }
            if now.saturating_sub(link.last_activity) >= LINK_STALE_SECS {
                link.status = LinkStatus::Closed;
                closed.push(id.0);
            } else if link.initiator
                && now.saturating_sub(link.last_keepalive) >= LINK_KEEPALIVE_SECS
            {
                link.last_keepalive = now;
                keepalives.push((link.interface, id.0));
            }
        }
        for (interface, link_id) in keepalives {
            self.outbound.push_back((
                interface,
                Packet::link_data_with_context(&link_id, alloc::vec![0xFF], KEEPALIVE).encode(),
            ));
        }
        for link_id in closed {
            self.pending_events.push_back(Event::LinkClosed { link_id });
        }
        self.pending_events.drain(..).collect()
    }

    pub fn handle_inbound(&mut self, bytes: &[u8], interface: u16) -> Vec<Event> {
        self.handle_inbound_inner(bytes, interface, None)
    }

    pub fn handle_inbound_with_entropy<R: EntropySource>(
        &mut self,
        bytes: &[u8],
        interface: u16,
        rng: &mut R,
    ) -> Vec<Event> {
        self.handle_inbound_inner(bytes, interface, Some(rng))
    }

    fn handle_inbound_inner(
        &mut self,
        bytes: &[u8],
        interface: u16,
        rng: Option<&mut dyn EntropySource>,
    ) -> Vec<Event> {
        let mut packet = match Packet::decode(bytes) {
            Ok(packet) => packet,
            Err(_) => return Vec::new(),
        };
        if packet.hops >= PATHFINDER_MAX_HOPS {
            return Vec::new();
        }
        let now = self.clock.now_secs();
        self.seen_packets.retain(|_, expires_at| *expires_at > now);
        let packet_hash = packet.packet_hash();
        if self.seen_packets.contains_key(&packet_hash) {
            return Vec::new();
        }
        self.seen_packets
            .insert(packet_hash, now.saturating_add(PACKET_HASH_TTL_SECS));
        packet.hops = packet.hops.saturating_add(1);
        let dest_hash = match <[u8; 16]>::try_from(packet.dest_hash.as_slice()) {
            Ok(dest_hash) => dest_hash,
            Err(_) => return Vec::new(),
        };
        if packet.packet_type == DATA
            && packet.dest_type == PLAIN
            && dest_hash == Packet::path_request_destination_hash()
        {
            self.handle_path_request(&packet, interface);
            return Vec::new();
        }
        if packet.packet_type == LINKREQUEST {
            return match rng {
                Some(rng) => self.handle_link_request(&packet, &dest_hash, interface, rng),
                None => Vec::new(),
            };
        }
        if packet.packet_type == PROOF && packet.dest_type == LINK && packet.context == LRPROOF {
            return self.handle_link_proof(&packet, &dest_hash, rng);
        }
        if packet.packet_type == DATA && packet.dest_type == LINK {
            return self.handle_link_data(&packet, &dest_hash, interface);
        }
        match packet.packet_type {
            ANNOUNCE => self.handle_announce(&packet, &dest_hash, interface),
            DATA => self.handle_data(&packet, &dest_hash, interface),
            _ => Vec::new(),
        }
    }

    fn handle_link_request(
        &mut self,
        packet: &Packet,
        dest_hash: &[u8; 16],
        interface: u16,
        rng: &mut dyn EntropySource,
    ) -> Vec<Event> {
        if packet.header_type == HEADER_2
            && (!self.transport_enabled || packet.transport_id != Some(self.identity.hash()))
        {
            return Vec::new();
        }
        if !self
            .locals
            .iter()
            .any(|local| &local.dest_hash == dest_hash)
        {
            return Vec::new();
        }
        let Ok((peer_x25519_pub, _peer_ed25519_pub)) = parse_link_request(&packet.data) else {
            return Vec::new();
        };
        let link_id = link_id_from_request(packet);
        if self.links.get(&link_id).is_some() {
            return Vec::new();
        }
        let mut x25519_prv = [0u8; 32];
        let mut ed25519_prv = [0u8; 32];
        rng.fill(&mut x25519_prv);
        rng.fill(&mut ed25519_prv);
        let ephemeral = LinkEphemeral::from_private_bytes(x25519_prv, ed25519_prv);
        let key = derive_link_key(&ephemeral.x25519_prv, &peer_x25519_pub, &link_id);
        let proof = build_link_proof(&self.identity, &link_id, &ephemeral);
        let now = self.clock.now_secs();
        self.links.insert(
            link_id,
            LinkEntry {
                status: LinkStatus::Active,
                initiator: false,
                ephemeral,
                peer_x25519_pub: Some(peer_x25519_pub),
                destination_public: None,
                derived_key: Some(key),
                interface,
                last_activity: now,
                last_keepalive: now,
            },
        );
        self.outbound
            .push_back((interface, Packet::proof(&link_id, proof, LRPROOF).encode()));
        alloc::vec![Event::LinkEstablished { link_id }]
    }

    fn handle_link_proof(
        &mut self,
        packet: &Packet,
        link_id: &[u8; 16],
        rng: Option<&mut dyn EntropySource>,
    ) -> Vec<Event> {
        let Some(link) = self
            .links
            .get(link_id)
            .filter(|link| link.status == LinkStatus::Pending && link.initiator)
        else {
            return Vec::new();
        };
        let Some(destination_public) = link.destination_public.as_ref() else {
            return Vec::new();
        };
        let peer_x25519_pub = match verify_link_proof(destination_public, link_id, &packet.data) {
            Ok(public) => public,
            Err(error) => return alloc::vec![Event::Error(NodeError::Core(error))],
        };
        let key = derive_link_key(&link.ephemeral.x25519_prv, &peer_x25519_pub, link_id);
        let interface = link.interface;
        let now = self.clock.now_secs();
        if let Some(link) = self.links.get_mut(link_id) {
            link.status = LinkStatus::Active;
            link.peer_x25519_pub = Some(peer_x25519_pub);
            link.derived_key = Some(key);
            link.last_activity = now;
        }
        if let Some(rng) = rng {
            let mut iv = [0u8; 16];
            rng.fill(&mut iv);
            // RNS expects an encrypted MessagePack float before the responder
            // finalises its side and invokes the established callback.
            let rtt = [0xCB, 0, 0, 0, 0, 0, 0, 0, 0];
            let encrypted = token::seal_with_key(&key, &rtt, &iv);
            self.outbound.push_back((
                interface,
                Packet::link_data_with_context(link_id, encrypted, LRRTT).encode(),
            ));
        }
        alloc::vec![Event::LinkEstablished { link_id: *link_id }]
    }

    fn handle_link_data(
        &mut self,
        packet: &Packet,
        link_id: &[u8; 16],
        interface: u16,
    ) -> Vec<Event> {
        let Some(link) = self
            .links
            .get(link_id)
            .filter(|link| link.status == LinkStatus::Active && link.interface == interface)
        else {
            return Vec::new();
        };
        let Some(key) = link.derived_key else {
            return Vec::new();
        };
        if packet.context == KEEPALIVE {
            if packet.data == [0xFF] {
                self.outbound.push_back((
                    interface,
                    Packet::link_data_with_context(link_id, alloc::vec![0xFE], KEEPALIVE).encode(),
                ));
            }
            if let Some(link) = self.links.get_mut(link_id) {
                link.last_activity = self.clock.now_secs();
            }
            return Vec::new();
        }
        let plaintext = match token::open_with_key(&key, &packet.data) {
            Ok(plaintext) => plaintext,
            Err(error) => return alloc::vec![Event::Error(NodeError::Core(error))],
        };
        if let Some(link) = self.links.get_mut(link_id) {
            link.last_activity = self.clock.now_secs();
        }
        match packet.context {
            LRRTT => Vec::new(),
            LINKCLOSE => {
                if plaintext == link_id {
                    self.close_link(link_id);
                    self.tick()
                } else {
                    Vec::new()
                }
            }
            0 => alloc::vec![Event::LinkData {
                link_id: *link_id,
                plaintext,
            }],
            _ => Vec::new(),
        }
    }

    fn handle_announce(
        &mut self,
        packet: &Packet,
        dest_hash: &[u8; 16],
        interface: u16,
    ) -> Vec<Event> {
        if self
            .locals
            .iter()
            .any(|local| &local.dest_hash == dest_hash)
        {
            return Vec::new();
        }
        let announce = match Announce::parse(&packet.data, packet.context_flag) {
            Ok(announce) => announce,
            Err(_) => return Vec::new(),
        };
        if let Err(error) = announce.verify(dest_hash) {
            return alloc::vec![Event::Error(NodeError::Core(error))];
        }
        let now = self.clock.now_secs();
        self.seen_announces
            .retain(|_, expires_at| *expires_at > now);
        let seen_key = (*dest_hash, announce.random_hash);
        if self.seen_announces.contains_key(&seen_key) {
            return Vec::new();
        }
        self.seen_announces
            .insert(seen_key, now.saturating_add(PATH_EXPIRY_SECS));
        let public = match PublicIdentity::from_bytes(&announce.public) {
            Ok(public) => public,
            Err(error) => return alloc::vec![Event::Error(NodeError::Core(error))],
        };
        let timestamp = announce
            .random_hash
            .iter()
            .skip(5)
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
        let next_hop_transport_id = if packet.header_type == HEADER_2 {
            packet.transport_id
        } else {
            None
        };
        let accepted = self.paths.update(
            *dest_hash,
            PathEntry {
                interface,
                next_hop_transport_id,
                hops: packet.hops,
                expires_at: now.saturating_add(PATH_EXPIRY_SECS),
                timestamp,
                public,
                ratchet: announce.ratchet,
            },
            now,
        );
        if !accepted {
            return Vec::new();
        }
        self.cached_announces.insert(*dest_hash, packet.clone());
        if self.transport_enabled
            && packet.hops < PATHFINDER_MAX_HOPS
            && packet.context != PATH_RESPONSE
        {
            let mut forwarded = packet.clone();
            forwarded.header_type = HEADER_2;
            forwarded.propagation = TRANSPORT;
            forwarded.transport_id = Some(self.identity.hash());
            let encoded = forwarded.encode();
            for outbound_interface in &self.interfaces {
                if *outbound_interface != interface {
                    self.outbound
                        .push_back((*outbound_interface, encoded.clone()));
                }
            }
        }
        alloc::vec![Event::Announce {
            dest_hash: *dest_hash,
            hops: packet.hops,
        }]
    }

    fn handle_path_request(&mut self, packet: &Packet, interface: u16) {
        if packet.data.len() < 32 {
            return;
        }
        let Ok(target) = <[u8; 16]>::try_from(&packet.data[..16]) else {
            return;
        };
        let (requester, tag_offset) = if packet.data.len() >= 48 {
            let Ok(requester) = <[u8; 16]>::try_from(&packet.data[16..32]) else {
                return;
            };
            (Some(requester), 32)
        } else {
            (None, 16)
        };
        let Ok(tag) = <[u8; 16]>::try_from(&packet.data[tag_offset..tag_offset + 16]) else {
            return;
        };
        let now = self.clock.now_secs();
        self.seen_path_requests
            .retain(|_, expires_at| *expires_at > now);
        if self.seen_path_requests.contains_key(&(target, tag)) {
            return;
        }
        self.seen_path_requests
            .insert((target, tag), now.saturating_add(15));

        let is_local = self.locals.iter().any(|local| local.dest_hash == target);
        let path = self.paths.get(&target).cloned();
        if !is_local && (!self.transport_enabled || path.is_none()) {
            return;
        }
        if requester.is_some_and(|requester| {
            path.as_ref()
                .is_some_and(|path| path.next_hop_transport_id == Some(requester))
        }) {
            return;
        }
        let Some(mut response) = self.cached_announces.get(&target).cloned() else {
            return;
        };
        response.context = PATH_RESPONSE;
        if is_local {
            response.header_type = HEADER_1;
            response.propagation = BROADCAST;
            response.hops = 0;
            response.transport_id = None;
        } else if let Some(path) = path {
            response.header_type = HEADER_2;
            response.propagation = TRANSPORT;
            response.hops = path.hops;
            response.transport_id = Some(self.identity.hash());
        }
        self.outbound.push_back((interface, response.encode()));
    }

    fn handle_data(&mut self, packet: &Packet, dest_hash: &[u8; 16], interface: u16) -> Vec<Event> {
        if packet.header_type == HEADER_2
            && (!self.transport_enabled || packet.transport_id != Some(self.identity.hash()))
        {
            return Vec::new();
        }
        if !self
            .locals
            .iter()
            .any(|local| &local.dest_hash == dest_hash)
        {
            if packet.header_type == HEADER_2 && packet.hops < PATHFINDER_MAX_HOPS {
                self.paths.prune(self.clock.now_secs());
                if let Some(path) = self
                    .paths
                    .get(dest_hash)
                    .filter(|path| path.interface != interface)
                {
                    let mut forwarded = packet.clone();
                    if path.hops > 1 {
                        let Some(next_hop_transport_id) = path.next_hop_transport_id else {
                            return Vec::new();
                        };
                        forwarded.transport_id = Some(next_hop_transport_id);
                    } else {
                        forwarded.header_type = HEADER_1;
                        forwarded.propagation = BROADCAST;
                        forwarded.transport_id = None;
                    }
                    self.outbound
                        .push_back((path.interface, forwarded.encode()));
                }
            }
            return Vec::new();
        }
        match token::decrypt(&self.identity, &packet.data) {
            Ok(plaintext) => alloc::vec![Event::Message {
                dest_hash: *dest_hash,
                plaintext,
            }],
            Err(error) => alloc::vec![Event::Error(NodeError::Core(error))],
        }
    }

    pub fn local_destinations(&self) -> impl Iterator<Item = [u8; 16]> + '_ {
        self.locals.iter().map(|local| local.dest_hash)
    }

    pub fn knows_path(&self, dest_hash: &[u8; 16]) -> bool {
        self.paths.get(dest_hash).is_some()
    }

    pub fn prune_paths(&mut self) -> usize {
        self.paths.prune(self.clock.now_secs())
    }
}
