use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use reticulum_core::{
    announce::Announce,
    destination::{
        destination_hash, group_destination_hash, group_destination_hash_with_identity, name_hash,
    },
    identity::{Identity, PublicIdentity},
    link::{
        LinkEphemeral, build_link_proof, derive_link_key, link_id_from_request,
        link_request_payload, parse_link_request, verify_link_proof,
    },
    packet::{
        ANNOUNCE, BROADCAST, DATA, GROUP, HEADER_1, HEADER_2, KEEPALIVE, LINK, LINKCLOSE,
        LINKREQUEST, LRPROOF, LRRTT, PATH_RESPONSE, PLAIN, PROOF, Packet, RESOURCE, RESOURCE_ADV,
        RESOURCE_HMU, RESOURCE_ICL, RESOURCE_PRF, RESOURCE_RCL, RESOURCE_REQ, SINGLE, TRANSPORT,
    },
    proof::{build_proof, proof_destination_hash, verify_proof},
    resource::ResourceAdvertisement,
    token,
};

const PATH_EXPIRY_SECS: u64 = 604_800;
const PATHFINDER_MAX_HOPS: u8 = 128;
const PACKET_HASH_TTL_SECS: u64 = 60;
const LINK_KEEPALIVE_SECS: u64 = 360;
const LINK_STALE_SECS: u64 = 720;
const RECEIPT_TIMEOUT_SECS: u64 = 30;

use crate::{
    Event, NodeError,
    clock::{Clock, NoClock},
    link_state::{LinkEntry, LinkRegistry, LinkStatus},
    path_table::{PathEntry, PathTable},
    resource_state::{InboundResource, OutboundResource, ResourceOutput},
    rng::EntropySource,
};

#[derive(Debug)]
struct LocalDestination {
    name_hash: [u8; 10],
    dest_hash: [u8; 16],
    kind: LocalDestinationKind,
}

enum LocalDestinationKind {
    Single { prove: bool },
    Group { key: [u8; 64] },
    Plain,
}

impl core::fmt::Debug for LocalDestinationKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never expose the shared GROUP key via Debug (leak-safety, mirrors Identity/LinkEphemeral).
        match self {
            Self::Single { prove } => f.debug_struct("Single").field("prove", prove).finish(),
            Self::Group { .. } => f.debug_struct("Group").field("key", &"<redacted>").finish(),
            Self::Plain => f.write_str("Plain"),
        }
    }
}

#[derive(Debug)]
struct PendingReceipt {
    destination_public: PublicIdentity,
    expires_at: u64,
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
    pending_receipts: BTreeMap<[u8; 32], PendingReceipt>,
    outbound_resources: BTreeMap<([u8; 16], [u8; 32]), OutboundResource>,
    inbound_resources: BTreeMap<([u8; 16], [u8; 32]), InboundResource>,
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
            pending_receipts: BTreeMap::new(),
            outbound_resources: BTreeMap::new(),
            inbound_resources: BTreeMap::new(),
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
            kind: LocalDestinationKind::Single { prove: false },
        });
        dest_hash
    }

    /// Register an interoperable GROUP destination using the shared key as
    /// deterministic RNS Identity private material as well as its Token key.
    pub fn register_group_destination(
        &mut self,
        app_name: &str,
        aspects: &[&str],
        group_key: [u8; 64],
    ) -> [u8; 16] {
        let mut x25519 = [0u8; 32];
        let mut ed25519 = [0u8; 32];
        x25519.copy_from_slice(&group_key[..32]);
        ed25519.copy_from_slice(&group_key[32..]);
        let identity_hash = Identity::from_private_bytes(&x25519, &ed25519).hash();
        self.register_group_destination_with_identity(app_name, aspects, identity_hash, group_key)
    }

    /// Register a GROUP destination with separately supplied address Identity
    /// and symmetric Token key, matching RNS's two-key model.
    pub fn register_group_destination_with_identity(
        &mut self,
        app_name: &str,
        aspects: &[&str],
        identity_hash: [u8; 16],
        group_key: [u8; 64],
    ) -> [u8; 16] {
        let name_hash = name_hash(app_name, aspects);
        let dest_hash = group_destination_hash_with_identity(app_name, aspects, &identity_hash);
        self.locals.push(LocalDestination {
            name_hash,
            dest_hash,
            kind: LocalDestinationKind::Group { key: group_key },
        });
        dest_hash
    }

    pub fn register_plain_destination(&mut self, app_name: &str, aspects: &[&str]) -> [u8; 16] {
        let name_hash = name_hash(app_name, aspects);
        let dest_hash = group_destination_hash(app_name, aspects);
        self.locals.push(LocalDestination {
            name_hash,
            dest_hash,
            kind: LocalDestinationKind::Plain,
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
        let Some(local) = self.locals.iter().find(|local| {
            &local.dest_hash == dest_hash
                && matches!(local.kind, LocalDestinationKind::Single { .. })
        }) else {
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
        self.send_single_message(dest_hash, plaintext, rng, false)
            .map(|_| ())
    }

    pub fn send_message_with_receipt<R: EntropySource>(
        &mut self,
        dest_hash: &[u8; 16],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<[u8; 32], NodeError> {
        self.send_single_message(dest_hash, plaintext, rng, true)?
            .ok_or(NodeError::Unknown)
    }

    fn send_single_message<R: EntropySource>(
        &mut self,
        dest_hash: &[u8; 16],
        plaintext: &[u8],
        rng: &mut R,
        create_receipt: bool,
    ) -> Result<Option<[u8; 32]>, NodeError> {
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
        let packet_hash = packet.full_packet_hash();
        self.outbound.push_back((interface, packet.encode()));
        if create_receipt {
            self.pending_receipts.insert(
                packet_hash,
                PendingReceipt {
                    destination_public: public,
                    expires_at: self.clock.now_secs().saturating_add(RECEIPT_TIMEOUT_SECS),
                },
            );
            Ok(Some(packet_hash))
        } else {
            Ok(None)
        }
    }

    pub fn set_prove(&mut self, dest_hash: &[u8; 16], enabled: bool) -> bool {
        let Some(local) = self
            .locals
            .iter_mut()
            .find(|local| &local.dest_hash == dest_hash)
        else {
            return false;
        };
        let LocalDestinationKind::Single { prove } = &mut local.kind else {
            return false;
        };
        *prove = enabled;
        true
    }

    pub fn pending_receipt_count(&self) -> usize {
        self.pending_receipts.len()
    }

    pub fn send_group_message<R: EntropySource>(
        &mut self,
        dest_hash: &[u8; 16],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<(), NodeError> {
        let key = self
            .locals
            .iter()
            .find_map(|local| {
                (&local.dest_hash == dest_hash)
                    .then_some(&local.kind)
                    .and_then(|kind| match kind {
                        LocalDestinationKind::Group { key } => Some(*key),
                        _ => None,
                    })
            })
            .ok_or(NodeError::Unknown)?;
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        let ciphertext = token::seal_with_key(&key, plaintext, &iv);
        self.enqueue_destination_packet(Packet::data_for(GROUP, dest_hash, ciphertext), dest_hash)
    }

    pub fn send_plain_message(
        &mut self,
        dest_hash: &[u8; 16],
        plaintext: &[u8],
    ) -> Result<(), NodeError> {
        self.enqueue_destination_packet(
            Packet::data_for(PLAIN, dest_hash, plaintext.to_vec()),
            dest_hash,
        )
    }

    fn enqueue_destination_packet(
        &mut self,
        mut packet: Packet,
        dest_hash: &[u8; 16],
    ) -> Result<(), NodeError> {
        self.paths.prune(self.clock.now_secs());
        if let Some(path) = self.paths.get(dest_hash) {
            if path.hops > 1 {
                let Some(next_hop) = path.next_hop_transport_id else {
                    return Err(NodeError::Unknown);
                };
                packet.header_type = HEADER_2;
                packet.propagation = TRANSPORT;
                packet.transport_id = Some(next_hop);
            }
            self.outbound.push_back((path.interface, packet.encode()));
            return Ok(());
        }
        if self.interfaces.is_empty() {
            return Err(NodeError::Unknown);
        }
        let encoded = packet.encode();
        for interface in &self.interfaces {
            self.outbound.push_back((*interface, encoded.clone()));
        }
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

    pub fn send_resource<R: EntropySource>(
        &mut self,
        link_id: &[u8; 16],
        data: &[u8],
        rng: &mut R,
    ) -> Result<[u8; 32], NodeError> {
        let (key, interface) = self
            .links
            .get(link_id)
            .filter(|link| link.status == LinkStatus::Active)
            .and_then(|link| link.derived_key.map(|key| (key, link.interface)))
            .ok_or(NodeError::Unknown)?;
        let (resource, advertisement) =
            OutboundResource::new(data, &key, rng, self.clock.now_secs())?;
        let hash = resource.hash;
        self.outbound_resources.insert((*link_id, hash), resource);
        self.enqueue_encrypted_link_context(
            link_id,
            interface,
            RESOURCE_ADV,
            &advertisement,
            &key,
            rng,
        );
        Ok(hash)
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
        self.tick_inner(None)
    }

    pub fn tick_with_entropy<R: EntropySource>(&mut self, rng: &mut R) -> Vec<Event> {
        self.tick_inner(Some(rng))
    }

    fn tick_inner(&mut self, mut rng: Option<&mut dyn EntropySource>) -> Vec<Event> {
        let now = self.clock.now_secs();
        self.pending_receipts
            .retain(|_, receipt| receipt.expires_at > now);
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
        let resource_keys: Vec<_> = self.inbound_resources.keys().copied().collect();
        for (link_id, hash) in resource_keys {
            let retry = self
                .inbound_resources
                .get_mut(&(link_id, hash))
                .map(|resource| resource.retry_due(now));
            match retry {
                Some(Ok(Some(request))) => {
                    if let (Some(rng), Some(link)) = (rng.as_deref_mut(), self.links.get(&link_id))
                        && let Some(key) = link.derived_key
                    {
                        self.enqueue_encrypted_link_context(
                            &link_id,
                            link.interface,
                            RESOURCE_REQ,
                            &request,
                            &key,
                            rng,
                        );
                    }
                }
                Some(Err(_)) => {
                    self.inbound_resources.remove(&(link_id, hash));
                    self.pending_events
                        .push_back(Event::ResourceFailed { link_id, hash });
                }
                _ => {}
            }
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
        if packet.packet_type == PROOF && packet.dest_type == SINGLE {
            return self.handle_delivery_proof(&packet, &dest_hash);
        }
        if packet.packet_type == PROOF && packet.dest_type == LINK && packet.context == RESOURCE_PRF
        {
            return self.handle_resource_proof(&packet, &dest_hash);
        }
        if packet.packet_type == DATA && packet.dest_type == LINK {
            return self.handle_link_data(&packet, &dest_hash, interface, rng);
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
        if !self.locals.iter().any(|local| {
            &local.dest_hash == dest_hash
                && matches!(local.kind, LocalDestinationKind::Single { .. })
        }) {
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
        rng: Option<&mut dyn EntropySource>,
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
        if packet.context == RESOURCE {
            return self.handle_resource_part(link_id, interface, &key, &packet.data, rng);
        }
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
            RESOURCE_ADV | RESOURCE_REQ | RESOURCE_HMU | RESOURCE_ICL | RESOURCE_RCL => match rng {
                Some(rng) => self.handle_resource_context(
                    link_id,
                    interface,
                    &key,
                    packet.context,
                    &plaintext,
                    rng,
                ),
                None => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    fn handle_resource_context(
        &mut self,
        link_id: &[u8; 16],
        interface: u16,
        key: &[u8; 64],
        context: u8,
        plaintext: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Vec<Event> {
        match context {
            RESOURCE_ADV => {
                let advertisement = match ResourceAdvertisement::unpack(plaintext) {
                    Ok(advertisement) => advertisement,
                    Err(error) => return alloc::vec![Event::Error(NodeError::Core(error))],
                };
                let resource = match InboundResource::from_advertisement(advertisement) {
                    Ok(resource) => resource,
                    Err(error) => return alloc::vec![Event::Error(NodeError::Core(error))],
                };
                let hash = resource.hash;
                let size = resource.total_size;
                self.inbound_resources.insert((*link_id, hash), resource);
                if let Some(request) = self
                    .inbound_resources
                    .get_mut(&(*link_id, hash))
                    .and_then(|resource| resource.next_request(self.clock.now_secs()))
                {
                    self.enqueue_encrypted_link_context(
                        link_id,
                        interface,
                        RESOURCE_REQ,
                        &request,
                        key,
                        rng,
                    );
                }
                alloc::vec![Event::ResourceStarted {
                    link_id: *link_id,
                    hash,
                    size,
                }]
            }
            RESOURCE_REQ => {
                let hash = if plaintext.first() == Some(&0xFF) {
                    plaintext.get(5..37)
                } else {
                    plaintext.get(1..33)
                }
                .and_then(|hash| <[u8; 32]>::try_from(hash).ok());
                let Some(hash) = hash else {
                    return Vec::new();
                };
                let outputs = self
                    .outbound_resources
                    .get_mut(&(*link_id, hash))
                    .map(|resource| resource.on_request(plaintext, self.clock.now_secs()))
                    .unwrap_or_default();
                for output in outputs {
                    match output {
                        ResourceOutput::Part(part) => self.outbound.push_back((
                            interface,
                            Packet::link_context(link_id, RESOURCE, part).encode(),
                        )),
                        ResourceOutput::HashmapUpdate(update) => {
                            self.enqueue_encrypted_link_context(
                                link_id,
                                interface,
                                RESOURCE_HMU,
                                &update,
                                key,
                                rng,
                            );
                        }
                    }
                }
                Vec::new()
            }
            RESOURCE_HMU => {
                let Some(hash) = plaintext
                    .get(..32)
                    .and_then(|hash| <[u8; 32]>::try_from(hash).ok())
                else {
                    return Vec::new();
                };
                let result = self
                    .inbound_resources
                    .get_mut(&(*link_id, hash))
                    .map(|resource| resource.on_hashmap_update(plaintext));
                if !matches!(result, Some(Ok(()))) {
                    return Vec::new();
                }
                if let Some(request) = self
                    .inbound_resources
                    .get_mut(&(*link_id, hash))
                    .and_then(|resource| resource.next_request(self.clock.now_secs()))
                {
                    self.enqueue_encrypted_link_context(
                        link_id,
                        interface,
                        RESOURCE_REQ,
                        &request,
                        key,
                        rng,
                    );
                }
                Vec::new()
            }
            RESOURCE_ICL | RESOURCE_RCL => {
                let Some(hash) = plaintext
                    .get(..32)
                    .and_then(|hash| <[u8; 32]>::try_from(hash).ok())
                else {
                    return Vec::new();
                };
                self.inbound_resources.remove(&(*link_id, hash));
                self.outbound_resources.remove(&(*link_id, hash));
                alloc::vec![Event::ResourceFailed {
                    link_id: *link_id,
                    hash,
                }]
            }
            _ => Vec::new(),
        }
    }

    fn handle_resource_part(
        &mut self,
        link_id: &[u8; 16],
        interface: u16,
        key: &[u8; 64],
        part: &[u8],
        rng: Option<&mut dyn EntropySource>,
    ) -> Vec<Event> {
        let candidates: Vec<_> = self
            .inbound_resources
            .keys()
            .filter(|(candidate_link, _)| candidate_link == link_id)
            .copied()
            .collect();
        for resource_key @ (_, hash) in candidates {
            let accepted = self
                .inbound_resources
                .get_mut(&resource_key)
                .is_some_and(|resource| resource.on_part(part.to_vec()));
            if !accepted {
                continue;
            }
            let (received, total, complete) = self
                .inbound_resources
                .get(&resource_key)
                .map(|resource| {
                    (
                        resource.received_parts(),
                        resource.total_parts(),
                        resource.is_complete(),
                    )
                })
                .unwrap_or_default();
            let mut events = alloc::vec![Event::ResourceProgress {
                link_id: *link_id,
                hash,
                fraction: received as f32 / total as f32,
            }];
            if complete {
                let finalized = self
                    .inbound_resources
                    .get(&resource_key)
                    .and_then(|resource| {
                        resource
                            .finalize(key)
                            .ok()
                            .map(|data| (resource.proof_packet(&data), data))
                    });
                self.inbound_resources.remove(&resource_key);
                match finalized {
                    Some((proof, data)) => {
                        self.outbound.push_back((
                            interface,
                            Packet::proof(link_id, proof, RESOURCE_PRF).encode(),
                        ));
                        events.push(Event::ResourceComplete {
                            link_id: *link_id,
                            hash,
                            data,
                        });
                    }
                    None => events.push(Event::ResourceFailed {
                        link_id: *link_id,
                        hash,
                    }),
                }
            } else if let Some(rng) = rng
                && self
                    .inbound_resources
                    .get(&resource_key)
                    .is_some_and(InboundResource::ready_for_request)
            {
                let request = self
                    .inbound_resources
                    .get_mut(&resource_key)
                    .and_then(|resource| {
                        resource
                            .next_request(self.clock.now_secs())
                            .filter(|_| resource.retries == 0)
                    });
                if let Some(request) = request {
                    self.enqueue_encrypted_link_context(
                        link_id,
                        interface,
                        RESOURCE_REQ,
                        &request,
                        key,
                        rng,
                    );
                }
            }
            return events;
        }
        Vec::new()
    }

    fn handle_resource_proof(&mut self, packet: &Packet, link_id: &[u8; 16]) -> Vec<Event> {
        let Some(hash) = packet
            .data
            .get(..32)
            .and_then(|hash| <[u8; 32]>::try_from(hash).ok())
        else {
            return Vec::new();
        };
        let completed = self
            .outbound_resources
            .get_mut(&(*link_id, hash))
            .is_some_and(|resource| resource.on_proof(&packet.data));
        if completed {
            self.outbound_resources.remove(&(*link_id, hash));
            return alloc::vec![Event::ResourceComplete {
                link_id: *link_id,
                hash,
                data: Vec::new(),
            }];
        }
        Vec::new()
    }

    fn handle_delivery_proof(
        &mut self,
        packet: &Packet,
        proof_destination: &[u8; 16],
    ) -> Vec<Event> {
        let Some(packet_hash) = packet
            .data
            .get(..32)
            .and_then(|hash| <[u8; 32]>::try_from(hash).ok())
        else {
            return Vec::new();
        };
        if proof_destination_hash(&packet_hash) != *proof_destination {
            return Vec::new();
        }
        let Some(receipt) = self.pending_receipts.get(&packet_hash) else {
            return Vec::new();
        };
        if verify_proof(&receipt.destination_public, &packet.data) != Ok(packet_hash) {
            return Vec::new();
        }
        self.pending_receipts.remove(&packet_hash);
        alloc::vec![Event::Delivered { packet_hash }]
    }

    fn enqueue_encrypted_link_context(
        &mut self,
        link_id: &[u8; 16],
        interface: u16,
        context: u8,
        plaintext: &[u8],
        key: &[u8; 64],
        rng: &mut dyn EntropySource,
    ) {
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        let encrypted = token::seal_with_key(key, plaintext, &iv);
        self.outbound.push_back((
            interface,
            Packet::link_context(link_id, context, encrypted).encode(),
        ));
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
        let local = self
            .locals
            .iter()
            .find(|local| &local.dest_hash == dest_hash);
        if local.is_none() {
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
        let Some(local) = local else {
            return Vec::new();
        };
        let (result, prove) = match (&local.kind, packet.dest_type) {
            (LocalDestinationKind::Single { prove }, SINGLE) => {
                (token::decrypt(&self.identity, &packet.data), *prove)
            }
            (LocalDestinationKind::Group { key }, GROUP) => {
                (token::open_with_key(key, &packet.data), false)
            }
            (LocalDestinationKind::Plain, PLAIN) => (Ok(packet.data.clone()), false),
            _ => return Vec::new(),
        };
        match result {
            Ok(plaintext) => {
                if prove {
                    let packet_hash = packet.full_packet_hash();
                    let proof = build_proof(&self.identity, &packet_hash);
                    self.outbound.push_back((
                        interface,
                        Packet::explicit_proof(&proof_destination_hash(&packet_hash), proof)
                            .encode(),
                    ));
                }
                alloc::vec![Event::Message {
                    dest_hash: *dest_hash,
                    plaintext,
                }]
            }
            Err(error) => alloc::vec![Event::Error(NodeError::Core(error))],
        }
    }

    pub fn local_destinations(&self) -> impl Iterator<Item = [u8; 16]> + '_ {
        self.locals.iter().filter_map(|local| {
            matches!(local.kind, LocalDestinationKind::Single { .. }).then_some(local.dest_hash)
        })
    }

    pub fn knows_path(&self, dest_hash: &[u8; 16]) -> bool {
        self.paths.get(dest_hash).is_some()
    }

    pub fn prune_paths(&mut self) -> usize {
        self.paths.prune(self.clock.now_secs())
    }
}
