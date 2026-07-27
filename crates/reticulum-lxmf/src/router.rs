use alloc::{collections::BTreeMap, vec::Vec};

use reticulum_core::{
    CoreError, EntropySource,
    destination::{destination_hash, name_hash},
    identity::PublicIdentity,
};
use reticulum_node::{Clock, NodeError, node::Node};

use crate::LxmfMessage;

const LXMF_APP_NAME: &str = "lxmf";
const DELIVERY_ASPECTS: &[&str] = &["delivery"];

pub fn delivery_destination_hash(identity: &PublicIdentity) -> [u8; 16] {
    destination_hash(
        &name_hash(LXMF_APP_NAME, DELIVERY_ASPECTS),
        &identity.hash(),
    )
}

#[derive(Debug, Clone, PartialEq)]
pub enum LxmfEvent {
    Message(LxmfMessage),
}

pub struct LxmfRouter {
    local_destination: [u8; 16],
    source_identities: BTreeMap<[u8; 16], PublicIdentity>,
}

impl LxmfRouter {
    pub fn new(local_identity: &PublicIdentity) -> Self {
        Self {
            local_destination: delivery_destination_hash(local_identity),
            source_identities: BTreeMap::new(),
        }
    }

    pub fn local_destination(&self) -> [u8; 16] {
        self.local_destination
    }

    pub fn remember_source(&mut self, source: PublicIdentity) -> [u8; 16] {
        let destination = delivery_destination_hash(&source);
        self.source_identities.insert(destination, source);
        destination
    }

    /// Send the complete packed message over an established RNS link.
    ///
    /// LXMF 1.1.0 `LXMessage.__as_packet()` retains the destination prefix for
    /// direct delivery because the link packet is addressed by its link ID.
    pub fn send_direct<C: Clock, R: EntropySource>(
        &self,
        node: &mut Node<C>,
        link_id: &[u8; 16],
        message: &LxmfMessage,
        entropy: &mut R,
    ) -> Result<(), NodeError> {
        node.link_send(link_id, &message.pack(), entropy)
    }

    pub fn receive_direct(&self, bytes: &[u8]) -> Result<LxmfEvent, CoreError> {
        self.unpack_for_local_destination(bytes)
    }

    /// Send the LXMF payload opportunistically in one destination packet.
    ///
    /// LXMF omits the leading destination hash because the RNS packet already
    /// carries it in its destination field.
    pub fn send_opportunistic<C: Clock, R: EntropySource>(
        &self,
        node: &mut Node<C>,
        message: &LxmfMessage,
        entropy: &mut R,
    ) -> Result<(), NodeError> {
        let packed = message.pack();
        node.send_message(&message.destination, &packed[16..], entropy)
    }

    pub fn receive_opportunistic(
        &self,
        destination: [u8; 16],
        bytes: &[u8],
    ) -> Result<LxmfEvent, CoreError> {
        if destination != self.local_destination {
            return Err(CoreError::InvalidField);
        }
        let mut packed = Vec::with_capacity(16 + bytes.len());
        packed.extend_from_slice(&destination);
        packed.extend_from_slice(bytes);
        self.unpack_for_local_destination(&packed)
    }

    fn unpack_for_local_destination(&self, bytes: &[u8]) -> Result<LxmfEvent, CoreError> {
        let message = LxmfMessage::unpack(bytes)?;
        if message.destination != self.local_destination {
            return Err(CoreError::InvalidField);
        }
        let source = self
            .source_identities
            .get(&message.source)
            .ok_or(CoreError::InvalidField)?;
        message.verify(source)?;
        Ok(LxmfEvent::Message(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use reticulum_core::identity::Identity;
    use reticulum_node::{Event, TestClock, rng::SeededRng};

    fn identity(seed: u8) -> Identity {
        Identity::from_private_bytes(&[seed; 32], &[seed.wrapping_add(1); 32])
    }

    fn drain_one<C: Clock>(node: &mut Node<C>) -> Vec<u8> {
        node.poll_outbound().expect("expected outbound packet").1
    }

    #[test]
    fn delivery_destination_matches_registered_lxmf_destination() {
        let identity = identity(1);
        let expected = delivery_destination_hash(&identity.public());
        let mut node = Node::new(identity);
        assert_eq!(
            node.register_single_destination(LXMF_APP_NAME, DELIVERY_ASPECTS),
            expected
        );
    }

    #[test]
    fn two_nodes_deliver_and_verify_lxmf_over_an_established_link() {
        let source_identity = identity(1);
        let recipient_identity = identity(3);
        let mut source = Node::with_clock(identity(1), TestClock::new(10));
        let mut recipient = Node::with_clock(identity(3), TestClock::new(10));
        let source_destination =
            source.register_single_destination(LXMF_APP_NAME, DELIVERY_ASPECTS);
        let recipient_destination =
            recipient.register_single_destination(LXMF_APP_NAME, DELIVERY_ASPECTS);
        source.register_interface(7);
        recipient.register_interface(7);
        let mut source_entropy = SeededRng::new(10);
        let mut recipient_entropy = SeededRng::new(20);

        recipient.send_announce(&recipient_destination, b"", &mut recipient_entropy, 7);
        source.handle_inbound_with_entropy(&drain_one(&mut recipient), 7, &mut source_entropy);
        let link_id = source
            .establish_link(&recipient_destination, &mut source_entropy)
            .unwrap();
        let events = recipient.handle_inbound_with_entropy(
            &drain_one(&mut source),
            7,
            &mut recipient_entropy,
        );
        assert!(events.contains(&Event::LinkEstablished { link_id }));
        let events =
            source.handle_inbound_with_entropy(&drain_one(&mut recipient), 7, &mut source_entropy);
        assert!(events.contains(&Event::LinkEstablished { link_id }));
        recipient.handle_inbound_with_entropy(&drain_one(&mut source), 7, &mut recipient_entropy);

        let source_router = LxmfRouter::new(&source_identity.public());
        let mut recipient_router = LxmfRouter::new(&recipient_identity.public());
        recipient_router.remember_source(source_identity.public());
        let fields = vec![0x81, 0xa4, b't', b'y', b'p', b'e', 0x01];
        let message = LxmfMessage::build(
            &source_identity,
            recipient_destination,
            source_destination,
            42.5,
            b"direct",
            b"hello over link",
            &fields,
        );
        source_router
            .send_direct(&mut source, &link_id, &message, &mut source_entropy)
            .unwrap();
        let events = recipient.handle_inbound_with_entropy(
            &drain_one(&mut source),
            7,
            &mut recipient_entropy,
        );
        let plaintext = events.into_iter().find_map(|event| match event {
            Event::LinkData { plaintext, .. } => Some(plaintext),
            _ => None,
        });
        let LxmfEvent::Message(received) = recipient_router
            .receive_direct(&plaintext.unwrap())
            .unwrap();
        assert_eq!(received.title, b"direct");
        assert_eq!(received.content, b"hello over link");
        assert_eq!(received.fields, fields);
    }

    #[test]
    fn two_nodes_deliver_and_verify_opportunistic_lxmf() {
        let source_identity = identity(11);
        let recipient_identity = identity(13);
        let mut source = Node::with_clock(identity(11), TestClock::new(10));
        let mut recipient = Node::with_clock(identity(13), TestClock::new(10));
        let source_destination =
            source.register_single_destination(LXMF_APP_NAME, DELIVERY_ASPECTS);
        let recipient_destination =
            recipient.register_single_destination(LXMF_APP_NAME, DELIVERY_ASPECTS);
        source.register_interface(8);
        recipient.register_interface(8);
        let mut source_entropy = SeededRng::new(30);
        let mut recipient_entropy = SeededRng::new(40);

        recipient.send_announce(&recipient_destination, b"", &mut recipient_entropy, 8);
        source.handle_inbound_with_entropy(&drain_one(&mut recipient), 8, &mut source_entropy);

        let source_router = LxmfRouter::new(&source_identity.public());
        let mut recipient_router = LxmfRouter::new(&recipient_identity.public());
        recipient_router.remember_source(source_identity.public());
        let message = LxmfMessage::build(
            &source_identity,
            recipient_destination,
            source_destination,
            52.5,
            b"opportunistic",
            b"hello in one packet",
            &[0x80],
        );
        source_router
            .send_opportunistic(&mut source, &message, &mut source_entropy)
            .unwrap();
        let events = recipient.handle_inbound_with_entropy(
            &drain_one(&mut source),
            8,
            &mut recipient_entropy,
        );
        let (destination, plaintext) = events
            .into_iter()
            .find_map(|event| match event {
                Event::Message {
                    dest_hash,
                    plaintext,
                } => Some((dest_hash, plaintext)),
                _ => None,
            })
            .unwrap();
        let LxmfEvent::Message(received) = recipient_router
            .receive_opportunistic(destination, &plaintext)
            .unwrap();
        assert_eq!(received.title, b"opportunistic");
        assert_eq!(received.content, b"hello in one packet");
        assert_eq!(received.fields, [0x80]);
    }
}
