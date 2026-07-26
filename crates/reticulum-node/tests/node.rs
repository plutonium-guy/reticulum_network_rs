use reticulum_core::identity::Identity;
use reticulum_core::packet::{ANNOUNCE, Packet};
use reticulum_node::node::Node;
use reticulum_node::rng::SeededRng;

#[test]
fn node_emits_announce_packet() {
    let identity = Identity::from_private_bytes(&[1u8; 32], &[2u8; 32]);
    let mut node = Node::new(identity);
    let dest_hash = node.register_single_destination("chat", &["v1"]);
    let mut rng = SeededRng::new(7);
    node.send_announce(&dest_hash, b"hi", &mut rng, 0);
    let (interface, bytes) = node.poll_outbound().expect("one outbound");
    assert_eq!(interface, 0);
    let packet = Packet::decode(&bytes).unwrap();
    assert_eq!(packet.packet_type, ANNOUNCE);
    assert_eq!(packet.dest_hash, dest_hash.to_vec());
    assert!(node.poll_outbound().is_none());
}

#[test]
fn node_learns_path_from_announce() {
    let sender_identity = Identity::from_private_bytes(&[3u8; 32], &[4u8; 32]);
    let mut sender = Node::new(sender_identity);
    let dest_hash = sender.register_single_destination("chat", &["v1"]);
    let mut rng = SeededRng::new(1);
    sender.send_announce(&dest_hash, b"hello", &mut rng, 0);
    let (_, announce_bytes) = sender.poll_outbound().unwrap();

    let receiver_identity = Identity::from_private_bytes(&[5u8; 32], &[6u8; 32]);
    let mut receiver = Node::new(receiver_identity);
    let events = receiver.handle_inbound(&announce_bytes, 2);
    assert_eq!(events.len(), 1);
    match &events[0] {
        reticulum_node::Event::Announce {
            dest_hash: announced,
            ..
        } => assert_eq!(*announced, dest_hash),
        other => panic!("expected Announce, got {other:?}"),
    }
    assert!(receiver.knows_path(&dest_hash));
}

#[test]
fn node_decrypts_data_to_local_destination() {
    use reticulum_core::{packet::Packet, token};

    let mut receiver = Node::new(Identity::from_private_bytes(&[10u8; 32], &[11u8; 32]));
    let dest_hash = receiver.register_single_destination("chat", &["v1"]);
    let recipient = Identity::from_private_bytes(&[10u8; 32], &[11u8; 32]).public();
    let ciphertext = token::encrypt(&recipient, b"secret", &[9u8; 32], &[3u8; 16]);
    let packet = Packet::data_single(&dest_hash, ciphertext);

    let events = receiver.handle_inbound(&packet.encode(), 0);
    assert_eq!(events.len(), 1);
    match &events[0] {
        reticulum_node::Event::Message {
            dest_hash: received,
            plaintext,
        } => {
            assert_eq!(*received, dest_hash);
            assert_eq!(plaintext, b"secret");
        }
        other => panic!("expected Message, got {other:?}"),
    }
}

#[test]
fn node_sends_encrypted_message_to_known_path() {
    let mut receiver = Node::new(Identity::from_private_bytes(&[10u8; 32], &[11u8; 32]));
    let dest_hash = receiver.register_single_destination("chat", &["v1"]);
    let mut receiver_rng = SeededRng::new(1);
    receiver.send_announce(&dest_hash, b"", &mut receiver_rng, 0);
    let (_, announce) = receiver.poll_outbound().unwrap();

    let mut sender = Node::new(Identity::from_private_bytes(&[20u8; 32], &[21u8; 32]));
    sender.handle_inbound(&announce, 5);
    let mut sender_rng = SeededRng::new(99);
    sender
        .send_message(&dest_hash, b"secret", &mut sender_rng)
        .unwrap();
    let (interface, data_bytes) = sender.poll_outbound().unwrap();
    assert_eq!(interface, 5);

    let events = receiver.handle_inbound(&data_bytes, 0);
    assert!(matches!(
        &events[0],
        reticulum_node::Event::Message { plaintext, .. } if plaintext == b"secret"
    ));
}
