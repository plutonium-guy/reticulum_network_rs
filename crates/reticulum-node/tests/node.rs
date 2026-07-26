use reticulum_core::identity::Identity;
use reticulum_core::packet::{ANNOUNCE, HEADER_2, Packet, TRANSPORT};
use reticulum_node::clock::TestClock;
use reticulum_node::node::Node;
use reticulum_node::rng::SeededRng;

#[test]
fn node_uses_injected_clock() {
    let identity = Identity::from_private_bytes(&[1u8; 32], &[2u8; 32]);
    let node = Node::with_clock(identity, TestClock::new(41));
    assert_eq!(node.now_secs(), 41);
    node.clock().advance(1);
    assert_eq!(node.now_secs(), 42);
}

#[test]
fn node_prunes_expired_announce_paths_using_injected_time() {
    let mut sender = Node::new(Identity::from_private_bytes(&[3u8; 32], &[4u8; 32]));
    let dest_hash = sender.register_single_destination("chat", &["expiry"]);
    let mut rng = SeededRng::new(1);
    sender.send_announce(&dest_hash, b"", &mut rng, 0);
    let (_, announce) = sender.poll_outbound().unwrap();

    let mut receiver = Node::with_clock(
        Identity::from_private_bytes(&[5u8; 32], &[6u8; 32]),
        TestClock::new(10),
    );
    receiver.handle_inbound(&announce, 2);
    assert!(receiver.knows_path(&dest_hash));
    receiver.clock().advance(604_800);
    assert_eq!(receiver.prune_paths(), 1);
    assert!(!receiver.knows_path(&dest_hash));
}

#[test]
fn transport_propagates_valid_announce_to_other_interfaces_as_header2() {
    let mut origin = Node::new(Identity::from_private_bytes(&[3u8; 32], &[4u8; 32]));
    let dest_hash = origin.register_single_destination("chat", &["transported"]);
    let mut rng = SeededRng::new(1);
    origin.send_announce(&dest_hash, b"", &mut rng, 1);
    let (_, announce) = origin.poll_outbound().unwrap();

    let relay_identity = Identity::from_private_bytes(&[5u8; 32], &[6u8; 32]);
    let relay_transport_id = relay_identity.hash();
    let mut relay = Node::new(relay_identity);
    relay.enable_transport();
    relay.register_interface(1);
    relay.register_interface(2);

    let events = relay.handle_inbound(&announce, 1);
    assert!(matches!(
        &events[..],
        [reticulum_node::Event::Announce { .. }]
    ));
    let (interface, forwarded) = relay.poll_outbound().unwrap();
    assert_eq!(interface, 2);
    let packet = Packet::decode(&forwarded).unwrap();
    assert_eq!(packet.header_type, HEADER_2);
    assert_eq!(packet.propagation, TRANSPORT);
    assert_eq!(packet.transport_id, relay_transport_id);
    assert_eq!(packet.dest_hash, dest_hash);
    assert_eq!(packet.hops, 1);
    assert!(relay.poll_outbound().is_none());
}

#[test]
fn transport_suppresses_duplicate_announces_and_hop_limit_propagation() {
    let mut origin = Node::new(Identity::from_private_bytes(&[3u8; 32], &[4u8; 32]));
    let dest_hash = origin.register_single_destination("chat", &["duplicate"]);
    let mut rng = SeededRng::new(1);
    origin.send_announce(&dest_hash, b"", &mut rng, 1);
    let (_, announce) = origin.poll_outbound().unwrap();

    let mut relay = Node::new(Identity::from_private_bytes(&[5u8; 32], &[6u8; 32]));
    relay.enable_transport();
    relay.register_interface(1);
    relay.register_interface(2);
    relay.handle_inbound(&announce, 1);
    relay.poll_outbound().unwrap();

    assert!(relay.handle_inbound(&announce, 1).is_empty());
    assert!(relay.poll_outbound().is_none());

    origin.send_announce(&dest_hash, b"", &mut rng, 1);
    let (_, mut at_limit) = origin.poll_outbound().unwrap();
    at_limit[1] = 127;
    relay.handle_inbound(&at_limit, 1);
    assert!(relay.poll_outbound().is_none());
}

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

#[test]
fn two_nodes_announce_and_message_both_directions() {
    let mut a = Node::new(Identity::from_private_bytes(&[1u8; 32], &[2u8; 32]));
    let mut b = Node::new(Identity::from_private_bytes(&[3u8; 32], &[4u8; 32]));
    let a_dest = a.register_single_destination("chat", &["a"]);
    let b_dest = b.register_single_destination("chat", &["b"]);
    let mut a_rng = SeededRng::new(10);
    let mut b_rng = SeededRng::new(20);

    a.send_announce(&a_dest, b"", &mut a_rng, 0);
    b.send_announce(&b_dest, b"", &mut b_rng, 0);
    let (_, a_announce) = a.poll_outbound().unwrap();
    let (_, b_announce) = b.poll_outbound().unwrap();
    b.handle_inbound(&a_announce, 1);
    a.handle_inbound(&b_announce, 1);
    assert!(a.knows_path(&b_dest) && b.knows_path(&a_dest));

    a.send_message(&b_dest, b"ping", &mut a_rng).unwrap();
    let (_, ping) = a.poll_outbound().unwrap();
    let ping_events = b.handle_inbound(&ping, 1);
    assert!(matches!(
        &ping_events[0],
        reticulum_node::Event::Message { plaintext, .. } if plaintext == b"ping"
    ));

    b.send_message(&a_dest, b"pong", &mut b_rng).unwrap();
    let (_, pong) = b.poll_outbound().unwrap();
    let pong_events = a.handle_inbound(&pong, 1);
    assert!(matches!(
        &pong_events[0],
        reticulum_node::Event::Message { plaintext, .. } if plaintext == b"pong"
    ));
}
