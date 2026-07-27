use reticulum_core::{EntropySource, identity::Identity};
use reticulum_lxmf::{
    LxmfMessage, build_propagation_upload, decrypt_propagated_message,
    propagation_destination_hash, unpack_propagation_container,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    source_prv_x: String,
    source_prv_ed: String,
    source_public: String,
    destination: String,
    source: String,
    timestamp: f64,
    title: String,
    content: String,
    fields_msgpack: String,
    packed_hex: String,
    hash: String,
    signature: String,
}

fn vector() -> Vector {
    serde_json::from_str(include_str!("../../../vectors/lxmf_message.json")).unwrap()
}

fn bytes<const N: usize>(encoded: &str) -> [u8; N] {
    hex::decode(encoded).unwrap().try_into().unwrap()
}

#[derive(Deserialize)]
struct PropagationVector {
    recipient_public: String,
    recipient_prv_x: String,
    recipient_prv_ed: String,
    propagation_node_public: String,
    propagation_node_destination: String,
    ephemeral_prv_x25519: String,
    iv: String,
    timestamp: f64,
    message_packed: String,
    encrypted: String,
    lxmf_data: String,
    transient_id: String,
    propagation_packed: String,
}

struct VectorEntropy {
    bytes: Vec<u8>,
    position: usize,
}

impl EntropySource for VectorEntropy {
    fn fill(&mut self, out: &mut [u8]) {
        let end = self.position + out.len();
        out.copy_from_slice(&self.bytes[self.position..end]);
        self.position = end;
    }
}

#[test]
fn build_sign_and_pack_match_python_lxmf_1_1_0() {
    let expected = vector();
    let identity = Identity::from_private_bytes(
        &bytes(&expected.source_prv_x),
        &bytes(&expected.source_prv_ed),
    );
    let message = LxmfMessage::build(
        &identity,
        bytes(&expected.destination),
        bytes(&expected.source),
        expected.timestamp,
        &hex::decode(expected.title).unwrap(),
        &hex::decode(expected.content).unwrap(),
        &hex::decode(expected.fields_msgpack).unwrap(),
    );

    assert_eq!(message.hash, bytes(&expected.hash));
    assert_eq!(message.signature, bytes(&expected.signature));
    assert_eq!(message.pack(), hex::decode(expected.packed_hex).unwrap());
}

#[test]
fn unpack_and_verify_match_python_lxmf_1_1_0() {
    let expected = vector();
    let packed = hex::decode(&expected.packed_hex).unwrap();
    let message = LxmfMessage::unpack(&packed).unwrap();
    let public = reticulum_core::identity::PublicIdentity::from_bytes(
        &hex::decode(expected.source_public).unwrap(),
    )
    .unwrap();

    assert_eq!(message.destination, bytes(&expected.destination));
    assert_eq!(message.source, bytes(&expected.source));
    assert_eq!(message.timestamp, expected.timestamp);
    assert_eq!(message.title, hex::decode(expected.title).unwrap());
    assert_eq!(message.content, hex::decode(expected.content).unwrap());
    assert_eq!(
        message.fields,
        hex::decode(expected.fields_msgpack).unwrap()
    );
    assert_eq!(message.hash, bytes(&expected.hash));
    message.verify(&public).unwrap();
}

#[test]
fn verification_rejects_tampered_payload_signature_and_mutation() {
    let expected = vector();
    let public = reticulum_core::identity::PublicIdentity::from_bytes(
        &hex::decode(expected.source_public).unwrap(),
    )
    .unwrap();

    let mut payload_tampered = hex::decode(&expected.packed_hex).unwrap();
    *payload_tampered.last_mut().unwrap() ^= 1;
    let message = LxmfMessage::unpack(&payload_tampered).unwrap();
    assert!(message.verify(&public).is_err());

    let mut signature_tampered = hex::decode(&expected.packed_hex).unwrap();
    signature_tampered[32] ^= 1;
    let message = LxmfMessage::unpack(&signature_tampered).unwrap();
    assert!(message.verify(&public).is_err());

    let mut message = LxmfMessage::unpack(&hex::decode(&expected.packed_hex).unwrap()).unwrap();
    message.content.push(1);
    assert!(message.verify(&public).is_err());
}

#[test]
fn every_truncated_prefix_is_rejected_without_panicking() {
    let expected = vector();
    let packed = hex::decode(expected.packed_hex).unwrap();
    for end in 0..packed.len() {
        assert!(LxmfMessage::unpack(&packed[..end]).is_err());
    }
}

#[test]
fn propagation_upload_matches_python_lxmf_1_1_0() {
    let expected: PropagationVector =
        serde_json::from_str(include_str!("../../../vectors/lxmf_propagation.json")).unwrap();
    let recipient_public = reticulum_core::identity::PublicIdentity::from_bytes(
        &hex::decode(&expected.recipient_public).unwrap(),
    )
    .unwrap();
    let propagation_public = reticulum_core::identity::PublicIdentity::from_bytes(
        &hex::decode(&expected.propagation_node_public).unwrap(),
    )
    .unwrap();
    let message = LxmfMessage::unpack(&hex::decode(&expected.message_packed).unwrap()).unwrap();
    let mut entropy_bytes = hex::decode(&expected.ephemeral_prv_x25519).unwrap();
    entropy_bytes.extend_from_slice(&hex::decode(&expected.iv).unwrap());
    let mut entropy = VectorEntropy {
        bytes: entropy_bytes,
        position: 0,
    };

    let upload = build_propagation_upload(
        &message,
        &recipient_public,
        expected.timestamp,
        None,
        &mut entropy,
    )
    .unwrap();
    assert_eq!(
        &upload.lxmf_data[16..],
        hex::decode(expected.encrypted).unwrap()
    );
    assert_eq!(upload.lxmf_data, hex::decode(expected.lxmf_data).unwrap());
    assert_eq!(upload.transient_id, bytes(&expected.transient_id));
    assert_eq!(
        upload.packed,
        hex::decode(expected.propagation_packed).unwrap()
    );
    assert_eq!(
        propagation_destination_hash(&propagation_public),
        bytes(&expected.propagation_node_destination)
    );

    let container = unpack_propagation_container(&upload.packed).unwrap();
    assert_eq!(container.timestamp, expected.timestamp);
    assert_eq!(container.messages.len(), 1);
    assert_eq!(container.messages[0], upload.lxmf_data);
    let recipient = Identity::from_private_bytes(
        &bytes(&expected.recipient_prv_x),
        &bytes(&expected.recipient_prv_ed),
    );
    assert_eq!(
        decrypt_propagated_message(&recipient, &upload.lxmf_data, 0)
            .unwrap()
            .pack(),
        message.pack()
    );

    for end in 0..upload.packed.len() {
        assert!(unpack_propagation_container(&upload.packed[..end]).is_err());
    }
}
