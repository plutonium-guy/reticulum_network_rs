use reticulum_core::identity::Identity;
use reticulum_lxmf::LxmfMessage;
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
