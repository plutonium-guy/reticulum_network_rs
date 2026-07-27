use reticulum_core::identity::Identity;
use reticulum_lxmf::LxmfMessage;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    source_prv_x: String,
    source_prv_ed: String,
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
