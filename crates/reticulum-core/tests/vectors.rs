use reticulum_core::hash::{full_hash, truncated_hash};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/../../vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let s = std::fs::read_to_string(path).expect("vector file");
    serde_json::from_str(&s).expect("valid json")
}
fn hexf(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().expect(key)).expect("hex")
}

#[test]
fn truncated_is_first_16_of_full() {
    let data = b"reticulum";
    assert_eq!(truncated_hash(data), full_hash(data)[..16]);
}

use reticulum_core::identity::Identity;

#[test]
fn identity_pubkey_and_hash_match_rns() {
    let v = load("identity.json");
    let x: [u8; 32] = hexf(&v, "prv_x25519").try_into().unwrap();
    let e: [u8; 32] = hexf(&v, "prv_ed25519").try_into().unwrap();
    let id = Identity::from_private_bytes(&x, &e);
    assert_eq!(id.public().to_bytes().to_vec(), hexf(&v, "pub"));
    assert_eq!(id.hash().to_vec(), hexf(&v, "hash"));
}

#[test]
fn public_identity_verifies_own_signature() {
    let v = load("identity.json");
    let x: [u8; 32] = hexf(&v, "prv_x25519").try_into().unwrap();
    let e: [u8; 32] = hexf(&v, "prv_ed25519").try_into().unwrap();
    let id = Identity::from_private_bytes(&x, &e);
    let sig = id.sign(b"msg");
    assert!(id.public().verify(b"msg", &sig).is_ok());
    assert!(id.public().verify(b"tampered", &sig).is_err());
}
