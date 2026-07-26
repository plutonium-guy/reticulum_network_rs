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

use reticulum_core::destination::{destination_hash, name_hash};

#[test]
fn destination_hashes_match_rns() {
    let v = load("destination.json");
    let app = v["app_name"].as_str().unwrap();
    let aspects: Vec<String> = v["aspects"].as_array().unwrap()
        .iter().map(|a| a.as_str().unwrap().to_string()).collect();
    let aspect_refs: Vec<&str> = aspects.iter().map(|s| s.as_str()).collect();

    let nh = name_hash(app, &aspect_refs);
    assert_eq!(nh.to_vec(), hexf(&v, "name_hash"));

    let ih: [u8;16] = hexf(&v, "identity_hash").try_into().unwrap();
    let dh = destination_hash(&nh, &ih);
    assert_eq!(dh.to_vec(), hexf(&v, "dest_hash"));
}

use reticulum_core::token;

#[test]
fn token_decrypts_rns_vector() {
    let idv = load("identity.json");
    let x: [u8;32] = hexf(&idv, "prv_x25519").try_into().unwrap();
    let e: [u8;32] = hexf(&idv, "prv_ed25519").try_into().unwrap();
    let id = Identity::from_private_bytes(&x, &e);

    let tv = load("token.json");
    let token_bytes = hexf(&tv, "token");
    let expected = hexf(&tv, "plaintext");

    let out = token::decrypt(&id, &token_bytes).expect("decrypt");
    assert_eq!(out, expected);
}

#[test]
fn token_roundtrip() {
    let idv = load("identity.json");
    let x: [u8;32] = hexf(&idv, "prv_x25519").try_into().unwrap();
    let e: [u8;32] = hexf(&idv, "prv_ed25519").try_into().unwrap();
    let id = Identity::from_private_bytes(&x, &e);
    let enc_pub = id.public().enc_pub;

    let ephemeral = [7u8; 32];
    let ct = token::encrypt(&enc_pub, b"roundtrip", &ephemeral);
    let pt = token::decrypt(&id, &ct).expect("decrypt");
    assert_eq!(pt, b"roundtrip");
}
