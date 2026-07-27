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
    let aspects: Vec<String> = v["aspects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_string())
        .collect();
    let aspect_refs: Vec<&str> = aspects.iter().map(|s| s.as_str()).collect();

    let nh = name_hash(app, &aspect_refs);
    assert_eq!(nh.to_vec(), hexf(&v, "name_hash"));

    let ih: [u8; 16] = hexf(&v, "identity_hash").try_into().unwrap();
    let dh = destination_hash(&nh, &ih);
    assert_eq!(dh.to_vec(), hexf(&v, "dest_hash"));
}

use reticulum_core::token;

#[test]
fn token_decrypts_rns_vector() {
    let idv = load("identity.json");
    let x: [u8; 32] = hexf(&idv, "prv_x25519").try_into().unwrap();
    let e: [u8; 32] = hexf(&idv, "prv_ed25519").try_into().unwrap();
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
    let x: [u8; 32] = hexf(&idv, "prv_x25519").try_into().unwrap();
    let e: [u8; 32] = hexf(&idv, "prv_ed25519").try_into().unwrap();
    let id = Identity::from_private_bytes(&x, &e);
    let pub_id = id.public();

    let ephemeral = [7u8; 32];
    let iv = [3u8; 16];
    let ct = token::encrypt(&pub_id, b"roundtrip", &ephemeral, &iv);
    let pt = token::decrypt(&id, &ct).expect("decrypt");
    assert_eq!(pt, b"roundtrip");
}

#[test]
fn token_encrypt_matches_rns_vector() {
    use reticulum_core::identity::PublicIdentity;

    let v = load("token_encrypt.json");
    let recipient = PublicIdentity::from_bytes(&hexf(&v, "recipient_pub")).unwrap();
    let ephemeral: [u8; 32] = hexf(&v, "ephemeral_prv_x25519").try_into().unwrap();
    let iv: [u8; 16] = hexf(&v, "iv").try_into().unwrap();
    let plaintext = hexf(&v, "plaintext");
    let out = token::encrypt(&recipient, &plaintext, &ephemeral, &iv);
    assert_eq!(out, hexf(&v, "token"));
}

#[test]
fn token_keyed_matches_rns_vector() {
    let vector = load("token_keyed.json");
    let key: [u8; 64] = hexf(&vector, "derived_key").try_into().unwrap();
    let iv: [u8; 16] = hexf(&vector, "iv").try_into().unwrap();
    let plaintext = hexf(&vector, "plaintext");
    let expected = hexf(&vector, "token");

    assert_eq!(token::open_with_key(&key, &expected).unwrap(), plaintext);
    assert_eq!(token::seal_with_key(&key, &plaintext, &iv), expected);
}

use reticulum_core::packet::Packet;

#[test]
fn packet_roundtrips_rns_vector() {
    let v = load("packet_data.json");
    let raw = hexf(&v, "bytes");
    let p = Packet::decode(&raw).expect("decode");
    assert_eq!(p.packet_type as u64, v["packet_type"].as_u64().unwrap());
    assert_eq!(p.dest_type as u64, v["dest_type"].as_u64().unwrap());
    assert_eq!(p.hops as u64, v["hops"].as_u64().unwrap());
    assert_eq!(p.dest_hash, hexf(&v, "dest_hash"));
    assert_eq!(p.context as u64, v["context"].as_u64().unwrap());
    assert_eq!(p.data, hexf(&v, "data"));
    assert_eq!(p.encode(), raw); // byte-exact re-encode
}

#[test]
fn packet_header2_roundtrips_rns_vector_without_losing_transport_id() {
    let vector = load("packet_header2.json");
    let raw = hexf(&vector, "bytes");
    let packet = Packet::decode(&raw).expect("decode HEADER_2");
    assert_eq!(
        packet.header_type as u64,
        vector["header_type"].as_u64().unwrap()
    );
    assert_eq!(
        packet.transport_id.unwrap().to_vec(),
        hexf(&vector, "transport_id")
    );
    assert_eq!(packet.dest_hash, hexf(&vector, "dest_hash"));
    assert_eq!(packet.encode(), raw);
}

#[test]
fn path_request_constructor_matches_rns_vector() {
    let vector = load("path_request.json");
    let target: [u8; 16] = hexf(&vector, "target").try_into().unwrap();
    let requester: [u8; 16] = hexf(&vector, "requester_transport_id").try_into().unwrap();
    let tag: [u8; 16] = hexf(&vector, "tag").try_into().unwrap();
    let packet = Packet::path_request(&target, Some(&requester), &tag);
    assert_eq!(
        Packet::path_request_destination_hash().to_vec(),
        hexf(&vector, "dest_hash")
    );
    assert_eq!(packet.encode(), hexf(&vector, "bytes"));
}

#[test]
fn packet_announce_constructor_matches_vector() {
    let vector = load("announce.json");
    let raw = hexf(&vector, "bytes");
    let dest_hash: [u8; 16] = hexf(&vector, "dest_hash").try_into().unwrap();
    let packet = Packet::announce(&dest_hash, raw[19..].to_vec());
    assert_eq!(packet.encode(), raw);
}

#[test]
fn packet_data_single_shape() {
    use reticulum_core::packet::DATA;

    let dest_hash = [7u8; 16];
    let packet = Packet::data_single(&dest_hash, vec![1, 2, 3]);
    assert_eq!(packet.packet_type, DATA);
    assert_eq!(packet.dest_hash, dest_hash.to_vec());
    assert_eq!(Packet::decode(&packet.encode()).unwrap(), packet);
}

#[test]
fn link_packet_constructors_have_rns_shapes() {
    use reticulum_core::packet::{LINK, LINKREQUEST, LRPROOF, PROOF};

    let destination = [7u8; 16];
    let request = Packet::link_request(&destination, vec![1; 64]);
    assert_eq!(request.packet_type, LINKREQUEST);
    assert_eq!(request.dest_type, Packet::SINGLE);
    assert_eq!(Packet::decode(&request.encode()).unwrap(), request);
    assert_eq!(
        request.packet_hash(),
        truncated_hash(&request.hashable_part())
    );

    let link_id = request.packet_hash();
    let proof = Packet::proof(&link_id, vec![2; 96], LRPROOF);
    assert_eq!(proof.packet_type, PROOF);
    assert_eq!(proof.dest_type, LINK);
    assert_eq!(proof.context, LRPROOF);

    let data = Packet::link_data(&link_id, vec![3; 64]);
    assert_eq!(data.dest_type, LINK);
    assert_eq!(Packet::decode(&data.encode()).unwrap(), data);
}

#[test]
fn packet_decode_rejects_short_input() {
    assert!(Packet::decode(&[0x00]).is_err());
}

use reticulum_core::announce::Announce;

#[test]
fn announce_parses_and_verifies_rns_vector() {
    let v = load("announce.json");
    // The announce "payload" is the data field of the ANNOUNCE packet.
    // capture_vectors.py stores full packet bytes; slice off the 19-byte
    // header (flags+hops+16B dest+context) to get the payload.
    let raw = hexf(&v, "bytes");
    let payload = &raw[19..]; // 1 flags +1 hops +16 dest +1 context = 19
    let a = Announce::parse(payload, false).expect("parse");
    assert_eq!(a.public.to_vec(), hexf(&v, "pub"));
    assert_eq!(a.name_hash.to_vec(), hexf(&v, "name_hash"));
    assert_eq!(a.random_hash.to_vec(), hexf(&v, "random_hash"));
    assert_eq!(a.signature.to_vec(), hexf(&v, "signature"));

    let dh: [u8; 16] = hexf(&v, "dest_hash").try_into().unwrap();
    assert!(a.verify(&dh).is_ok());
}

#[test]
fn announce_build_reproduces_rns_vector() {
    let idv = load("identity.json");
    let x: [u8; 32] = hexf(&idv, "prv_x25519").try_into().unwrap();
    let e: [u8; 32] = hexf(&idv, "prv_ed25519").try_into().unwrap();
    let id = Identity::from_private_bytes(&x, &e);

    let av = load("announce.json");
    let dest_hash: [u8; 16] = hexf(&av, "dest_hash").try_into().unwrap();
    let name_hash: [u8; 10] = hexf(&av, "name_hash").try_into().unwrap();
    let random_hash: [u8; 10] = hexf(&av, "random_hash").try_into().unwrap();
    let app_data = hexf(&av, "app_data");

    let built = Announce::build(&id, &dest_hash, &name_hash, &random_hash, &app_data);
    assert_eq!(built.signature.to_vec(), hexf(&av, "signature"));
    let raw = hexf(&av, "bytes");
    assert_eq!(built.to_payload(), raw[19..].to_vec());
    assert!(built.verify(&dest_hash).is_ok());
}

#[test]
fn announce_with_ratchet_parses_and_verifies() {
    let vector = load("announce_ratchet.json");
    let raw = hexf(&vector, "bytes");
    let announce = Announce::parse(&raw[19..], true).expect("parse ratchet");
    assert_eq!(announce.ratchet.unwrap().to_vec(), hexf(&vector, "ratchet"));
    let dest_hash: [u8; 16] = hexf(&vector, "dest_hash").try_into().unwrap();
    assert!(announce.verify(&dest_hash).is_ok());
}

#[test]
fn packet_flags_roundtrip_self_consistent() {
    let p = Packet {
        ifac: true,
        header_type: 0,
        context_flag: true,
        propagation: 1,
        dest_type: 2,
        packet_type: 3,
        hops: 7,
        transport_id: None,
        dest_hash: (0u8..16).collect(),
        context: 5,
        data: vec![9, 9, 9],
    };
    let decoded = Packet::decode(&p.encode()).expect("decode");
    assert_eq!(decoded, p);
}
