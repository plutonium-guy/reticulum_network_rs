use reticulum_interface::hdlc::{deframe, frame};

fn load_hdlc() -> (Vec<u8>, Vec<u8>) {
    let path = format!("{}/../../vectors/hdlc.json", env!("CARGO_MANIFEST_DIR"));
    let s = std::fs::read_to_string(path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    (
        hex::decode(v["raw"].as_str().unwrap()).unwrap(),
        hex::decode(v["framed"].as_str().unwrap()).unwrap(),
    )
}

#[test]
fn frame_matches_rns_vector() {
    let (raw, framed) = load_hdlc();
    assert_eq!(frame(&raw), framed);
}

#[test]
fn frame_deframe_roundtrip() {
    let data = [0x7E, 0x00, 0x7D, 0xFF, 0x7E, 0x7D];
    assert_eq!(deframe(&frame(&data)).unwrap(), data);
}
