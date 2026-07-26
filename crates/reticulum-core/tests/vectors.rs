use reticulum_core::hash::{full_hash, truncated_hash};

#[test]
fn truncated_is_first_16_of_full() {
    let data = b"reticulum";
    assert_eq!(truncated_hash(data), full_hash(data)[..16]);
}
