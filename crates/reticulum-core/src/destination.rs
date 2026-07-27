use crate::hash::{full_hash, truncated_hash};
use alloc::string::String;

/// RNS name hash: SHA-256 of "app_name.aspect1.aspect2..." truncated to 10 bytes.
pub fn name_hash(app_name: &str, aspects: &[&str]) -> [u8; 10] {
    let mut name = String::from(app_name);
    for a in aspects {
        name.push('.');
        name.push_str(a);
    }
    let full = full_hash(name.as_bytes());
    let mut out = [0u8; 10];
    out.copy_from_slice(&full[..10]);
    out
}

/// RNS destination hash: truncated SHA-256(name_hash || identity_hash) -> 16 bytes.
pub fn destination_hash(name_hash: &[u8; 10], identity_hash: &[u8; 16]) -> [u8; 16] {
    let mut buf = [0u8; 26];
    buf[..10].copy_from_slice(name_hash);
    buf[10..].copy_from_slice(identity_hash);
    truncated_hash(&buf)
}

/// Address produced by `RNS.Destination.hash(None, ...)`.
///
/// Real RNS GROUP destinations are identity-bound; use
/// [`group_destination_hash_with_identity`] for an interoperable GROUP.
pub fn group_destination_hash(app_name: &str, aspects: &[&str]) -> [u8; 16] {
    truncated_hash(&name_hash(app_name, aspects))
}

/// Address of an RNS GROUP destination holding the supplied Identity.
pub fn group_destination_hash_with_identity(
    app_name: &str,
    aspects: &[&str],
    identity_hash: &[u8; 16],
) -> [u8; 16] {
    destination_hash(&name_hash(app_name, aspects), identity_hash)
}
