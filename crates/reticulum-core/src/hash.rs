use sha2::{Digest, Sha256};

/// Full SHA-256 of `data`.
pub fn full_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// First 16 bytes of SHA-256 — RNS `TRUNCATED_HASHLENGTH` (128 bit).
pub fn truncated_hash(data: &[u8]) -> [u8; 16] {
    let full = full_hash(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}
