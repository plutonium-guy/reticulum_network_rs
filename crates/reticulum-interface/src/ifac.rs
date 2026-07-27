use alloc::vec;
use alloc::vec::Vec;

use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

pub const IFAC_KEY_SIZE: usize = 64;
pub const DEFAULT_IFAC_SIZE: usize = 16;
pub const IFAC_FLAG: u8 = 0x80;
const IFAC_SALT: [u8; 32] = [
    0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80, 0x77, 0x1e, 0xb4, 0x99, 0x5d, 0x70, 0x2d, 0x4a,
    0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0, 0xf5, 0x3f, 0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfacError {
    InvalidSize,
    Truncated,
    Authentication,
    Derivation,
}

/// Derive the 64-byte RNS IFAC identity from the configured network name and
/// passphrase.
pub fn derive_key(network_name: &str, passphrase: &str) -> [u8; IFAC_KEY_SIZE] {
    let mut origin = Vec::with_capacity(64);
    if !network_name.is_empty() {
        origin.extend_from_slice(&Sha256::digest(network_name.as_bytes()));
    }
    if !passphrase.is_empty() {
        origin.extend_from_slice(&Sha256::digest(passphrase.as_bytes()));
    }
    let origin_hash = Sha256::digest(&origin);
    let hkdf = Hkdf::<Sha256>::new(Some(&IFAC_SALT), &origin_hash);
    let mut key = [0u8; IFAC_KEY_SIZE];
    // SHA-256 HKDF supports this fixed 64-byte output by construction.
    hkdf.expand(&[], &mut key)
        .expect("64-byte IFAC HKDF output is valid");
    key
}

/// Apply RNS's default 128-bit IFAC transform.
pub fn apply(frame: &[u8], key: &[u8; IFAC_KEY_SIZE]) -> Vec<u8> {
    apply_with_size(frame, key, DEFAULT_IFAC_SIZE).unwrap_or_default()
}

pub fn apply_with_size(
    frame: &[u8],
    key: &[u8; IFAC_KEY_SIZE],
    ifac_size: usize,
) -> Result<Vec<u8>, IfacError> {
    validate(frame, ifac_size)?;
    let signing_seed: [u8; 32] = key[32..].try_into().map_err(|_| IfacError::Derivation)?;
    let signature = SigningKey::from_bytes(&signing_seed).sign(frame).to_bytes();
    let ifac = &signature[signature.len() - ifac_size..];

    let mut wire = Vec::with_capacity(frame.len() + ifac_size);
    wire.extend_from_slice(&[frame[0] | IFAC_FLAG, frame[1]]);
    wire.extend_from_slice(ifac);
    wire.extend_from_slice(&frame[2..]);
    mask(&mut wire, key, ifac, ifac_size)?;
    wire[0] |= IFAC_FLAG;
    Ok(wire)
}

/// Verify, unmask and remove RNS's default 128-bit IFAC transform.
pub fn strip(frame: &[u8], key: &[u8; IFAC_KEY_SIZE]) -> Result<Vec<u8>, IfacError> {
    strip_with_size(frame, key, DEFAULT_IFAC_SIZE)
}

pub fn strip_with_size(
    frame: &[u8],
    key: &[u8; IFAC_KEY_SIZE],
    ifac_size: usize,
) -> Result<Vec<u8>, IfacError> {
    validate(frame, ifac_size)?;
    if frame[0] & IFAC_FLAG == 0 || frame.len() <= ifac_size + 2 {
        return Err(IfacError::Truncated);
    }
    let ifac = frame[2..2 + ifac_size].to_vec();
    let mut unmasked = frame.to_vec();
    mask(&mut unmasked, key, &ifac, ifac_size)?;
    unmasked[0] &= !IFAC_FLAG;

    let mut plain = Vec::with_capacity(frame.len() - ifac_size);
    plain.extend_from_slice(&unmasked[..2]);
    plain.extend_from_slice(&unmasked[2 + ifac_size..]);

    let signing_seed: [u8; 32] = key[32..].try_into().map_err(|_| IfacError::Derivation)?;
    let expected = SigningKey::from_bytes(&signing_seed)
        .sign(&plain)
        .to_bytes();
    if constant_time_eq(&ifac, &expected[expected.len() - ifac_size..]) {
        Ok(plain)
    } else {
        Err(IfacError::Authentication)
    }
}

fn validate(frame: &[u8], ifac_size: usize) -> Result<(), IfacError> {
    if !(1..=64).contains(&ifac_size) {
        return Err(IfacError::InvalidSize);
    }
    if frame.len() < 2 {
        return Err(IfacError::Truncated);
    }
    Ok(())
}

fn mask(
    frame: &mut [u8],
    key: &[u8; IFAC_KEY_SIZE],
    ifac: &[u8],
    ifac_size: usize,
) -> Result<(), IfacError> {
    let hkdf = Hkdf::<Sha256>::new(Some(key), ifac);
    let mut mask = vec![0u8; frame.len()];
    hkdf.expand(&[], &mut mask)
        .map_err(|_| IfacError::Derivation)?;
    for (index, byte) in frame.iter_mut().enumerate() {
        if index <= 1 || index > ifac_size + 1 {
            *byte ^= mask[index];
        }
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vector {
        network_name: String,
        passphrase: String,
        ifac_size: usize,
        ifac_key: String,
        plain_frame: String,
        ifac_frame: String,
    }

    fn vector() -> Vector {
        serde_json::from_str(include_str!("../../../vectors/ifac_frame.json")).unwrap()
    }

    #[test]
    fn matches_rns_1_4_1_vector() {
        let vector = vector();
        let key = derive_key(&vector.network_name, &vector.passphrase);
        assert_eq!(hex::encode(key), vector.ifac_key);
        let plain = hex::decode(vector.plain_frame).unwrap();
        let wire = hex::decode(vector.ifac_frame).unwrap();
        assert_eq!(
            apply_with_size(&plain, &key, vector.ifac_size).unwrap(),
            wire
        );
        assert_eq!(
            strip_with_size(&wire, &key, vector.ifac_size).unwrap(),
            plain
        );
    }

    #[test]
    fn rejects_tampering_and_invalid_inputs() {
        let key = derive_key("network", "passphrase");
        let mut wire = apply(b"\x08\x00payload", &key);
        let last = wire.len() - 1;
        wire[last] ^= 1;
        assert_eq!(strip(&wire, &key), Err(IfacError::Authentication));
        assert_eq!(strip(b"\x08", &key), Err(IfacError::Truncated));
        assert_eq!(
            apply_with_size(b"\x08\x00payload", &key, 0),
            Err(IfacError::InvalidSize)
        );
    }
}
