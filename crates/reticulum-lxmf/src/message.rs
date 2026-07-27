use alloc::vec::Vec;

use reticulum_core::{hash::full_hash, identity::Identity};
use rmp::encode::{write_array_len, write_bin, write_f64};

pub const DESTINATION_LENGTH: usize = 16;
pub const SIGNATURE_LENGTH: usize = 64;
pub const HASH_LENGTH: usize = 32;
pub const HEADER_LENGTH: usize = DESTINATION_LENGTH * 2 + SIGNATURE_LENGTH;

#[derive(Debug, Clone, PartialEq)]
pub struct LxmfMessage {
    pub destination: [u8; DESTINATION_LENGTH],
    pub source: [u8; DESTINATION_LENGTH],
    pub timestamp: f64,
    pub title: Vec<u8>,
    pub content: Vec<u8>,
    /// One complete MessagePack map value, retained byte-for-byte.
    pub fields: Vec<u8>,
    pub signature: [u8; SIGNATURE_LENGTH],
    pub hash: [u8; HASH_LENGTH],
}

impl LxmfMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        source_identity: &Identity,
        destination: [u8; DESTINATION_LENGTH],
        source: [u8; DESTINATION_LENGTH],
        timestamp: f64,
        title: &[u8],
        content: &[u8],
        fields_msgpack: &[u8],
    ) -> Self {
        let payload = encode_payload(timestamp, title, content, fields_msgpack);
        let hashed_part = hashed_part(&destination, &source, &payload);
        let hash = full_hash(&hashed_part);
        let mut signed_part = Vec::with_capacity(hashed_part.len() + HASH_LENGTH);
        signed_part.extend_from_slice(&hashed_part);
        signed_part.extend_from_slice(&hash);

        Self {
            destination,
            source,
            timestamp,
            title: title.to_vec(),
            content: content.to_vec(),
            fields: fields_msgpack.to_vec(),
            signature: source_identity.sign(&signed_part),
            hash,
        }
    }

    pub fn pack(&self) -> Vec<u8> {
        let payload = self.payload();
        let mut packed = Vec::with_capacity(HEADER_LENGTH + payload.len());
        packed.extend_from_slice(&self.destination);
        packed.extend_from_slice(&self.source);
        packed.extend_from_slice(&self.signature);
        packed.extend_from_slice(&payload);
        packed
    }

    pub fn payload(&self) -> Vec<u8> {
        encode_payload(self.timestamp, &self.title, &self.content, &self.fields)
    }
}

fn encode_payload(timestamp: f64, title: &[u8], content: &[u8], fields: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(title.len() + content.len() + fields.len() + 16);
    write_array_len(&mut payload, 4).expect("writing to Vec cannot fail");
    write_f64(&mut payload, timestamp).expect("writing to Vec cannot fail");
    write_bin(&mut payload, title).expect("writing to Vec cannot fail");
    write_bin(&mut payload, content).expect("writing to Vec cannot fail");
    payload.extend_from_slice(fields);
    payload
}

fn hashed_part(
    destination: &[u8; DESTINATION_LENGTH],
    source: &[u8; DESTINATION_LENGTH],
    payload: &[u8],
) -> Vec<u8> {
    let mut hashed = Vec::with_capacity(DESTINATION_LENGTH * 2 + payload.len());
    hashed.extend_from_slice(destination);
    hashed.extend_from_slice(source);
    hashed.extend_from_slice(payload);
    hashed
}
