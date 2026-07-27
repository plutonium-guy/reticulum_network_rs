use alloc::vec::Vec;

use crate::{
    CoreError,
    identity::{Identity, PublicIdentity},
};

pub const PACKET_HASH_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const EXPLICIT_PROOF_LEN: usize = PACKET_HASH_LEN + SIGNATURE_LEN;

/// Build an RNS explicit proof: full packet hash followed by its signature.
pub fn build_proof(identity: &Identity, packet_hash: &[u8; PACKET_HASH_LEN]) -> Vec<u8> {
    let mut proof = Vec::with_capacity(EXPLICIT_PROOF_LEN);
    proof.extend_from_slice(packet_hash);
    proof.extend_from_slice(&identity.sign(packet_hash));
    proof
}

/// Verify an RNS explicit proof and return the proved full packet hash.
pub fn verify_proof(
    destination_public: &PublicIdentity,
    proof: &[u8],
) -> Result<[u8; PACKET_HASH_LEN], CoreError> {
    if proof.len() < EXPLICIT_PROOF_LEN {
        return Err(CoreError::Truncated);
    }
    if proof.len() != EXPLICIT_PROOF_LEN {
        return Err(CoreError::InvalidField);
    }
    let packet_hash: [u8; PACKET_HASH_LEN] = proof[..PACKET_HASH_LEN]
        .try_into()
        .map_err(|_| CoreError::Truncated)?;
    let signature: [u8; SIGNATURE_LEN] = proof[PACKET_HASH_LEN..]
        .try_into()
        .map_err(|_| CoreError::Truncated)?;
    destination_public.verify(&packet_hash, &signature)?;
    Ok(packet_hash)
}

/// RNS ProofDestination address: the first 16 bytes of the full packet hash.
pub fn proof_destination_hash(packet_hash: &[u8; PACKET_HASH_LEN]) -> [u8; 16] {
    let mut destination = [0u8; 16];
    destination.copy_from_slice(&packet_hash[..16]);
    destination
}
