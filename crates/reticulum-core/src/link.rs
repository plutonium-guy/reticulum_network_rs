use crate::{
    CoreError, EntropySource,
    hash::truncated_hash,
    identity::{Identity, PublicIdentity},
    packet::Packet,
};
use alloc::vec::Vec;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

pub const LINK_PUBLIC_KEY_LEN: usize = 32;
pub const LINK_REQUEST_LEN: usize = 64;
pub const LINK_SIGNALLING_LEN: usize = 3;

#[derive(Clone, PartialEq, Eq)]
pub struct LinkEphemeral {
    pub x25519_prv: [u8; LINK_PUBLIC_KEY_LEN],
    pub x25519_pub: [u8; LINK_PUBLIC_KEY_LEN],
    pub ed25519_prv: [u8; LINK_PUBLIC_KEY_LEN],
    pub ed25519_pub: [u8; LINK_PUBLIC_KEY_LEN],
}

impl core::fmt::Debug for LinkEphemeral {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never expose the private key halves via Debug (leak-safety, mirrors Identity).
        f.debug_struct("LinkEphemeral")
            .field("x25519_pub", &self.x25519_pub)
            .field("ed25519_pub", &self.ed25519_pub)
            .field("x25519_prv", &"<redacted>")
            .field("ed25519_prv", &"<redacted>")
            .finish()
    }
}

impl LinkEphemeral {
    pub fn generate<R: EntropySource>(rng: &mut R) -> Self {
        let mut x25519_prv = [0u8; LINK_PUBLIC_KEY_LEN];
        let mut ed25519_prv = [0u8; LINK_PUBLIC_KEY_LEN];
        rng.fill(&mut x25519_prv);
        rng.fill(&mut ed25519_prv);
        Self::from_private_bytes(x25519_prv, ed25519_prv)
    }

    pub fn from_private_bytes(
        x25519_prv: [u8; LINK_PUBLIC_KEY_LEN],
        ed25519_prv: [u8; LINK_PUBLIC_KEY_LEN],
    ) -> Self {
        let x25519_secret = StaticSecret::from(x25519_prv);
        let ed25519_signing = SigningKey::from_bytes(&ed25519_prv);
        Self {
            x25519_prv,
            x25519_pub: XPublic::from(&x25519_secret).to_bytes(),
            ed25519_prv,
            ed25519_pub: ed25519_signing.verifying_key().to_bytes(),
        }
    }
}

pub fn link_request_payload(ephemeral: &LinkEphemeral) -> Vec<u8> {
    let mut payload = Vec::with_capacity(LINK_REQUEST_LEN);
    payload.extend_from_slice(&ephemeral.x25519_pub);
    payload.extend_from_slice(&ephemeral.ed25519_pub);
    payload
}

/// Parses the 64-byte key payload and accepts RNS 1.4.1's optional 3-byte
/// MTU/mode signalling suffix for live interoperability.
pub fn parse_link_request(data: &[u8]) -> Result<([u8; 32], [u8; 32]), CoreError> {
    if data.len() != LINK_REQUEST_LEN && data.len() != LINK_REQUEST_LEN + LINK_SIGNALLING_LEN {
        return Err(CoreError::InvalidField);
    }
    let x25519_pub = data[..32].try_into().map_err(|_| CoreError::Truncated)?;
    let ed25519_pub = data[32..64].try_into().map_err(|_| CoreError::Truncated)?;
    Ok((x25519_pub, ed25519_pub))
}

pub fn link_id_from_request(packet: &Packet) -> [u8; 16] {
    let mut hashable = packet.hashable_part();
    if packet.data.len() > LINK_REQUEST_LEN {
        hashable.truncate(hashable.len() - (packet.data.len() - LINK_REQUEST_LEN));
    }
    truncated_hash(&hashable)
}

pub fn derive_link_key(
    own_x25519_prv: &[u8; 32],
    peer_x25519_pub: &[u8; 32],
    link_id: &[u8; 16],
) -> [u8; 64] {
    let secret = StaticSecret::from(*own_x25519_prv);
    let shared = secret
        .diffie_hellman(&XPublic::from(*peer_x25519_pub))
        .to_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(link_id), &shared);
    let mut derived_key = [0u8; 64];
    let _ = hkdf.expand(&[], &mut derived_key);
    derived_key
}

pub fn build_link_proof(
    destination_identity: &Identity,
    link_id: &[u8; 16],
    responder_ephemeral: &LinkEphemeral,
) -> Vec<u8> {
    let mut signed = Vec::with_capacity(80);
    signed.extend_from_slice(link_id);
    signed.extend_from_slice(&responder_ephemeral.x25519_pub);
    signed.extend_from_slice(&destination_identity.public().sig_pub);
    let signature = destination_identity.sign(&signed);

    let mut proof = Vec::with_capacity(96);
    proof.extend_from_slice(&signature);
    proof.extend_from_slice(&responder_ephemeral.x25519_pub);
    proof
}

/// Verifies both the 96-byte base proof emitted by this port and the 99-byte
/// proof with MTU/mode signalling emitted by RNS 1.4.1.
pub fn verify_link_proof(
    destination_public: &PublicIdentity,
    link_id: &[u8; 16],
    proof_data: &[u8],
) -> Result<[u8; 32], CoreError> {
    if proof_data.len() < 96 {
        return Err(CoreError::Truncated);
    }
    if proof_data.len() != 96 && proof_data.len() != 96 + LINK_SIGNALLING_LEN {
        return Err(CoreError::InvalidField);
    }
    let signature: [u8; 64] = proof_data[..64]
        .try_into()
        .map_err(|_| CoreError::Truncated)?;
    let peer_x25519_pub: [u8; 32] = proof_data[64..96]
        .try_into()
        .map_err(|_| CoreError::Truncated)?;

    let mut signed = Vec::with_capacity(80 + LINK_SIGNALLING_LEN);
    signed.extend_from_slice(link_id);
    signed.extend_from_slice(&peer_x25519_pub);
    signed.extend_from_slice(&destination_public.sig_pub);
    signed.extend_from_slice(&proof_data[96..]);
    destination_public.verify(&signed, &signature)?;
    Ok(peer_x25519_pub)
}
