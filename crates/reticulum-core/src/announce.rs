use crate::{
    CoreError,
    identity::{Identity, PublicIdentity},
};
use alloc::vec::Vec;

const PUB_LEN: usize = 64;
const NAME_LEN: usize = 10;
const RAND_LEN: usize = 10;
const SIG_LEN: usize = 64;
const MIN: usize = PUB_LEN + NAME_LEN + RAND_LEN + SIG_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announce {
    pub public: [u8; 64],
    pub name_hash: [u8; 10],
    pub random_hash: [u8; 10],
    pub signature: [u8; 64],
    pub app_data: Vec<u8>,
}

impl Announce {
    /// Parses the ANNOUNCE packet *data* field (no ratchet support in M1).
    pub fn parse(payload: &[u8]) -> Result<Announce, CoreError> {
        if payload.len() < MIN {
            return Err(CoreError::Truncated);
        }
        let mut off = 0usize;
        let public: [u8; 64] = payload
            .get(off..off + PUB_LEN)
            .ok_or(CoreError::Truncated)?
            .try_into()
            .map_err(|_| CoreError::Truncated)?;
        off += PUB_LEN;
        let name_hash: [u8; 10] = payload
            .get(off..off + NAME_LEN)
            .ok_or(CoreError::Truncated)?
            .try_into()
            .map_err(|_| CoreError::Truncated)?;
        off += NAME_LEN;
        let random_hash: [u8; 10] = payload
            .get(off..off + RAND_LEN)
            .ok_or(CoreError::Truncated)?
            .try_into()
            .map_err(|_| CoreError::Truncated)?;
        off += RAND_LEN;
        let signature: [u8; 64] = payload
            .get(off..off + SIG_LEN)
            .ok_or(CoreError::Truncated)?
            .try_into()
            .map_err(|_| CoreError::Truncated)?;
        off += SIG_LEN;
        let app_data = payload[off..].to_vec();
        Ok(Announce {
            public,
            name_hash,
            random_hash,
            signature,
            app_data,
        })
    }

    pub fn build(
        identity: &Identity,
        dest_hash: &[u8; 16],
        name_hash: &[u8; 10],
        random_hash: &[u8; 10],
        app_data: &[u8],
    ) -> Announce {
        let public = identity.public().to_bytes();
        let signed = signed_data(dest_hash, &public, name_hash, random_hash, app_data);
        Announce {
            public,
            name_hash: *name_hash,
            random_hash: *random_hash,
            signature: identity.sign(&signed),
            app_data: app_data.to_vec(),
        }
    }

    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MIN + self.app_data.len());
        out.extend_from_slice(&self.public);
        out.extend_from_slice(&self.name_hash);
        out.extend_from_slice(&self.random_hash);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.app_data);
        out
    }

    /// Verifies the announce signature against `dest_hash`.
    ///
    /// Signed message (RNS 1.4.1, `RNS/Destination.py::announce`):
    /// `dest_hash ‖ public ‖ name_hash ‖ random_hash ‖ ratchet ‖ app_data`.
    /// M1 does not support ratchets, so the ratchet segment is empty.
    pub fn verify(&self, dest_hash: &[u8; 16]) -> Result<(), CoreError> {
        let signed = signed_data(
            dest_hash,
            &self.public,
            &self.name_hash,
            &self.random_hash,
            &self.app_data,
        );
        let pubid = PublicIdentity::from_bytes(&self.public)?;
        pubid.verify(&signed, &self.signature)
    }
}

fn signed_data(
    dest_hash: &[u8; 16],
    public: &[u8; 64],
    name_hash: &[u8; 10],
    random_hash: &[u8; 10],
    app_data: &[u8],
) -> Vec<u8> {
    let mut signed = Vec::with_capacity(16 + PUB_LEN + NAME_LEN + RAND_LEN + app_data.len());
    signed.extend_from_slice(dest_hash);
    signed.extend_from_slice(public);
    signed.extend_from_slice(name_hash);
    signed.extend_from_slice(random_hash);
    signed.extend_from_slice(app_data);
    signed
}
