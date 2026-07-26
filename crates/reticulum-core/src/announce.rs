use crate::{CoreError, identity::PublicIdentity};
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
        let public: [u8; 64] = payload[off..off + PUB_LEN].try_into().unwrap();
        off += PUB_LEN;
        let name_hash: [u8; 10] = payload[off..off + NAME_LEN].try_into().unwrap();
        off += NAME_LEN;
        let random_hash: [u8; 10] = payload[off..off + RAND_LEN].try_into().unwrap();
        off += RAND_LEN;
        let signature: [u8; 64] = payload[off..off + SIG_LEN].try_into().unwrap();
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

    /// Verifies the announce signature against `dest_hash`.
    ///
    /// Signed message (RNS 1.4.1, `RNS/Destination.py::announce`):
    /// `dest_hash ‖ public ‖ name_hash ‖ random_hash ‖ ratchet ‖ app_data`.
    /// M1 does not support ratchets, so the ratchet segment is empty.
    pub fn verify(&self, dest_hash: &[u8; 16]) -> Result<(), CoreError> {
        let mut signed =
            Vec::with_capacity(16 + PUB_LEN + NAME_LEN + RAND_LEN + self.app_data.len());
        signed.extend_from_slice(dest_hash);
        signed.extend_from_slice(&self.public);
        signed.extend_from_slice(&self.name_hash);
        signed.extend_from_slice(&self.random_hash);
        signed.extend_from_slice(&self.app_data);

        let pubid = PublicIdentity::from_bytes(&self.public)?;
        pubid.verify(&signed, &self.signature)
    }
}
