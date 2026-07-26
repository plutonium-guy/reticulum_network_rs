use crate::{hash::truncated_hash, CoreError};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

pub struct PublicIdentity {
    pub enc_pub: [u8; 32],
    pub sig_pub: [u8; 32],
}

impl PublicIdentity {
    pub fn from_bytes(b: &[u8]) -> Result<Self, CoreError> {
        if b.len() != 64 { return Err(CoreError::Truncated); }
        let mut enc = [0u8; 32];
        let mut sig = [0u8; 32];
        enc.copy_from_slice(&b[..32]);
        sig.copy_from_slice(&b[32..64]);
        Ok(Self { enc_pub: enc, sig_pub: sig })
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.enc_pub);
        out[32..].copy_from_slice(&self.sig_pub);
        out
    }

    pub fn hash(&self) -> [u8; 16] {
        truncated_hash(&self.to_bytes())
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<(), CoreError> {
        let vk = VerifyingKey::from_bytes(&self.sig_pub)
            .map_err(|_| CoreError::InvalidField)?;
        let signature = Signature::from_bytes(sig);
        vk.verify(msg, &signature).map_err(|_| CoreError::BadSignature)
    }
}

pub struct Identity {
    enc_prv: StaticSecret,
    sig: SigningKey,
}

impl Identity {
    pub fn from_private_bytes(x25519: &[u8; 32], ed25519: &[u8; 32]) -> Self {
        Self {
            enc_prv: StaticSecret::from(*x25519),
            sig: SigningKey::from_bytes(ed25519),
        }
    }

    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            enc_pub: XPublic::from(&self.enc_prv).to_bytes(),
            sig_pub: self.sig.verifying_key().to_bytes(),
        }
    }

    pub fn hash(&self) -> [u8; 16] {
        self.public().hash()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.sig.sign(msg).to_bytes()
    }

    #[allow(dead_code)]
    pub(crate) fn diffie_hellman(&self, peer_enc_pub: &[u8; 32]) -> [u8; 32] {
        self.enc_prv.diffie_hellman(&XPublic::from(*peer_enc_pub)).to_bytes()
    }
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Identity(<redacted>)")
    }
}
