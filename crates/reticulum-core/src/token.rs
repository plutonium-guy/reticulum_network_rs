//! RNS Token: the authenticated-encryption primitive behind `Identity.encrypt`
//! / `Identity.decrypt` in RNS 1.4.1.
//!
//! Construction (read from RNS 1.4.1 Python source and verified against the
//! real vector in `vectors/token.json` via
//! `tests/vectors.rs::token_decrypts_rns_vector`):
//!
//! - **ECDH**: X25519 between an ephemeral secret and the recipient's
//!   encryption public key (encrypt side), or the recipient's static secret
//!   and the ephemeral public key embedded in the token (decrypt side).
//! - **KDF**: HKDF-SHA256 (RFC 5869; `RNS.Cryptography.HKDF.hkdf` is a
//!   from-scratch but spec-compliant HKDF) over the 32-byte ECDH shared
//!   secret. `salt = Identity.get_salt()` = the recipient's identity hash,
//!   `truncated_hash(enc_pub || sig_pub)` (16 bytes) — **not** empty/None.
//!   `info = Identity.get_context()` = `None` -> `b""`. Output length is
//!   `Identity.DERIVED_KEY_LENGTH` = 512 bits = 64 bytes.
//! - **Key split**: RNS `Token.__init__` for a 64-byte key sets
//!   `signing_key = key[:32]` (HMAC-SHA256 key) and
//!   `encryption_key = key[32:]` (AES-256 key) — HMAC key **first**, AES key
//!   **second** (the reverse of a naive guess).
//! - **Layout**: `ephemeral_x25519_pub(32) || iv(16) || AES-256-CBC/PKCS7
//!   ciphertext || HMAC-SHA256(32)`. `Identity.encrypt` prepends the
//!   ephemeral public key *outside* of `Token.encrypt`; `Token.encrypt` signs
//!   `signed_parts = iv + ciphertext` — the HMAC covers **iv || ciphertext
//!   only**, not the ephemeral public key.
//!
//! `encrypt()` takes the recipient's full [`crate::identity::PublicIdentity`]
//! (not just the raw X25519 public key) so it can compute the real RNS salt,
//! `recipient.hash()` = `truncated_hash(enc_pub || sig_pub)`. `decrypt()`
//! uses the same single salt, derived from the local `Identity`'s own public
//! half. This makes tokens produced by [`encrypt`] decryptable by real RNS
//! nodes, and vice versa.

use crate::{
    CoreError,
    identity::{Identity, PublicIdentity},
};
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use alloc::vec::Vec;
use hkdf::Hkdf;
use hmac::{Mac, SimpleHmac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

// vectors/token.json: "aes_key_bits": 256, traced to RNS AES_256_CBC /
// Identity.DERIVED_KEY_LENGTH = 64 bytes (32 HMAC + 32 AES-256).
type Aes = aes::Aes256;
type Enc = cbc::Encryptor<Aes>;
type Dec = cbc::Decryptor<Aes>;
type HmacSha256 = SimpleHmac<Sha256>;

const KEY_LEN: usize = 32; // AES-256 key
const HMAC_LEN: usize = 32; // HMAC-SHA256 signing key / tag
const IV_LEN: usize = 16;
const EPH_LEN: usize = 32;
const SALT_LEN: usize = 16; // RNS TRUNCATED_HASHLENGTH / 8

/// Derive `(hmac_key, aes_key)` from the ECDH shared secret via HKDF-SHA256,
/// salted per RNS `Identity.get_salt()`. RNS key order is signing key first,
/// encryption key second (`Token.__init__`, 64-byte-key branch).
fn derive_keys(shared: &[u8; 32], salt: &[u8; SALT_LEN]) -> ([u8; HMAC_LEN], [u8; KEY_LEN]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut okm = [0u8; HMAC_LEN + KEY_LEN];
    let _ = hk.expand(&[], &mut okm);
    let mut hmac_key = [0u8; HMAC_LEN];
    let mut aes_key = [0u8; KEY_LEN];
    hmac_key.copy_from_slice(&okm[..HMAC_LEN]);
    aes_key.copy_from_slice(&okm[HMAC_LEN..]);
    (hmac_key, aes_key)
}

fn seal_parts(
    hmac_key: &[u8; HMAC_LEN],
    aes_key: &[u8; KEY_LEN],
    plaintext: &[u8],
    iv: &[u8; IV_LEN],
) -> Vec<u8> {
    let ciphertext =
        Enc::new(aes_key[..].into(), iv[..].into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    let mut signed_parts = Vec::with_capacity(IV_LEN + ciphertext.len());
    signed_parts.extend_from_slice(iv);
    signed_parts.extend_from_slice(&ciphertext);

    let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(hmac_key) else {
        return Vec::new();
    };
    mac.update(&signed_parts);
    let tag = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(signed_parts.len() + HMAC_LEN);
    out.extend_from_slice(&signed_parts);
    out.extend_from_slice(&tag);
    out
}

fn open_parts(
    hmac_key: &[u8; HMAC_LEN],
    aes_key: &[u8; KEY_LEN],
    token: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if token.len() < IV_LEN + 16 + HMAC_LEN {
        return Err(CoreError::Truncated);
    }
    let (signed_parts, tag) = token.split_at(token.len() - HMAC_LEN);
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(hmac_key).map_err(|_| CoreError::InvalidField)?;
    mac.update(signed_parts);
    mac.verify_slice(tag)
        .map_err(|_| CoreError::DecryptFailed)?;

    let (iv, ciphertext) = signed_parts.split_at(IV_LEN);
    Dec::new(aes_key[..].into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| CoreError::DecryptFailed)
}

/// Seal plaintext with an already-derived 64-byte RNS Link key.
pub fn seal_with_key(
    derived_key: &[u8; HMAC_LEN + KEY_LEN],
    plaintext: &[u8],
    iv: &[u8; IV_LEN],
) -> Vec<u8> {
    let mut hmac_key = [0u8; HMAC_LEN];
    let mut aes_key = [0u8; KEY_LEN];
    hmac_key.copy_from_slice(&derived_key[..HMAC_LEN]);
    aes_key.copy_from_slice(&derived_key[HMAC_LEN..]);
    seal_parts(&hmac_key, &aes_key, plaintext, iv)
}

/// Open a token sealed with an already-derived 64-byte RNS Link key.
pub fn open_with_key(
    derived_key: &[u8; HMAC_LEN + KEY_LEN],
    token: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let mut hmac_key = [0u8; HMAC_LEN];
    let mut aes_key = [0u8; KEY_LEN];
    hmac_key.copy_from_slice(&derived_key[..HMAC_LEN]);
    aes_key.copy_from_slice(&derived_key[HMAC_LEN..]);
    open_parts(&hmac_key, &aes_key, token)
}

/// Encrypt `plaintext` for `recipient` using the given ephemeral X25519
/// secret and IV. Both `ephemeral_x25519` and `iv` are caller-supplied;
/// production callers must draw both from a CSPRNG.
///
/// The HKDF salt is `recipient.hash()`, the recipient's full identity hash
/// (`truncated_hash(enc_pub || sig_pub)`), matching real RNS 1.4.1.
pub fn encrypt(
    recipient: &PublicIdentity,
    plaintext: &[u8],
    ephemeral_x25519: &[u8; 32],
    iv: &[u8; IV_LEN],
) -> Vec<u8> {
    let eph = StaticSecret::from(*ephemeral_x25519);
    let eph_pub = XPublic::from(&eph).to_bytes();
    let shared = eph
        .diffie_hellman(&XPublic::from(recipient.enc_pub))
        .to_bytes();

    let salt = recipient.hash();
    let (hmac_key, aes_key) = derive_keys(&shared, &salt);

    let sealed = seal_parts(&hmac_key, &aes_key, plaintext, iv);

    // RNS Identity.encrypt prepends the ephemeral public key outside the Token.
    let mut out = Vec::with_capacity(EPH_LEN + sealed.len());
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&sealed);
    out
}

/// Decrypt a Token addressed to `recipient`.
///
/// Uses the real RNS per-identity salt (`truncated_hash(enc_pub||sig_pub)`,
/// i.e. `recipient.public().hash()`), strictly RNS-conformant.
pub fn decrypt(recipient: &Identity, token: &[u8]) -> Result<Vec<u8>, CoreError> {
    if token.len() < EPH_LEN + IV_LEN + 16 + HMAC_LEN {
        return Err(CoreError::Truncated);
    }
    let eph_pub: [u8; 32] = token[..EPH_LEN]
        .try_into()
        .map_err(|_| CoreError::Truncated)?;

    let salt = recipient.public().hash();
    let shared = recipient.diffie_hellman(&eph_pub);
    let (hmac_key, aes_key) = derive_keys(&shared, &salt);
    open_parts(&hmac_key, &aes_key, &token[EPH_LEN..])
}
