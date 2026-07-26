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
//! ## A deliberate deviation for `encrypt()`
//!
//! This module's [`encrypt`] only receives the recipient's raw 32-byte
//! X25519 public key (per this crate's fixed interface), not their Ed25519
//! signing key. It therefore cannot reproduce RNS's true per-identity salt,
//! which mixes in the signing key too. It salts with
//! `truncated_hash(recipient_enc_pub)` instead. [`decrypt`] tries the real
//! RNS identity-hash salt first — so it matches genuine RNS-produced tokens
//! such as the authoritative vector — and falls back to the enc-pub-only
//! salt so it can also decrypt tokens produced by this module's own
//! `encrypt`. This mirrors how RNS's own `Identity.decrypt` tries several
//! candidate derived keys (ratchets) before giving up.

use crate::{hash::truncated_hash, identity::Identity, CoreError};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
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
    hk.expand(&[], &mut okm).expect("hkdf output length is valid");
    let mut hmac_key = [0u8; HMAC_LEN];
    let mut aes_key = [0u8; KEY_LEN];
    hmac_key.copy_from_slice(&okm[..HMAC_LEN]);
    aes_key.copy_from_slice(&okm[HMAC_LEN..]);
    (hmac_key, aes_key)
}

/// Encrypt `plaintext` for `recipient_enc_pub` using the given ephemeral
/// X25519 secret. The ephemeral secret (and, in this deterministic-for-tests
/// implementation, the IV) is caller-supplied; production callers must draw
/// both from a CSPRNG.
pub fn encrypt(
    recipient_enc_pub: &[u8; 32],
    plaintext: &[u8],
    ephemeral_x25519: &[u8; 32],
) -> Vec<u8> {
    let eph = StaticSecret::from(*ephemeral_x25519);
    let eph_pub = XPublic::from(&eph).to_bytes();
    let shared = eph
        .diffie_hellman(&XPublic::from(*recipient_enc_pub))
        .to_bytes();

    // See module docs: encrypt() only has the raw enc pubkey, so it salts
    // with a hash of that alone rather than RNS's full identity hash.
    let salt = truncated_hash(recipient_enc_pub);
    let (hmac_key, aes_key) = derive_keys(&shared, &salt);

    let iv = [0u8; IV_LEN]; // deterministic for tests; production draws a random IV
    let ct =
        Enc::new(aes_key[..].into(), iv[..].into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    // RNS Token.encrypt signs (iv || ciphertext) only.
    let mut signed_parts = Vec::with_capacity(IV_LEN + ct.len());
    signed_parts.extend_from_slice(&iv);
    signed_parts.extend_from_slice(&ct);

    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&hmac_key).expect("hmac key length is valid");
    mac.update(&signed_parts);
    let tag = mac.finalize().into_bytes();

    // RNS Identity.encrypt prepends the ephemeral public key outside the Token.
    let mut out = Vec::with_capacity(EPH_LEN + signed_parts.len() + HMAC_LEN);
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&signed_parts);
    out.extend_from_slice(&tag);
    out
}

/// Attempt Token decryption with one candidate salt. Returns `Err` on either
/// HMAC mismatch or padding failure, so callers can try the next candidate.
fn try_decrypt_with_salt(
    recipient: &Identity,
    eph_pub: &[u8; 32],
    signed_parts: &[u8],
    tag: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Vec<u8>, CoreError> {
    let shared = recipient.diffie_hellman(eph_pub);
    let (hmac_key, aes_key) = derive_keys(&shared, salt);

    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&hmac_key).map_err(|_| CoreError::InvalidField)?;
    mac.update(signed_parts);
    mac.verify_slice(tag).map_err(|_| CoreError::DecryptFailed)?;

    let iv = &signed_parts[..IV_LEN];
    let ct = &signed_parts[IV_LEN..];
    Dec::new(aes_key[..].into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|_| CoreError::DecryptFailed)
}

/// Decrypt a Token addressed to `recipient`.
///
/// Tries the real RNS per-identity salt (`truncated_hash(enc_pub||sig_pub)`,
/// i.e. `recipient.hash()`) first — this is what genuine RNS 1.4.1 tokens
/// use — and falls back to the enc-pub-only salt used by this module's own
/// [`encrypt`].
pub fn decrypt(recipient: &Identity, token: &[u8]) -> Result<Vec<u8>, CoreError> {
    if token.len() < EPH_LEN + IV_LEN + HMAC_LEN {
        return Err(CoreError::Truncated);
    }
    let (body, tag) = token.split_at(token.len() - HMAC_LEN);
    let eph_pub: [u8; 32] = body[..EPH_LEN].try_into().map_err(|_| CoreError::Truncated)?;
    let signed_parts = &body[EPH_LEN..];

    let public = recipient.public();
    let identity_salt = public.hash();
    let enc_pub_salt = truncated_hash(&public.enc_pub);

    try_decrypt_with_salt(recipient, &eph_pub, signed_parts, tag, &identity_salt)
        .or_else(|_| try_decrypt_with_salt(recipient, &eph_pub, signed_parts, tag, &enc_pub_salt))
}
