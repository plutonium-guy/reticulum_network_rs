#![no_std]

extern crate alloc;

pub mod hash;

/// Errors returned by fallible core operations. No core function panics on
/// untrusted input; malformed data always surfaces as one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// Input buffer too short for the structure being parsed.
    Truncated,
    /// A signature failed to verify.
    BadSignature,
    /// Authenticated decryption failed (HMAC mismatch or bad padding).
    DecryptFailed,
    /// A field held a value outside its permitted range.
    InvalidField,
}
