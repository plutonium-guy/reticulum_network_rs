#![no_std]

extern crate alloc;
#[cfg(feature = "compression")]
extern crate std;

pub mod announce;
pub mod destination;
pub mod hash;
pub mod identity;
pub mod link;
pub mod packet;
pub mod resource;
pub mod token;

/// Randomness injected into sans-I/O protocol code.
pub trait EntropySource {
    fn fill(&mut self, out: &mut [u8]);
}

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
    /// The input requires an optional capability that is not enabled.
    Unsupported,
}
