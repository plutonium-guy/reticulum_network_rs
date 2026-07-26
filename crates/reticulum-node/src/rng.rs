/// Source of randomness injected into the sans-I/O node.
///
/// Production implementations must use a cryptographically secure source.
pub trait EntropySource {
    fn fill(&mut self, out: &mut [u8]);
}

/// Deterministic SplitMix64 generator for tests and development only.
///
/// This generator is not cryptographically secure.
pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }
}

impl EntropySource for SeededRng {
    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_rng_is_deterministic_and_fills() {
        let mut a = SeededRng::new(42);
        let mut b = SeededRng::new(42);
        let mut ba = [0u8; 32];
        let mut bb = [0u8; 32];
        a.fill(&mut ba);
        b.fill(&mut bb);
        assert_eq!(ba, bb);
        assert_ne!(ba, [0u8; 32]);
    }
}
