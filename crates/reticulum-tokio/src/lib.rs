pub mod driver;
pub mod tcp;

use reticulum_node::rng::EntropySource;

/// Production entropy source backed by the operating system CSPRNG.
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&mut self, out: &mut [u8]) {
        getrandom::getrandom(out).expect("operating system entropy is unavailable");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_node::rng::EntropySource;

    #[test]
    fn os_entropy_fills_nonzero_and_varies() {
        let mut entropy = OsEntropy;
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        entropy.fill(&mut a);
        entropy.fill(&mut b);
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }
}
