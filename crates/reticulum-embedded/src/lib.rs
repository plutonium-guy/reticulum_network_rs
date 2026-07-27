#![no_std]

extern crate alloc;

pub mod uart;

use embassy_time::Instant;
use reticulum_core::EntropySource;
use reticulum_node::Clock;

/// An infallible adapter for a hardware random-number peripheral.
///
/// Implementations must use a cryptographically secure source. This trait is
/// intentionally small so platform HAL RNG types can be wrapped without
/// coupling this crate to a particular microcontroller family.
pub trait HardwareRng {
    fn fill_random(&mut self, out: &mut [u8]);
}

/// Reticulum entropy backed by the selected MCU's hardware RNG peripheral.
pub struct EmbeddedEntropy<R> {
    rng: R,
}

impl<R> EmbeddedEntropy<R> {
    pub const fn new(rng: R) -> Self {
        Self { rng }
    }

    pub fn into_inner(self) -> R {
        self.rng
    }
}

impl<R: HardwareRng> EntropySource for EmbeddedEntropy<R> {
    fn fill(&mut self, out: &mut [u8]) {
        self.rng.fill_random(out);
    }
}

/// Monotonic seconds supplied by Embassy's platform time driver.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmbeddedClock;

impl Clock for EmbeddedClock {
    fn now_secs(&self) -> u64 {
        Instant::now().as_secs()
    }
}

/// Deterministic entropy for emulators without an RNG peripheral.
///
/// # Security
///
/// This generator is predictable and MUST NOT be enabled in production. It
/// exists only to make serial plumbing demonstrable under MCU emulators.
#[cfg(feature = "insecure-demo-rng")]
pub struct InsecureDemoEntropy {
    state: u64,
}

#[cfg(feature = "insecure-demo-rng")]
impl InsecureDemoEntropy {
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }
}

#[cfg(feature = "insecure-demo-rng")]
impl HardwareRng for InsecureDemoEntropy {
    fn fill_random(&mut self, out: &mut [u8]) {
        for byte in out {
            self.state ^= self.state << 13;
            self.state ^= self.state >> 7;
            self.state ^= self.state << 17;
            *byte = self.state as u8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CountingRng(u8);

    impl HardwareRng for CountingRng {
        fn fill_random(&mut self, out: &mut [u8]) {
            for byte in out {
                self.0 = self.0.wrapping_add(1);
                *byte = self.0;
            }
        }
    }

    #[test]
    fn hardware_rng_adapter_fills_the_requested_buffer() {
        let mut entropy = EmbeddedEntropy::new(CountingRng(0));
        let mut bytes = [0; 4];
        entropy.fill(&mut bytes);
        assert_eq!(bytes, [1, 2, 3, 4]);
    }
}
