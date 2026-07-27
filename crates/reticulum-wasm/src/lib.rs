mod node_api;
mod ws;

pub use node_api::ReticulumNode;
pub use ws::HdlcStreamDecoder;

use reticulum_node::{clock::Clock, rng::EntropySource};

/// Browser entropy backed by `crypto.getRandomValues` through `getrandom`.
#[derive(Debug, Clone, Copy, Default)]
pub struct WasmEntropy;

impl EntropySource for WasmEntropy {
    fn fill(&mut self, out: &mut [u8]) {
        getrandom::getrandom(out).expect("browser CSPRNG is unavailable");
    }
}

/// Wall-clock adapter for protocol expiry and freshness decisions.
#[derive(Debug, Clone, Copy, Default)]
pub struct WasmClock;

impl Clock for WasmClock {
    fn now_secs(&self) -> u64 {
        (js_sys::Date::now() / 1_000.0).max(0.0) as u64
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn entropy_is_nonzero_and_varies() {
        let mut entropy = WasmEntropy;
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        entropy.fill(&mut first);
        entropy.fill(&mut second);
        assert_ne!(first, [0u8; 32]);
        assert_ne!(first, second);
    }

    #[wasm_bindgen_test]
    fn clock_tracks_javascript_time() {
        let before = (js_sys::Date::now() / 1_000.0) as u64;
        let actual = WasmClock.now_secs();
        let after = (js_sys::Date::now() / 1_000.0) as u64;
        assert!(actual >= before && actual <= after);
    }
}
