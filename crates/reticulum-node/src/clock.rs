use core::cell::Cell;

/// Monotonic-enough wall-clock seconds supplied by the platform adapter.
pub trait Clock {
    fn now_secs(&self) -> u64;
}

/// Clock used by the backwards-compatible `Node::new` constructor.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoClock;

impl Clock for NoClock {
    fn now_secs(&self) -> u64 {
        0
    }
}

/// Deterministic clock for protocol tests.
#[derive(Debug, Default)]
pub struct TestClock {
    now: Cell<u64>,
}

impl TestClock {
    pub const fn new(now: u64) -> Self {
        Self {
            now: Cell::new(now),
        }
    }

    pub fn set(&self, now: u64) {
        self.now.set(now);
    }

    pub fn advance(&self, seconds: u64) {
        self.now.set(self.now.get().saturating_add(seconds));
    }
}

impl Clock for TestClock {
    fn now_secs(&self) -> u64 {
        self.now.get()
    }
}
