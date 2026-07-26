#![no_std]

extern crate alloc;

pub mod rng;

/// Errors surfaced by node operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeError {
    Core(reticulum_core::CoreError),
    Unknown,
}

impl From<reticulum_core::CoreError> for NodeError {
    fn from(error: reticulum_core::CoreError) -> Self {
        Self::Core(error)
    }
}
