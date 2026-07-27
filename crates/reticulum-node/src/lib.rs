#![no_std]

extern crate alloc;

pub mod clock;
pub mod link_state;
pub mod node;
pub mod path_table;
pub mod rng;

pub use clock::{Clock, NoClock, TestClock};

use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Announce {
        dest_hash: [u8; 16],
        hops: u8,
    },
    Message {
        dest_hash: [u8; 16],
        plaintext: Vec<u8>,
    },
    LinkEstablished {
        link_id: [u8; 16],
    },
    LinkData {
        link_id: [u8; 16],
        plaintext: Vec<u8>,
    },
    LinkClosed {
        link_id: [u8; 16],
    },
    Error(NodeError),
}

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
