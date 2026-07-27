#![no_std]

extern crate alloc;

pub mod message;
pub mod router;

pub use message::LxmfMessage;
pub use router::{LxmfEvent, LxmfRouter, delivery_destination_hash};
