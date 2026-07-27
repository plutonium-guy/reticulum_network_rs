#![no_std]

extern crate alloc;

pub mod message;
pub mod propagation;
pub mod router;

pub use message::LxmfMessage;
pub use propagation::{
    PropagationContainer, PropagationUpload, build_propagation_upload, decrypt_propagated_message,
    pack_propagation_container, propagation_destination_hash, unpack_propagation_container,
};
pub use router::{LxmfEvent, LxmfRouter, delivery_destination_hash};
