#![no_std]

extern crate alloc;

pub mod message;
pub mod propagation;
pub mod router;
pub mod stamp;

pub use message::LxmfMessage;
pub use propagation::{
    PropagationContainer, PropagationUpload, build_propagation_upload, decrypt_propagated_message,
    pack_propagation_container, propagation_destination_hash, unpack_propagation_container,
};
pub use router::{LxmfEvent, LxmfRouter, delivery_destination_hash};
pub use stamp::{
    DELIVERY_WORKBLOCK_ROUNDS, PROPAGATION_WORKBLOCK_ROUNDS, STAMP_SIZE, StampValidation,
    stamp_value, stamp_workblock, verify_optional_stamp, verify_stamp, verify_ticket_stamp,
};
