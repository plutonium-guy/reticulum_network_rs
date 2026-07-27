#![no_std]

extern crate alloc;

pub mod hdlc;
pub mod ifac;
pub mod kiss;

/// Framing supplied by a physical interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    Raw,
    Hdlc,
    Kiss,
}

/// Static capabilities of a framed Reticulum medium.
///
/// Async I/O intentionally lives in `reticulum-tokio`; this trait remains
/// usable by `no_std` targets and protocol-only integrations.
pub trait Interface {
    const FRAMING: Framing;
    const HW_MTU: usize;
}
