#![no_std]

//! Board entry-point integration contract.
//!
//! A concrete firmware owns its HAL initialization and calls
//! `reticulum_embedded::uart::run_uart` with the board's async UART, hardware
//! RNG adapter, and an Embassy time driver. Keeping that ownership in the
//! board crate avoids baking a vendor HAL or pin mapping into the portable
//! Reticulum adapter.
