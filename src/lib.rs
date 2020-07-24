//! Headcrab, a modern Rust debugging library.

#[macro_use]
extern crate rental;

/// Functions to work with target processes: reading & writing memory, process control functions, etc.
pub mod target;

/// Symbolication layer.
pub mod symbol;
