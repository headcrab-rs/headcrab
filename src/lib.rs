//! Headcrab, a modern Rust debugging library.

#[macro_use]
extern crate lazy_static;

/// Functions to work with target processes: reading & writing memory, process control functions, etc.
pub mod target;

/// Symbolication layer.
pub mod symbol;
