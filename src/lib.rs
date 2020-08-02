//! Headcrab, a modern Rust debugging library.

/// Functions to work with target processes: reading & writing memory, process control functions, etc.
pub mod target;

#[cfg(unix)]
/// Symbolication layer.
pub mod symbol;
