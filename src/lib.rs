//! Headcrab, a modern Rust debugging library.

/// Functions to work with target processes: reading & writing memory, process control functions, etc.
pub mod target;

/// Symbolication layer.
#[cfg(unix)]
pub mod symbol;
