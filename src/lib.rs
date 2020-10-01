//! Headcrab, a modern Rust debugging library.

pub type CrabResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync + Sync>>;

/// Functions to work with target processes: reading & writing memory, process control functions, etc.
pub mod target;

/// Symbolication layer.
#[cfg(unix)]
pub mod symbol;
