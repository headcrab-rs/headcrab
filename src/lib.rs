//! Headcrab, a modern Rust debugging library.

pub type CrabResult<T> = Result<T, error::CrabError>;

pub mod error;
/// Functions to work with target processes: reading & writing memory, process control functions, etc.
pub mod target;

/// Symbolication layer.
#[cfg(unix)]
pub mod symbol;

pub use error::CrabError;
