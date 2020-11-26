#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

mod registers;
mod thread;

pub use registers::Registers;
pub use thread::Thread;

#[derive(Debug)]
pub struct MemoryMap {
    /// Start and end range of the mapped memory.
    pub address: (u64, u64),
    /// The file and file offset backing the mapped memory if any.
    pub backing_file: Option<(std::path::PathBuf, u64)>,

    /// Is mapped memory readable.
    pub is_readable: bool,
    /// Is mapped memory writable.
    pub is_writable: bool,
    /// Is mapped memory executable.
    pub is_executable: bool,
    /// Is mapped memory private.
    pub is_private: bool,
}
