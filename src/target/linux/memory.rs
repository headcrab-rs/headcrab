//! Utility functions to work with memory.

use crate::target::MemoryMap;
use std::cmp::{self, Ordering};

lazy_static::lazy_static! {
    /// Memory page size from system configuration.
    pub(crate) static ref PAGE_SIZE: usize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
}

/// Individual memory operation (reading or writing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemoryOp {
    /// Remote memory location.
    pub remote_base: usize,
    /// Pointer to a local destination or source buffer.
    pub local_ptr: *mut libc::c_void,
    /// Size of the `local_ptr` buffer.
    pub local_ptr_len: usize,
}

impl MemoryOp {
    /// Converts the memory operation into a remote IoVec suitable for use in vector read/write syscalls.
    pub fn as_remote_iovec(&self) -> libc::iovec {
        libc::iovec {
            iov_base: self.remote_base as *const libc::c_void as *mut _,
            iov_len: self.local_ptr_len,
        }
    }

    /// Converts the memory operation into a local IoVec suitable for use in vector read/write syscalls.
    pub fn as_local_iovec(&self) -> libc::iovec {
        libc::iovec {
            iov_base: self.local_ptr,
            iov_len: self.local_ptr_len,
        }
    }

    /// Splits `MemoryOp` so that each resulting `MemoryOp` resides in only one memory page.
    pub(crate) fn split_on_page_boundary(&self, out: &mut Vec<impl From<MemoryOp>>) {
        // Number of bytes left to be read or written
        let mut left = self.local_ptr_len;

        let next_page_distance = *PAGE_SIZE - ((*PAGE_SIZE - 1) & self.remote_base);
        let to_next_read_op = cmp::min(left, next_page_distance);
        // Read or write from remote_base to the end or to the next page
        out.push(From::from(MemoryOp {
            remote_base: self.remote_base,
            local_ptr: self.local_ptr,
            local_ptr_len: to_next_read_op,
        }));
        left -= to_next_read_op;

        while left > 0 {
            if left < *PAGE_SIZE {
                // Read or write from beginning of the page to a part in the middle (last read or write)
                out.push(From::from(MemoryOp {
                    remote_base: self.remote_base + (self.local_ptr_len - left),
                    local_ptr: (self.local_ptr as usize + (self.local_ptr_len - left))
                        as *mut libc::c_void,
                    local_ptr_len: left,
                }));
                break;
            } else {
                // Whole page is being read or written
                out.push(From::from(MemoryOp {
                    remote_base: self.remote_base + (self.local_ptr_len - left),
                    local_ptr: (self.local_ptr as usize + (self.local_ptr_len - left))
                        as *mut libc::c_void,
                    local_ptr_len: *PAGE_SIZE,
                }));
                left -= *PAGE_SIZE;
            }
        }
    }
}

/// Splits memory operations to those that can access protected memory and those that do not.
/// This function can be used for both write or read operations, and `protected_maps` should be
/// pre-filtered to contain only protected pages, e.g.:
/// ```
/// use headcrab::target::MemoryMap;
///
/// let maps: Vec<MemoryMap> = vec![];
/// let protected_maps = maps.into_iter().filter(|map| !map.is_writable);
/// ```
pub(crate) fn split_protected<'a>(
    protected_maps: &'a [MemoryMap],
    operations: impl Iterator<Item = MemoryOp>,
) -> (Vec<MemoryOp>, Vec<MemoryOp>) {
    let (protected, permissioned): (_, Vec<_>) = operations.partition(|op| {
        protected_maps
            .binary_search_by(|map| {
                if op.remote_base < map.address.0 as usize {
                    Ordering::Greater
                } else if op.remote_base > map.address.1 as usize {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            })
            .is_ok()
    });

    (protected, permissioned)
}
