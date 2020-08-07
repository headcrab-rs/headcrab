//! Utility functions to work with memory.

use crate::target::MemoryMap;
use std::cmp::Ordering;

lazy_static::lazy_static! {
    /// Memory page size from system configuration.
    pub(crate) static ref PAGE_SIZE: usize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
}

/// Abstract memory operation (reading or writing).
pub trait MemoryOp {
    /// Returns a remote address at which this memory operation will be applied to.
    fn remote_base(&self) -> usize;
}

/// Splits memory operations to those that can access protected memory and those that do not.
/// This function can be used for both write or read operations, and `maps` should be pre-filtered
/// to contain only protected pages, e.g.:
/// ```
/// use headcrab::target::MemoryMap;
///
/// let maps: Vec<MemoryMap> = vec![];
/// let protected_maps = maps.into_iter().filter(|map| !map.is_writable);
/// ```
pub fn split_protected<'a, M: MemoryOp>(
    maps: &'a [MemoryMap],
    operations: impl Iterator<Item = M>,
) -> Result<(Vec<M>, Vec<M>), Box<dyn std::error::Error>> {
    let (protected, permissioned): (_, Vec<_>) = operations.partition(|op| {
        maps.binary_search_by(|map| {
            if op.remote_base() < map.address.0 as usize {
                Ordering::Greater
            } else if op.remote_base() > map.address.1 as usize {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        })
        .is_ok()
    });

    Ok((protected, permissioned))
}
