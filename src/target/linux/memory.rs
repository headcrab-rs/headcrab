//! Utility functions to work with memory.

use crate::target::MemoryMap;
use std::cmp::Ordering;

/// Abstract memory operation (reading or writing).
pub trait MemoryOp {
    /// Returns a remote address at which this memory operation will be applied to.
    fn remote_base(&self) -> usize;
}

/// Splits memory operations to those that read from read protected memory and those that do not.
pub fn split_protected<'a, M: MemoryOp>(
    maps: &'a [MemoryMap],
    operations: &'a [M],
) -> Result<(Vec<&'a M>, Vec<&'a M>), Box<dyn std::error::Error>> {
    let (protected, readable): (_, Vec<_>) = operations.iter().partition(|op| {
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

    Ok((protected, readable))
}
