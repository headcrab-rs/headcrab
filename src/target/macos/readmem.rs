use mach::{kern_return, port, vm, vm_types::*};
use std::{io, marker::PhantomData, mem};

use crate::CrabResult;

/// A single memory read operation.
struct ReadOp {
    // Remote memory location.
    remote_base: usize,
    // Size of the `local_ptr` buffer.
    len: usize,
    // Pointer to a local destination buffer.
    local_ptr: *mut libc::c_void,
}

/// Allows to read memory from different locations in debuggee's memory as a single operation.
pub struct ReadMemory<'a> {
    target_port: port::mach_port_name_t,
    read_ops: Vec<ReadOp>,
    _marker: PhantomData<&'a mut ()>,
}

impl<'a> ReadMemory<'a> {
    pub(super) fn new(target_port: port::mach_port_name_t) -> Self {
        ReadMemory {
            target_port,
            read_ops: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Reads a value of type `T` from debuggee's memory at location `remote_base`.
    /// This value will be written to the provided variable `val`.
    /// You should call `apply` in order to execute the memory read operation.
    /// The provided variable `val` can't be accessed until either `apply` is called or `self` is
    /// dropped.
    ///
    /// # Safety
    ///
    /// The type `T` must not have any invalid values.
    /// For example `T` must not be a `bool`, as `transmute::<u8, bool>(2)` is not a valid value for a bool.
    /// In case of doubt, wrap the type in [`mem::MaybeUninit`].
    // todo: further document mem safety - e.g., what happens in the case of partial read
    pub fn read<T>(mut self, val: &'a mut T, remote_base: usize) -> Self {
        self.read_ops.push(ReadOp {
            remote_base,
            len: mem::size_of::<T>(),
            local_ptr: val as *mut T as *mut libc::c_void,
        });

        self
    }

    /// Executes the memory read operation.
    pub fn apply(self) -> CrabResult<()> {
        for read_op in &self.read_ops {
            unsafe {
                let mut data_size: mach_vm_size_t = 0;

                let res = vm::mach_vm_read_overwrite(
                    self.target_port,
                    read_op.remote_base as mach_vm_address_t,
                    read_op.len as mach_vm_size_t,
                    read_op.local_ptr as *mut _ as mach_vm_size_t,
                    &mut data_size,
                );

                if res != kern_return::KERN_SUCCESS {
                    // TODO: account for partial reads
                    // TODO: properly wrap error types
                    return Err(Box::new(io::Error::last_os_error()));
                }
            }
        }

        Ok(())
    }
}
