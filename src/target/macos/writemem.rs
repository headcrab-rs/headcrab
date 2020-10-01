use mach::{kern_return, message::mach_msg_type_number_t, port, vm, vm_types::*};
use std::{io, marker::PhantomData, mem};

use crate::CrabResult;

/// Allows to write data to different locations in debuggee's memory as a single operation.
pub struct WriteMemory<'a> {
    target_port: port::mach_port_name_t,
    write_ops: Vec<WriteOp>,
    _marker: PhantomData<&'a ()>,
}

impl<'a> WriteMemory<'a> {
    pub(super) fn new(target_port: port::mach_port_name_t) -> Self {
        WriteMemory {
            target_port,
            write_ops: Vec::new(),
            _marker: PhantomData,
        }
    }

    pub fn write<T: ?Sized>(mut self, val: &'a T, remote_base: usize) -> Self {
        self.write_ops.push(WriteOp {
            remote_base,
            source_len: mem::size_of_val(val),
            source_ptr: val as *const T as *const libc::c_void,
        });
        self
    }

    /// Executes the memory write operation.
    pub fn apply(self) -> CrabResult<()> {
        for write_op in &self.write_ops {
            let res = unsafe {
                vm::mach_vm_write(
                    self.target_port,
                    write_op.remote_base as mach_vm_address_t,
                    write_op.source_ptr as vm_offset_t,
                    write_op.source_len as mach_msg_type_number_t,
                )
            };

            if res != kern_return::KERN_SUCCESS {
                // TODO: account for partial writes
                // TODO: properly wrap error types
                return Err(Box::new(io::Error::last_os_error()));
            }
        }

        Ok(())
    }
}

/// A single memory write operation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct WriteOp {
    /// Remote destation location.
    remote_base: usize,
    /// Pointer to a source.
    source_ptr: *const libc::c_void,
    /// Size of `source_ptr`.
    source_len: usize,
}

#[cfg(test)]
mod tests {
    use super::{WriteMemory, WriteOp};
    use mach::traps::mach_task_self;
    use std::{mem, ptr};

    #[test]
    fn write_memory() {
        let var: usize = 52;
        let var2: u8 = 128;

        let write_var_op: usize = 0;
        let write_var2_op: u8 = 0;

        unsafe {
            WriteMemory::new(mach_task_self())
                .write(&var, &write_var_op as *const _ as usize)
                .write(&var2, &write_var2_op as *const _ as usize)
                .apply()
                .expect("Failed to write memory")
        };

        unsafe {
            assert_eq!(ptr::read_volatile(&write_var_op), var);
            assert_eq!(ptr::read_volatile(&write_var2_op), var2);
        }
    }
}
