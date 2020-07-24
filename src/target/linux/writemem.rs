use nix::unistd::Pid;
use std::{marker::PhantomData, mem};

/// Allows to write data to different locations in debuggee's memory as a single operation.
/// This implementation can select different strategies for different memory pages.
pub struct WriteMemory<'a> {
    pid: Pid,
    write_ops: Vec<WriteOp>,
    _marker: PhantomData<&'a ()>,
}

impl<'a> WriteMemory<'a> {
    pub(super) fn new(pid: Pid) -> Self {
        WriteMemory {
            pid,
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
    pub unsafe fn apply(self) -> Result<(), Box<dyn std::error::Error>> {
        write_process_vm(self.pid, &self.write_ops)
    }
}

/// A single memory write operation.
pub(crate) struct WriteOp {
    // Remote destation location.
    remote_base: usize,
    // Pointer to a source.
    source_ptr: *const libc::c_void,
    // Size of `source_ptr`.
    source_len: usize,
}

impl WriteOp {
    /// Converts the memory read operation into a remote IoVec.
    fn as_remote_iovec(&self) -> libc::iovec {
        libc::iovec {
            iov_base: self.remote_base as *const libc::c_void as *mut _,
            iov_len: self.source_len,
        }
    }

    /// Converts the memory read operation into a local IoVec.
    fn as_local_iovec(&self) -> libc::iovec {
        libc::iovec {
            iov_base: self.source_ptr as *mut _,
            iov_len: self.source_len,
        }
    }
}

/// Allows to write to write-protected pages.
/// On Linux, this will result in multiple system calls and it's inefficient.
pub(crate) fn write_ptrace(
    _pid: Pid,
    _write_ops: &[WriteOp],
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

/// Allows to write data to different locations in debuggee's memory as a single operation.
/// It requires a memory page to be writable.
pub(crate) fn write_process_vm(
    pid: Pid,
    write_ops: &[WriteOp],
) -> Result<(), Box<dyn std::error::Error>> {
    // Create a list of `IoVec`s and remote `IoVec`s
    let remote_iov = write_ops
        .iter()
        .map(WriteOp::as_remote_iovec)
        .collect::<Vec<_>>();

    let local_iov = write_ops
        .iter()
        .map(WriteOp::as_local_iovec)
        .collect::<Vec<_>>();

    let bytes_written = unsafe {
        libc::process_vm_writev(
            pid.into(),
            local_iov.as_ptr(),
            local_iov.len() as libc::c_ulong,
            remote_iov.as_ptr(),
            remote_iov.len() as libc::c_ulong,
            0,
        )
    };

    if bytes_written == -1 {
        // fixme: return a proper error type
        return Err(Box::new(nix::Error::last()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::WriteMemory;
    use nix::unistd::getpid;

    #[test]
    fn write_memory() {
        let var: usize = 52;
        let var2: u8 = 128;

        let write_var_op: usize = 0;
        let write_var2_op: u8 = 0;

        unsafe {
            WriteMemory::new(getpid())
                .write(&var, &write_var_op as *const _ as usize)
                .write(&var2, &write_var2_op as *const _ as usize)
                .apply()
                .expect("Failed to apply memop");
        }

        assert_eq!(write_var2_op, var2);
        assert_eq!(write_var_op, var);
    }
}
