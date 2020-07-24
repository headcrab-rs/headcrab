use nix::unistd::{getpid, Pid};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    mem,
};

use crate::target::unix::UnixTarget;
/// This structure holds the state of a debuggee on Linux based systems
/// You can use it to read & write debuggee's memory, pause it, set breakpoints, etc.
pub struct LinuxTarget {
    pid: Pid,
}

impl UnixTarget for LinuxTarget {
    /// Provides the Pid of the debugee process
    fn pid(&self) -> Pid {
        self.pid
    }
}

impl LinuxTarget {
    /// Launches a new debuggee process
    pub fn launch(path: &str) -> Result<LinuxTarget, Box<dyn std::error::Error>> {
        let pid = crate::target::unix::launch(path)?;
        Ok(LinuxTarget { pid })
    }

    /// Uses this process as a debuggee.
    pub fn me() -> LinuxTarget {
        LinuxTarget { pid: getpid() }
    }

    /// Reads memory from a debuggee process.
    pub fn read(&self) -> ReadMemory {
        ReadMemory::new(self.pid())
    }
}

/// A single memory read operation.
struct ReadOp {
    // Remote memory location.
    remote_base: usize,
    // Size of the `local_ptr` buffer.
    len: usize,
    // Pointer to a local destination buffer.
    local_ptr: *mut libc::c_void,
}

impl ReadOp {
    /// Converts the memory read operation into a remote IoVec.
    fn as_remote_iovec(&self) -> libc::iovec {
        libc::iovec {
            iov_base: self.remote_base as *const libc::c_void as *mut _,
            iov_len: self.len,
        }
    }

    /// Converts the memory read operation into a local IoVec.
    fn as_local_iovec(&self) -> libc::iovec {
        libc::iovec {
            iov_base: self.local_ptr,
            iov_len: self.len,
        }
    }
}

/// Allows to read memory from different locations in debuggee's memory as a single operation.
/// On Linux, this will correspond to a single system call / context switch.
pub struct ReadMemory {
    pid: Pid,
    read_ops: Vec<ReadOp>,
}

impl ReadMemory {
    fn new(pid: Pid) -> ReadMemory {
        ReadMemory {
            pid,
            read_ops: Vec::new(),
        }
    }

    /// Reads a value of type `T` from debuggee's memory at location `remote_base`.
    /// This value will be written to the provided variable `val`.
    /// You should call `apply` in order to execute the memory read operation.
    // todo: document mem safety - e.g., what happens in the case of partial read
    pub fn read<T>(mut self, val: &mut T, remote_base: usize) -> Self {
        self.read_ops.push(ReadOp {
            remote_base,
            len: mem::size_of::<T>(),
            local_ptr: val as *mut T as *mut libc::c_void,
        });

        self
    }

    /// Executes the memory read operation.
    pub fn apply(self) -> Result<(), Box<dyn std::error::Error>> {
        // Create a list of `IoVec`s and remote `IoVec`s
        let remote_iov = self
            .read_ops
            .iter()
            .map(ReadOp::as_remote_iovec)
            .collect::<Vec<_>>();

        let local_iov = self
            .read_ops
            .iter()
            .map(ReadOp::as_local_iovec)
            .collect::<Vec<_>>();

        let bytes_read = unsafe {
            // todo: document unsafety
            libc::process_vm_readv(
                self.pid.into(),
                local_iov.as_ptr(),
                local_iov.len() as libc::c_ulong,
                remote_iov.as_ptr(),
                remote_iov.len() as libc::c_ulong,
                0,
            )
        };

        if bytes_read == -1 {
            // fixme: return a proper error type
            return Err(Box::new(nix::Error::last()));
        }

        // fixme: check that it's an expected number of read bytes and account for partial reads

        Ok(())
    }
}

/// Returns the start of a process's virtual memory address range.
/// This can be useful for calculation of relative addresses in memory.
pub fn get_addr_range(pid: Pid) -> Result<usize, Box<dyn std::error::Error>> {
    let file = File::open(format!("/proc/{}/maps", pid))?;
    let mut bufread = BufReader::new(file);
    let mut proc_map = String::new();

    bufread.read_line(&mut proc_map)?;

    let proc_data: Vec<_> = proc_map.split(' ').collect();
    let addr_range: Vec<_> = proc_data[0].split('-').collect();

    Ok(usize::from_str_radix(addr_range[0], 16)?)
}

#[cfg(test)]
mod tests {
    use super::ReadMemory;
    use nix::unistd::getpid;

    #[test]
    fn read_memory() {
        let var: usize = 52;
        let var2: u8 = 128;

        let mut read_var_op: usize = 0;
        let mut read_var2_op: u8 = 0;

        ReadMemory::new(getpid())
            .read(&mut read_var_op, &var as *const _ as usize)
            .read(&mut read_var2_op, &var2 as *const _ as usize)
            .apply()
            .expect("Failed to apply memop");

        assert_eq!(read_var2_op, var2);
        assert_eq!(read_var_op, var);
    }
}
