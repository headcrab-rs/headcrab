use nix::{
    sys::ptrace,
    sys::uio,
    sys::wait::waitpid,
    unistd::{execv, fork, ForkResult, Pid},
};
use std::{
    ffi::CString,
    fs::File,
    io::{BufRead, BufReader},
    mem,
};

pub struct Target {
    pid: Pid,
}

impl Target {
    /// Launch a new debuggee process.
    /// Returns an opaque target handle which you can use to control the debuggee.
    pub fn launch(path: &str) -> Result<Target, Box<dyn std::error::Error>> {
        // We start the debuggee by forking the parent process.
        // The child process invokes `ptrace(2)` with the `PTRACE_TRACEME` parameter to enable debugging features for the parent.
        // This requires a user to have a `SYS_CAP_PTRACE` permission. See `man capabilities(7)` for more information.
        match fork()? {
            ForkResult::Parent { child, .. } => {
                let _status = waitpid(child, None);

                // todo: handle this properly

                Ok(Target { pid: child })
            }
            ForkResult::Child => {
                ptrace::traceme()?;

                let path = CString::new(path)?;
                execv(&path, &[])?;

                // execv replaces the process image, so this place in code will not be reached.
                unreachable!();
            }
        }
    }

    /// Continues execution of a debuggee.
    pub fn unpause(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Read current value
        ptrace::cont(self.pid, None)?;
        Ok(())
    }

    /// Reads a string from the debuggee's memory.
    // TODO: move this to a trait blanket impl
    pub fn read_string(
        &self,
        base: usize,
        len: usize,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut read_buf = vec![0; len];
        let buf_iov = uio::IoVec::from_mut_slice(&mut read_buf);
        uio::process_vm_readv(self.pid, &[buf_iov], &[uio::RemoteIoVec { base, len }])?;

        Ok(String::from_utf8(read_buf)?)
    }

    /// Reads pointer-sized data from the debuggee's memory.
    /// The size of a result will be platform-dependent (32 or 64 bits).
    // TODO: move this to a trait blanket impl
    pub fn read_usize(&self, base: usize) -> Result<usize, Box<dyn std::error::Error>> {
        let mut read_buf = [0; mem::size_of::<usize>()];
        let buf_iov = uio::IoVec::from_mut_slice(&mut read_buf);

        let remote_iov = uio::RemoteIoVec {
            base,
            len: mem::size_of::<usize>(),
        };

        uio::process_vm_readv(self.pid, &[buf_iov], &[remote_iov])?;

        Ok(usize::from_ne_bytes(read_buf))
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
