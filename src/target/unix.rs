use nix::{
    sys::ptrace,
    sys::wait::{waitpid, WaitStatus},
    unistd::{execv, fork, ForkResult, Pid},
};
use std::ffi::CString;

/// This trait defines the common behavior for all *nix targets
pub trait UnixTarget {
    /// Provides the Pid of the debugee process
    fn pid(&self) -> Pid;

    /// Step the debuggee one instruction further.
    fn step(&self) -> Result<WaitStatus, Box<dyn std::error::Error>> {
        ptrace::step(self.pid(), None)?;
        let status = waitpid(self.pid(), None)?;
        Ok(status)
    }

    /// Continues execution of a debuggee.
    fn unpause(&self) -> Result<WaitStatus, Box<dyn std::error::Error>> {
        ptrace::cont(self.pid(), None)?;
        let status = waitpid(self.pid(), None)?;
        Ok(status)
    }

    /// Detach from the debuggee, continuing it's execution.
    fn detach(&self) -> Result<(), Box<dyn std::error::Error>> {
        ptrace::detach(self.pid(), None)?;
        Ok(())
    }

    /// Kills the debuggee.
    fn kill(&self) -> Result<WaitStatus, Box<dyn std::error::Error>> {
        ptrace::kill(self.pid())?;
        let status = waitpid(self.pid(), None)?;
        Ok(status)
    }
}

/// Launch a new debuggee process.
pub(in crate::target) fn launch(
    path: &str,
) -> Result<(Pid, WaitStatus), Box<dyn std::error::Error>> {
    // We start the debuggee by forking the parent process.
    // The child process invokes `ptrace(2)` with the `PTRACE_TRACEME` parameter to enable debugging features for the parent.
    // This requires a user to have a `SYS_CAP_PTRACE` permission. See `man capabilities(7)` for more information.
    match fork()? {
        ForkResult::Parent { child, .. } => {
            let status = waitpid(child, None)?;
            Ok((child, status))
        }
        ForkResult::Child => {
            ptrace::traceme()?;

            // Disable ASLR
            #[cfg(target_os = "linux")]
            unsafe {
                const ADDR_NO_RANDOMIZE: libc::c_ulong = 0x0040000;
                libc::personality(ADDR_NO_RANDOMIZE);
            }

            let path = CString::new(path)?;
            execv(&path, &[path.as_ref()])?;

            // execv replaces the process image, so this place in code will not be reached.
            unreachable!();
        }
    }
}

/// Attach existing process as a debugee.
pub(in crate::target) fn attach(pid: Pid) -> Result<WaitStatus, Box<dyn std::error::Error>> {
    ptrace::attach(pid)?;
    let status = waitpid(pid, None)?;
    Ok(status)
}
