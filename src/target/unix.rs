use nix::{
    sys::ptrace,
    sys::wait::waitpid,
    unistd::{execv, fork, ForkResult, Pid},
};
use std::ffi::CString;
impl UnixTarget for Target {}
pub struct Target {
    pub pid: Pid,
}

pub trait UnixTarget {
    /// Launches the debugee from the path provided
    fn launch(path: &str) -> Result<Target, Box<dyn std::error::Error>> {
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
    fn unpause(&self, t: &Target) -> Result<(), Box<dyn std::error::Error>> {
        ptrace::cont(t.pid, None)?;
        Ok(())
    }
}
