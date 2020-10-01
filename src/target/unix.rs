use nix::{
    sys::ptrace,
    sys::wait::{waitpid, WaitStatus},
    unistd::Pid,
};
use std::process::Command;

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

    /// Detach from the debuggee, continuing its execution.
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
    mut cmd: Command,
) -> Result<(Pid, WaitStatus), Box<dyn std::error::Error>> {
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            // Disable ASLR
            #[cfg(target_os = "linux")]
            {
                const ADDR_NO_RANDOMIZE: libc::c_ulong = 0x0040000;
                libc::personality(ADDR_NO_RANDOMIZE);
            }

            ptrace::traceme().map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

            Ok(())
        });
    }
    let child = cmd.spawn()?;
    let pid = Pid::from_raw(child.id() as i32);
    let status = waitpid(pid, None)?;
    Ok((pid, status))
}

/// Attach existing process as a debugee.
pub(in crate::target) fn attach(pid: Pid) -> Result<WaitStatus, Box<dyn std::error::Error>> {
    ptrace::attach(pid)?;
    let status = waitpid(pid, None)?;
    Ok(status)
}
