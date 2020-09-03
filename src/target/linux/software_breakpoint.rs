//! Bundles functionalities related to software breakpoints
//! Software Breakpoints work by overwritting the target program's memory.
//! replacing an instruction with one that causes a signal to be raised by the
//! cpu.

use nix::sys::ptrace;
use nix::unistd::Pid;
const INT3: libc::c_long = 0xcc;

#[derive(Debug, Clone, Copy)]
pub struct Breakpoint {
    /// The address at which the debugger should insert this breakpoint
    pub addr: usize,
    /// The shadowed variable
    pub(crate) shadow: Option<i64>,
    pid: Pid,
}

impl Breakpoint {
    /// Set a breakpoint at a given address
    pub(crate) fn new(addr: usize, pid: Pid) -> Self {
        Breakpoint {
            addr,
            shadow: None,
            pid,
        }
    }

    /// Put in place the trap instruction
    pub fn set(&mut self) -> Result<(), BreakpointError> {
        let instr = ptrace::read(self.pid, self.addr as *mut _)?;
        self.shadow = Some(instr);
        let trap_instr = (instr & !0xff) | INT3;
        ptrace::write(self.pid, self.addr as *mut _, trap_instr as *mut _)?;
        Ok(())
    }

    /// Restore the previous instruction for the breakpoint.
    pub fn restore(&mut self) -> Result<(), BreakpointError> {
        if let None = self.shadow {
            // Tried to restore a breakpoint that isn't set, fail silently
            return Ok(());
        }

        ptrace::write(
            self.pid,
            self.addr as *mut _,
            // Checked above
            self.shadow.take().unwrap() as *mut _,
        )
        .map_err(|e| e.into())
    }

    /// Delete the breakpoint, clearing the trap instruction
    pub fn remove(mut self) -> Result<(), BreakpointError> {
        self.restore()
    }
}

#[derive(Debug)]
pub enum BreakpointError {
    NoSuchSymbol,
    IoError,
    NixError(nix::Error),
}

impl std::convert::From<nix::Error> for BreakpointError {
    fn from(error: nix::Error) -> Self {
        BreakpointError::NixError(error)
    }
}

impl std::fmt::Display for BreakpointError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{:?}", self)
    }
}

impl std::error::Error for BreakpointError {}
