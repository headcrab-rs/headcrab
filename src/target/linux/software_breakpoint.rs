//! Bundles functionalities related to software breakpoints
//! Software Breakpoints work by overwritting the target program's memory.
//! replacing an instruction with one that causes a signal to be raised by the
//! cpu.

use nix::sys::ptrace;
use nix::unistd::Pid;
const INT3: libc::c_long = 0xcc;

#[derive(Debug, Copy, Clone)]
pub struct Breakpoint {
    /// The address at which the debugger should insert this breakpoint
    pub addr: usize,
    /// The original instruction overwritten by the breakpoint
    pub(super) shadow: i64,
    pid: Pid,
}

impl Breakpoint {
    /// Set a breakpoint at a given address
    pub(crate) fn new(addr: usize, pid: Pid) -> Result<Self, BreakpointError> {
        let shadow = ptrace::read(pid, addr as *mut _)?;
        Ok(Breakpoint { addr, shadow, pid })
    }

    /// Put in place the trap instruction
    pub fn set(&mut self) -> Result<(), BreakpointError> {
        if self.is_active() {
            // We don't allow setting breakpoint twice
            // else it would be possible to create a breakpoint that
            // would 'restore' an `INT3` instruction
            return Ok(());
        }
        let instr = ptrace::read(self.pid, self.addr as *mut _)?;
        self.shadow = instr;
        let trap_instr = (instr & !0xff) | INT3;
        ptrace::write(self.pid, self.addr as *mut _, trap_instr as *mut _)?;
        Ok(())
    }

    /// Restore the previous instruction for the breakpoint.
    pub fn disable(&self) -> Result<(), BreakpointError> {
        if !self.is_active() {
            // Tried to restore a breakpoint that isn't set, fail silently
            return Ok(());
        }

        ptrace::write(self.pid, self.addr as *mut _, self.shadow as *mut _)?;
        Ok(())
    }

    /// Wether this breakpoint has instrumented the target's code
    pub fn is_active(&self) -> bool {
        let instr = ptrace::read(self.pid, self.addr as *mut _).unwrap();
        (instr & 0xff) == INT3
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
