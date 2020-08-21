//! Bundles functionalities related to software breakpoints
//! Software Breakpoints work by overwritting the target program's memory.
//! replacing an instruction with one that causes a signal to be raised by the
//! cpu.

#[derive(Debug, Clone, Copy)]
pub struct Breakpoint {
    /// The address at which the debugger should insert this breakpoint
    pub addr: usize,
}

impl Breakpoint {
    /// Set a breakpoint at a given Symbol
    pub fn at_symbol(_symbol: String) -> Result<Self, BreakpointError> {
        //TODO(galileo) Update to look for a given symbol in the target's dwarf info
        Err(BreakpointError::NoSuchSymbol)
    }

    /// Set a breakpoint at a given address
    pub fn at_addr(addr: usize) -> Result<Self, BreakpointError> {
        Ok(Breakpoint {
            addr,
        })
    }
}

#[derive(Debug)]
pub enum BreakpointError {
    NoSuchSymbol,
    IoError,
}

impl std::fmt::Display for BreakpointError {
    fn  fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{:?}", self)
    }
}

impl std::error::Error for BreakpointError { }
/// Metadata about an active breakpoint
#[derive(Debug)]
pub struct BreakpointEntry {
    pub(crate) addr: usize,
    // We only overrite one byte of the instruction
    pub(crate) saved_instr: i64,
}

impl  BreakpointEntry {
    /// Create a new breakpoint entry at a given address
    pub fn at(addr: usize, instr: i64) -> Self {
        BreakpointEntry {
            addr,
            saved_instr: instr,
        }
    }
}