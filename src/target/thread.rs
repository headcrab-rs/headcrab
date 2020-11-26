use super::registers::Registers;
use crate::CrabResult;

pub trait Thread<Reg>
where
    Reg: Registers,
{
    type ThreadId;

    /// Return a thread name.
    fn name(&self) -> CrabResult<Option<String>>;

    /// Return a thread ID.
    fn thread_id(&self) -> Self::ThreadId;

    /// Return CPU registers structure for this thread.
    fn read_regs(&self) -> CrabResult<Reg>;

    /// Write CPU registers for this thread.
    fn write_regs(&self, registers: Reg) -> CrabResult<()>;
}
