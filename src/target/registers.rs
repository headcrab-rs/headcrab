//! Interfaces related to registers reading & writing.

use std::fmt::Debug;

/// Trait that can be used to read & write the target's registers.
pub trait Registers: Debug {
    /// Returns a current instruction pointer.
    fn ip(&self) -> u64;

    /// Sets an instruction pointer to the provided value.
    fn set_ip(&mut self, ip: u64);

    /// Returns a current stack pointer.
    fn sp(&self) -> u64;

    /// Sets a stack pointer to the provided value.
    fn set_sp(&mut self, sp: u64);

    /// Returns a base pointer.
    /// Returns `None` if the standard ABI on the platform has no base pointer.
    fn bp(&self) -> Option<u64>;

    /// Sets a base pointer to the provided value.
    /// Returns `None` if the standard ABI on the platform has no base pointer.
    #[must_use]
    fn set_bp(&mut self, bp: u64) -> Option<()>;

    /// Translates a DWARF register type into a value.
    /// See [`gimli::Register`](https://docs.rs/gimli/*/gimli/struct.Register.html) definition for a list of
    /// available registers. Returns `None` when a specified register doesn't exist.
    fn reg_for_dwarf(&self, reg: gimli::Register) -> Option<u64>;

    /// Sets a DWARF register to the provided value.
    /// See [`gimli::Register`](https://docs.rs/gimli/*/gimli/struct.Register.html) definition for a list of
    /// available registers. Returns `None` when a specified register doesn't exist.
    #[must_use]
    fn set_reg_for_dwarf(&mut self, reg: gimli::Register, val: u64) -> Option<()>;

    /// Converts a DWARF register type into a lower-case string value (the register name).
    /// Returns `None` when a register doesn't exist.
    fn name_for_dwarf(reg: gimli::Register) -> Option<&'static str>
    where
        Self: Sized;

    /// Converts a name of a register into a corresponding DWARF register type.
    /// Returns `None` when a register doesn't exist (e.g., a name is invalid).
    fn dwarf_for_name(name: &str) -> Option<gimli::Register>
    where
        Self: Sized;
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use x86_64::Registers as RegistersX86_64;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod x86_64 {
    use gimli::Register;
    // This struct is available only on Linux.
    use libc::user_regs_struct;

    #[derive(Copy, Clone, Debug)]
    pub struct Registers {
        regs: user_regs_struct,
    }

    impl From<user_regs_struct> for Registers {
        fn from(regs: user_regs_struct) -> Registers {
            Registers { regs }
        }
    }

    impl Into<user_regs_struct> for Registers {
        fn into(self) -> user_regs_struct {
            self.regs
        }
    }

    impl super::Registers for Registers {
        fn ip(&self) -> u64 {
            self.regs.rip
        }

        fn sp(&self) -> u64 {
            self.regs.rsp
        }

        fn bp(&self) -> Option<u64> {
            Some(self.regs.rbp)
        }

        fn set_ip(&mut self, ip: u64) {
            self.regs.rip = ip;
        }

        fn set_bp(&mut self, bp: u64) -> Option<()> {
            self.regs.rbp = bp;
            Some(())
        }

        fn set_sp(&mut self, sp: u64) {
            self.regs.rsp = sp;
        }

        fn set_reg_for_dwarf(&mut self, register: Register, val: u64) -> Option<()> {
            use gimli::X86_64;
            match register {
                X86_64::RAX => self.regs.rax = val,
                X86_64::RBX => self.regs.rbx = val,
                X86_64::RCX => self.regs.rcx = val,
                X86_64::RDX => self.regs.rdx = val,
                X86_64::RSI => self.regs.rsi = val,
                X86_64::RDI => self.regs.rdi = val,
                X86_64::RSP => self.regs.rsp = val,
                X86_64::RBP => self.regs.rbp = val,
                X86_64::R8 => self.regs.r8 = val,
                X86_64::R9 => self.regs.r9 = val,
                X86_64::R10 => self.regs.r10 = val,
                X86_64::R11 => self.regs.r11 = val,
                X86_64::R12 => self.regs.r12 = val,
                X86_64::R13 => self.regs.r13 = val,
                X86_64::R14 => self.regs.r14 = val,
                X86_64::R15 => self.regs.r15 = val,
                X86_64::CS => self.regs.cs = val,
                X86_64::SS => self.regs.ss = val,
                X86_64::DS => self.regs.ds = val,
                X86_64::GS => self.regs.gs = val,
                X86_64::ES => self.regs.es = val,
                X86_64::FS => self.regs.fs = val,
                X86_64::FS_BASE => self.regs.fs_base = val,
                X86_64::GS_BASE => self.regs.gs_base = val,
                X86_64::RFLAGS => self.regs.eflags = val,
                reg => unimplemented!("{:?}", reg), // FIXME
            }
            Some(())
        }

        fn dwarf_for_name(_name: &str) -> Option<Register> {
            unimplemented!()
        }

        fn name_for_dwarf(register: Register) -> Option<&'static str> {
            gimli::X86_64::register_name(register)
        }

        fn reg_for_dwarf(&self, register: Register) -> Option<u64> {
            use gimli::X86_64;
            match register {
                X86_64::RAX => Some(self.regs.rax),
                X86_64::RBX => Some(self.regs.rbx),
                X86_64::RCX => Some(self.regs.rcx),
                X86_64::RDX => Some(self.regs.rdx),
                X86_64::RSI => Some(self.regs.rsi),
                X86_64::RDI => Some(self.regs.rdi),
                X86_64::RSP => Some(self.regs.rsp),
                X86_64::RBP => Some(self.regs.rbp),
                X86_64::R8 => Some(self.regs.r8),
                X86_64::R9 => Some(self.regs.r9),
                X86_64::R10 => Some(self.regs.r10),
                X86_64::R11 => Some(self.regs.r11),
                X86_64::R12 => Some(self.regs.r12),
                X86_64::R13 => Some(self.regs.r13),
                X86_64::R14 => Some(self.regs.r14),
                X86_64::R15 => Some(self.regs.r15),
                X86_64::CS => Some(self.regs.cs),
                X86_64::SS => Some(self.regs.ss),
                X86_64::DS => Some(self.regs.ds),
                X86_64::GS => Some(self.regs.gs),
                X86_64::ES => Some(self.regs.es),
                X86_64::FS => Some(self.regs.fs),
                X86_64::FS_BASE => Some(self.regs.fs_base),
                X86_64::GS_BASE => Some(self.regs.gs_base),
                X86_64::RFLAGS => Some(self.regs.eflags),
                reg => unimplemented!("{:?}", reg), // FIXME
            }
        }
    }
}
