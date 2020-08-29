//! Interfaces related to registers reading & writing.

/// Trait that can be used to read & write the target's registers.
pub trait Registers {
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
    fn name_for_dwarf(reg: gimli::Register) -> Option<&'static str>;

    /// Converts a name of a register into a corresponding DWARF register type.
    /// Returns `None` when a register doesn't exist (e.g., a name is invalid).
    fn dwarf_for_name(name: &str) -> Option<gimli::Register>;
}
