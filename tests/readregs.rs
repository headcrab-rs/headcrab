//! This is a simple test to read registers from a child process.

mod test_utils;

static BIN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testees/hello");

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn read_regs() -> headcrab::CrabResult<()> {
    use gimli::X86_64;
    use headcrab::target::Registers;

    test_utils::ensure_testees();

    let target = test_utils::launch(BIN_PATH);

    let regs = target.main_thread()?.read_regs()?;

    // Assert that the register values match the expected initial values on Linux
    assert_eq!(regs.reg_for_dwarf(X86_64::R15).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::R14).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::R13).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::R12).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::RBP).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::RBX).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::R11).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::R10).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::R9).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::R8).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::RAX).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::RCX).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::RDX).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::RSI).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::RDI).unwrap(), 0);

    // https://github.com/torvalds/linux/blob/f359287765c04711ff54fbd11645271d8e5ff763/arch/x86/entry/syscalls/syscall_64.tbl#L70
    let user_regs: libc::user_regs_struct = regs.into();

    const X86_64_SYSCALL_EXECVE: u64 = 59;
    assert_eq!(user_regs.orig_rax, X86_64_SYSCALL_EXECVE);

    //assert_eq!(regs.rip, 140188621074576); // non-deterministic
    assert_eq!(regs.reg_for_dwarf(X86_64::CS).unwrap(), 51);

    // IF=EI: interrupt enable flag = enable interrupts
    const EFLAGS_EI: u64 = 0x0200;
    assert_eq!(regs.reg_for_dwarf(X86_64::RFLAGS).unwrap(), EFLAGS_EI);

    //assert_eq!(regs.rsp, 140735406980896); // non-deterministic
    assert_eq!(regs.reg_for_dwarf(X86_64::SS).unwrap(), 43);
    assert_eq!(regs.reg_for_dwarf(X86_64::FS_BASE).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::GS_BASE).unwrap(), 0);

    assert_eq!(regs.reg_for_dwarf(X86_64::DS).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::ES).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::FS).unwrap(), 0);
    assert_eq!(regs.reg_for_dwarf(X86_64::GS).unwrap(), 0);

    test_utils::continue_to_end(&target);

    Ok(())
}
