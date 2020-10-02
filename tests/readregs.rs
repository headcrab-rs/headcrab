//! This is a simple test to read registers from a child process.

mod test_utils;

static BIN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testees/hello");

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn read_regs() -> headcrab::CrabResult<()> {
    test_utils::ensure_testees();

    let target = test_utils::launch(BIN_PATH);

    let regs = target.read_regs()?;

    // Assert that the register values match the expected initial values on Linux
    assert_eq!(regs.r15, 0);
    assert_eq!(regs.r14, 0);
    assert_eq!(regs.r13, 0);
    assert_eq!(regs.r12, 0);
    assert_eq!(regs.rbp, 0);
    assert_eq!(regs.rbx, 0);
    assert_eq!(regs.r11, 0);
    assert_eq!(regs.r10, 0);
    assert_eq!(regs.r9, 0);
    assert_eq!(regs.r8, 0);
    assert_eq!(regs.rax, 0);
    assert_eq!(regs.rcx, 0);
    assert_eq!(regs.rdx, 0);
    assert_eq!(regs.rsi, 0);
    assert_eq!(regs.rdi, 0);

    // https://github.com/torvalds/linux/blob/f359287765c04711ff54fbd11645271d8e5ff763/arch/x86/entry/syscalls/syscall_64.tbl#L70
    const X86_64_SYSCALL_EXECVE: u64 = 59;
    assert_eq!(regs.orig_rax, X86_64_SYSCALL_EXECVE);

    //assert_eq!(regs.rip, 140188621074576); // non-deterministic
    assert_eq!(regs.cs, 51);

    // IF=EI: interrupt enable flag = enable interrupts
    const EFLAGS_EI: u64 = 0x0200;
    assert_eq!(regs.eflags, EFLAGS_EI);

    //assert_eq!(regs.rsp, 140735406980896); // non-deterministic
    assert_eq!(regs.ss, 43);
    assert_eq!(regs.fs_base, 0);
    assert_eq!(regs.gs_base, 0);
    assert_eq!(regs.ds, 0);
    assert_eq!(regs.es, 0);
    assert_eq!(regs.fs, 0);
    assert_eq!(regs.gs, 0);

    test_utils::continue_to_end(&target);

    Ok(())
}
