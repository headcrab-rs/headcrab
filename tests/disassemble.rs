//! This is a simple test to disassemble bytes from a child process.

mod test_utils;

#[cfg(target_os = "linux")]
use headcrab::{symbol::RelocatedDwarf, target::UnixTarget};

static BIN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testees/known_asm");

// FIXME: this should be an internal impl detail
#[cfg(target_os = "macos")]
static MAC_DSYM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/testees/known_asm.dSYM/Contents/Resources/DWARF/known_asm"
);

// FIXME: Running this test just for linux because of privileges issue on macOS. Enable for everything after fixing.
#[cfg(target_os = "linux")]
#[test]
fn disassemble() -> headcrab::CrabResult<()> {
    test_utils::ensure_testees();

    let target = test_utils::launch(BIN_PATH);
    let debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;

    // First breakpoint
    target.unpause()?;
    let ip = target.read_regs()?.ip();
    println!("{:08x}", ip);
    assert_eq!(
        debuginfo.get_address_symbol_name(ip as usize).as_deref(),
        Some("main")
    );

    dbg!();
    let mut code = [0; 10];
    unsafe {
        target.read().read(&mut code, ip as usize).apply()?;
    }
    dbg!();

    let disassembly =
        headcrab::symbol::DisassemblySource::default().source_snippet(&code, ip, false)?;
    assert_eq!(
        disassembly,
        "nop \n\
int3 \n\
movq $0, %rax\n\
retq \n"
    );

    // Second breakpoint
    target.unpause()?;

    test_utils::continue_to_end(&target);

    Ok(())
}
