//! This is a simple test for waiting for a fixed breakpoint in a child process.
//! Here the testee has hardcoded INT3 instructions that should trigger breaks
//! so that headcrab can gain control at certain key points of execution.

mod test_utils;

#[cfg(target_os = "linux")]
use headcrab::{symbol::RelocatedDwarf, target::UnixTarget, CrabResult};

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
fn fixed_breakpoint() -> CrabResult<()> {
    test_utils::ensure_testees();

    let target = test_utils::launch(BIN_PATH);

    let debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;

    // First breakpoint
    target.unpause()?;
    let ip = target.read_regs()?.ip();
    assert_eq!(
        debuginfo.get_address_symbol_name(ip as usize).as_deref(),
        Some("main")
    );

    // Second breakpoint
    target.unpause()?;
    let ip = target.read_regs()?.ip();
    assert_eq!(
        debuginfo.get_address_symbol_name(ip as usize).as_deref(),
        Some("main")
    );

    test_utils::continue_to_end(&target);

    Ok(())
}
