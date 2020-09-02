//! This is a basic test for the software breakpoints

mod test_utils;

#[cfg(target_os = "linux")]
use headcrab::{symbol::RelocatedDwarf, target::UnixTarget};

static BIN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testees/hello");

// FIXME: this should be an internal impl detail
#[cfg(target_os = "macos")]
static MAC_DSYM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/testees/hello.dSYM/Contents/Resources/DWARF/hello"
);

// FIXME: Running this test just for linux because of privileges issue on macOS. Enable for everything after fixing.
#[cfg(target_os = "linux")]
#[test]
fn runtime_breakpoint() -> Result<(), Box<dyn std::error::Error>> {
    test_utils::ensure_testees();

    let mut target = test_utils::launch(BIN_PATH);
    let debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;
    let main_addr = debuginfo
        .get_symbol_address("main")
        .expect("No 'main' symbol");
    let bp1 = headcrab::target::Breakpoint::at_addr(main_addr)?;
    target
        .set_breakpoint(bp1)
        .expect("Cannot set first breakpoint");

    // run the program
    target.unpause()?;
    let ip = target.read_regs()?.rip;

    // have we hit the breakpoint ?
    assert_eq!(ip as usize, main_addr);

    test_utils::continue_to_end(&target);
    Ok(())
}
