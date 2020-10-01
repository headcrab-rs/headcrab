//! This is a simple test to get the source line from a child process.

mod test_utils;

#[cfg(target_os = "linux")]
use headcrab::{symbol::RelocatedDwarf, target::UnixTarget, CrabResult};

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
fn source() -> CrabResult<()> {
    test_utils::ensure_testees();

    let target = test_utils::launch(BIN_PATH);
    let debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;

    test_utils::patch_breakpoint(&target, &debuginfo);

    // First breakpoint
    target.unpause()?;
    let ip = target.read_regs()?.rip;
    println!("{:08x}", ip);
    assert_eq!(
        debuginfo.get_address_symbol_name(ip as usize).as_deref(),
        Some("breakpoint")
    );

    let source_location = debuginfo.source_location(ip as usize)?.unwrap();
    assert!(source_location.0.ends_with("x86/sse2.rs"));

    test_utils::continue_to_end(&target);

    Ok(())
}
