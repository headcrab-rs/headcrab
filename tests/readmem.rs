//! This is a simple test to read memory from a child process.

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
fn read_memory() -> CrabResult<()> {
    test_utils::ensure_testees();

    let target = test_utils::launch(BIN_PATH);

    println!("{:#?}", target.memory_maps()?);
    let debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;

    // Test that `a_function` resolves to a function.
    let breakpoint_addr = debuginfo.get_symbol_address("breakpoint");
    assert!(breakpoint_addr.is_some());

    // Test that the address of `a_function` and one byte further both resolves back to that symbol.
    assert_eq!(
        debuginfo
            .get_address_symbol_name(breakpoint_addr.unwrap())
            .as_ref()
            .map(|name| &**name),
        Some("breakpoint")
    );
    assert_eq!(
        debuginfo
            .get_address_symbol_name(breakpoint_addr.unwrap() + 1)
            .as_ref()
            .map(|name| &**name),
        Some("breakpoint")
    );

    // Test that invalid addresses don't resolve to a symbol.
    assert_eq!(
        debuginfo
            .get_address_symbol_name(0)
            .as_ref()
            .map(|name| &**name),
        None,
    );

    assert_eq!(
        debuginfo
            .get_address_symbol_name(0xffff_ffff_ffff_ffff)
            .as_ref()
            .map(|name| &**name),
        None,
    );

    test_utils::patch_breakpoint(&target, &debuginfo);

    // Wait for the breakpoint to get hit.
    target.unpause().unwrap();

    let ip = target.read_regs().unwrap().ip();
    assert_eq!(
        debuginfo.get_address_symbol_name(ip as usize).as_deref(),
        Some("breakpoint")
    );

    let str_addr = debuginfo
        .get_var_address("STATICVAR")?
        .expect("Expected static var has not been found in the target binary");

    // Read pointer
    let mut ptr_addr: usize = 0;
    unsafe {
        target.read().read(&mut ptr_addr, str_addr).apply()?;
    }

    // Read current value
    let mut rval = [0u8; 13];
    unsafe {
        target.read().read(&mut rval, ptr_addr).apply()?;
    }

    assert_eq!(&rval, b"Hello, world!");

    test_utils::continue_to_end(&target);

    Ok(())
}
