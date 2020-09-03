//! This is a basic test for the software breakpoints
//! Here we take a simple rust program, and instrument it using headcrab.
//! Setting breakpoints at a symbol's address, and then checking that we
//! do have the expected state once the breakpoint is hit.

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

    let target = test_utils::launch(BIN_PATH);
    let debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;
    let main_addr = debuginfo
        .get_symbol_address("main")
        .expect("No 'main' symbol");
    let _breakpoint = target
        .register_breakpoint(main_addr)
        .expect("Cannot set breakpoint");

    //assert!(breakpoint.is_active());

    // run the program
    target.unpause()?;
    // have we hit the breakpoint ?
    let ip = target.read_regs()?.rip;
    assert_eq!(ip as usize, main_addr);
    //assert!(breakpoint.is_active());

    test_utils::continue_to_end(&target);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn multiple_breakpoints() -> Result<(), Box<dyn std::error::Error>> {
    test_utils::ensure_testees();

    let target = test_utils::launch(BIN_PATH);
    let debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;
    let main_addr = debuginfo
        .get_symbol_address("main")
        .expect("No 'main' symbol");
    // set a breakpoint at main
    let breakpoint = target.register_breakpoint(main_addr)?;
    assert!(breakpoint.is_active());
    // Test that duplicate breakpoints do no harm
    let breakpoint2 = target.register_breakpoint(main_addr)?;

    // make sure we hit the breakpoint
    let status = target.unpause()?;
    assert_eq!(
        status,
        nix::sys::wait::WaitStatus::Stopped(target.pid(), nix::sys::signal::SIGTRAP)
    );
    let mut regs = target.read_regs()?;
    assert_eq!(regs.rip as usize, main_addr);

    //  Let's go a few instructions back and see if disabling the breakpoint works
    regs.rip -= 3;
    target.write_regs(regs)?;
    breakpoint2.restore()?;

    // Same, let's check that creating a new breakpoint and unsetting it right away
    // disarms the trap
    let mut bp3 = target.register_breakpoint(main_addr + 4)?;
    bp3.set()?;
    bp3.restore()?;
    test_utils::continue_to_end(&target);
    Ok(())
}
