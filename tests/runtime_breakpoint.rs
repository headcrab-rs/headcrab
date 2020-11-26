//! This is a basic test for the software breakpoints
//! Here we take a simple rust program, and instrument it using headcrab.
//! Setting breakpoints at a symbol's address, and then checking that we
//! do have the expected state once the breakpoint is hit.

mod test_utils;

#[cfg(target_os = "linux")]
use headcrab::{
    symbol::RelocatedDwarf,
    target::{Registers, UnixTarget},
    CrabResult,
};

static BIN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testees/hello");
static LOOPING_BIN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testees/loop");

// FIXME: this should be an internal impl detail
#[cfg(target_os = "macos")]
static MAC_DSYM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/testees/hello.dSYM/Contents/Resources/DWARF/hello"
);

// FIXME: Running this test just for linux because of privileges issue on macOS. Enable for everything after fixing.
#[cfg(target_os = "linux")]
#[test]
fn runtime_breakpoint() -> CrabResult<()> {
    test_utils::ensure_testees();

    let target = test_utils::launch(BIN_PATH);
    let debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;
    let main_addr = debuginfo
        .get_symbol_address("main")
        .expect("No 'main' symbol");
    let breakpoint = target
        .set_breakpoint(main_addr)
        .expect("Cannot set breakpoint");

    assert!(breakpoint.is_armed());

    // run the program
    target.unpause()?;
    // have we hit the breakpoint ?
    let ip = target.read_regs()?.ip();
    assert_eq!(ip as usize, main_addr);
    let status = target.step()?;
    assert_eq!(status, test_utils::ws_sigtrap(&target));
    assert!(breakpoint.is_armed());

    test_utils::continue_to_end(&target);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn multiple_breakpoints() -> CrabResult<()> {
    test_utils::ensure_testees();

    let target = test_utils::launch(BIN_PATH);
    let debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;
    let main_addr = debuginfo
        .get_symbol_address("main")
        .expect("No 'main' symbol");
    // set a breakpoint at main
    let breakpoint = target.set_breakpoint(main_addr)?;
    assert!(breakpoint.is_armed());
    // Test that duplicate breakpoints do no harm
    let breakpoint2 = target.set_breakpoint(main_addr)?;

    // make sure we hit the breakpoint
    let status = target.unpause()?;
    assert_eq!(status, test_utils::ws_sigtrap(&target));

    let mut regs = target.main_thread()?.read_regs()?;
    assert_eq!(regs.ip() as usize, main_addr);

    //  Let's go a few instructions back and see if disabling the breakpoint works
    regs.set_ip(regs.ip() - 3);

    target.main_thread()?.write_regs(regs)?;
    breakpoint2.disable()?;
    assert!(!breakpoint.is_armed());

    regs.set_ip(regs.ip() + 3);
    target.main_thread()?.write_regs(regs)?;

    // Same, let's check that creating a new breakpoint and unsetting it right away
    // disarms the trap
    let mut bp3 = target.set_breakpoint(main_addr + 4)?;
    bp3.set()?;
    bp3.disable()?;
    test_utils::continue_to_end(&target);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn looping_breakpoint() -> CrabResult<()> {
    test_utils::ensure_testees();

    let target = test_utils::launch(LOOPING_BIN_PATH);
    let debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;
    let bp_addr = debuginfo
        .get_symbol_address("breakpoint")
        .expect("No 'breakpoint' symbol");
    // set the breakpoint
    let breakpoint = target.set_breakpoint(bp_addr)?;
    assert!(breakpoint.is_armed());
    assert!(breakpoint.is_enabled());

    // The testee should call the `breakpoint()` function 8 times
    // make sure we hit the breakpoint each time
    for _ in 0..8 {
        let status = target.unpause()?;
        assert_eq!(status, test_utils::ws_sigtrap(&target));

        let regs = target.read_regs()?;
        assert_eq!(regs.ip() as usize, bp_addr);
        assert!(!breakpoint.is_armed());
    }
    test_utils::continue_to_end(&target);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
// Make sure that calling single_step advances the P.C by 1,
// and gives back control
fn single_step() -> CrabResult<()> {
    test_utils::ensure_testees();
    let target = test_utils::launch(BIN_PATH);
    let debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;
    let main_addr = debuginfo
        .get_symbol_address("main")
        .expect("No 'main' symbol in target program.");
    let _ = target.set_breakpoint(main_addr)?;

    // start the program
    target.unpause()?;
    // Order of instructions:
    // <main>, <main+1> <main+4>, <main+8>, <main+11>,  <main+17>
    let offsets = [0, 1, 4, 8, 11, 17];
    for offset in offsets.iter() {
        let rip = test_utils::current_ip(&target);
        assert_eq!(rip, (main_addr as u64 + offset), "Steps");
        let status = target.step()?;
        assert_eq!(status, test_utils::ws_sigtrap(&target), "status");
    }
    test_utils::continue_to_end(&target);
    Ok(())
}
