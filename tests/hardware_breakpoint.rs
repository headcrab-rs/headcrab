//! This is a simple test to running a syscall in a child process.

mod test_utils;

#[cfg(target_os = "linux")]
use headcrab::{symbol::RelocatedDwarf, target::UnixTarget};

static BIN_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/testees/hardware_breakpoint"
);

// FIXME: Running this test just for linux because of privileges issue on macOS. Enable for everything after fixing.
#[cfg(target_os = "linux")]
#[test]
fn hardware_breakpoint() -> Result<(), Box<dyn std::error::Error>> {
    use headcrab::target::{WatchSize, Watchpoint, WatchpointType};

    test_utils::ensure_testees();

    let mut target = test_utils::launch(BIN_PATH);

    let debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;

    let var_addr = debuginfo.get_symbol_address("STATICVAR");
    assert!(var_addr.is_some());

    target.set_watchpoint(Watchpoint {
        addr: var_addr.unwrap(),
        typ: WatchpointType::Write,
        size: WatchSize::_1,
    })?;

    target.unpause()?;

    target.unpause()?;

    Ok(())
}
