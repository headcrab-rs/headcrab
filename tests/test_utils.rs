use std::sync::Once;

#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
use headcrab::{
    symbol::RelocatedDwarf,
    target::{LinuxTarget, UnixTarget},
};

static TESTEES_BUILD: Once = Once::new();

/// Ensure that all testees are built.
pub fn ensure_testees() {
    TESTEES_BUILD.call_once(|| {
        let status = std::process::Command::new("make")
            .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testees"))
            .spawn()
            .unwrap()
            .wait()
            .unwrap();
        assert!(status.success());
    });
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn launch(path: &str) -> LinuxTarget {
    let (target, status) = LinuxTarget::launch(Path::new(path)).unwrap();
    match status {
        nix::sys::wait::WaitStatus::Stopped(_, nix::sys::signal::SIGTRAP) => {}
        _ => panic!("Status: {:?}", status),
    }
    target
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn continue_to_end(target: &LinuxTarget) {
    match target.unpause().unwrap() {
        nix::sys::wait::WaitStatus::Exited(_, 0) => {}
        status => panic!("Status: {:?}", status),
    }
}

/// Turn the `pause` instruction inside the `breakpoint` function into a breakpoint.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn patch_breakpoint(target: &LinuxTarget, debuginfo: &RelocatedDwarf) {
    // Get the address of the `breakpoint` function.
    let breakpoint_addr = debuginfo.get_symbol_address("breakpoint").unwrap() + 4 /* prologue */;
    // Write breakpoint to the `breakpoint` function.
    let mut pause_inst = 0 as libc::c_ulong;
    unsafe {
        target
            .read()
            .read(&mut pause_inst, breakpoint_addr)
            .apply()
            .unwrap();
    }
    // pause (rep nop); ...
    assert_eq!(&pause_inst.to_ne_bytes()[0..2], &[0xf3, 0x90]);
    let mut breakpoint_inst = pause_inst.to_ne_bytes();
    // int3; nop; ...
    breakpoint_inst[0] = 0xcc;
    nix::sys::ptrace::write(
        target.pid(),
        breakpoint_addr as *mut _,
        libc::c_ulong::from_ne_bytes(breakpoint_inst) as *mut _,
    )
    .unwrap();
}
