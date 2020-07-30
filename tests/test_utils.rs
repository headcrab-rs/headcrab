use std::sync::Once;

#[cfg(target_os = "linux")]
use headcrab::target::{LinuxTarget, UnixTarget};

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
    let (target, status) = LinuxTarget::launch(path).unwrap();
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
