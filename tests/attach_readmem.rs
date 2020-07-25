//! This is a simple test to attach to already running debugee process

use nix::{
    sys::wait::waitpid,
    unistd::{execv, fork, ForkResult, Pid},
};
use std::ffi::CString;

mod test_utils;

#[cfg(target_os = "linux")]
use headcrab::{symbol::Dwarf, target::LinuxTarget, target::UnixTarget};

static BIN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testees/hello");

// Ignoring because most linux distributions have attaching to a running process disabled
#[ignore]
#[cfg(target_os = "linux")]
#[test]
fn attach_readmem() -> Result<(), Box<dyn std::error::Error>> {
    test_utils::ensure_testees();

    let debuginfo = Dwarf::new(BIN_PATH)?;

    let str_addr = debuginfo
        .get_var_address("STATICVAR")
        .expect("Expected static var has not been found in the target binary");

    match fork()? {
        ForkResult::Parent { child, .. } => {
            let target = LinuxTarget::attach(child)?;

            // Read pointer
            let mut ptr_addr: usize = 0;
            unsafe {
                target.read().read(&mut ptr_addr, str_addr).apply()?;
            }

            // // Read current value
            // let mut rval = [0u8; 13];
            // unsafe {
            //     target.read().read(&mut rval, ptr_addr).apply()?;
            // }

            // assert_eq!(&rval, b"Hello, world!");

            Ok(())
        }
        ForkResult::Child => {
            let path = CString::new(BIN_PATH)?;
            execv(&path, &[])?;

            // execv replaces the process image, so this place in code will not be reached.
            unreachable!();
        }
    }
}
