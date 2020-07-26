//! This is a simple test to attach to already running debugee process

use nix::unistd::{execv, fork, ForkResult};
use std::ffi::CString;

mod test_utils;

#[cfg(target_os = "linux")]
use headcrab::{symbol::Dwarf, target::LinuxTarget};

static BIN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testees/longer_hello");

// Ignoring because most linux distributions have attaching to a running process disabled.
// To run the test it either requires root privilages or CAP_SYS_PTRACE capability.
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
            use std::{thread, time};
            thread::sleep(time::Duration::from_millis(50));

            let target = LinuxTarget::attach(child)?;

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
