//! This is a simple test to read memory from a child process.

use headcrab::target::{read_string, read_usize};
use nix::{
    sys::ptrace,
    sys::wait::waitpid,
    unistd::{execv, fork, ForkResult},
};
use std::ffi::CString;

static BIN_PATH: &str = "./tests/hello";
const STR_ADDR: usize = 0x404028;

#[test]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    match fork()? {
        ForkResult::Parent { child, .. } => {
            let _status = waitpid(child, None);

            // Read pointer
            let str_addr = read_usize(child, STR_ADDR)?;

            // Read current value
            let rval = read_string(child, str_addr, 13)?;
            assert_eq!(rval, "Hello, world!");

            ptrace::cont(child, None)?;
        }
        ForkResult::Child => {
            ptrace::traceme()?;

            let path = CString::new(BIN_PATH)?;
            execv(&path, &[])?;
        }
    }

    Ok(())
}
