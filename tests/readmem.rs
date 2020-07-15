//! This is a simple test to read memory from a child process.

use headcrab::{symbol::Dwarf, target::Target};

static BIN_PATH: &str = "./tests/hello";

// FIXME: this should be an internal impl detail
#[cfg(target_os = "macos")]
static MAC_DSYM_PATH: &str = "./tests/hello.dSYM/Contents/Resources/DWARF/hello";

#[test]
fn read_memory() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    let debuginfo = Dwarf::new(MAC_DSYM_PATH)?;
    #[cfg(not(target_os = "macos"))]
    let debuginfo = Dwarf::new(BIN_PATH)?;

    let str_addr = debuginfo
        .get_var_address("STATICVAR")
        .expect("Expected static var has not been found in the target binary");

    let target = Target::launch(BIN_PATH)?;

    // Read pointer
    let ptr_addr = target.read_usize(str_addr)?;

    // Read current value
    let rval = target.read_string(ptr_addr, 13)?;
    assert_eq!(rval, "Hello, world!");

    target.unpause()?;

    Ok(())
}
