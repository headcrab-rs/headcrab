//! This is a simple test to read memory from a child process.

use headcrab::target::Target;

static BIN_PATH: &str = "./tests/hello";
const STR_ADDR: usize = 0x404028;

#[test]
fn read_memory() -> Result<(), Box<dyn std::error::Error>> {
    let target = Target::launch(BIN_PATH)?;

    // Read pointer
    let str_addr = target.read_usize(STR_ADDR)?;

    // Read current value
    let rval = target.read_string(str_addr, 13)?;
    assert_eq!(rval, "Hello, world!");

    target.unpause()?;

    Ok(())
}
