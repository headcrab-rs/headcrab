//! This is a simple test to read memory from a child process.

mod test_utils;

#[cfg(target_os = "linux")]
use headcrab::{symbol::RelocatedDwarf, target::UnixTarget, CrabResult};

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
fn unwind_stack() -> CrabResult<()> {
    test_utils::ensure_testees();

    let target = test_utils::launch(BIN_PATH);

    println!("{:#?}", target.memory_maps()?);
    let debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;

    test_utils::patch_breakpoint(&target, &debuginfo);

    // Wait for the breakpoint to get hit.
    target.unpause().unwrap();

    let regs = target.read_regs().unwrap();

    // Read stack
    let mut stack: [usize; 256] = [0; 256];
    unsafe {
        target.read().read(&mut stack, regs.rsp as usize).apply()?;
    }

    let call_stack: Vec<_> =
        headcrab::symbol::unwind::naive_unwinder(&debuginfo, &stack[..], regs.rip as usize)
            .map(|func| {
                debuginfo
                    .get_address_symbol_name(func)
                    .unwrap_or_else(|| "<unknown>".to_string())
            })
            .collect();

    let expected = &["breakpoint", "_ZN5hello4main17h"];

    test_backtrace(call_stack, expected);

    let call_stack: Vec<_> = headcrab::symbol::unwind::frame_pointer_unwinder(
        &debuginfo,
        &stack[..],
        regs.rip as usize,
        regs.rsp as usize,
        regs.rbp as usize,
    )
    .map(|func| {
        debuginfo
            .get_address_symbol_name(func)
            .unwrap_or_else(|| "<unknown>".to_string())
    })
    .collect();

    println!("{:?}", call_stack);

    let expected = &["breakpoint", "_ZN5hello4main17h"];

    test_backtrace(call_stack, expected);

    target.unpause()?;

    Ok(())
}

fn test_backtrace(real: Vec<String>, expected: &[&str]) {
    println!("\nReal: {:?}\nExpected: {:?}", real, expected);
    let mut real = real.into_iter();
    let mut expected = expected.iter();
    loop {
        match (real.next(), expected.next()) {
            (Some(real), Some(expected)) => assert!(
                real.starts_with(expected),
                "`{}` doesn't start with `{}`",
                real,
                expected
            ),
            (Some(_real), None) => break, // Ignore extra frames
            (None, Some(expected)) => panic!("Missing frame {:?}", expected),
            (None, None) => break,
        }
    }
}
