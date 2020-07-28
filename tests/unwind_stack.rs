//! This is a simple test to read memory from a child process.

mod test_utils;

#[cfg(target_os = "linux")]
use headcrab::{symbol::RelocatedDwarf, target::LinuxTarget, target::UnixTarget};

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
fn read_memory() -> Result<(), Box<dyn std::error::Error>> {
    test_utils::ensure_testees();

    let target = test_utils::launch(BIN_PATH);

    println!("{:#?}", target.memory_maps()?);
    let debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;

    test_utils::patch_breakpoint(&target, &debuginfo);

    // Wait for the breakpoint to get hit.
    target.unpause().unwrap();

    let sp = target.read_regs().unwrap().rsp;

    // Read stack
    let mut stack: [usize; 1024] = [0; 1024];
    unsafe {
        target.read().read(&mut stack, sp as usize).apply()?;
    }

    for func in headcrab::symbol::unwind::naive_unwinder(&debuginfo, &stack[..]) {
        println!(
            "{:016x} {}",
            func,
            debuginfo
                .get_address_symbol_name(func)
                .as_deref()
                .unwrap_or("<unknown>")
        );
    }

    let call_stack: Vec<_> = headcrab::symbol::unwind::naive_unwinder(&debuginfo, &stack[..])
        .map(|func| {
            debuginfo
                .get_address_symbol_name(func)
                .unwrap_or_else(|| "<unknown>".to_string())
        })
        .collect();

    let expected = &[
        "_ZN5hello4main17h",
        "_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h",
        "_ZN3std2rt19lang_start_internal17h",
        "_dl_rtld_di_serinfo",
        "_start",
        "_start",
        "main",
        "_ZN5hello4main17h",
        "__libc_csu_init",
        "main",
        "_start",
        "_dl_rtld_di_serinfo",
        "_start",
        "_start",
        "_start",
    ];

    for (real, expected) in call_stack.into_iter().zip(expected) {
        assert!(real.starts_with(expected), "`{}` doesn't start with `{}`", real, expected);
    }

    target.unpause()?;

    Ok(())
}
