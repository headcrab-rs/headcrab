//! Tests we can inject code in a process calling `abort()`.

mod test_utils;

#[cfg(target_os = "linux")]
use cranelift_module::FuncId;
#[cfg(target_os = "linux")]
use headcrab::{symbol::RelocatedDwarf, target::UnixTarget};
#[cfg(target_os = "linux")]
use headcrab_inject::InjectionModule;
#[cfg(target_os = "linux")]
use nix::sys::{signal::Signal, wait::WaitStatus};

static BIN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testees/hello");

// FIXME: Running this test just for linux because of privileges issue on macOS. Enable for everything after fixing.
#[cfg(target_os = "linux")]
#[test]
fn inject_abort() -> headcrab::CrabResult<()> {
    test_utils::ensure_testees();

    let target = test_utils::launch(BIN_PATH);

    let mut debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;

    test_utils::patch_breakpoint(&target, &debuginfo);

    target.unpause()?;

    debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;
    let mut inj_module = InjectionModule::new(&target)?;
    let abort_function = debuginfo.get_symbol_address("abort").unwrap() as u64;
    println!("exit fn ptr: {:016x}", abort_function);
    inj_module.define_function(FuncId::from_u32(0), abort_function);

    let isa = headcrab_inject::target_isa();

    let functions = cranelift_reader::parse_functions(
        r#"
        function u0:1() system_v {
            sig0 = () system_v
            fn0 = u0:0 sig0

        block0:
            call fn0()
            return
        }"#,
    )
    .unwrap();
    let mut ctx = cranelift_codegen::Context::new();
    for func in functions {
        ctx.clear();
        ctx.func = func;
        inj_module.compile_clif_code(&*isa, &mut ctx)?;
    }

    let run_function = inj_module.lookup_function(FuncId::from_u32(1));
    let stack_region = inj_module.inj_ctx().allocate_readwrite(0x1000, Some(16))?;
    println!(
        "run function: 0x{:016x} stack: 0x{:016x}",
        run_function, stack_region
    );

    let orig_regs = inj_module.target().read_regs()?;
    println!("orig rip: {:016x}", orig_regs.rip);
    let regs = libc::user_regs_struct {
        rip: run_function,
        rsp: stack_region + 0x1000,
        ..orig_regs
    };
    inj_module.target().write_regs(regs)?;
    let res = inj_module.target().unpause()?;
    if let WaitStatus::Stopped(_, Signal::SIGABRT) = res {
    } else {
        println!("rip: {:016x}", inj_module.target().read_regs()?.rip);
        panic!("{:?}", res);
    }

    Ok(())
}
