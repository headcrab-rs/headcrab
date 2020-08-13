//! This is a simple test for reading the value of locals from a child process.

mod test_utils;

#[cfg(target_os = "linux")]
use headcrab::{
    symbol::{LocalValue, RelocatedDwarf},
    target::UnixTarget,
};

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
fn read_locals() -> Result<(), Box<dyn std::error::Error>> {
    test_utils::ensure_testees();

    let target = test_utils::launch(BIN_PATH);

    let debuginfo = RelocatedDwarf::from_maps(&target.memory_maps()?)?;

    // Breakpoint
    test_utils::patch_breakpoint(&target, &debuginfo);
    target.unpause()?;
    let ip = target.read_regs()?.rip;
    assert_eq!(
        debuginfo.get_address_symbol_name(ip as usize).as_deref(),
        Some("breakpoint")
    );

    while debuginfo
        .get_address_symbol_name(target.read_regs()?.rip as usize)
        .as_deref()
        == Some("breakpoint")
    {
        target.step()?;
    }

    let regs = target.read_regs()?;
    let ip = regs.rip;
    assert!(debuginfo
        .get_address_symbol_name(ip as usize)
        .as_deref()
        .unwrap()
        .starts_with("_ZN5hello4main17h"));

    let () = debuginfo
        .with_addr_frames(ip as usize, |ip, mut frames| {
            let mut first_frame = true;
            while let Some(frame) = frames.next()? {
                if !first_frame {
                    panic!("Function inlined into main");
                }

                first_frame = false;

                let (_dwarf, unit, dw_die_offset) = frame
                    .function_debuginfo()
                    .ok_or_else(|| "No dwarf debuginfo for function".to_owned())?;

                let frame_base = if let Some(frame_base) =
                    unit.entry(dw_die_offset)?.attr(gimli::DW_AT_frame_base)?
                {
                    let frame_base = frame_base.exprloc_value().unwrap();
                    let res = headcrab::symbol::dwarf_utils::evaluate_expression(
                        unit,
                        frame_base,
                        None,
                        get_linux_x86_64_reg(regs),
                    )?;
                    assert_eq!(res.len(), 1);
                    assert_eq!(res[0].bit_offset, None);
                    assert_eq!(res[0].size_in_bits, None);
                    Some(match res[0].location {
                        gimli::Location::Register {
                            register: gimli::X86_64::RBP,
                        } => regs.rbp,
                        ref loc => unimplemented!("{:?}", loc), // FIXME
                    })
                } else {
                    None
                };

                frame.each_argument::<Box<dyn std::error::Error>, _>(ip as u64, |local| {
                    panic!("Main should not have any arguments, but it has {:?}", local);
                })?;

                frame.each_local::<Box<dyn std::error::Error>, _>(ip as u64, |local| {
                    match local.name().unwrap().unwrap() {
                        "var" => {
                            let expr = match local.value() {
                                LocalValue::Expr(expr) => expr,
                                value => panic!("{:?}", value),
                            };
                            let res = headcrab::symbol::dwarf_utils::evaluate_expression(
                                unit,
                                expr.clone(),
                                frame_base,
                                get_linux_x86_64_reg(regs),
                            )?;
                            assert_eq!(res.len(), 1);
                            assert_eq!(res[0].bit_offset, None);
                            assert_eq!(res[0].size_in_bits, None);
                            match res[0].location {
                                gimli::Location::Value { value } => match value {
                                    gimli::Value::Generic(val) => assert_eq!(val, 42),
                                    val => panic!("{:?}", val),
                                },
                                ref loc => panic!("{:?}", loc),
                            }
                        }
                        "reg_var" => match local.value() {
                            LocalValue::Const(43) => {}
                            val => panic!("{:?}", val),
                        },
                        name => panic!("{}", name),
                    }

                    Ok(())
                })?;
            }
            Ok(())
        })?
        .expect("No frames found");

    test_utils::continue_to_end(&target);

    Ok(())
}

fn get_linux_x86_64_reg(
    regs: libc::user_regs_struct,
) -> impl Fn(gimli::Register, gimli::ValueType) -> gimli::Value {
    move |reg, ty| {
        let val = match reg {
            gimli::X86_64::RAX => regs.rax,
            gimli::X86_64::RBX => regs.rbx,
            gimli::X86_64::RDI => regs.rdi,
            gimli::X86_64::RBP => regs.rbp,
            reg => unimplemented!("{:?}", reg), // FIXME
        };
        match ty {
            gimli::ValueType::Generic => gimli::Value::Generic(val),
            gimli::ValueType::U64 => gimli::Value::U64(val),
            _ => unimplemented!(),
        }
    }
}
