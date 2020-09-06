use cranelift_codegen::{binemit, ir, isa, settings};
use headcrab::target::{LinuxTarget, UnixTarget};
use std::error::Error;

#[derive(Debug)]
struct RelocEntry {
    offset: binemit::CodeOffset,
    reloc: binemit::Reloc,
    name: ir::ExternalName,
    addend: binemit::Addend,
}

#[derive(Default)]
struct VecRelocSink(Vec<RelocEntry>);

impl binemit::RelocSink for VecRelocSink {
    fn reloc_block(&mut self, _: binemit::CodeOffset, _: binemit::Reloc, _: binemit::CodeOffset) {
        todo!()
    }
    fn reloc_external(
        &mut self,
        offset: binemit::CodeOffset,
        _: ir::SourceLoc,
        reloc: binemit::Reloc,
        name: &ir::ExternalName,
        addend: binemit::Addend,
    ) {
        self.0.push(RelocEntry {
            offset,
            reloc,
            name: name.clone(),
            addend,
        });
    }
    fn reloc_constant(&mut self, _: binemit::CodeOffset, _: binemit::Reloc, _: ir::ConstantOffset) {
        todo!()
    }
    fn reloc_jt(&mut self, _: binemit::CodeOffset, _: binemit::Reloc, _: ir::entities::JumpTable) {
        todo!()
    }
}

pub struct CompiledInjection {
    code_region: u64,
    rodata_region: u64,
}

pub fn compile_clif_code(
    remote: &LinuxTarget,
    code: &str,
    puts_addr: u64,
) -> Result<CompiledInjection, Box<dyn Error>> {
    let functions = cranelift_reader::parse_functions(code).unwrap();
    assert!(functions.len() == 1);
    println!("{}", functions[0]);

    let flags_builder = settings::builder();
    let flags = settings::Flags::new(flags_builder);
    let isa = isa::lookup("x86_64".parse().unwrap())
        .unwrap()
        .finish(flags);

    let mut code_mem = Vec::new();
    let mut relocs = VecRelocSink::default();

    let mut ctx = cranelift_codegen::Context::new();
    ctx.func = functions.into_iter().next().unwrap();
    ctx.compile_and_emit(
        &*isa,
        &mut code_mem,
        &mut relocs,
        &mut binemit::NullTrapSink {},
        &mut binemit::NullStackmapSink {},
    )
    .unwrap();
    println!("{}", ctx.func);
    println!("{:?}", relocs.0);

    let code_region = remote.mmap(
        0 as *mut _,
        code_mem.len(),
        libc::PROT_READ | libc::PROT_EXEC,
        libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
        0,
        0,
    )?;
    let rodata_region = remote.mmap(
        0 as *mut _,
        "Hello World from injected code!\n\0".len(),
        libc::PROT_READ,
        libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
        0,
        0,
    )?;

    for reloc_entry in relocs.0 {
        let sym = match reloc_entry.name {
            ir::ExternalName::User {
                namespace: 0,
                index: 0,
            } => {
                // puts
                puts_addr
            }
            ir::ExternalName::User {
                namespace: 1,
                index: 0,
            } => rodata_region,
            _ => todo!("{:?}", reloc_entry.name),
        };
        match reloc_entry.reloc {
            binemit::Reloc::Abs8 => {
                code_mem[reloc_entry.offset as usize..reloc_entry.offset as usize + 8]
                    .copy_from_slice(&u64::to_ne_bytes((sym as i64 + reloc_entry.addend) as u64));
            }
            _ => todo!("reloc kind for {:?}", reloc_entry),
        }
    }

    remote
        .write()
        .write_slice(&code_mem, code_region as usize)
        .write_slice(
            "Hello World from injected code!\n\0".as_bytes(),
            rodata_region as usize,
        )
        .apply()?;

    Ok(CompiledInjection {
        code_region,
        rodata_region,
    })
}

pub fn inject_clif_code(remote: &LinuxTarget, puts_addr: u64) -> Result<(), Box<dyn Error>> {
    let CompiledInjection {
        code_region,
        rodata_region: _,
    } = compile_clif_code(
        remote,
        r#"
    target x86_64-unknown-linux-gnu haswell

    function u0:0() system_v {
        gv0 = symbol colocated u1:0
        sig0 = (i64) system_v
        fn0 = u0:0 sig0

    block0:
        v0 = global_value.i64 gv0
        call fn0(v0)
        return
    }
    "#,
        puts_addr,
    )?;

    let stack_region = remote.mmap(
        0 as *mut _,
        0x1000,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
        0,
        0,
    )?;
    println!(
        "code: 0x{:016x} stack: 0x{:016x}",
        code_region, stack_region
    );

    let orig_regs = remote.read_regs()?;
    println!("{:?}", orig_regs);
    let regs = libc::user_regs_struct {
        rip: code_region,
        rsp: stack_region + 0x1000,
        ..orig_regs
    };
    remote.write_regs(regs)?;
    println!("{:?}", remote.unpause()?);
    println!("{:016x}", remote.read_regs()?.rip);
    remote.write_regs(orig_regs)?;

    Ok(())
}
