use std::{collections::HashMap, error::Error};

use cranelift_codegen::{
    binemit, ir,
    isa::{self, TargetIsa},
    settings::{self, Configurable},
    Context,
};
use cranelift_module::{DataId, FuncId, FuncOrDataId};
use headcrab::target::{LinuxTarget, UnixTarget};

mod memory;

pub use memory::Memory;

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

// FIXME unmap memory when done
pub struct InjectionContext<'a> {
    target: &'a LinuxTarget,
    code: Memory,
    readonly: Memory,
    readwrite: Memory,
    functions: HashMap<FuncId, u64>,
    data_objects: HashMap<DataId, u64>,
    breakpoint_trap: u64,
}

impl<'a> InjectionContext<'a> {
    pub fn new(target: &'a LinuxTarget) -> Result<Self, Box<dyn Error>> {
        let mut inj_ctx = Self {
            target,
            code: Memory::new_executable(),
            readonly: Memory::new_readonly(),
            readwrite: Memory::new_writable(),
            functions: HashMap::new(),
            data_objects: HashMap::new(),
            breakpoint_trap: 0,
        };

        inj_ctx.breakpoint_trap = inj_ctx.code.allocate(target, 1, 8)?;
        inj_ctx
            .target
            .write()
            .write(&0xcc, inj_ctx.breakpoint_trap as usize)
            .apply()?;

        Ok(inj_ctx)
    }

    pub fn target(&self) -> &LinuxTarget {
        self.target
    }

    pub fn allocate_code(&mut self, size: u64) -> Result<u64, Box<dyn Error>> {
        self.code.allocate(self.target, size, 8)
    }

    pub fn allocate_readonly(&mut self, size: u64) -> Result<u64, Box<dyn Error>> {
        self.readonly.allocate(self.target, size, 8)
    }

    pub fn allocate_readwrite(&mut self, size: u64) -> Result<u64, Box<dyn Error>> {
        self.readwrite.allocate(self.target, size, 8)
    }

    pub fn define_function(&mut self, func_id: FuncId, addr: u64) {
        assert!(self.functions.insert(func_id, addr).is_none());
    }

    pub fn lookup_function(&self, func_id: FuncId) -> u64 {
        self.functions[&func_id]
    }

    pub fn define_data_object(&mut self, data_id: DataId, addr: u64) {
        assert!(self.data_objects.insert(data_id, addr).is_none());
    }

    pub fn lookup_data_object(&self, data_id: DataId) -> u64 {
        self.data_objects[&data_id]
    }
}

pub fn compile_clif_code(
    inj_ctx: &mut InjectionContext,
    isa: &dyn TargetIsa,
    ctx: &mut Context,
) -> Result<(), Box<dyn Error>> {
    let mut code_mem = Vec::new();
    let mut relocs = VecRelocSink::default();

    ctx.compile_and_emit(
        isa,
        &mut code_mem,
        &mut relocs,
        &mut binemit::NullTrapSink {},
        &mut binemit::NullStackmapSink {},
    )
    .unwrap();

    let code_region = inj_ctx.allocate_code(code_mem.len() as u64)?;

    for reloc_entry in relocs.0.drain(..) {
        let sym = match reloc_entry.name {
            ir::ExternalName::User {
                namespace: 0,
                index,
            } => inj_ctx.lookup_function(FuncId::from_u32(index)),
            ir::ExternalName::User {
                namespace: 1,
                index,
            } => inj_ctx.lookup_data_object(DataId::from_u32(index)),
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

    inj_ctx
        .target
        .write()
        .write_slice(&code_mem, code_region as usize)
        .apply()?;

    inj_ctx.define_function(
        match ctx.func.name {
            ir::ExternalName::User { namespace, index } => {
                assert_eq!(namespace, 0);
                FuncId::from_u32(index)
            }
            ir::ExternalName::TestCase {
                length: _,
                ascii: _,
            } => todo!(),
            ir::ExternalName::LibCall(_) => panic!("Can't define libcall"),
        },
        code_region,
    );

    Ok(())
}

fn parse_func_or_data(s: &str) -> FuncOrDataId {
    let (kind, index) = s.split_at(4);
    let index: u32 = index.parse().unwrap();

    match kind {
        "func" => FuncOrDataId::Func(FuncId::from_u32(index)),
        "data" => FuncOrDataId::Data(DataId::from_u32(index)),
        _ => panic!("`Unknown kind {}`", kind),
    }
}

pub fn inject_clif_code(
    remote: &LinuxTarget,
    lookup_symbol: &dyn Fn(&str) -> u64,
    code: &str,
) -> Result<(), Box<dyn Error>> {
    let mut inj_ctx = InjectionContext::new(remote)?;
    let mut run_function = None;

    for line in code.lines() {
        let line = line.trim();
        if !line.starts_with(';') {
            continue;
        }
        let line = line.trim_start_matches(';').trim_start();
        let (directive, content) = line.split_at(line.find(':').unwrap_or(line.len()));
        let content = content[1..].trim_start();

        match directive {
            "declare" => {
                let (id, content) = content.split_at(content.find(" ").unwrap_or(content.len()));
                let content = content.trim_start();
                match parse_func_or_data(id) {
                    FuncOrDataId::Func(func_id) => {
                        inj_ctx.define_function(func_id, lookup_symbol(content));
                    }
                    FuncOrDataId::Data(data_id) => {
                        inj_ctx.define_data_object(data_id, lookup_symbol(content));
                    }
                }
            }
            "define" => {
                let (id, content) = content.split_at(content.find(" ").unwrap_or(content.len()));
                let content = content.trim_start();
                match parse_func_or_data(id) {
                    FuncOrDataId::Data(data_id) => {
                        if content.starts_with('"') {
                            let content = content
                                .trim_matches('"')
                                .replace("\\n", "\n")
                                .replace("\\0", "\0");
                            let data_region = inj_ctx.allocate_readonly(content.len() as u64)?;
                            inj_ctx
                                .target
                                .write()
                                .write_slice(content.as_bytes(), data_region as usize)
                                .apply()?;
                            inj_ctx.define_data_object(data_id, data_region);
                        } else {
                            todo!();
                        }
                    }
                    FuncOrDataId::Func(func_id) => {
                        panic!("Please use `function u0:{}()` instead", func_id.as_u32());
                    }
                }
            }
            "run" => {
                assert!(run_function.is_none());
                match parse_func_or_data(content) {
                    FuncOrDataId::Func(func_id) => run_function = Some(func_id),
                    FuncOrDataId::Data(_) => panic!("Can't execute data object"),
                }
            }
            _ => panic!("Unknown directive `{}`", directive),
        }
    }

    let mut flag_builder = settings::builder();
    flag_builder.set("use_colocated_libcalls", "false").unwrap();
    let flags = settings::Flags::new(flag_builder);
    let isa = isa::lookup("x86_64".parse().unwrap())
        .unwrap()
        .finish(flags);

    let functions = cranelift_reader::parse_functions(code).unwrap();
    let mut ctx = cranelift_codegen::Context::new();
    for func in functions {
        ctx.clear();
        ctx.func = func;
        compile_clif_code(&mut inj_ctx, &*isa, &mut ctx)?;
    }

    let run_function = inj_ctx.lookup_function(run_function.expect("Missing `run` directive"));
    let stack_region = inj_ctx.allocate_readwrite(0x1000)?;

    // Ensure that we hit a breakpoint trap when returning from the injected function.
    inj_ctx
        .target
        .write()
        .write(
            &(inj_ctx.breakpoint_trap as usize),
            stack_region as usize + 0x1000 - std::mem::size_of::<usize>(),
        )
        .apply()?;

    println!(
        "run function: 0x{:016x} stack: 0x{:016x}",
        run_function, stack_region
    );

    let orig_regs = remote.read_regs()?;
    let regs = libc::user_regs_struct {
        rip: run_function,
        rsp: stack_region + 0x1000 - std::mem::size_of::<usize>() as u64,
        ..orig_regs
    };
    remote.write_regs(regs)?;
    println!("{:?}", remote.unpause()?);
    println!("{:016x}", remote.read_regs()?.rip);
    remote.write_regs(orig_regs)?;

    Ok(())
}
