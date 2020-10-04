use std::collections::HashMap;

use cranelift_codegen::{binemit, ir, isa::TargetIsa, Context};
use cranelift_module::{DataId, FuncId};
use headcrab::{target::LinuxTarget, CrabResult};

use crate::InjectionContext;

// FIXME unmap memory when done
pub struct InjectionModule<'a> {
    inj_ctx: InjectionContext<'a>,
    functions: HashMap<FuncId, u64>,
    data_objects: HashMap<DataId, u64>,
    breakpoint_trap: u64,
}

impl<'a> InjectionModule<'a> {
    pub fn new(target: &'a LinuxTarget) -> CrabResult<Self> {
        let mut inj_module = Self {
            inj_ctx: InjectionContext::new(target),
            functions: HashMap::new(),
            data_objects: HashMap::new(),
            breakpoint_trap: 0,
        };

        inj_module.breakpoint_trap = inj_module.inj_ctx.allocate_code(1, None)?;
        inj_module
            .target()
            .write()
            .write(&0xcc, inj_module.breakpoint_trap as usize)
            .apply()?;

        Ok(inj_module)
    }

    pub fn inj_ctx(&mut self) -> &mut InjectionContext<'a> {
        &mut self.inj_ctx
    }

    pub fn target(&self) -> &LinuxTarget {
        self.inj_ctx.target()
    }

    pub fn breakpoint_trap(&self) -> u64 {
        self.breakpoint_trap
    }

    /// Allocate a new stack and return the bottom of the stack.
    pub fn new_stack(&mut self, size: u64) -> CrabResult<u64> {
        let stack = self.inj_ctx.allocate_readwrite(size, Some(16))?;

        // Ensure that we hit a breakpoint trap when returning from the injected function.
        self.target()
            .write()
            .write(
                &(self.breakpoint_trap() as usize),
                stack as usize + size as usize - std::mem::size_of::<usize>(),
            )
            .apply()?;

        // Stack grows downwards on x86_64
        Ok(stack + size - std::mem::size_of::<usize>() as u64)
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

    pub fn define_data_object_with_bytes(
        &mut self,
        data_id: DataId,
        bytes: &[u8],
    ) -> CrabResult<()> {
        let alloc = self.inj_ctx.allocate_readonly(bytes.len() as u64, None)?;
        self.target()
            .write()
            .write_slice(bytes, alloc as usize)
            .apply()?;
        self.define_data_object(data_id, alloc);

        Ok(())
    }

    pub fn compile_clif_code(&mut self, isa: &dyn TargetIsa, ctx: &mut Context) -> CrabResult<()> {
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

        let code_region = self.inj_ctx.allocate_code(code_mem.len() as u64, None)?;

        for reloc_entry in relocs.0.drain(..) {
            let sym = match reloc_entry.name {
                ir::ExternalName::User {
                    namespace: 0,
                    index,
                } => self.lookup_function(FuncId::from_u32(index)),
                ir::ExternalName::User {
                    namespace: 1,
                    index,
                } => self.lookup_data_object(DataId::from_u32(index)),
                _ => todo!("{:?}", reloc_entry.name),
            };
            match reloc_entry.reloc {
                binemit::Reloc::Abs8 => {
                    code_mem[reloc_entry.offset as usize..reloc_entry.offset as usize + 8]
                        .copy_from_slice(&u64::to_ne_bytes(
                            (sym as i64 + reloc_entry.addend) as u64,
                        ));
                }
                _ => todo!("reloc kind for {:?}", reloc_entry),
            }
        }

        self.target()
            .write()
            .write_slice(&code_mem, code_region as usize)
            .apply()?;

        self.define_function(
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
}

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
