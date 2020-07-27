use capstone::Capstone;

pub struct DisassemblySource(Capstone);

impl DisassemblySource {
    pub fn new() -> Self {
        use capstone::arch::{BuildsCapstone, BuildsCapstoneSyntax};

        let cs = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .syntax(capstone::arch::x86::ArchSyntax::Att)
            .detail(true)
            .build()
            .unwrap();

        DisassemblySource(cs)
    }

    pub fn source_snippet(
        &self,
        bytes: &[u8],
        addr: u64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        use std::fmt::Write;

        let mut fmt = String::new();

        for insn in self.0.disasm_all(&bytes, addr).unwrap().iter() {
            if let Some(mnemonic) = insn.mnemonic() {
                write!(fmt, "{} ", mnemonic).unwrap();
                if let Some(op_str) = insn.op_str() {
                    writeln!(fmt, "{}", op_str).unwrap();
                } else {
                    fmt.push('\n');
                }
            }
        }

        Ok(fmt)
    }
}
