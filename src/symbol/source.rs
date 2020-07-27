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

impl super::Dwarf {
    pub fn source_location(
        &self,
        addr: usize,
    ) -> Result<(String, u64, u64), Box<dyn std::error::Error>> {
        self.rent(|parsed| {
            let addr2line: &addr2line::Context<_> = &parsed.addr2line;
            println!("{:08x}", addr);
            assert!(addr2line.find_dwarf_unit(addr as u64).is_some());
            let location = addr2line
                .find_location(addr as u64)?
                .ok_or_else(|| "source location not found".to_string())?;
            Ok((
                location
                    .file
                    .ok_or_else(|| "Unknown file".to_string())?
                    .to_string(),
                location.line.unwrap_or(0) as u64,
                location.column.unwrap_or(0) as u64,
            ))
        })
    }

    pub fn source_snippet(&self, addr: usize) -> Result<String, Box<dyn std::error::Error>> {
        let (file, line, _column) = self.source_location(addr)?;
        let file = std::fs::read_to_string(file)?;
        Ok(file
            .lines()
            .nth(line as usize)
            .ok_or_else(|| "Line not found".to_string())?
            .to_string())
    }
}
