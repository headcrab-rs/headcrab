use capstone::Capstone;

use std::fs::File;
use std::io::{prelude::*, BufReader};

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
        show_address: bool,
    ) -> Result<String, Box<dyn std::error::Error>> {
        use std::fmt::Write;

        let mut fmt = String::new();

        for insn in self.0.disasm_all(&bytes, addr).unwrap().iter() {
            if show_address {
                write!(fmt, "0x{:016x}: ", insn.address()).unwrap();
            }
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

pub type CrabResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
/// A line in a source code is represented as a line number and the string.
struct SourceLine {
    line_no: usize,
    line_str: String,
}

#[derive(Debug)]
/// This represents a snippet of source code. The snippet usually consists of a key line and some
/// lines of context around it.
pub struct Snippet {
    /// The full path to the file, whose snippet we capture.
    file_path: String,
    /// The lines from the source file that is part of the snippet. Lines are a tuple of line
    /// number and the line string
    lines: Vec<SourceLine>,
    /// The index of the key line in the `lines` vector. If there is no specified key, then it will
    /// be 0.
    key_line_idx: usize,
    /// The column containing the symbol we are interested in.
    key_column_idx: usize,
}

impl Snippet {
    /// This creates a source code snippet given the source file and the key line and the
    /// surrounding line count as context.
    pub fn from_file(
        file_path: &str,
        line_no: usize,
        lines_as_context: usize,
        column: usize,
    ) -> CrabResult<Self> {
        if line_no == 0 {
            return Err("Line numbers should start at 1.".into());
        }
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        let mut lines = vec![];

        // The line number from the debuginfo starts at 1 but the one for iterator gives by
        // `reader.lines()` starts at 0.
        let key = line_no - 1;
        let start = if key > lines_as_context {
            key - lines_as_context
        } else {
            0
        };
        let end = key + lines_as_context;
        for (i, line) in reader.lines().enumerate().skip(start) {
            if i <= end {
                lines.push(SourceLine {
                    line_no: i + 1,
                    line_str: line?,
                });
            } else {
                // If we have printed the asked for line and the context around it,
                // There is no point in iterating through the whole file. So, break
                // out of the loop and make an early return.
                break;
            }
        }
        Ok(Snippet {
            file_path: file_path.to_string(),
            lines,
            key_line_idx: lines_as_context,
            key_column_idx: column - 1,
        })
    }
}
pub mod pretty {
    use super::{Snippet, SourceLine};
    use syntect::{
        easy::HighlightLines,
        highlighting::{Style, ThemeSet},
        parsing::SyntaxSet,
    };

    lazy_static::lazy_static! {
        static ref SYNTAX_SET: SyntaxSet = SyntaxSet::load_defaults_nonewlines();
        static ref THEME_SET: ThemeSet = ThemeSet::load_defaults();
    }
    impl Snippet {
        pub fn highlight(&self) {
            let t = &THEME_SET.themes["Solarized (dark)"];
            let mut h = HighlightLines::new(
                &SYNTAX_SET
                    .find_syntax_by_extension("rs")
                    .unwrap()
                    .to_owned(),
                t,
            );
            for (idx, SourceLine { line_no, line_str }) in self.lines.iter().enumerate() {
                let line_marker = if idx == self.key_line_idx {
                    "\x1b[91m>\x1b[0m"
                } else {
                    " \x1b[2m"
                };
                let hl_line = h.highlight(line_str, &SYNTAX_SET);
                eprintln!(
                    "{} {:>6} | {}",
                    line_marker,
                    *line_no,
                    as_16_bit_terminal_escaped(&hl_line[..])
                );
                if idx == self.key_line_idx && self.key_column_idx != 0 {
                    eprintln!(
                        "         | {:width$}\x1b[91m^\x1b[0m",
                        " ",
                        width = self.key_column_idx
                    );
                }
            }
        }
    }

    fn as_16_bit_terminal_escaped(v: &[(Style, &str)]) -> String {
        use std::fmt::Write;
        let mut s: String = String::new();
        for &(ref style, text) in v.iter() {
            // 256/6 = 42
            write!(
                s,
                "\x1b[38;5;{}m{}",
                16u8 + 36 * (style.foreground.r / 42)
                    + 6 * (style.foreground.g / 42)
                    + (style.foreground.b / 42),
                text
            )
            .unwrap();
        }
        s.push_str("\x1b[0m");
        s
    }
}
