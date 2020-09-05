use rustyline::completion::{Completer, FilenameCompleter, Pair};

#[doc(hidden)]
pub use rustyline as __rustyline;

#[derive(Default)]
pub struct NullArgument;

impl NullArgument {
    pub fn highlight<'l>(&self, line: &'l str, _pos: usize) -> std::borrow::Cow<'l, str> {
        line.into()
    }
}

impl Completer for NullArgument {
    type Candidate = Pair;
}

#[derive(Default)]
pub struct FileNameArgument(FilenameCompleter);

impl FileNameArgument {
    pub fn highlight<'l>(&self, line: &'l str, _pos: usize) -> std::borrow::Cow<'l, str> {
        let path = std::path::Path::new(line.trim());
        if path.is_file() {
            // FIXME better colors
            format!("\x1b[96m{}\x1b[0m", line).into()
        } else if path.exists() {
            format!("\x1b[95m{}\x1b[0m", line).into()
        } else {
            line.into()
        }
    }
}

impl Completer for FileNameArgument {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        self.0.complete(line, pos, ctx)
    }

    fn update(&self, line: &mut rustyline::line_buffer::LineBuffer, start: usize, elected: &str) {
        self.0.update(line, start, elected)
    }
}

#[macro_export]
macro_rules! define_repl_cmds {
    ($helper:ty {
        $(
            #[doc = $doc:literal]
            $($field:ident)|+: $argument_helper:ty,
        )*
    }) => {
        impl $helper {
            fn print_help(mut w: impl std::io::Write) -> std::io::Result<()> {
                $(
                    writeln!(w, "\x1b[1m{}\x1b[0m -- {}", concat!(stringify!($($field)|+)), $doc.trim())?;
                )*
                Ok(())
            }
        }

        impl $crate::__rustyline::highlight::Highlighter for $helper {
            fn highlight<'l>(&self, line: &'l str, pos: usize) -> std::borrow::Cow<'l, str> {
                let cmd_len = line.find(' ').unwrap_or(line.len());
                let (chosen_cmd, rest) = line.split_at(cmd_len);
                $(
                    if [$(stringify!($field)),+][..].iter().copied().any(|cmd| cmd == chosen_cmd) {
                        let pos = if pos < cmd_len {
                            usize::max_value()
                        } else {
                            pos - cmd_len
                        };
                        let highlighted_argument = <$argument_helper>::default().highlight(rest, pos);
                        return format!("\x1b[93m{}\x1b[0m{}", chosen_cmd, highlighted_argument).into();
                    }
                )*
                line.into()
            }

            fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
                &'s self,
                prompt: &'p str,
                _default: bool,
            ) -> std::borrow::Cow<'b, str> {
                format!("\x1b[90m{}\x1b[0m", prompt).into()
            }

            fn highlight_char(&self, _line: &str, _pos: usize) -> bool {
                true
            }
        }

        impl $crate::__rustyline::completion::Completer for $helper {
            type Candidate = $crate::__rustyline::completion::Pair;

            fn complete(
                &self,
                line: &str,
                pos: usize,
                ctx: &$crate::__rustyline::Context<'_>,
            ) -> $crate::__rustyline::Result<(usize, Vec<Self::Candidate>)> {
                let cmd_len = line.find(' ').unwrap_or(line.len());
                if pos <= cmd_len {
                    let candidates = [$($(stringify!($field)),+),*][..]
                        .iter()
                        .copied()
                        .filter(|cmd| cmd.starts_with(line))
                        .map(|cmd| $crate::__rustyline::completion::Pair {
                            display: cmd.to_owned(),
                            replacement: cmd.to_owned() + " ",
                        })
                        .collect::<Vec<_>>();

                    let _ = (line, pos, ctx);
                    return Ok((0, candidates));
                }

                let (chosen_cmd, rest) = line.split_at(cmd_len);
                $(
                    if [$(stringify!($field)),+][..].iter().copied().any(|cmd| cmd == chosen_cmd) {
                        let pos = pos - cmd_len;
                        let (at, completions) = <$argument_helper>::default().complete(rest, pos, ctx)?;
                        return Ok((at + cmd_len, completions));
                    }
                )*

                Ok((0, vec![]))
            }

            // FIXME forward update to argument completer
        }
    };
}
