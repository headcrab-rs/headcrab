use std::{borrow::Cow, marker::PhantomData};

use rustyline::{
    completion::{Completer, FilenameCompleter, Pair},
    highlight::Highlighter,
    hint::Hinter,
    validate::Validator,
    Helper,
};

#[doc(hidden)]
pub use rustyline as __rustyline;

pub trait HighlightAndComplete {
    fn highlight<'l>(line: &'l str) -> Cow<'l, str>;
    fn complete(
        line: &str,
        pos: usize,
        ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)>;
}

pub struct MakeHelper<T: HighlightAndComplete>(PhantomData<T>);

impl<T: HighlightAndComplete> Default for MakeHelper<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T: HighlightAndComplete> Helper for MakeHelper<T> {}

impl<T: HighlightAndComplete> Validator for MakeHelper<T> {}

impl<T: HighlightAndComplete> Hinter for MakeHelper<T> {}

impl<T: HighlightAndComplete> Highlighter for MakeHelper<T> {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        T::highlight(line)
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

impl<T: HighlightAndComplete> Completer for MakeHelper<T> {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        T::complete(line, pos, ctx)
    }
}

pub struct NullArgument(());

impl HighlightAndComplete for NullArgument {
    fn highlight<'l>(line: &'l str) -> Cow<'l, str> {
        line.into()
    }

    fn complete(
        line: &str,
        pos: usize,
        ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let _ = (line, pos, ctx);
        Ok((0, vec![]))
    }
}

pub struct FileNameArgument;

impl HighlightAndComplete for FileNameArgument {
    fn highlight<'l>(line: &'l str) -> Cow<'l, str> {
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

    fn complete(
        line: &str,
        pos: usize,
        _ctx: &__rustyline::Context<'_>,
    ) -> __rustyline::Result<(usize, Vec<Pair>)> {
        FilenameCompleter::new().complete_path(line, pos)
    }
}

#[macro_export]
macro_rules! define_repl_cmds {
    (enum $command:ident {
        $(
            #[doc = $doc:literal]
            $($field:ident)|+: $argument_helper:ty,
        )*
    }) => {
        enum $command {}

        impl $command {
            fn print_help(mut w: impl std::io::Write) -> std::io::Result<()> {
                $(
                    writeln!(w, "\x1b[1m{}\x1b[0m -- {}", concat!(stringify!($($field)|+)), $doc.trim())?;
                )*
                Ok(())
            }
        }

        impl $crate::HighlightAndComplete for $command {
            fn highlight<'l>(line: &'l str) -> std::borrow::Cow<'l, str> {
                let cmd_len = line.find(' ').unwrap_or(line.len());
                let (chosen_cmd, rest) = line.split_at(cmd_len);
                $(
                    if [$(stringify!($field)),+][..].iter().copied().any(|cmd| cmd == chosen_cmd) {
                        let highlighted_argument =
                            <$argument_helper as $crate::HighlightAndComplete>::highlight(rest);
                        return format!("\x1b[93m{}\x1b[0m{}", chosen_cmd, highlighted_argument).into();
                    }
                )*
                line.into()
            }

            fn complete(
                line: &str,
                pos: usize,
                ctx: &$crate::__rustyline::Context<'_>,
            ) -> $crate::__rustyline::Result<(usize, Vec<$crate::__rustyline::completion::Pair>)> {
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
                        let (at, completions) =
                            <$argument_helper as $crate::HighlightAndComplete>::complete(rest, pos, ctx)?;
                        return Ok((at + cmd_len, completions));
                    }
                )*

                Ok((0, vec![]))
            }

            // FIXME forward update to argument completer
        }
    };
}
