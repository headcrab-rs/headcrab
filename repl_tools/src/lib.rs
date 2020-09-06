use std::{
    borrow::Cow,
    marker::PhantomData,
    path::{Path, PathBuf},
};

use rustyline::{
    completion::{Completer, FilenameCompleter, Pair},
    highlight::Highlighter,
    hint::Hinter,
    validate::Validator,
    Helper,
};

#[doc(hidden)]
pub use rustyline as __rustyline;

pub trait HighlightAndComplete: Sized {
    fn from_str(line: &str) -> Result<Self, Box<dyn std::error::Error>>;
    fn highlight<'l>(line: &'l str) -> Cow<'l, str>;
    fn complete(
        line: &str,
        pos: usize,
        ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)>;
}

pub struct MakeHelper<T: HighlightAndComplete> {
    pub color: bool,
    _marker: PhantomData<T>,
}

impl<T: HighlightAndComplete> MakeHelper<T> {
    pub fn new(color: bool) -> Self {
        Self {
            color,
            _marker: PhantomData,
        }
    }
}

impl<T: HighlightAndComplete> Helper for MakeHelper<T> {}

impl<T: HighlightAndComplete> Validator for MakeHelper<T> {}

impl<T: HighlightAndComplete> Hinter for MakeHelper<T> {}

impl<T: HighlightAndComplete> Highlighter for MakeHelper<T> {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        if self.color {
            T::highlight(line)
        } else {
            line.into()
        }
    }

    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        _default: bool,
    ) -> std::borrow::Cow<'b, str> {
        if self.color {
            format!("\x1b[90m{}\x1b[0m", prompt).into()
        } else {
            prompt.into()
        }
    }

    fn highlight_char(&self, _line: &str, _pos: usize) -> bool {
        self.color
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

impl HighlightAndComplete for () {
    fn from_str(line: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if line.trim() == "" {
            Ok(())
        } else {
            Err(format!("No arguments were expected, found `{}`", line.trim()).into())
        }
    }

    fn highlight<'l>(line: &'l str) -> Cow<'l, str> {
        format!("\x1b[91m{}\x1b[0m", line).into()
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

impl HighlightAndComplete for String {
    fn from_str(line: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(line.trim().to_owned())
    }

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

pub struct FileNameArgument(PathBuf);

impl HighlightAndComplete for PathBuf {
    fn from_str(line: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Path::new(line.trim()).to_owned())
    }

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
            $cmd:ident$(|$alias:ident)*: $argument:ty,
        )*
    }) => {
        enum $command {
            $(
                $cmd($argument),
            )*
        }

        impl $command {
            fn print_help(mut w: impl std::io::Write, color: bool) -> std::io::Result<()> {
                $(
                    if color {
                        write!(w, "\x1b[1m{}\x1b[0m -- ", concat!(stringify!($cmd $(|$alias)*)).to_lowercase())?;
                    } else {
                        write!(w, "{} -- ", concat!(stringify!($cmd $(|$alias)*)).to_lowercase())?;
                    }
                    writeln!(w, "{}", $doc.trim())?;
                )*
                Ok(())
            }
        }

        impl $crate::HighlightAndComplete for $command {
            fn from_str(line: &str) -> Result<Self, Box<dyn std::error::Error>> {
                let cmd_len = line.find(' ').unwrap_or(line.len());
                let (chosen_cmd, rest) = line.split_at(cmd_len);

                $(
                    if [stringify!($cmd) $(,stringify!($alias))*][..].iter().any(|cmd| cmd.eq_ignore_ascii_case(chosen_cmd)) {
                        return Ok(Self::$cmd(<$argument as $crate::HighlightAndComplete>::from_str(rest)?));
                    }
                )*

                Err(format!("Unknown command `{}`", chosen_cmd).into())
            }

            fn highlight<'l>(line: &'l str) -> std::borrow::Cow<'l, str> {
                let cmd_len = line.find(' ').unwrap_or(line.len());
                let (chosen_cmd, rest) = line.split_at(cmd_len);
                $(
                    if [stringify!($cmd) $(,stringify!($alias))*][..].iter().any(|cmd| cmd.eq_ignore_ascii_case(chosen_cmd)) {
                        let highlighted_argument =
                            <$argument as $crate::HighlightAndComplete>::highlight(rest);
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
                    let candidates = [$(stringify!($cmd).to_lowercase() $(,stringify!($alias).to_lowercase())*),*][..]
                        .iter()
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
                    if [stringify!($cmd) $(,stringify!($alias))*][..].iter().copied().any(|cmd| cmd.eq_ignore_ascii_case(chosen_cmd)) {
                        let pos = pos - cmd_len;
                        let (at, completions) =
                            <$argument as $crate::HighlightAndComplete>::complete(rest, pos, ctx)?;
                        return Ok((at + cmd_len, completions));
                    }
                )*

                Ok((0, vec![]))
            }

            // FIXME forward update to argument completer
        }
    };
}
