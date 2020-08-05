//! Implementation of a symbol table entry that will automatically
//! demangle rustc names.

use addr2line::demangle_auto;
use std::borrow::Cow;
use std::ops::{Deref, DerefMut};

/// A symbol table entry.
#[derive(Clone, Debug)]
pub struct Symbol<'data> {
    symbol: object::Symbol<'data>,
}

impl<'data> Symbol<'data> {
    /// Returns the demangled name if this symbol has a name.
    #[inline]
    pub fn name(&self) -> Option<String> {
        // TODO: Avoid this allocation in every call. (lifetime errors)
        self.orig_name()
            .map(|name| demangle_auto(Cow::Borrowed(name), None).to_string())
    }

    /// Returns the unmangled name of this symbol.
    #[inline]
    pub fn orig_name(&self) -> Option<&'data str> {
        self.symbol.name()
    }
}

impl<'data> From<object::Symbol<'data>> for Symbol<'data> {
    fn from(symbol: object::Symbol<'data>) -> Self {
        Symbol { symbol }
    }
}

impl<'data> Deref for Symbol<'data> {
    type Target = object::Symbol<'data>;

    fn deref(&self) -> &Self::Target {
        &self.symbol
    }
}

impl DerefMut for Symbol<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.symbol
    }
}
