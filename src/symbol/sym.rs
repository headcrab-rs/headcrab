//! Implementation of a symbol table entry that will automatically
//! demangle rustc names.

use addr2line::demangle_auto;
use object::{SectionIndex, SymbolFlags, SymbolKind, SymbolScope, SymbolSection};
use std::borrow::Cow;

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

    /// Return the kind of this symbol.
    #[inline]
    pub fn kind(&self) -> SymbolKind {
        self.symbol.kind()
    }

    /// Returns the section where the symbol is defined.
    #[inline]
    pub fn section(&self) -> SymbolSection {
        self.symbol.section()
    }

    /// Returns the section index for the section containing this symbol.
    ///
    /// May return `None` if the symbol is not defined in a section.
    #[inline]
    pub fn section_index(&self) -> Option<SectionIndex> {
        self.symbol.section().index()
    }

    /// Return true if the symbol is undefined.
    #[inline]
    pub fn is_undefined(&self) -> bool {
        self.symbol.section() == SymbolSection::Undefined
    }

    /// Return true if the symbol is weak.
    #[inline]
    pub fn is_weak(&self) -> bool {
        self.symbol.is_weak()
    }

    /// Return true if the symbol visible outside of the compilation unit.
    ///
    /// This treats `SymbolScope::Unknown` as global.
    #[inline]
    pub fn is_global(&self) -> bool {
        self.symbol.is_global()
    }

    /// Return true if the symbol is only visible within the compilation unit.
    #[inline]
    pub fn is_local(&self) -> bool {
        self.symbol.scope() == SymbolScope::Compilation
    }

    /// Returns the symbol scope.
    #[inline]
    pub fn scope(&self) -> SymbolScope {
        self.symbol.scope()
    }

    /// Symbol flags that are specific to each file format.
    #[inline]
    pub fn flags(&self) -> SymbolFlags<SectionIndex> {
        self.symbol.flags()
    }

    /// The address of the symbol. May be zero if the address is unknown.
    #[inline]
    pub fn address(&self) -> u64 {
        self.symbol.address()
    }

    /// The size of the symbol. May be zero if the size is unknown.
    #[inline]
    pub fn size(&self) -> u64 {
        self.symbol.size()
    }
}

impl<'data> From<object::Symbol<'data>> for Symbol<'data> {
    fn from(symbol: object::Symbol<'data>) -> Self {
        Symbol { symbol }
    }
}
