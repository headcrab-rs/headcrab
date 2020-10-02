//! This module provides a naive implementation of symbolication for the time being.
//! It should be expanded to support multiple data sources.

#[macro_use]
pub mod dwarf_utils;
pub mod unwind;

use gimli::read::{EvaluationResult, Reader as _};
use object::{
    read::{Object, ObjectSection, ObjectSegment},
    SymbolKind,
};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    fs::File,
    path::Path,
};
pub use sym::Symbol;

mod frame;
mod relocate;
mod source;
mod sym;

use crate::CrabResult;
pub use frame::{Frame, FrameIter, Local, LocalValue, PrimitiveValue};
pub use relocate::RelocatedDwarf;
pub use source::{DisassemblySource, Snippet};

mod rc_cow {
    use std::rc::Rc;

    // Avoid private-in-public error by making this public.
    #[derive(Debug)]
    pub enum RcCow<'a, T: ?Sized> {
        Owned(Rc<T>),
        Borrowed(&'a T),
    }
}

use rc_cow::RcCow;

impl<T: ?Sized> Clone for RcCow<'_, T> {
    fn clone(&self) -> Self {
        match self {
            RcCow::Owned(rc) => RcCow::Owned(rc.clone()),
            RcCow::Borrowed(slice) => RcCow::Borrowed(&**slice),
        }
    }
}

impl<T: ?Sized> std::ops::Deref for RcCow<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            RcCow::Owned(rc) => &**rc,
            RcCow::Borrowed(slice) => &**slice,
        }
    }
}

unsafe impl<T: ?Sized> gimli::StableDeref for RcCow<'_, T> {}
unsafe impl<T: ?Sized> gimli::CloneStableDeref for RcCow<'_, T> {}

pub type Reader<'a> = gimli::EndianReader<gimli::RunTimeEndian, RcCow<'a, [u8]>>;

pub struct ParsedDwarf<'a> {
    object: object::File<'a>,
    addr2line: addr2line::Context<Reader<'a>>,
    vars: BTreeMap<
        String,
        (
            gimli::CompilationUnitHeader<Reader<'a>>,
            gimli::Expression<Reader<'a>>,
        ),
    >,
    symbols: Vec<Symbol<'a>>,
    symbol_names: HashMap<String, usize>,
}

impl<'a> ParsedDwarf<'a> {
    pub fn new(bytes: &'a [u8]) -> CrabResult<ParsedDwarf<'a>> {
        // This is completely inefficient and hackish code, but currently it serves the only
        // purpose of getting addresses of static variables.
        // TODO: this will be reworked in a more complete symbolication framework.

        let object = object::File::parse(bytes)?;

        let endian = if object.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };

        // This can be also processed in parallel.
        let loader = |id: gimli::SectionId| -> Result<Reader, gimli::Error> {
            match object.section_by_name(id.name()) {
                Some(ref section) => {
                    let data = section
                        .uncompressed_data()
                        .unwrap_or(Cow::Borrowed(&[][..]));
                    let data = match data {
                        Cow::Owned(vec) => RcCow::Owned(vec.into()),
                        Cow::Borrowed(slice) => RcCow::Borrowed(slice),
                    };
                    Ok(gimli::EndianReader::new(data, endian))
                }
                None => Ok(gimli::EndianReader::new(RcCow::Borrowed(&[][..]), endian)),
            }
        };
        // we don't support supplementary object files for now
        let sup_loader = |_| Ok(gimli::EndianReader::new(RcCow::Borrowed(&[][..]), endian));

        // Create `EndianSlice`s for all of the sections.
        let dwarf = gimli::Dwarf::load(loader, sup_loader)?;

        let addr2line = addr2line::Context::from_dwarf(dwarf)?;
        let dwarf = addr2line.dwarf();

        let mut units = dwarf.units();

        let mut vars = BTreeMap::new();
        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header.clone())?;
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs()? {
                if entry.tag() == gimli::DW_TAG_variable {
                    let name = dwarf_attr!(str(dwarf, unit) entry.DW_AT_name || continue)
                        .to_string()?
                        .into_owned();
                    if let Some(expr) =
                        dwarf_attr!(entry.DW_AT_location || continue).exprloc_value()
                    {
                        vars.insert(name, (header.clone(), expr));
                    }
                }
            }
        }

        let mut symbols: Vec<_> = object
            .symbols()
            .chain(object.dynamic_symbols())
            .map(|(_, sym)| sym)
            .filter(|symbol| {
                // Copied from `object::read::SymbolMap::filter`
                match symbol.kind() {
                    SymbolKind::Unknown | SymbolKind::Text | SymbolKind::Data => {}
                    SymbolKind::Null
                    | SymbolKind::Section
                    | SymbolKind::File
                    | SymbolKind::Label
                    | SymbolKind::Tls => {
                        return false;
                    }
                }
                !symbol.is_undefined() && symbol.section() != object::SymbolSection::Common
            })
            .map(Into::into)
            .collect();
        symbols.sort_by_key(|sym: &Symbol| sym.address());

        let mut symbol_names = HashMap::new();
        for sym in &symbols {
            if let Some(name) = sym.demangled_name() {
                symbol_names.insert(name.to_string(), sym.address() as usize);
            }
        }

        Ok(ParsedDwarf {
            object,
            addr2line,
            vars,
            symbols,
            symbol_names,
        })
    }

    pub fn get_symbol_address(&self, name: &str) -> Option<usize> {
        self.symbol_names.get(name).copied()
    }

    pub fn get_address_symbol(&self, addr: usize) -> Option<Symbol<'a>> {
        let index = match self
            .symbols
            .binary_search_by(|sym| sym.address().cmp(&(addr as u64)))
        {
            // Found an exact match.
            Ok(index) => index,
            // Address before the first symbol.
            Err(0) => return None,
            // Address between two symbols. `index` is the index of the later of the two.
            Err(index) => index - 1,
        };
        let symbol = &self.symbols[index];
        if self.symbols.get(index + 1).map(|sym| sym.address()) <= Some(addr as u64) {
            return None;
        }
        Some(symbol.clone())

        // FIXME `size` is wrong in some cases. Once this is solved use the following instead.
        /*
        let sym = symbols.binary_search_by(|sym| {
            use std::cmp::Ordering;
            if svma < Svma(sym.address()) {
                Ordering::Greater
            } else if svma < Svma(sym.address() + sym.size()) {
                Ordering::Equal
            } else {
                Ordering::Less
            }
        }).ok().and_then(|idx| symbols.get(idx));
        */
    }

    pub fn get_var_address(&self, name: &str) -> CrabResult<Option<usize>> {
        if let Some((unit_header, expr)) = self.vars.get(name) {
            let unit = self.addr2line.dwarf().unit(unit_header.clone())?;
            let mut eval = expr.clone().evaluation(unit.encoding());
            match eval.evaluate()? {
                EvaluationResult::RequiresRelocatedAddress(reloc_addr) => {
                    return Ok(Some(reloc_addr as usize));
                }
                _ev_res => {} // do nothing for now
            }
        }
        Ok(None)
    }

    pub fn get_addr_frames(&'a self, addr: usize) -> CrabResult<FrameIter<'a>> {
        Ok(FrameIter {
            dwarf: self.addr2line.dwarf(),
            unit: self.addr2line.find_dwarf_unit(addr as u64),
            iter: self.addr2line.find_frames(addr as u64)?,
        })
    }
}

mod inner {
    use super::*;
    use std::mem::{self, ManuallyDrop};

    pub struct Dwarf {
        _mmap: memmap::Mmap,
        parsed: ManuallyDrop<ParsedDwarf<'static>>,
    }

    impl Dwarf {
        // todo: impl loader struct instead of taking 'path' as an argument.
        // It will be required to e.g. load coredumps, or external debug info, or to
        // communicate with rustc/lang servers.
        pub fn new<P: AsRef<std::path::Path>>(path: P) -> CrabResult<Dwarf> {
            // Load ELF/Mach-O object file
            let file = File::open(path)?;

            // Safety: Not really, this assumes that the backing file will not be truncated or
            // written to while it is used by us.
            let mmap = unsafe { memmap::Mmap::map(&file)? };

            let parsed = ManuallyDrop::new(ParsedDwarf::new(&*mmap)?);

            // Safety: `parsed` doesn't outlive `mmap`, from which it borrows, because no reference
            // to `parsed` can be obtained without the lifetime being shortened to be smaller than
            // the `Dwarf` that contains both `parsed` and the `mmap` it borrows from.
            let parsed = unsafe {
                mem::transmute::<ManuallyDrop<ParsedDwarf<'_>>, ManuallyDrop<ParsedDwarf<'static>>>(
                    parsed,
                )
            };

            Ok(Dwarf {
                _mmap: mmap,
                parsed,
            })
        }

        pub fn rent<T>(&self, f: impl for<'a> FnOnce(&'a ParsedDwarf<'a>) -> T) -> T {
            // Safety: `ParsedDwarf` is invariant in `'a`. This means that `ParsedDwarf<'static>`
            // can't safely turn into `ParsedDwarf<'a>`, as otherwise it would be possible to put a
            // short living reference into `ParsedDwarf`. However because of the `for<'a>` on
            // `FnOnce`, this is prevented, so the transmute here is safe.
            f(unsafe { mem::transmute::<&ParsedDwarf<'static>, &ParsedDwarf<'_>>(&*self.parsed) })
        }
    }

    impl Drop for Dwarf {
        fn drop(&mut self) {
            unsafe {
                ManuallyDrop::drop(&mut self.parsed);
            }
        }
    }
}

pub use inner::Dwarf;

impl Dwarf {
    pub fn get_symbol_address(&self, name: &str) -> Option<usize> {
        self.rent(|parsed| parsed.get_symbol_address(name))
    }

    pub fn get_address_symbol_name(&self, addr: usize) -> Option<String> {
        self.rent(|parsed| Some(parsed.get_address_symbol(addr)?.name()?.to_string()))
    }

    pub fn get_address_demangled_name(&self, addr: usize) -> Option<String> {
        self.rent(|parsed| {
            Some(
                parsed
                    .get_address_symbol(addr)?
                    .demangled_name()?
                    .to_string(),
            )
        })
    }

    pub fn get_address_symbol_kind(&self, addr: usize) -> Option<SymbolKind> {
        self.rent(|parsed| Some(parsed.get_address_symbol(addr)?.kind()))
    }

    pub fn get_var_address(&self, name: &str) -> CrabResult<Option<usize>> {
        self.rent(|parsed| parsed.get_var_address(name))
    }

    pub fn with_addr_frames<T, F: for<'a> FnOnce(usize, FrameIter<'a>) -> CrabResult<T>>(
        &self,
        addr: usize,
        f: F,
    ) -> CrabResult<T> {
        self.rent(|parsed| f(addr, parsed.get_addr_frames(addr)?))
    }
}
