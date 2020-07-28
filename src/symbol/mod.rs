// This module provides a naive implementation of symbolication for the time being.
// It should be expanded to support multiple data sources.

use gimli::read::{EvaluationResult, Reader as _};
use object::{
    read::{Object, ObjectSection, ObjectSegment, Symbol},
    SymbolKind,
};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    fs::File,
    path::Path,
    rc::Rc,
};

macro_rules! dwarf_attr_or_continue {
    (str($dwarf:ident,$unit:ident) $entry:ident.$name:ident) => {
        $dwarf
            .attr_string(&$unit, dwarf_attr_or_continue!($entry.$name).value())?
            .to_string()?;
    };
    ($entry:ident.$name:ident) => {
        if let Some(attr) = $entry.attr(gimli::$name)? {
            attr
        } else {
            continue;
        }
    };
}

#[derive(Debug)]
enum RcCow<'a, T: ?Sized> {
    Owned(Rc<T>),
    Borrowed(&'a T),
}

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

type Reader<'a> = gimli::EndianReader<gimli::RunTimeEndian, RcCow<'a, [u8]>>;

pub struct ParsedDwarf<'a> {
    object: object::File<'a>,
    dwarf: gimli::Dwarf<Reader<'a>>,
    vars: BTreeMap<String, usize>,
    symbols: Vec<Symbol<'a>>,
    symbol_names: HashMap<&'a str, usize>,
}

impl<'a> ParsedDwarf<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<ParsedDwarf<'a>, Box<dyn std::error::Error>> {
        // This is completely inefficient and hacky code, but currently it serves the only
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

        let mut units = dwarf.units();

        let mut vars = BTreeMap::new();
        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs()? {
                if entry.tag() == gimli::DW_TAG_variable {
                    let name =
                        dwarf_attr_or_continue!(str(dwarf, unit) entry.DW_AT_name).into_owned();
                    let expr = dwarf_attr_or_continue!(entry.DW_AT_location).exprloc_value();

                    // TODO: evaluation should not happen here
                    if let Some(expr) = expr {
                        let mut eval = expr.evaluation(unit.encoding());
                        match eval.evaluate()? {
                            EvaluationResult::RequiresRelocatedAddress(reloc_addr) => {
                                vars.insert(name.to_owned(), reloc_addr as usize);
                            }
                            _ev_res => {} // do nothing for now
                        }
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
                !symbol.is_undefined()
                    && symbol.section() != object::SymbolSection::Common
                    && symbol.size() > 0
            })
            .collect();
        symbols.sort_by_key(|sym| sym.address());

        let mut symbol_names = HashMap::new();
        for sym in &symbols {
            if let Some(name) = sym.name() {
                symbol_names.insert(name, sym.address() as usize);
            }
        }

        Ok(ParsedDwarf {
            object,
            dwarf,
            vars,
            symbols,
            symbol_names,
        })
    }

    pub fn get_symbol_address(&self, name: &str) -> Option<usize> {
        self.symbol_names.get(name).copied()
    }

    pub fn get_address_symbol(&self, addr: usize) -> Option<String> {
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
        Some(symbol.name()?.to_string())

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

    pub fn get_var_address(&self, name: &str) -> Option<usize> {
        self.vars.get(name).cloned()
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
        pub fn new<P: AsRef<std::path::Path>>(
            path: P,
        ) -> Result<Dwarf, Box<dyn std::error::Error>> {
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

        pub fn rent<T>(&self, f: impl for<'a> FnOnce(&ParsedDwarf<'a>) -> T) -> T {
            f(&*self.parsed)
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

    pub fn get_address_symbol(&self, addr: usize) -> Option<String> {
        self.rent(|parsed| parsed.get_address_symbol(addr))
    }

    pub fn get_var_address(&self, name: &str) -> Option<usize> {
        self.rent(|parsed| parsed.get_var_address(name))
    }
}

pub struct RelocatedDwarf(Vec<RelocatedDwarfEntry>);

struct RelocatedDwarfEntry {
    address_range: (u64, u64),
    file_range: (u64, u64),
    bias: u64,
    dwarf: Dwarf,
}

impl std::fmt::Debug for RelocatedDwarfEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelocatedDwarfEntry")
            .field(
                "address_range",
                &format!(
                    "{:016x}..{:016x}",
                    self.address_range.0, self.address_range.1
                ),
            )
            .field(
                "file_range",
                &format!("{:016x}..{:016x}", self.file_range.0, self.file_range.1),
            )
            .field("bias", &format!("{:016x}", self.bias))
            .field(
                "stated_range",
                &format!(
                    "{:016x}..{:016x}",
                    self.address_range.0 - self.bias,
                    self.address_range.1 - self.bias
                ),
            )
            .finish()
    }
}

impl RelocatedDwarfEntry {
    fn from_file_and_offset(
        address: (u64, u64),
        file: &Path,
        offset: u64,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        match Dwarf::new(file) {
            Ok(dwarf) => {
                let (file_range, stated_address) = dwarf
                    .rent(|parsed| {
                        let object: &object::File = &parsed.object;
                        object.segments().find_map(|segment: object::Segment| {
                            // Sometimes the offset is just before the start file offset of the segment.
                            if offset <= segment.file_range().0 {
                                Some((
                                    segment.file_range(),
                                    segment.address() - (segment.file_range().0 - offset),
                                ))
                            } else {
                                None
                            }
                        })
                    })
                    .ok_or_else(|| {
                        format!(
                            "Couldn't find segment for `{}`+0x{:x}",
                            file.display(),
                            offset
                        )
                    })?;
                Ok(RelocatedDwarfEntry {
                    address_range: address,
                    file_range,
                    bias: address.0 - stated_address,
                    dwarf,
                })
            }
            Err(err) => Err(err),
        }
    }
}

impl RelocatedDwarf {
    pub fn from_maps(
        maps: &[crate::target::MemoryMap],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let vec: Result<Vec<_>, _> = maps
            .iter()
            .filter_map(|map| {
                map.backing_file.as_ref().map(|&(ref file, offset)| {
                    RelocatedDwarfEntry::from_file_and_offset(map.address, file, offset)
                })
            })
            .collect();
        let vec = vec?;
        Ok(RelocatedDwarf(vec))
    }

    pub fn get_symbol_address(&self, name: &str) -> Option<usize> {
        for entry in &self.0 {
            if let Some(addr) = entry.dwarf.get_symbol_address(name) {
                if addr as u64 + entry.bias >= entry.address_range.1 {
                    continue;
                }
                return Some(addr + entry.bias as usize);
            }
        }
        None
    }

    pub fn get_address_symbol(&self, addr: usize) -> Option<String> {
        for entry in &self.0 {
            if (addr as u64) < entry.address_range.0 || addr as u64 >= entry.address_range.1 {
                continue;
            }
            return entry.dwarf.get_address_symbol(addr - entry.bias as usize);
        }
        None
    }

    pub fn get_var_address(&self, name: &str) -> Option<usize> {
        for entry in &self.0 {
            if let Some(addr) = entry.dwarf.get_var_address(name) {
                if addr as u64 + entry.bias >= entry.address_range.1 {
                    continue;
                }
                return Some(addr + entry.bias as usize);
            }
        }
        None
    }
}
