// This module provides a naive implementation of symbolication for the time being.
// It should be expanded to support multiple data sources.

use gimli::{self, read::EvaluationResult};
use object::read::{Object, ObjectSection};
use std::{borrow::Cow, collections::BTreeMap, fs::File};

macro_rules! dwarf_attr_or_continue {
    (str($dwarf:ident,$unit:ident) $entry:ident.$name:ident) => {
        $dwarf.attr_string(&$unit, dwarf_attr_or_continue!($entry.$name).value())?.to_string()?;
    };
    ($entry:ident.$name:ident) => {
        if let Some(attr) = $entry.attr(gimli::$name)? {
            attr
        } else {
            continue;
        }
    };
}

rental! {
    mod inner {
        use super::*;

        #[rental]
        pub(super) struct DwarfInner {
            mmap: Box<memmap::Mmap>,
            parsed: ParsedDwarf<'mmap>,
        }
    }
}

impl inner::DwarfInner {
    fn dwarf<T, F: FnOnce(gimli::Dwarf<gimli::EndianSlice<gimli::RunTimeEndian>>) -> T>(
        &self,
        f: F,
    ) -> T {
        self.rent(|parsed| {
            let endian = if parsed.object.is_little_endian() {
                gimli::RunTimeEndian::Little
            } else {
                gimli::RunTimeEndian::Big
            };

            let borrow_section: &dyn for<'a> Fn(
                &'a Cow<[u8]>,
            )
                -> gimli::EndianSlice<'a, gimli::RunTimeEndian> =
                &|section| gimli::EndianSlice::new(&*section, endian);

            let dwarf = parsed.dwarf.borrow(&borrow_section);
            f(dwarf)
        })
    }
}

struct ParsedDwarf<'mmap> {
    object: object::File<'mmap>,
    dwarf: gimli::Dwarf<Cow<'mmap, [u8]>>,
}

pub struct Dwarf {
    inner: inner::DwarfInner,
    vars: BTreeMap<String, usize>,
}

impl Dwarf {
    // todo: impl loader struct instead of taking 'path' as an argument.
    // It will be required to e.g. load coredumps, or external debug info, or to
    // communicate with rustc/lang servers.
    pub fn new(path: &str) -> Result<Dwarf, Box<dyn std::error::Error>> {
        // This is completely inefficient and hacky code, but currently it serves the only
        // purpose of getting addresses of static variables.
        // TODO: this will be reworked in a more complete symbolication framework.
        let mut vars = BTreeMap::new();

        // Load ELF/Mach-O object file
        let file = File::open(path)?;
        let mmap = unsafe { memmap::Mmap::map(&file)? };

        let inner = inner::DwarfInner::try_new(Box::new(mmap), |mmap| {
            let object = object::File::parse(&*mmap)?;

            // This can be also processed in parallel.
            let loader = |id: gimli::SectionId| -> Result<Cow<[u8]>, gimli::Error> {
                match object.section_by_name(id.name()) {
                    Some(ref section) => Ok(section
                        .uncompressed_data()
                        .unwrap_or(Cow::Borrowed(&[][..]))),
                    None => Ok(Cow::Borrowed(&[][..])),
                }
            };
            let sup_loader = |_| Ok(Cow::Borrowed(&[][..])); // we don't support supplementary object files for now

            // Create `EndianSlice`s for all of the sections.
            let dwarf_cow = gimli::Dwarf::load(loader, sup_loader)?;

            Ok(ParsedDwarf {
                object,
                dwarf: dwarf_cow,
            })
        })
        .map_err(|err: rental::RentalError<Box<dyn std::error::Error>, _>| err.0)?;

        let vars = inner.dwarf::<Result<_, Box<dyn std::error::Error>>, _>(|dwarf| {
            let mut units = dwarf.units();

            while let Some(header) = units.next()? {
                let unit = dwarf.unit(header)?;
                let mut entries = unit.entries();
                while let Some((_, entry)) = entries.next_dfs()? {
                    if entry.tag() == gimli::DW_TAG_variable {
                        let name = dwarf_attr_or_continue!(str(dwarf, unit) entry.DW_AT_name);
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

            // DW_TAG_variable
            Ok(vars)
        })?;

        Ok(Dwarf { inner, vars })
    }

    pub fn get_var_address(&self, name: &str) -> Option<usize> {
        self.vars.get(name).cloned()
    }
}
