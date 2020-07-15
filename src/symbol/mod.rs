// This module provides a naive implementation of symbolication for the time being.
// It should be expanded to support multiple data sources.

use gimli::{self, read::EvaluationResult};
use memmap;
use object::read::{Object, ObjectSection};
use std::{borrow::Cow, collections::BTreeMap, fs::File};

pub struct Dwarf {
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

        let object = object::File::parse(&*mmap)?;
        let endian = if object.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };

        // This can be also processed in parallel.
        let loader = |id: gimli::SectionId| -> Result<Cow<[u8]>, gimli::Error> {
            match object.section_by_name(id.name()) {
                Some(ref section) => Ok(section
                    .uncompressed_data()
                    .unwrap_or(Cow::Borrowed(&[][..]))),
                None => Ok(Cow::Borrowed(&[][..])),
            }
        };
        let sup_loader = |_| Ok(Cow::Borrowed(&[][..])); // we don't need a supplementary object file for now

        let dwarf_cow = gimli::Dwarf::load(loader, sup_loader)?;

        let borrow_section: &dyn for<'a> Fn(
            &'a Cow<[u8]>,
        )
            -> gimli::EndianSlice<'a, gimli::RunTimeEndian> =
            &|section| gimli::EndianSlice::new(&*section, endian);

        let dwarf = dwarf_cow.borrow(&borrow_section);

        // Create `EndianSlice`s for all of the sections.
        let mut units = dwarf.units();

        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs()? {
                // If we find an entry for a function, print it.
                if entry.tag() == gimli::DW_TAG_variable {
                    let name = if let Some(attr) = entry.attr(gimli::DW_AT_name)? {
                        dwarf.attr_string(&unit, attr.value())?.to_string()?
                    } else {
                        continue;
                    };

                    let expr = if let Some(attr) = entry.attr(gimli::DW_AT_location)? {
                        attr.exprloc_value()
                    } else {
                        continue;
                    };

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
        Ok(Dwarf { vars })
    }

    pub fn get_var_address(&self, name: &str) -> Option<usize> {
        self.vars.get(name).cloned()
    }
}
