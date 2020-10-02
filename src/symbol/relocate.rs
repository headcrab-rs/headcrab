use super::*;

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
    fn from_file_and_offset(address: (u64, u64), file: &Path, offset: u64) -> CrabResult<Self> {
        match Dwarf::new(file) {
            Ok(dwarf) => {
                let (file_range, stated_address) = dwarf
                    .rent(|parsed| {
                        let object: &object::File = &parsed.object;
                        object.segments().find_map(|segment: object::Segment| {
                            // Sometimes the offset is just before the start file offset of the segment.
                            if offset <= segment.file_range().0 + segment.file_range().1 {
                                Some((
                                    segment.file_range(),
                                    segment.address() - segment.file_range().0 + offset,
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
    pub fn from_maps(maps: &[crate::target::MemoryMap]) -> CrabResult<Self> {
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
                if addr as u64 + entry.bias >= entry.address_range.0 + entry.address_range.1 {
                    continue;
                }
                return Some(addr + entry.bias as usize);
            }
        }
        None
    }

    pub fn get_address_symbol_name(&self, addr: usize) -> Option<String> {
        for entry in &self.0 {
            if (addr as u64) < entry.address_range.0
                || addr as u64 >= entry.address_range.0 + entry.address_range.1
            {
                continue;
            }
            return entry
                .dwarf
                .get_address_symbol_name(addr - entry.bias as usize);
        }
        None
    }

    pub fn get_address_demangled_name(&self, addr: usize) -> Option<String> {
        for entry in &self.0 {
            if (addr as u64) < entry.address_range.0
                || addr as u64 >= entry.address_range.0 + entry.address_range.1
            {
                continue;
            }
            return entry
                .dwarf
                .get_address_demangled_name(addr - entry.bias as usize);
        }
        None
    }

    pub fn get_address_symbol_kind(&self, addr: usize) -> Option<SymbolKind> {
        for entry in &self.0 {
            if (addr as u64) < entry.address_range.0
                || addr as u64 >= entry.address_range.0 + entry.address_range.1
            {
                continue;
            }
            return entry
                .dwarf
                .get_address_symbol_kind(addr - entry.bias as usize);
        }
        None
    }

    pub fn get_var_address(&self, name: &str) -> CrabResult<Option<usize>> {
        for entry in &self.0 {
            if let Some(addr) = entry.dwarf.get_var_address(name)? {
                if addr as u64 + entry.bias >= entry.address_range.0 + entry.address_range.1 {
                    continue;
                }
                return Ok(Some(addr + entry.bias as usize));
            }
        }
        Ok(None)
    }

    pub fn source_location(&self, addr: usize) -> CrabResult<Option<(String, u64, u64)>> {
        for entry in &self.0 {
            if (addr as u64) < entry.address_range.0
                || addr as u64 >= entry.address_range.0 + entry.address_range.1
            {
                continue;
            }
            return Ok(Some(
                entry.dwarf.source_location(addr - entry.bias as usize)?,
            ));
        }
        Ok(None)
    }

    pub fn source_snippet(&self, addr: usize) -> CrabResult<Option<String>> {
        for entry in &self.0 {
            if (addr as u64) < entry.address_range.0
                || addr as u64 >= entry.address_range.0 + entry.address_range.1
            {
                continue;
            }
            return Ok(Some(
                entry.dwarf.source_snippet(addr - entry.bias as usize)?,
            ));
        }
        Ok(None)
    }

    pub fn with_addr_frames<T, F: for<'a> FnOnce(usize, FrameIter<'a>) -> CrabResult<T>>(
        &self,
        addr: usize,
        f: F,
    ) -> CrabResult<Option<T>> {
        for entry in &self.0 {
            if (addr as u64) < entry.address_range.0 || addr as u64 >= entry.address_range.1 {
                continue;
            }
            return Ok(Some(
                entry
                    .dwarf
                    .with_addr_frames(addr - entry.bias as usize, f)?,
            ));
        }
        Ok(None)
    }
}
