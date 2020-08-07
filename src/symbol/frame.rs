use super::*;

pub struct Frame<'a> {
    dwarf: &'a gimli::Dwarf<Reader<'a>>,
    unit: Option<&'a gimli::Unit<Reader<'a>>>,
    frame: addr2line::Frame<'a, Reader<'a>>,
}

impl<'a> Frame<'a> {
    pub fn function_debuginfo(
        &self,
    ) -> Option<(
        &'a gimli::Dwarf<Reader<'a>>,
        &'a gimli::Unit<Reader<'a>>,
        gimli::UnitOffset<usize>,
    )> {
        self.frame
            .dw_die_offset
            .map(|unit_offset| (self.dwarf, self.unit.unwrap(), unit_offset))
    }
}

pub struct FrameIter<'a> {
    pub(super) dwarf: &'a gimli::Dwarf<Reader<'a>>,
    pub(super) unit: Option<&'a gimli::Unit<Reader<'a>>>,
    pub(super) iter: addr2line::FrameIter<'a, Reader<'a>>,
}

impl<'a> FrameIter<'a> {
    pub fn next(&mut self) -> Result<Option<Frame<'a>>, gimli::Error> {
        Ok(self.iter.next()?.map(|frame| Frame {
            dwarf: self.dwarf,
            unit: self.unit,
            frame,
        }))
    }
}

impl<'a> std::ops::Deref for Frame<'a> {
    type Target = addr2line::Frame<'a, Reader<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.frame
    }
}
