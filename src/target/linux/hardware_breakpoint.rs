#[derive(Debug)]
pub struct HardwareBreakpoint {
    pub typ: HardwareBreakpointType,
    pub addr: usize,
    pub size: HardwareBreakpointSize,
}

impl HardwareBreakpoint {
    pub(super) fn size_bits(&self, index: usize) -> u64 {
        (self.size as u64) << (18 + index * 4)
    }

    pub(super) const fn bit_mask(index: usize) -> u64 {
        (0b11 << (2 * index)) | (0b1111 << (16 + 4 * index))
    }

    pub(super) fn rw_bits(&self, index: usize) -> u64 {
        let type_bites = match self.typ {
            HardwareBreakpointType::Execute => 0b00,
            HardwareBreakpointType::Read => 0b11,
            HardwareBreakpointType::ReadWrite => 0b11,
            HardwareBreakpointType::Write => 0b01,
        };
        type_bites << 16 + index * 4
    }
}

#[derive(Copy, Clone, Debug)]
pub enum HardwareBreakpointSize {
    _1 = 0b00,
    _2 = 0b01,
    _4 = 0b11,
    _8 = 0b10,
}
impl HardwareBreakpointSize {
    pub fn from_usize(size: usize) -> crate::CrabResult<Self> {
        match size {
            1 => Ok(Self::_1),
            2 => Ok(Self::_2),
            4 => Ok(Self::_4),
            8 => Ok(Self::_8),
            x => Err(Box::new(HardwareBreakpointError::UnsupportedWatchSize(x))),
        }
    }
}

#[derive(Debug)]
pub enum HardwareBreakpointType {
    Execute,
    Write,
    Read,
    ReadWrite,
}

#[derive(Debug, Clone)]
pub enum HardwareBreakpointError {
    NoEmptyWatchpoint,
    DoesNotExist(usize),
    UnsupportedPlatform,
    UnsupportedWatchSize(usize),
}

impl std::fmt::Display for HardwareBreakpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let string = match self {
            HardwareBreakpointError::NoEmptyWatchpoint => {
                "No unused hardware breakpoints left".to_string()
            }
            HardwareBreakpointError::DoesNotExist(index) => format!(
                "Hardware breakpoint at specified index ({}) does not exist",
                index
            ),
            HardwareBreakpointError::UnsupportedPlatform => {
                "Hardware breakpoints not supported on this platform".to_string()
            }
            HardwareBreakpointError::UnsupportedWatchSize(size) => {
                format!("Hardware breakpoint size of {} is not supported", size)
            }
        };
        write!(f, "{}", string)
    }
}

impl std::error::Error for HardwareBreakpointError {}
