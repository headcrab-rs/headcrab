use thiserror::Error;

#[derive(Error, Debug)]
pub enum CrabError {
    #[error("Error occurred in headcrab: {0}")]
    HeadCrab(String),

    #[error("{0}")]
    Dwarf(String),

    #[error("Hardware breakpoint error: {0}")]
    HardwareBP(#[from] crate::target::HardwareBreakpointError),

    #[error("Error occurred with breakpoint: {0}")]
    Breakpoint(#[from] crate::target::BreakpointError),

    #[error("Error occurred during gmili parsing: {0}")]
    Symbol(#[from] gimli::Error),

    #[error("Error occurred while reading object file: {0}")]
    Object(#[from] object::read::Error),

    #[error("Error occurred while monitoring process: {0}")]
    NixPtrace(#[from] nix::Error),

    #[error("Error occurred while reading /proc: {0}")]
    // NOTE: If a `ProcError::InternalError` is found this is a bug in the `procfs` crate.
    ProcFs(#[from] procfs::ProcError),

    #[error("{0}")]
    StdIo(#[from] std::io::Error),

    #[error("{0}")]
    ParseInt(#[from] std::num::ParseIntError),

    #[error("{0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error("{0}")]
    FfiNull(#[from] std::ffi::NulError),
}
