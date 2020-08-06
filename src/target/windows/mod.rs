use std::mem;
use std::ptr;
use winapi::shared::minwindef::FALSE;
use winapi::um::dbghelp;
use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
use winapi::um::winbase;

/// This structure holds the state of the debuggee on windows systems
pub struct Target {
    proc_info: PROCESS_INFORMATION,
}

macro_rules! wide_string {
    ($string:expr) => {{
        use std::os::windows::ffi::OsStrExt;
        let input = std::ffi::OsStr::new($string);
        let vec: Vec<u16> = input.encode_wide().chain(Some(0)).collect();
        vec
    }};
}

impl Target {
    /// Launch a new debuggee process
    pub fn launch(path: &str) -> Result<Target, Box<dyn std::error::Error>> {
        let mut si: STARTUPINFOW = unsafe { mem::zeroed() };
        let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };

        if unsafe {
            CreateProcessW(
                std::ptr::null_mut(),
                wide_string!(&path).as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                FALSE,
                winbase::DEBUG_ONLY_THIS_PROCESS,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut si,
                &mut pi,
            )
        } == FALSE
        {
            return Err(Box::new(std::io::Error::last_os_error()));
        }
        // Initialize the SymbolHandler
        unsafe {
            dbghelp::SymSetOptions(
                dbghelp::SymGetOptions() | dbghelp::SYMOPT_DEBUG | dbghelp::SYMOPT_LOAD_LINES,
            )
        };
        if unsafe { dbghelp::SymInitializeW(pi.hProcess, ptr::null(), FALSE) } == FALSE {
            return Err(Box::new(std::io::Error::last_os_error()));
        }

        Ok(Target { proc_info: pi })
    }
}
