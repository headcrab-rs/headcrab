use std::mem;
use winapi::shared::minwindef::FALSE;
use winapi::um::processthreadsapi::{
    CreateProcessW, OpenProcess, PROCESS_INFORMATION, STARTUPINFOW,
};
use winapi::um::winbase;
use winapi::um::winnt;

use crate::CrabResult;

/// This structure holds the state of the debuggee on windows systems.
pub struct Target {
    proc_handle: winnt::HANDLE,
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
    /// Launch a new debuggee process.
    pub fn launch(path: &str) -> CrabResult<Target> {
        let startup_info = mem::MaybeUninit::<STARTUPINFOW>::zeroed();
        let mut startup_info = unsafe { startup_info.assume_init() };
        let proc_info = mem::MaybeUninit::<PROCESS_INFORMATION>::zeroed();
        let mut proc_info = unsafe { proc_info.assume_init() };

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
                &mut startup_info,
                &mut proc_info,
            )
        } == FALSE
        {
            return Err(Box::new(std::io::Error::last_os_error()));
        }

        Ok(Target {
            proc_handle: proc_info.hProcess,
        })
    }

    /// Attach to a running Process.
    pub fn attach(pid: u32) -> CrabResult<Target> {
        let access = winnt::PROCESS_VM_OPERATION | winnt::PROCESS_VM_READ | winnt::PROCESS_VM_WRITE;
        let proc_handle = unsafe { OpenProcess(access, FALSE, pid) };
        if proc_handle == std::ptr::null_mut() {
            return Err(Box::new(std::io::Error::last_os_error()));
        }
        Ok(Target { proc_handle })
    }
}
