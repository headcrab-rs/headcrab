use std::mem;
use winapi::shared::minwindef::FALSE;
use winapi::um::processthreadsapi::{
    CreateProcessW, OpenProcess, PROCESS_INFORMATION, STARTUPINFOW,
};
use winapi::um::winbase;
use winapi::um::winnt;

/// This structure holds the state of the debuggee on windows systems.
pub struct Target {
    process_handle: winnt::HANDLE,
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

        Ok(Target {
            process_handle: pi.hProcess,
        })
    }

    /// Attach to a running Process.
    pub fn attach(pid: u32) -> Result<Target, Box<dyn std::error::Error>> {
        let access = winnt::PROCESS_VM_OPERATION | winnt::PROCESS_VM_READ | winnt::PROCESS_VM_WRITE;
        let process_handle = unsafe { OpenProcess(access, FALSE, pid) };
        if process_handle == std::ptr::null_mut() {
            return Err(Box::new(std::io::Error::last_os_error()));
        }
        Ok(Target { process_handle })
    }
}
