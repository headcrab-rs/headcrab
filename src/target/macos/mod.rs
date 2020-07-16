mod vmmap;

use libc::pid_t;
use mach::{kern_return, message, port, traps, vm, vm_types::*};
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use security_framework_sys::authorization::*;
use std::{
    ffi::CString,
    io,
    mem::{self, MaybeUninit},
    ptr,
};

// Undocumented flag to disable address space layout randomization.
// For more information about ASLR, you can refer to https://en.wikipedia.org/wiki/Address_space_layout_randomization
const _POSIX_SPAWN_DISABLE_ASLR: i32 = 0x0100;

pub struct Target {
    /// Port for a target task
    port: port::mach_port_name_t,
    pid: Pid,
}

impl Target {
    /// Launch a new debuggee process.
    /// Returns an opaque target handle which you can use to control the debuggee.
    pub fn launch(path: &str) -> Result<Target, Box<dyn std::error::Error>> {
        request_authorization()?;

        let path = CString::new(path)?;

        let child = unsafe {
            let mut pid: pid_t = 0;

            let mut attr = MaybeUninit::<libc::posix_spawnattr_t>::uninit();
            let res = libc::posix_spawnattr_init(attr.as_mut_ptr());
            if res != 0 {
                // TODO: properly wrap error types
                return Err(Box::new(io::Error::last_os_error()));
            }

            let mut attr = attr.assume_init();

            let res = libc::posix_spawnattr_setflags(
                &mut attr,
                (libc::POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_DISABLE_ASLR) as i16,
            );
            if res != 0 {
                // TODO: properly wrap error types
                return Err(Box::new(io::Error::last_os_error()));
            }

            let res = libc::posix_spawn(
                &mut pid,
                path.as_ptr(),
                ptr::null(),
                &attr,
                ptr::null(),
                ptr::null(),
            );
            if res != 0 {
                // TODO: properly wrap error types
                return Err(Box::new(io::Error::last_os_error()));
            }

            pid
        };

        let target_port = unsafe {
            let self_port = traps::mach_task_self();
            let mut target_port = 0;

            let res = traps::task_for_pid(self_port, child, &mut target_port);

            if res != kern_return::KERN_SUCCESS {
                // TODO: properly wrap return errors
                return Err(Box::new(io::Error::new(
                            io::ErrorKind::Other,
                            "Could not obtain task port for a process. This might be caused by insufficient permissions.",
                        )));
            }

            target_port
        };

        Ok(Target {
            port: target_port,
            pid: Pid::from_raw(child),
        })
    }

    /// Continues execution of a debuggee.
    pub fn unpause(&self) -> Result<(), Box<dyn std::error::Error>> {
        signal::kill(self.pid, Signal::SIGCONT)?;
        Ok(())
    }

    /// Implements process memory read function.
    /// This function uses vm_read function from the Mach API.
    fn vm_read(
        &self,
        base: usize,
        len: usize,
        data: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            let mut data_count: message::mach_msg_type_number_t = 0;

            let res = vm::mach_vm_read(
                self.port,
                base as mach_vm_address_t,
                len as mach_vm_size_t,
                data.as_mut_ptr() as *mut _,
                &mut data_count,
            );

            if res != kern_return::KERN_SUCCESS {
                // TODO: properly wrap error types
                return Err(Box::new(io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    /// Returns a list of maps in the debuggee's virtual adddress space.
    pub fn get_addr_range(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let regs = vmmap::macosx_debug_regions(self.pid, self.port);
        for r in regs {
            println!(
                "{:x} -> {:x}, exec: {}, read: {}, write: {} [{:?}]",
                r.address,
                r.end(),
                r.is_exec(),
                r.is_read(),
                r.is_write(),
                r
            );
        }
        Ok(0)
    }

    /// Reads a string from the debuggee's memory.
    pub fn read_string(
        &self,
        base: usize,
        len: usize,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut read_buf = vec![0; len];
        self.vm_read(base, len, &mut read_buf)?;
        Ok(String::from_utf8(read_buf)?)
    }

    /// Reads pointer-sized data from the debuggee's memory.
    /// The size of a result will be platform-dependent (32 or 64 bits).
    pub fn read_usize(&self, base: usize) -> Result<usize, Box<dyn std::error::Error>> {
        let mut read_buf = [0; mem::size_of::<usize>()];
        self.vm_read(base, mem::size_of::<usize>(), &mut read_buf)?;
        Ok(usize::from_ne_bytes(read_buf))
    }
}

/// Requests task_for_pid privilege for this process.
fn request_authorization() -> Result<(), Box<dyn std::error::Error>> {
    // TODO: rewrite this ugly ugly code when AuthorizationCopyRights is available is security_framework

    let name = CString::new("system.privilege.taskport:")?;

    let auth_items = [AuthorizationItem {
        name: name.as_ptr(),
        valueLength: 0,
        value: ptr::null_mut(),
        flags: 0,
    }];

    let auth_item_set = AuthorizationRights {
        count: 1,
        items: auth_items.as_ptr() as *mut _,
    };

    let auth_flags = kAuthorizationFlagExtendRights
        | kAuthorizationFlagPreAuthorize
        | kAuthorizationFlagInteractionAllowed
        | (1 << 5);

    let mut auth_ref = MaybeUninit::<AuthorizationRef>::uninit();
    let res =
        unsafe { AuthorizationCreate(ptr::null(), ptr::null(), auth_flags, auth_ref.as_mut_ptr()) };

    if res != errAuthorizationSuccess {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::Other,
            "AuthorizationCreate",
        )));
    }

    let auth_ref = unsafe { auth_ref.assume_init() };

    let mut target_rights = MaybeUninit::<AuthorizationRights>::uninit();
    let res = unsafe {
        AuthorizationCopyRights(
            auth_ref,
            &auth_item_set,
            ptr::null(),
            auth_flags,
            target_rights.as_mut_ptr() as *mut *mut _,
        )
    };

    if res != errAuthorizationSuccess {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::Other,
            "AuthorizationCopyRights",
        )));
    }

    Ok(())
}
