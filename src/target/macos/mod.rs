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
    marker::PhantomData,
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

    /// Reads memory from a debuggee process.
    pub fn read(&self) -> ReadMemory {
        ReadMemory::new(self.port)
    }
}

/// A single memory read operation.
struct ReadOp {
    // Remote memory location.
    remote_base: usize,
    // Size of the `local_ptr` buffer.
    len: usize,
    // Pointer to a local destination buffer.
    local_ptr: *mut libc::c_void,
}

/// Allows to read memory from different locations in debuggee's memory as a single operation.
pub struct ReadMemory<'a> {
    target_port: port::mach_port_name_t,
    read_ops: Vec<ReadOp>,
    _marker: PhantomData<&'a mut ()>,
}

impl<'a> ReadMemory<'a> {
    fn new(target_port: port::mach_port_name_t) -> Self {
        ReadMemory {
            target_port,
            read_ops: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Reads a value of type `T` from debuggee's memory at location `remote_base`.
    /// This value will be written to the provided variable `val`.
    /// You should call `apply` in order to execute the memory read operation.
    /// The provided variable `val` can't be accessed until either `apply` is called or `self` is
    /// dropped.
    ///
    /// # Safety
    ///
    /// The type `T` must not have any invalid values.
    /// For example `T` must not be a `bool`, as `transmute::<u8, bool>(2)` is not a valid value for a bool.
    /// In case of doubt, wrap the type in [`mem::MaybeUninit`].
    // todo: further document mem safety - e.g., what happens in the case of partial read
    pub fn read<T>(mut self, val: &'a mut T, remote_base: usize) -> Self {
        self.read_ops.push(ReadOp {
            remote_base,
            len: mem::size_of::<T>(),
            local_ptr: val as *mut T as *mut libc::c_void,
        });

        self
    }

    /// Executes the memory read operation.
    pub fn apply(self) -> Result<(), Box<dyn std::error::Error>> {
        for read_op in &self.read_ops {
            unsafe {
                let mut data_size: mach_vm_size_t = 0;

                let res = vm::mach_vm_read_overwrite(
                    self.target_port,
                    read_op.remote_base as mach_vm_address_t,
                    read_op.len as mach_vm_size_t,
                    read_op.local_ptr as *mut _ as mach_vm_size_t,
                    &mut data_size,
                );

                if res != kern_return::KERN_SUCCESS {
                    // TODO: account for partial reads
                    // TODO: properly wrap error types
                    return Err(Box::new(io::Error::last_os_error()));
                }
            }
        }

        Ok(())
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

#[cfg(test)]
mod tests {
    use super::ReadMemory;
    use mach::traps::mach_task_self;

    #[test]
    fn read_memory() {
        let var: usize = 52;
        let var2: u8 = 128;

        let mut read_var_op: usize = 0;
        let mut read_var2_op: u8 = 0;

        unsafe {
            ReadMemory::new(unsafe { mach_task_self() })
                .read(&mut read_var_op, &var as *const _ as usize)
                .read(&mut read_var2_op, &var2 as *const _ as usize)
                .apply()
                .expect("Failed to apply memop");
        }

        assert_eq!(read_var2_op, var2);
        assert_eq!(read_var_op, var);

        assert!(true);
    }
}
