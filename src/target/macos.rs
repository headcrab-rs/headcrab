mod readmem;
mod vmmap;
mod writemem;

use crate::target::{registers::Registers, thread::Thread};
use crate::CrabResult;
use libc::pid_t;
use mach::{
    kern_return, mach_types, mach_types::ipc_space_t, message::mach_msg_type_number_t, port,
    port::mach_port_name_t, port::mach_port_t, traps, traps::current_task,
};
use nix::{unistd, unistd::Pid};
use security_framework_sys::authorization::*;
use std::{ffi::CStr, ffi::CString, io, mem::MaybeUninit, ptr};

pub use readmem::ReadMemory;
pub use writemem::WriteMemory;

// Undocumented flag to disable address space layout randomization.
// For more information about ASLR, you can refer to https://en.wikipedia.org/wiki/Address_space_layout_randomization
const _POSIX_SPAWN_DISABLE_ASLR: i32 = 0x0100;

// Max number of characters to read from a thread name.
const MAX_THREAD_NAME: usize = 100;

struct OSXThread {
    port: mach_port_name_t,
    pthread_id: Option<usize>,
    task_port: ipc_space_t,
}

impl Drop for OSXThread {
    fn drop(&mut self) {
        let result = unsafe { mach::mach_port::mach_port_deallocate(self.task_port, self.port) };
        if result != kern_return::KERN_SUCCESS {
            panic!("Failed to deallocate port!");
        }
    }
}

extern "C" {
    // FIXME: Use libc  > 0.2.74 when available
    pub fn pthread_from_mach_thread_np(port: libc::c_uint) -> libc::pthread_t;
}

// TODO: implement `Registers` properly for macOS x86_64
impl Registers for () {
    fn ip(&self) -> u64 {
        todo!()
    }
    fn set_ip(&mut self, ip: u64) {
        todo!()
    }
    fn sp(&self) -> u64 {
        todo!()
    }
    fn set_sp(&mut self, sp: u64) {
        todo!()
    }
    fn bp(&self) -> Option<u64> {
        todo!()
    }
    #[must_use]
    fn set_bp(&mut self, bp: u64) -> Option<()> {
        todo!()
    }
    fn reg_for_dwarf(&self, reg: gimli::Register) -> Option<u64> {
        todo!()
    }
    #[must_use]
    fn set_reg_for_dwarf(&mut self, reg: gimli::Register, val: u64) -> Option<()> {
        todo!()
    }
    fn name_for_dwarf(reg: gimli::Register) -> Option<&'static str>
    where
        Self: Sized,
    {
        todo!()
    }
    fn dwarf_for_name(name: &str) -> Option<gimli::Register>
    where
        Self: Sized,
    {
        todo!()
    }
}

impl Thread<()> for OSXThread {
    type ThreadId = mach_port_t;

    fn read_regs(&self) -> CrabResult<()> {
        todo!()
    }

    fn write_regs(&self, regs: ()) -> CrabResult<()> {
        todo!()
    }

    fn name(&self) -> CrabResult<Option<String>> {
        if let Some(pt_id) = self.pthread_id {
            let mut name = [0 as libc::c_char; MAX_THREAD_NAME];
            let name_ptr = &mut name as *mut [libc::c_char] as *mut libc::c_char;
            let get_name = unsafe { libc::pthread_getname_np(pt_id, name_ptr, MAX_THREAD_NAME) };
            if get_name == 0 {
                let name = unsafe { CStr::from_ptr(name_ptr) }.to_str()?.to_owned();
                Ok(Some(name))
            } else {
                Err(format!(
                    "Failure to read pthread {} name. Error: {}",
                    pt_id, get_name
                )
                .into())
            }
        } else {
            Ok(None)
        }
    }

    fn thread_id(&self) -> Self::ThreadId {
        self.port
    }
}

pub struct Target {
    /// Port for a target task
    port: port::mach_port_name_t,
    pid: Pid,
}

impl Target {
    /// Launch a new debuggee process.
    /// Returns an opaque target handle which you can use to control the debuggee.
    pub fn launch(path: &str) -> CrabResult<Target> {
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

    /// Returns a list of maps in the debuggee's virtual adddress space.
    pub fn get_addr_range(&self) -> CrabResult<usize> {
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

    /// Uses this process as a debuggee.
    pub fn me() -> Target {
        let port = unsafe { current_task() };
        let pid = unistd::getpid();
        Target { port, pid }
    }

    /// Returns the current snapshot view of this debuggee process threads.
    pub fn threads(&self) -> CrabResult<Vec<Box<dyn Thread<(), ThreadId = mach_port_t>>>> {
        let mut threads: mach_types::thread_act_array_t = std::ptr::null_mut();
        let mut tcount: mach_msg_type_number_t = 0;

        let result = unsafe { mach::task::task_threads(self.port, &mut threads, &mut tcount) };

        if result == kern_return::KERN_SUCCESS {
            let tcount = tcount as usize;
            let mut osx_threads = Vec::with_capacity(tcount);

            for i in 0..tcount {
                let port = unsafe { *threads.add(i) };
                let pthread_id = match unsafe { pthread_from_mach_thread_np(port) } {
                    0 => None,
                    id => Some(id),
                };
                let task_port = self.port;
                let thread = Box::new(OSXThread {
                    port,
                    pthread_id,
                    task_port,
                }) as Box<dyn Thread<(), ThreadId = mach_port_t>>;

                osx_threads.push(thread);
            }
            Ok(osx_threads)
        } else {
            Err(format!(
                "Failure to read task {} threads. Error: {}",
                self.port, result
            )
            .into())
        }
    }
}

/// Requests task_for_pid privilege for this process.
fn request_authorization() -> CrabResult<()> {
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
    use super::*;
    use mach::traps::mach_task_self;
    use std::sync::{Arc, Barrier};
    use std::thread;

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

    #[test]
    fn read_threads() -> CrabResult<()> {
        let start_barrier = Arc::new(Barrier::new(2));
        let end_barrier = Arc::new(Barrier::new(2));

        let t1_start = start_barrier.clone();
        let t1_end = end_barrier.clone();

        let thread_name = "thread-name";
        let t1_handle = thread::Builder::new()
            .name(thread_name.to_string())
            .spawn(move || {
                t1_start.wait();
                t1_end.wait();
            })
            .unwrap();

        start_barrier.wait();

        let proc = Target::me();
        let threads = proc.threads()?;

        let threads: Vec<_> = threads
            .iter()
            .map(|t| {
                let name = t.name().unwrap().unwrap_or_else(String::new);
                let id = t.thread_id();
                (name, id)
            })
            .collect();

        assert!(
            threads.len() >= 2,
            "Expected at least 2 threads in {:?}",
            threads
        );

        assert!(
            threads.iter().any(|(name, _)| name == thread_name),
            "Expected to find thread name={} in {:?}",
            thread_name,
            threads
        );

        end_barrier.wait();
        t1_handle.join().unwrap();
        Ok(())
    }
}
