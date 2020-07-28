use nix::unistd::{getpid, Pid};
use procfs::process::Process;
use std::{
    cmp::min,
    fs::File,
    io::{BufRead, BufReader},
    marker::PhantomData,
    mem,
};

use crate::target::unix::{self, UnixTarget};

/// This structure holds the state of a debuggee on Linux based systems
/// You can use it to read & write debuggee's memory, pause it, set breakpoints, etc.
pub struct LinuxTarget {
    pid: Pid,
}

impl UnixTarget for LinuxTarget {
    /// Provides the Pid of the debugee process
    fn pid(&self) -> Pid {
        self.pid
    }
}

impl LinuxTarget {
    /// Launches a new debuggee process
    pub fn launch(
        path: &str,
    ) -> Result<(LinuxTarget, nix::sys::wait::WaitStatus), Box<dyn std::error::Error>> {
        let (pid, status) = unix::launch(path)?;
        Ok((LinuxTarget { pid }, status))
    }

    /// Attaches process as a debugee.
    pub fn attach(
        pid: Pid,
    ) -> Result<(LinuxTarget, nix::sys::wait::WaitStatus), Box<dyn std::error::Error>> {
        let status = unix::attach(pid)?;
        Ok((LinuxTarget { pid }, status))
    }

    /// Uses this process as a debuggee.
    pub fn me() -> LinuxTarget {
        LinuxTarget { pid: getpid() }
    }

    /// Reads memory from a debuggee process.
    pub fn read(&self) -> ReadMemory {
        ReadMemory::new(self.pid())
    }

    /// Reads the register values from the main thread of a debuggee process.
    pub fn read_regs(&self) -> Result<libc::user_regs_struct, Box<dyn std::error::Error>> {
        nix::sys::ptrace::getregs(self.pid()).map_err(|err| err.into())
    }

    /// Writes the register values for the main thread of a debuggee process.
    pub fn write_regs(
        &self,
        regs: libc::user_regs_struct,
    ) -> Result<(), Box<dyn std::error::Error>> {
        nix::sys::ptrace::setregs(self.pid(), regs).map_err(|err| err.into())
    }

    /// Let the debuggee process execute the specified syscall.
    pub fn syscall(
        &self,
        num: libc::c_ulonglong,
        arg1: libc::c_ulonglong,
        arg2: libc::c_ulonglong,
        arg3: libc::c_ulonglong,
        arg4: libc::c_ulonglong,
        arg5: libc::c_ulonglong,
        arg6: libc::c_ulonglong,
    ) -> Result<libc::c_ulonglong, Box<dyn std::error::Error>> {
        // Write arguments
        let orig_regs = self.read_regs()?;
        let mut new_regs = orig_regs.clone();
        new_regs.rax = num;
        new_regs.rdi = arg1;
        new_regs.rsi = arg2;
        new_regs.rdx = arg3;
        new_regs.r10 = arg4;
        new_regs.r8 = arg5;
        new_regs.r9 = arg6;
        self.write_regs(new_regs)?;

        // Write syscall instruction
        // FIXME search for an existing syscall instruction once instead
        let old_inst = nix::sys::ptrace::read(self.pid(), new_regs.rip as *mut _)?;
        nix::sys::ptrace::write(
            self.pid(),
            new_regs.rip as *mut _,
            0x050f/*x86_64 syscall*/ as *mut _,
        )?;

        // Perform syscall
        nix::sys::ptrace::step(self.pid(), None)?;
        nix::sys::wait::waitpid(self.pid(), None)?;

        // Read return value
        let res = self.read_regs()?.rax;

        // Restore old code and registers
        nix::sys::ptrace::write(self.pid(), new_regs.rip as *mut _, old_inst as *mut _)?;
        self.write_regs(orig_regs)?;

        Ok(res)
    }

    /// Let the debuggee process map memory.
    pub fn mmap(
        &self,
        addr: *mut libc::c_void,
        length: libc::size_t,
        prot: libc::c_int,
        flags: libc::c_int,
        fd: libc::c_int,
        offset: libc::off_t,
    ) -> Result<libc::c_ulonglong, Box<dyn std::error::Error>> {
        self.syscall(
            libc::SYS_mmap as _,
            addr as _,
            length as _,
            prot as _,
            flags as _,
            fd as _,
            offset as _,
        )
    }

    pub fn memory_maps(&self) -> Result<Vec<super::MemoryMap>, Box<dyn std::error::Error>> {
        Ok(procfs::process::Process::new(self.pid.as_raw())?
            .maps()?
            .into_iter()
            .map(|map| super::MemoryMap {
                address: map.address,
                backing_file: match map.pathname {
                    procfs::process::MMapPath::Path(path) => Some((path, map.offset)),
                    _ => None,
                },
            })
            .collect())
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

impl ReadOp {
    /// Converts the memory read operation into a remote IoVec.
    fn as_remote_iovec(&self) -> libc::iovec {
        libc::iovec {
            iov_base: self.remote_base as *const libc::c_void as *mut _,
            iov_len: self.len,
        }
    }

    /// Converts the memory read operation into a local IoVec.
    fn as_local_iovec(&self) -> libc::iovec {
        libc::iovec {
            iov_base: self.local_ptr,
            iov_len: self.len,
        }
    }

    /// Splits ReadOp so that each resulting ReadOp resides in only one memory page.
    fn split_on_page_boundary(&self) -> Vec<ReadOp> {
        let page_size: usize;

        unsafe {
            page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        }

        let mut out = Vec::new();

        let mut left = self.len;

        let to_next_readop = std::cmp::min(left, page_size - ((page_size - 1) & self.remote_base));
        out.push(ReadOp {
            remote_base: self.remote_base,
            len: to_next_readop,
            local_ptr: self.local_ptr,
        });
        left -= to_next_readop;

        loop {
            if left == 0 {
                break;
            }
            if left < page_size {
                out.push(ReadOp {
                    remote_base: self.remote_base + (self.len - left),
                    len: left,
                    local_ptr: (self.local_ptr as usize + (self.len - left)) as *mut libc::c_void,
                });
                break;
            } else {
                out.push(ReadOp {
                    remote_base: self.remote_base + (self.len - left),
                    len: page_size,
                    local_ptr: (self.local_ptr as usize + (self.len - left)) as *mut libc::c_void,
                });
                left -= page_size;
            }
        }

        out
    }
}

/// Allows to read memory from different locations in debuggee's memory as a single operation.
/// On Linux, this will correspond to a single system call / context switch.
pub struct ReadMemory<'a> {
    pid: Pid,
    read_ops: Vec<ReadOp>,
    _marker: PhantomData<&'a mut ()>,
}

impl<'a> ReadMemory<'a> {
    fn new(pid: Pid) -> Self {
        ReadMemory {
            pid,
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
    pub unsafe fn read<T>(mut self, val: &'a mut T, remote_base: usize) -> Self {
        self.read_ops.append(
            &mut ReadOp {
                remote_base,
                len: mem::size_of::<T>(),
                local_ptr: val as *mut T as *mut libc::c_void,
            }
            .split_on_page_boundary(),
        );

        self
    }

    /// Executes the memory read operation.
    pub fn apply(self) -> Result<(), Box<dyn std::error::Error>> {
        // Create a list of `IoVec`s and remote `IoVec`s
        let remote_iov = self
            .read_ops
            .iter()
            .map(ReadOp::as_remote_iovec)
            .collect::<Vec<_>>();

        let local_iov = self
            .read_ops
            .iter()
            .map(ReadOp::as_local_iovec)
            .collect::<Vec<_>>();

        let read_len = self
            .read_ops
            .iter()
            .fold(0, |sum, read_op| sum + read_op.len);

        if read_len > isize::MAX as usize {
            panic!("Read size too big");
        };

        let bytes_read = unsafe {
            // todo: document unsafety
            libc::process_vm_readv(
                self.pid.into(),
                local_iov.as_ptr(),
                local_iov.len() as libc::c_ulong,
                remote_iov.as_ptr(),
                remote_iov.len() as libc::c_ulong,
                0,
            )
        };

        if bytes_read < read_len as isize {
            let maps = Process::new(self.pid.as_raw())?.maps()?;

            let protected_maps = maps
                .iter()
                .filter(|map| map.perms.chars().nth(0) != Some('r'))
                .collect::<Vec<_>>();

            // Splits readOps to those that read from read protected memory and those that do not.
            let (protected, readable): (_, Vec<_>) =
                self.read_ops.into_iter().partition(|read_op| {
                    protected_maps.iter().any(|map| {
                        map.address.0 as usize <= read_op.remote_base
                            && read_op.remote_base < map.address.1 as usize
                    })
                });

            // Read data that can be read using libc::process_vm_readv
            let new_remote_iov = readable
                .iter()
                .map(ReadOp::as_remote_iovec)
                .collect::<Vec<_>>();

            let new_local_iov = readable
                .iter()
                .map(ReadOp::as_local_iovec)
                .collect::<Vec<_>>();

            let new_bytes_read = unsafe {
                // todo: document unsafety
                libc::process_vm_readv(
                    self.pid.into(),
                    new_local_iov.as_ptr(),
                    new_local_iov.len() as libc::c_ulong,
                    new_remote_iov.as_ptr(),
                    new_remote_iov.len() as libc::c_ulong,
                    0,
                )
            };

            if new_bytes_read == -1 {
                return Err(Box::new(nix::Error::last()));
            }

            // Read rest of the data using PTRACE_PEEKDATA
            for read_op in protected {
                unix::read(
                    self.pid,
                    read_op.remote_base,
                    read_op.len,
                    read_op.local_ptr,
                )?;
            }
        }

        // fixme: check that it's an expected number of read bytes and account for partial reads
        Ok(())
    }
}

/// Returns the start of a process's virtual memory address range.
/// This can be useful for calculation of relative addresses in memory.
pub fn get_addr_range(pid: Pid) -> Result<usize, Box<dyn std::error::Error>> {
    let file = File::open(format!("/proc/{}/maps", pid))?;
    let mut bufread = BufReader::new(file);
    let mut proc_map = String::new();

    bufread.read_line(&mut proc_map)?;

    let proc_data: Vec<_> = proc_map.split(' ').collect();
    let addr_range: Vec<_> = proc_data[0].split('-').collect();

    Ok(usize::from_str_radix(addr_range[0], 16)?)
}

#[cfg(test)]
mod tests {
    use super::{LinuxTarget, ReadMemory};
    use nix::unistd::{fork, getpid, ForkResult};

    use std::alloc::{alloc_zeroed, dealloc, Layout};

    use nix::sys::{
        mman::{mprotect, ProtFlags},
        ptrace, signal, wait,
    };

    #[test]
    fn read_memory() {
        let var: usize = 52;
        let var2: u8 = 128;

        let mut read_var_op: usize = 0;
        let mut read_var2_op: u8 = 0;

        unsafe {
            ReadMemory::new(getpid())
                .read(&mut read_var_op, &var as *const _ as usize)
                .read(&mut read_var2_op, &var2 as *const _ as usize)
                .apply()
                .expect("Failed to apply memop");
        }

        assert_eq!(read_var2_op, var2);
        assert_eq!(read_var_op, var);
    }

    const PAGE_SIZE: usize = 4096;

    #[test]
    fn read_protected_memory() {
        let mut read_var1_op: u8 = 0;
        let mut read_var2_op: usize = 0;

        let var1: u8 = 1;
        let var2: usize = 2;

        let layout = Layout::from_size_align(2 * PAGE_SIZE, PAGE_SIZE).unwrap();

        unsafe {
            let ptr = alloc_zeroed(layout);

            match fork() {
                Ok(ForkResult::Child) => {
                    *(ptr as *mut u8) = var1;

                    mprotect(
                        ptr as *mut std::ffi::c_void,
                        PAGE_SIZE,
                        ProtFlags::PROT_WRITE,
                    )
                    .expect("Failed to mprotect");

                    // Parent reads memory

                    use std::{thread, time};
                    thread::sleep(time::Duration::from_millis(300));

                    dealloc(ptr, layout);
                }
                Ok(ForkResult::Parent { child, .. }) => {
                    use std::{thread, time};
                    thread::sleep(time::Duration::from_millis(100));

                    let target = LinuxTarget::attach(child).expect("Couldn't attach to child");

                    target
                        .read()
                        .read(&mut read_var1_op, ptr as *const _ as usize)
                        .read(&mut read_var2_op, &var2 as *const _ as usize)
                        .apply()
                        .expect("ReadMemory failed");

                    assert_eq!(std::ptr::read_volatile(&read_var1_op), var1);
                    assert_eq!(std::ptr::read_volatile(&read_var2_op), var2);

                    dealloc(ptr, layout);

                    ptrace::cont(child, Some(signal::Signal::SIGCONT)).unwrap();

                    wait::waitpid(child, None).unwrap();
                }
                Err(x) => panic!(x),
            }
        }
    }

    #[test]
    fn read_cross_page_memory() {
        let mut read_var_op = [0u32; PAGE_SIZE + 2];

        let mut var = [123; PAGE_SIZE + 2];
        var[0] = 321;
        var[PAGE_SIZE + 1] = 234;

        unsafe {
            let layout = Layout::from_size_align(PAGE_SIZE * 3, PAGE_SIZE).unwrap();
            let ptr = alloc_zeroed(layout);

            let array_ptr = (ptr as usize + PAGE_SIZE - std::mem::size_of::<u32>()) as *mut u8;

            let second_page_ptr = (ptr as usize + PAGE_SIZE) as *mut std::ffi::c_void;

            match fork() {
                Ok(ForkResult::Child) => {
                    *(array_ptr as *mut [u32; PAGE_SIZE + 2]) = var;
                    mprotect(second_page_ptr, PAGE_SIZE, ProtFlags::PROT_WRITE)
                        .expect("Failed to mprotect");

                    // Parent reads memory

                    use std::{thread, time};
                    thread::sleep(time::Duration::from_millis(300));

                    dealloc(ptr, layout);
                }
                Ok(ForkResult::Parent { child, .. }) => {
                    use std::{thread, time};
                    thread::sleep(time::Duration::from_millis(100));

                    let target = LinuxTarget::attach(child).expect("Couldn't attach to child");

                    target
                        .read()
                        .read(&mut read_var_op, array_ptr as *const _ as usize)
                        .apply()
                        .expect("Failed to apply memop");

                    for i in 0..PAGE_SIZE + 2 {
                        assert_eq!(var[i], read_var_op[i]);
                    }

                    dealloc(ptr, layout);

                    ptrace::cont(child, Some(signal::Signal::SIGCONT)).unwrap();

                    wait::waitpid(child, None).unwrap();
                }
                Err(x) => panic!(x),
            }
        }
    }
}
