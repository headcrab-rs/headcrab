use crate::target::thread::Thread;
use crate::target::unix::{self, UnixTarget};
use nix::sys::ptrace;
use nix::unistd::{getpid, Pid};
use procfs::process::{Process, Task};
use procfs::ProcError;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    marker::PhantomData,
    mem,
};

lazy_static::lazy_static! {
    static ref PAGE_SIZE: usize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    #[cfg(target_arch="x86_64")]
    static ref DEBUG_REG_OFFSET: usize = unsafe {
        let x = std::mem::zeroed::<libc::user>();
        (&x.u_debugreg as *const _ as usize) - (&x as *const _ as usize)
    };
}

#[cfg(target_arch = "x86_64")]
const SUPPORTED_HARDWARE_WATCHPOINTS: usize = 4;

#[cfg(not(target_arch = "x86_64"))]
const SUPPORTED_HARDWARE_WATCHPOINTS: usize = 0;

struct LinuxThread {
    task: Task,
}

impl LinuxThread {
    fn new(task: Task) -> LinuxThread {
        LinuxThread { task }
    }
}

impl Thread for LinuxThread {
    type ThreadId = i32;

    fn name(&self) -> Result<Option<String>, Box<dyn std::error::Error>> {
        match self.task.stat() {
            Ok(t_stat) => Ok(Some(t_stat.comm.clone())),
            Err(ProcError::NotFound(_)) | Err(ProcError::Incomplete(_)) => {
                // ok to skip. Thread is gone or it's page is not complete yet.
                Ok(None)
            }
            Err(err) => Err(Box::new(err)),
        }
    }

    fn thread_id(&self) -> Self::ThreadId {
        self.task.tid
    }
}

/// This structure holds the state of a debuggee on Linux based systems
/// You can use it to read & write debuggee's memory, pause it, set breakpoints, etc.
pub struct LinuxTarget {
    pid: Pid,
    watchpoints: [Option<Watchpoint>; SUPPORTED_HARDWARE_WATCHPOINTS],
}

/// This structure is used to pass options to attach
pub struct AttachOptions {
    /// Determines whether process will be killed on debugger exit or crash.
    pub kill_on_exit: bool,
}

#[derive(Debug)]
pub struct Watchpoint {
    typ: WatchpointType,
    addr: usize,
    size: WatchSize,
}

#[derive(Copy, Clone, Debug)]
pub enum WatchSize {
    _1 = 0b00,
    _2 = 0b01,
    _4 = 0b11,
    _8 = 0b10,
}
impl WatchSize {
    fn from_usize(size: usize) -> Result<Self, Box<dyn std::error::Error>> {
        match size {
            1 => Ok(WatchSize::_1),
            2 => Ok(WatchSize::_2),
            4 => Ok(WatchSize::_4),
            8 => Ok(WatchSize::_8),
            x => Err(Box::new(WatchpointError::UnsupportedWatchSize(x))),
        }
    }
}

#[derive(Debug)]
pub enum WatchpointType {
    Execute,
    Write,
    Read,
    ReadWrite,
}

#[derive(Debug, Clone)]
pub enum WatchpointError {
    NoEmptyWatchpoint,
    DoesNotExist(usize),
    UnsupportedPlatform,
    UnsupportedWatchSize(usize),
}

impl std::fmt::Display for WatchpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let string = match self {
            WatchpointError::NoEmptyWatchpoint => "No unused hardware options left".to_string(),
            WatchpointError::DoesNotExist(index) => {
                format!("Watchpoint at specified index ({}) does not exist", index)
            }
            WatchpointError::UnsupportedPlatform => {
                "Watchpoints not supported on this platform".to_string()
            }
            WatchpointError::UnsupportedWatchSize(size) => {
                format!("WatchSize of {} is not supported", size)
            }
        };
        write!(f, "{}", string)
    }
}

impl std::error::Error for WatchpointError {}

impl UnixTarget for LinuxTarget {
    /// Provides the Pid of the debuggee process
    fn pid(&self) -> Pid {
        self.pid
    }
}

impl LinuxTarget {
    fn new(pid: Pid) -> Self {
        Self {
            pid,
            watchpoints: Default::default(),
        }
    }

    /// Launches a new debuggee process
    pub fn launch(
        path: &str,
    ) -> Result<(LinuxTarget, nix::sys::wait::WaitStatus), Box<dyn std::error::Error>> {
        let (pid, status) = unix::launch(path)?;
        let target = LinuxTarget::new(pid);
        target.kill_on_exit()?;
        Ok((target, status))
    }

    /// Attaches process as a debuggee.
    pub fn attach(
        pid: Pid,
        options: AttachOptions,
    ) -> Result<(LinuxTarget, nix::sys::wait::WaitStatus), Box<dyn std::error::Error>> {
        let status = unix::attach(pid)?;
        let target = LinuxTarget::new(pid);

        if options.kill_on_exit {
            target.kill_on_exit()?;
        }

        Ok((target, status))
    }

    /// Uses this process as a debuggee.
    pub fn me() -> LinuxTarget {
        LinuxTarget::new(getpid())
    }

    /// Reads memory from a debuggee process.
    pub fn read(&self) -> ReadMemory {
        ReadMemory::new(&self)
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
            .map(|map| {
                let mut perms = map.perms.chars();
                super::MemoryMap {
                    address: map.address,
                    backing_file: match map.pathname {
                        procfs::process::MMapPath::Path(path) => Some((path, map.offset)),
                        _ => None,
                    },
                    is_readable: perms.next() == Some('r'),
                    is_writeable: perms.next() == Some('w'),
                    is_executable: perms.next() == Some('x'),
                    is_private: perms.next() == Some('p'),
                }
            })
            .collect())
    }

    /// Kill debuggee when debugger exits.
    fn kill_on_exit(&self) -> Result<(), Box<dyn std::error::Error>> {
        nix::sys::ptrace::setoptions(self.pid, nix::sys::ptrace::Options::PTRACE_O_EXITKILL)?;
        Ok(())
    }

    /// Returns the current snapshot view of this debuggee process threads.
    pub fn threads(
        &self,
    ) -> Result<Vec<Box<dyn Thread<ThreadId = i32>>>, Box<dyn std::error::Error>> {
        let tasks: Vec<_> = Process::new(self.pid.as_raw())?
            .tasks()?
            .flatten()
            .map(|task| Box::new(LinuxThread::new(task)) as Box<dyn Thread<ThreadId = i32>>)
            .collect();

        Ok(tasks)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn set_watchpoint(
        &mut self,
        watchpoint: Watchpoint,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        #[cfg(target_arch = "x86_64")]
        {
            let empty = self.find_empty_watchpoint();
            if empty.is_none() {
                return Err(Box::new(WatchpointError::NoEmptyWatchpoint));
            }
            let index = empty.unwrap();

            let rw_bits: u64 = match watchpoint.typ {
                WatchpointType::Execute => 0b00,
                WatchpointType::Read => 0b11,
                WatchpointType::ReadWrite => 0b11,
                WatchpointType::Write => 0b01,
            } << 16 + index * 2;

            let size_bits: u64 = (watchpoint.size as u64) << 18 + index * 2;

            let enable_bit: u64 = 1 << (2 * index);

            let ge_le_bits: u64 = 0b11 << 8;

            let reserved_bit: u64 = 1 << 10;

            let bit_mask: u64 = (0b11 << (2 * index)) | (0b11 << 8) | (1<<10) | (0b1111 << (16 + 4 * index));

            let mut dr7: u64;

            #[allow(deprecated)]
            unsafe {
                //Have to use deprecated function because of no alternative for PTRACE_PEEKUSER
                dr7 = ptrace::ptrace(
                    ptrace::Request::PTRACE_PEEKUSER,
                    self.pid,
                    (*DEBUG_REG_OFFSET + 8*7) as *mut libc::c_void,
                    0 as *mut libc::c_void,
                )? as u64;
            }

            // Check if hardware watchpoint is already used
            if dr7 & (1 << (2 * index)) != 0 {
                // Panic for now
                panic!("Invalid debug register state")
            }

            println!("{:b}", dr7);
            dr7 = (dr7 & !bit_mask) | (enable_bit | rw_bits | size_bits | ge_le_bits | reserved_bit);
            println!("{:b}", dr7);

            let mut addr = watchpoint.addr;

            #[allow(deprecated)]
            unsafe {
                //Have to use deprecated function because of no alternative for PTRACE_POKEUSER
                ptrace::ptrace(
                    ptrace::Request::PTRACE_POKEUSER,
                    self.pid,
                    (*DEBUG_REG_OFFSET + index*8) as *mut libc::c_void,
                    &mut addr as *mut _ as *mut libc::c_void,
                )?;
                ptrace::ptrace(
                    ptrace::Request::PTRACE_POKEUSER,
                    self.pid,
                    (*DEBUG_REG_OFFSET + 7*8) as *mut libc::c_void,
                    &mut dr7 as *mut _ as *mut libc::c_void,
                )?;
            }

            self.watchpoints[index] = Some(watchpoint);

            Ok(index)
        }
        #[cfg(not(target_arch = "x86_64"))]
        Err(Box::new(WatchpointError::UnsupportedPlatform))
    }

    pub fn clear_watchpoint(
        &mut self,
        index: usize,
    ) -> Result<Watchpoint, Box<dyn std::error::Error>> {
        #[cfg(target_arch = "x86_64")]
        {
            if self.watchpoints[index].is_none() {
                return Err(Box::new(WatchpointError::DoesNotExist(index)));
            }

            let mut dr7: u64;
            let mut dr6: u64;
            #[allow(deprecated)]
            unsafe {
                //Have to use deprecated function because of no alternative for PTRACE_PEEKUSER
                dr7 = ptrace::ptrace(
                    ptrace::Request::PTRACE_PEEKUSER,
                    self.pid,
                    (*DEBUG_REG_OFFSET + 7) as *mut libc::c_void,
                    0 as *mut libc::c_void,
                )? as u64;
                dr6 = ptrace::ptrace(
                    ptrace::Request::PTRACE_PEEKUSER,
                    self.pid,
                    (*DEBUG_REG_OFFSET + 6) as *mut libc::c_void,
                    0 as *mut libc::c_void,
                )? as u64;
            }

            let bit_mask: u32 = (0b11 << (2 * index)) | (0b1111 << (16 + 4 * index));
            dr7 = dr7 & !(bit_mask as u64);

            let bit_mask: u32 = 1 << index;
            dr6 = dr6 & !(bit_mask as u64);

            #[allow(deprecated)]
            unsafe {
                //Have to use deprecated function because of no alternative for PTRACE_POKEUSER
                ptrace::ptrace(
                    ptrace::Request::PTRACE_POKEUSER,
                    self.pid,
                    (*DEBUG_REG_OFFSET + 7) as *mut libc::c_void,
                    &mut dr7 as *mut _ as *mut libc::c_void,
                )?;
                ptrace::ptrace(
                    ptrace::Request::PTRACE_POKEUSER,
                    self.pid,
                    (*DEBUG_REG_OFFSET + 6) as *mut libc::c_void,
                    &mut dr6 as *mut _ as *mut libc::c_void,
                )?;
            }

            let watchpoint = std::mem::replace(&mut self.watchpoints[index], None);
            Ok(watchpoint.unwrap())
        }

        #[cfg(not(target_arch = "x86_64"))]
        Err(Box::new(WatchpointError::UnsupportedPlatform))
    }

    pub fn clear_all_watchpoints(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(target_arch = "x86_64")]
        {
            for index in 0..SUPPORTED_HARDWARE_WATCHPOINTS {
                match self.watchpoints[index] {
                    Some(_) => {
                        self.clear_watchpoint(index)?;
                    }
                    None => (),
                };
            }
            Ok(())
        }

        #[cfg(not(target_arch = "x86_64"))]
        Err(Box::new(WatchpointError::UnsupportedPlatform))
    }

    fn find_empty_watchpoint(&self) -> Option<usize> {
        self.watchpoints.iter().position(|w| w.is_none())
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
        let mut out = Vec::new();

        // Number of bytes left to be read
        let mut left = self.len;

        let next_page_distance = *PAGE_SIZE - ((*PAGE_SIZE - 1) & self.remote_base);
        let to_next_read_op = std::cmp::min(left, next_page_distance);
        // Read from remote_base to the end or to the next page
        out.push(ReadOp {
            remote_base: self.remote_base,
            len: to_next_read_op,
            local_ptr: self.local_ptr,
        });
        left -= to_next_read_op;

        while left > 0 {
            if left < *PAGE_SIZE {
                // Read from beginning of the page to a part in the middle (last read)
                out.push(ReadOp {
                    remote_base: self.remote_base + (self.len - left),
                    len: left,
                    local_ptr: (self.local_ptr as usize + (self.len - left)) as *mut libc::c_void,
                });
                break;
            } else {
                // Whole page is being read
                out.push(ReadOp {
                    remote_base: self.remote_base + (self.len - left),
                    len: *PAGE_SIZE,
                    local_ptr: (self.local_ptr as usize + (self.len - left)) as *mut libc::c_void,
                });
                left -= *PAGE_SIZE;
            }
        }
        out
    }
}

/// Allows to read memory from different locations in debuggee's memory as a single operation.
pub struct ReadMemory<'a> {
    target: &'a LinuxTarget,
    read_ops: Vec<ReadOp>,
    _marker: PhantomData<&'a mut ()>,
}

impl<'a> ReadMemory<'a> {
    fn new(target: &'a LinuxTarget) -> Self {
        ReadMemory {
            target,
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
        let read_len = self
            .read_ops
            .iter()
            .fold(0, |sum, read_op| sum + read_op.len);

        if read_len > isize::MAX as usize {
            panic!("Read size too big");
        };

        // FIXME: Probably a better way to do this
        let result = self.read_process_vm(
            &self
                .read_ops
                .iter()
                .map(|read_op| read_op)
                .collect::<Vec<_>>(),
        );

        if result.is_err() && result.unwrap_err() == nix::Error::Sys(nix::errno::Errno::EFAULT)
            || result.is_ok() && result.unwrap() != read_len as isize
        {
            let (protected, readable) = self.split_protected(&self.read_ops)?;

            self.read_process_vm(&readable)?;
            self.read_ptrace(&protected)?;
        }
        Ok(())
    }

    /// Allows to read from several different locations with one system call.
    /// It will ignore pages that are not readable. Returns number of bytes read at granularity of ReadOps.
    fn read_process_vm(&self, read_ops: &[&ReadOp]) -> Result<isize, nix::Error> {
        let remote_iov = read_ops
            .iter()
            .map(|read_op| read_op.as_remote_iovec())
            .collect::<Vec<_>>();

        let local_iov = read_ops
            .iter()
            .map(|read_op| read_op.as_local_iovec())
            .collect::<Vec<_>>();

        let bytes_read = unsafe {
            // todo: document unsafety
            libc::process_vm_readv(
                self.target.pid.into(),
                local_iov.as_ptr(),
                local_iov.len() as libc::c_ulong,
                remote_iov.as_ptr(),
                remote_iov.len() as libc::c_ulong,
                0,
            )
        };

        if bytes_read == -1 {
            return Err(nix::Error::last());
        }

        Ok(bytes_read)
    }

    /// Splits readOps to those that read from read protected memory and those that do not.
    fn split_protected(
        &self,
        read_ops: &'a [ReadOp],
    ) -> Result<(Vec<&'a ReadOp>, Vec<&'a ReadOp>), Box<dyn std::error::Error>> {
        use std::cmp::Ordering;

        let maps = self.target.memory_maps()?;

        let protected_maps = maps
            .iter()
            .filter(|map| !map.is_readable)
            .collect::<Vec<_>>();

        let (protected, readable): (_, Vec<_>) = read_ops.iter().partition(|read_op| {
            protected_maps
                .binary_search_by(|map| {
                    if read_op.remote_base < map.address.0 as usize {
                        Ordering::Greater
                    } else if read_op.remote_base > map.address.1 as usize {
                        Ordering::Less
                    } else {
                        Ordering::Equal
                    }
                })
                .is_ok()
        });

        Ok((protected, readable))
    }

    /// Allows to read from protected memory pages.
    /// This operation results in multiple system calls and is inefficient.
    fn read_ptrace(&self, read_ops: &[&ReadOp]) -> Result<(), Box<dyn std::error::Error>> {
        let long_size = std::mem::size_of::<std::os::raw::c_long>();

        for read_op in read_ops {
            let mut offset: usize = 0;
            // Read until all of the data is read
            while offset < read_op.len {
                let data = ptrace::read(
                    self.target.pid,
                    (read_op.remote_base + offset) as *mut std::ffi::c_void,
                )?;

                // Read full word. No need to preserve other data
                if (read_op.len - offset) >= long_size {
                    // todo: document unsafety
                    unsafe {
                        *((read_op.local_ptr as usize + offset) as *mut i64) = data;
                    }

                // Read part smaller than word. Need to preserve other data
                } else {
                    // todo: document unsafety
                    unsafe {
                        let previous_bytes: &mut [u8] = std::slice::from_raw_parts_mut(
                            (read_op.local_ptr as usize + offset) as *mut u8,
                            read_op.len - offset,
                        );
                        let data_bytes = data.to_ne_bytes();

                        previous_bytes[0..(read_op.len - offset)]
                            .clone_from_slice(&data_bytes[0..(read_op.len - offset)]);
                    }
                }
                offset += long_size;
            }
        }
        Ok(())
    }
}

/// Returns the start of a process's virtual memory address range.
/// This can be useful for calculation of relative addresses in memory.
pub fn get_addr_range(pid: Pid) -> Result<usize, Box<dyn std::error::Error>> {
    let file = File::open(format!("/proc/{}/maps", pid))?;
    let mut buf_read = BufReader::new(file);
    let mut proc_map = String::new();

    buf_read.read_line(&mut proc_map)?;

    let proc_data: Vec<_> = proc_map.split(' ').collect();
    let addr_range: Vec<_> = proc_data[0].split('-').collect();

    Ok(usize::from_str_radix(addr_range[0], 16)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::{AttachOptions, LinuxTarget, ReadMemory};
    use nix::unistd::{fork, getpid, ForkResult};
    use std::sync::{Arc, Barrier};
    use std::thread;

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
            let target = LinuxTarget::new(getpid());
            ReadMemory::new(&target)
                .read(&mut read_var_op, &var as *const _ as usize)
                .read(&mut read_var2_op, &var2 as *const _ as usize)
                .apply()
                .expect("Failed to apply mem_op");
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

                    let (target, _wait_status) =
                        LinuxTarget::attach(child, AttachOptions { kill_on_exit: true })
                            .expect("Couldn't attach to child");

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

                    let (target, _wait_status) =
                        LinuxTarget::attach(child, AttachOptions { kill_on_exit: true })
                            .expect("Couldn't attach to child");

                    target
                        .read()
                        .read(&mut read_var_op, array_ptr as *const _ as usize)
                        .apply()
                        .expect("Failed to apply mem_op");

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

    #[test]
    fn reads_threads() -> Result<(), Box<dyn std::error::Error>> {
        let start_barrier = Arc::new(Barrier::new(2));
        let end_barrier = Arc::new(Barrier::new(2));

        let t1_start = start_barrier.clone();
        let t1_end = end_barrier.clone();

        let thread_name = "thread_name";
        let t1_handle = thread::Builder::new()
            .name(thread_name.to_string())
            .spawn(move || {
                t1_start.wait();
                t1_end.wait();
            })
            .unwrap();

        start_barrier.wait();

        let proc = LinuxTarget::me();
        let threads = proc.threads()?;

        let threads: Vec<_> = threads
            .iter()
            .map(|t| (t.name().unwrap().unwrap().clone(), t.thread_id()))
            .collect();

        // Not always consistent: see https://github.com/rust-lang/rust/issues/74845
        let cargo_threads = std::env::var("RUST_TEST_THREADS")
            .map(|s| s.parse::<usize>())
            .unwrap_or(Ok(2))?;

        // Using >= because we can't trust the cargo_threads number
        assert!(
            threads.len() >= cargo_threads + 1,
            "Expected at least 3 threads in {:?}",
            threads
        );

        // Find test pid in result:
        let proc_pid = proc.pid().as_raw();
        assert!(
            threads.iter().any(|&(_, tid)| tid == proc_pid),
            "Expected to find main pid={} in {:?}",
            proc_pid,
            threads
        );

        // Find thread name
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

    #[test]
    fn watchpoint_set() -> Result<(), Box<dyn std::error::Error>> {
        let mut var: u8 = 124;

        match fork() {
            Ok(ForkResult::Child) => {
                use std::{thread, time};
                thread::sleep(time::Duration::from_millis(100));

                var = 145;
                
                thread::sleep(time::Duration::from_millis(100));
            }
            Ok(ForkResult::Parent { child, .. }) => {
                let (mut target, _wait_status) =
                    LinuxTarget::attach(child, AttachOptions { kill_on_exit: true })
                        .expect("Couldn't attach to child");

                target.set_watchpoint(Watchpoint {
                    addr: &var as *const _ as usize,
                    typ: WatchpointType::Write,
                    size: WatchSize::from_usize(std::mem::size_of::<u8>())?,
                })?;

                ptrace::cont(child, Some(signal::Signal::SIGCONT)).unwrap();
                wait::waitpid(child, None)?;
            }
            Err(x) => panic!(x),
        }

        Ok(())
    }
}
