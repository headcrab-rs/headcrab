mod hardware_breakpoint;
mod memory;
mod readmem;
mod software_breakpoint;
mod writemem;

use crate::target::{
    registers::Registers,
    thread::Thread,
    unix::{self, UnixTarget},
};
use crate::CrabResult;
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{getpid, Pid};
use procfs::process::{Process, Task};
use procfs::ProcError;
use std::cell::RefCell;
use std::collections::HashMap;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    process::Command,
};

pub use hardware_breakpoint::{
    HardwareBreakpoint, HardwareBreakpointError, HardwareBreakpointSize, HardwareBreakpointType,
};
pub use readmem::ReadMemory;
pub use software_breakpoint::Breakpoint;
pub use writemem::WriteMemory;

lazy_static::lazy_static! {
    pub static ref PAGE_SIZE: usize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    #[cfg(target_arch="x86_64")]
    static ref DEBUG_REG_OFFSET: usize = unsafe {
        let x = std::mem::zeroed::<libc::user>();
        (&x.u_debugreg as *const _ as usize) - (&x as *const _ as usize)
    };
}

#[cfg(target_arch = "x86_64")]
const SUPPORTED_HARDWARE_BREAKPOINTS: usize = 4;

#[cfg(not(target_arch = "x86_64"))]
const SUPPORTED_HARDWARE_BREAKPOINTS: usize = 0;

#[cfg(target_arch = "x86_64")]
use crate::target::registers::RegistersX86_64;

struct LinuxThread {
    task: Task,
}

impl LinuxThread {
    fn new(task: Task) -> LinuxThread {
        LinuxThread { task }
    }
}

impl<Regs> Thread<Regs> for LinuxThread
where
    Regs: Registers + From<libc::user_regs_struct> + Into<libc::user_regs_struct>,
{
    type ThreadId = i32;

    fn read_regs(&self) -> CrabResult<Regs> {
        let regs = nix::sys::ptrace::getregs(Pid::from_raw(self.task.tid))?;
        Ok(Regs::from(regs))
    }

    fn write_regs(&self, regs: Regs) -> CrabResult<()> {
        let regs = regs.into();
        nix::sys::ptrace::setregs(Pid::from_raw(self.task.tid), regs)?;
        Ok(())
    }

    fn name(&self) -> CrabResult<Option<String>> {
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

/// Type alias to use for boxed threads.
#[cfg(target_arch = "x86_64")]
type BoxedLinuxThread = Box<dyn Thread<RegistersX86_64, ThreadId = i32>>;

/// This structure holds the state of a debuggee on Linux based systems
/// You can use it to read & write debuggee's memory, pause it, set breakpoints, etc.
pub struct LinuxTarget {
    pid: Pid,
    hardware_breakpoints: [Option<HardwareBreakpoint>; SUPPORTED_HARDWARE_BREAKPOINTS],
    breakpoints: RefCell<HashMap<usize, Breakpoint>>,
    // Some if the target stopped because of a breakpoint
    // None if stopped for another status
    hit_breakpoint: RefCell<Option<Breakpoint>>,
}

/// This structure is used to pass options to attach
#[derive(Default)]
pub struct AttachOptions {
    /// Determines whether process will be killed on debugger exit or crash.
    pub kill_on_exit: bool,
}

impl UnixTarget for LinuxTarget {
    /// Provides the Pid of the debuggee process
    fn pid(&self) -> Pid {
        self.pid
    }

    fn unpause(&self) -> CrabResult<WaitStatus> {
        self.handle_breakpoint()?;
        ptrace::cont(self.pid(), None)?;
        let status = waitpid(self.pid(), None)?;

        // We may have hit a user defined breakpoint
        if let WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP) = status {
            let regs = self.main_thread()?.read_regs()?;

            if let Some(bp) = self
                .breakpoints
                .borrow_mut()
                .get_mut(&(regs.ip() as usize - 1))
            {
                // Register which breakpoint was  hit
                self.hit_breakpoint.borrow_mut().replace(bp.clone());

                // Restore the program to its uninstrumented state
                self.restore_breakpoint(bp)?;
            };
        }
        Ok(status)
    }

    fn step(&self) -> CrabResult<WaitStatus> {
        let status = self.handle_breakpoint()?;
        match status {
            None => {
                ptrace::step(self.pid(), None)?;
                Ok(waitpid(self.pid(), None)?)
            }
            Some(status) => Ok(status),
        }
    }
}

impl LinuxTarget {
    /// executes the code instrumented by a breakpoint if one has been hit
    /// and resets the breakpoint
    /// returns true if it executed an instruction, false otherwise
    /// The function may not execute the instrumented instruction if the
    /// P.C is not where the breakpoint was set
    fn handle_breakpoint(&self) -> CrabResult<Option<WaitStatus>> {
        let mut status = None;

        let bp = { self.hit_breakpoint.borrow_mut().take() };
        // if we have hit a breakpoint previously
        if let Some(mut bp) = bp {
            let rip = self.main_thread()?.read_regs()?.ip() as usize;
            // if we are not a the right address, we simply set the breakpoint again, and
            // carry on
            if (rip == bp.addr) && bp.is_enabled() {
                assert!(!bp.is_armed());
                ptrace::step(self.pid(), None)?;
                status = Some(waitpid(self.pid(), None)?);
            }
            // else user has modified rip and we're not at the breakpoint anymore
            if bp.is_enabled() {
                bp.set()?;
            }
        }
        Ok(status)
    }

    fn new(pid: Pid) -> Self {
        Self {
            pid,
            hardware_breakpoints: Default::default(),
            breakpoints: RefCell::new(HashMap::new()),
            hit_breakpoint: RefCell::new(None),
        }
    }

    /// Launches a new debuggee process
    pub fn launch(cmd: Command) -> CrabResult<(LinuxTarget, nix::sys::wait::WaitStatus)> {
        let (pid, status) = unix::launch(cmd)?;
        let target = LinuxTarget::new(pid);
        target.kill_on_exit()?;
        Ok((target, status))
    }

    /// Attaches process as a debuggee.
    pub fn attach(pid: Pid, options: AttachOptions) -> CrabResult<(LinuxTarget, WaitStatus)> {
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

    /// Writes memory to a debuggee process.
    pub fn write(&self) -> WriteMemory {
        WriteMemory::new(&self)
    }

    /// Reads the register values from the main thread of a debuggee process.
    pub fn read_regs(&self) -> CrabResult<Box<dyn Registers>> {
        Ok(Box::new(self.main_thread()?.read_regs()?))
    }

    /// Let the debuggee process execute the specified syscall.
    #[cfg(target_arch = "x86_64")]
    pub fn syscall(
        &self,
        num: libc::c_ulonglong,
        arg1: libc::c_ulonglong,
        arg2: libc::c_ulonglong,
        arg3: libc::c_ulonglong,
        arg4: libc::c_ulonglong,
        arg5: libc::c_ulonglong,
        arg6: libc::c_ulonglong,
    ) -> CrabResult<libc::c_ulonglong> {
        use gimli::X86_64;

        // Write arguments
        let orig_regs = self.main_thread()?.read_regs()?;

        let mut new_regs = orig_regs.clone();

        // unwraps are safe because we limit this impl to x86_64
        new_regs.set_reg_for_dwarf(X86_64::RAX, num).unwrap();
        new_regs.set_reg_for_dwarf(X86_64::RDI, arg1).unwrap();
        new_regs.set_reg_for_dwarf(X86_64::RSI, arg2).unwrap();
        new_regs.set_reg_for_dwarf(X86_64::RDX, arg3).unwrap();
        new_regs.set_reg_for_dwarf(X86_64::R10, arg4).unwrap();
        new_regs.set_reg_for_dwarf(X86_64::R8, arg5).unwrap();
        new_regs.set_reg_for_dwarf(X86_64::R9, arg6).unwrap();
        self.main_thread()?.write_regs(new_regs)?;

        // Write syscall instruction
        // FIXME search for an existing syscall instruction once instead
        let old_inst = nix::sys::ptrace::read(self.pid(), new_regs.ip() as *mut _)?;
        nix::sys::ptrace::write(
            self.pid(),
            new_regs.ip() as *mut _,
            0x050f/*x86_64 syscall*/ as *mut _,
        )?;

        // Perform syscall
        nix::sys::ptrace::step(self.pid(), None)?;
        nix::sys::wait::waitpid(self.pid(), None)?;

        // Read return value
        let regs = self.read_regs()?;
        let res = regs.reg_for_dwarf(X86_64::RAX);

        // Restore old code and registers
        nix::sys::ptrace::write(self.pid(), new_regs.ip() as *mut _, old_inst as *mut _)?;
        self.main_thread()?.write_regs(orig_regs)?;

        Ok(res.unwrap())
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
    ) -> CrabResult<libc::c_ulonglong> {
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

    pub fn memory_maps(&self) -> CrabResult<Vec<super::MemoryMap>> {
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
                    is_writable: perms.next() == Some('w'),
                    is_executable: perms.next() == Some('x'),
                    is_private: perms.next() == Some('p'),
                }
            })
            .collect())
    }

    /// Kill debuggee when debugger exits.
    fn kill_on_exit(&self) -> CrabResult<()> {
        nix::sys::ptrace::setoptions(self.pid, nix::sys::ptrace::Options::PTRACE_O_EXITKILL)?;
        Ok(())
    }

    /// Returns the main process thread.
    pub fn main_thread(&self) -> CrabResult<BoxedLinuxThread> {
        match Process::new(self.pid.as_raw())?.task_main_thread() {
            Ok(task) => Ok(Box::new(LinuxThread::new(task))),
            Err(e) => Err(From::from(e)),
        }
    }

    /// Returns the current snapshot view of this debuggee process threads.
    pub fn threads(&self) -> CrabResult<Vec<BoxedLinuxThread>> {
        let tasks: Vec<_> = Process::new(self.pid.as_raw())?
            .tasks()?
            .flatten()
            .map(|task| Box::new(LinuxThread::new(task)) as _)
            .collect();

        Ok(tasks)
    }

    pub fn set_hardware_breakpoint(&mut self, breakpoint: HardwareBreakpoint) -> CrabResult<usize> {
        #[cfg(target_arch = "x86_64")]
        {
            let index = if let Some(empty) = self.find_empty_watchpoint() {
                empty
            } else {
                return Err(Box::new(HardwareBreakpointError::NoEmptyWatchpoint));
            };

            let rw_bits: u64 = breakpoint.rw_bits(index);
            let size_bits = breakpoint.size_bits(index);
            let enable_bit: u64 = 1 << (2 * index);
            let bit_mask = HardwareBreakpoint::bit_mask(index);

            let mut dr7: u64 =
                self.ptrace_peekuser((*DEBUG_REG_OFFSET + 7 * 8) as *mut libc::c_void)? as u64;

            // Check if hardware watchpoint is already used
            if dr7 & (1 << (2 * index)) != 0 {
                // Panic for now
                panic!("Invalid debug register state")
            }

            dr7 = (dr7 & !bit_mask) | (enable_bit | rw_bits | size_bits);

            #[allow(deprecated)]
            unsafe {
                // Have to use deprecated function because of no alternative for PTRACE_POKEUSER
                ptrace::ptrace(
                    ptrace::Request::PTRACE_POKEUSER,
                    self.pid,
                    (*DEBUG_REG_OFFSET + index * 8) as *mut libc::c_void,
                    breakpoint.addr as *mut libc::c_void,
                )?;
                ptrace::ptrace(
                    ptrace::Request::PTRACE_POKEUSER,
                    self.pid,
                    (*DEBUG_REG_OFFSET + 7 * 8) as *mut libc::c_void,
                    dr7 as *mut libc::c_void,
                )?;
                ptrace::ptrace(
                    ptrace::Request::PTRACE_POKEUSER,
                    self.pid,
                    (*DEBUG_REG_OFFSET + 6 * 8) as *mut libc::c_void,
                    0 as *mut libc::c_void,
                )?;
            }

            self.hardware_breakpoints[index] = Some(breakpoint);

            Ok(index)
        }
        #[cfg(not(target_arch = "x86_64"))]
        Err(Box::new(HardwareBreakpointError::UnsupportedPlatform))
    }

    pub fn clear_hardware_breakpoint(&mut self, index: usize) -> CrabResult<HardwareBreakpoint> {
        #[cfg(target_arch = "x86_64")]
        {
            if self.hardware_breakpoints[index].is_none() {
                return Err(Box::new(HardwareBreakpointError::DoesNotExist(index)));
            }

            let mut dr7 =
                self.ptrace_peekuser((*DEBUG_REG_OFFSET + 7 * 8) as *mut libc::c_void)? as u64;
            let mut dr6 =
                self.ptrace_peekuser((*DEBUG_REG_OFFSET + 6 * 8) as *mut libc::c_void)? as u64;

            let dr7_bit_mask: u64 = HardwareBreakpoint::bit_mask(index);
            dr7 = dr7 & !dr7_bit_mask;

            let dr6_bit_mask: u64 = 1 << index;
            dr6 = dr6 & !dr6_bit_mask as u64;

            #[allow(deprecated)]
            unsafe {
                // Have to use deprecated function because of no alternative for PTRACE_POKEUSER
                ptrace::ptrace(
                    ptrace::Request::PTRACE_POKEUSER,
                    self.pid,
                    (*DEBUG_REG_OFFSET + 7 * 8) as *mut libc::c_void,
                    dr7 as *mut libc::c_void,
                )?;
                ptrace::ptrace(
                    ptrace::Request::PTRACE_POKEUSER,
                    self.pid,
                    (*DEBUG_REG_OFFSET + 6 * 8) as *mut libc::c_void,
                    dr6 as *mut libc::c_void,
                )?;
            }

            let watchpoint = std::mem::replace(&mut self.hardware_breakpoints[index], None);
            Ok(watchpoint.unwrap())
        }

        #[cfg(not(target_arch = "x86_64"))]
        Err(Box::new(HardwareBreakpointError::UnsupportedPlatform))
    }

    pub fn clear_all_hardware_breakpoints(&mut self) -> CrabResult<()> {
        for index in 0..SUPPORTED_HARDWARE_BREAKPOINTS {
            match self.hardware_breakpoints[index] {
                Some(_) => {
                    self.clear_hardware_breakpoint(index)?;
                }
                None => (),
            };
        }
        Ok(())
    }

    pub fn is_hardware_breakpoint_triggered(&self) -> CrabResult<Option<usize>> {
        #[cfg(target_arch = "x86_64")]
        {
            let mut dr7 = self.ptrace_peekuser((*DEBUG_REG_OFFSET + 6 * 8) as *mut libc::c_void)?;

            for i in 0..SUPPORTED_HARDWARE_BREAKPOINTS {
                if dr7 & (1 << i) != 0 && self.hardware_breakpoints[i].is_some() {
                    // Clear bit for this breakpoint
                    dr7 &= !(1 << i);
                    // Have to use deprecated function because of no alternative for PTRACE_POKEUSER
                    #[allow(deprecated)]
                    unsafe {
                        ptrace::ptrace(
                            ptrace::Request::PTRACE_POKEUSER,
                            self.pid,
                            (*DEBUG_REG_OFFSET + 6 * 8) as *mut libc::c_void,
                            dr7 as *mut libc::c_void,
                        )?;
                    }

                    return Ok(Some(i));
                }
            }

            Ok(None)
        }

        #[cfg(not(target_arch = "x86_64"))]
        Err(Box::new(HardwareBreakpointError::UnsupportedPlatform))
    }

    /// Set a breakpoint at a given address
    /// This modifies the Target's memory by writting an INT3 instr. at `addr`
    /// The returned Breakpoint object can then be used to disable the breakpoint
    /// or query its state
    pub fn set_breakpoint(&self, addr: usize) -> CrabResult<Breakpoint> {
        let bp = Breakpoint::new(addr, self.pid())?;
        let existing_breakpoint = {
            let hdl = self.breakpoints.borrow();
            hdl.get(&addr).map(|val| val.clone())
        };

        let mut bp = match existing_breakpoint {
            None => {
                self.breakpoints.borrow_mut().insert(addr, bp.clone());
                bp
            }
            // If there is already a breakpoint set, we give back the existing one
            Some(breakpoint) => breakpoint,
        };
        bp.set()?;
        Ok(bp)
    }

    /// Restore the instruction shadowed by `bp` & rollback the P.C by 1
    fn restore_breakpoint(&self, bp: &mut Breakpoint) -> CrabResult<()> {
        if !bp.is_armed() {
            // Fail silently if restoring an inactive breakpoint
            return Ok(());
        }
        // restore the instruction
        bp.unset()?;

        // rollback the P.C
        let mut regs = self.main_thread()?.read_regs()?;
        regs.set_ip(regs.ip() - 1);
        self.main_thread()?.write_regs(regs)?;

        Ok(())
    }

    /// Disable the breakpoint. Call `set()` on the Breakpoint to enable it again
    pub fn disable_breakpoint(&self, bp: &mut Breakpoint) -> CrabResult<()> {
        bp.disable().map_err(|e| e.into())
    }

    // Temporary function until ptrace_peekuser is fixed in nix crate
    #[cfg(target_arch = "x86_64")]
    fn ptrace_peekuser(&self, addr: *mut libc::c_void) -> CrabResult<libc::c_long> {
        let ret = unsafe {
            nix::errno::Errno::clear();
            libc::ptrace(
                ptrace::Request::PTRACE_PEEKUSER as libc::c_uint,
                libc::pid_t::from(self.pid),
                addr,
                std::ptr::null_mut() as *mut libc::c_void,
            )
        };
        match nix::errno::Errno::result(ret) {
            Ok(..) | Err(nix::Error::Sys(nix::errno::Errno::UnknownErrno)) => Ok(ret),
            Err(err) => Err(Box::new(err)),
        }
    }

    fn find_empty_watchpoint(&self) -> Option<usize> {
        self.hardware_breakpoints.iter().position(|w| w.is_none())
    }
}

/// Returns the start of a process's virtual memory address range.
/// This can be useful for calculation of relative addresses in memory.
pub fn get_addr_range(pid: Pid) -> CrabResult<usize> {
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

    use super::{memory::PAGE_SIZE, AttachOptions, LinuxTarget, ReadMemory};
    use nix::{
        sys::{
            mman::{mprotect, ProtFlags},
            ptrace, signal, wait,
        },
        unistd::{fork, getpid, ForkResult},
    };
    use std::alloc::{alloc_zeroed, dealloc, Layout};
    use std::sync::{Arc, Barrier};
    use std::{mem, ptr, thread, time};

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

    #[test]
    fn read_protected_memory() {
        let mut read_var1_op: u8 = 0;
        let mut read_var2_op: usize = 0;

        let var1: u8 = 1;
        let var2: usize = 2;

        let layout = Layout::from_size_align(2 * *PAGE_SIZE, *PAGE_SIZE).unwrap();

        unsafe {
            let ptr = alloc_zeroed(layout);

            match fork() {
                Ok(ForkResult::Child) => {
                    ptr::write(ptr, var1);

                    mprotect(
                        ptr as *mut std::ffi::c_void,
                        *PAGE_SIZE,
                        ProtFlags::PROT_WRITE,
                    )
                    .expect("Failed to mprotect");

                    // Wait for the parent to read memory before terminating this process
                    thread::sleep(time::Duration::from_millis(300));

                    dealloc(ptr, layout);
                }
                Ok(ForkResult::Parent { child, .. }) => {
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

                    assert_eq!(ptr::read_volatile(&read_var1_op), var1);
                    assert_eq!(ptr::read_volatile(&read_var2_op), var2);

                    dealloc(ptr, layout);

                    ptrace::cont(child, Some(signal::Signal::SIGCONT)).unwrap();

                    wait::waitpid(child, None).unwrap();
                }
                Err(x) => panic!(x),
            }
        }
    }

    /// This test attempts to read memory from 2 consecutive pages, one of which is read-protected.
    /// `ReadMemory` implementation should properly choose the memory reading strategy to cover this case:
    /// for read-protected page, it should use `ptrace()` and still return a valid result.
    #[test]
    fn read_cross_page_memory() {
        let mut read_var_op = vec![0u32; *PAGE_SIZE + 2];

        let mut var = vec![123u32; *PAGE_SIZE + 2];
        var[0] = 321;
        var[*PAGE_SIZE + 1] = 234;

        unsafe {
            let layout = Layout::from_size_align(*PAGE_SIZE * 3, *PAGE_SIZE).unwrap();
            let ptr = alloc_zeroed(layout);

            let array_ptr = ptr.offset((*PAGE_SIZE - mem::size_of::<u32>()) as isize);
            let second_page_ptr = ptr.offset(*PAGE_SIZE as _);

            match fork() {
                Ok(ForkResult::Child) => {
                    ptr::copy_nonoverlapping(var.as_ptr(), array_ptr as *mut u32, *PAGE_SIZE + 2);

                    mprotect(second_page_ptr as *mut _, *PAGE_SIZE, ProtFlags::PROT_WRITE)
                        .expect("Failed to mprotect");

                    // Parent reads memory
                    thread::sleep(time::Duration::from_millis(300));

                    std::process::exit(0);
                }
                Ok(ForkResult::Parent { child, .. }) => {
                    thread::sleep(time::Duration::from_millis(100));

                    let (target, _wait_status) =
                        LinuxTarget::attach(child, AttachOptions { kill_on_exit: true })
                            .expect("Couldn't attach to child");

                    target
                        .read()
                        .read_slice(&mut read_var_op, array_ptr as *const _ as usize)
                        .apply()
                        .expect("Failed to apply mem_op");

                    for i in 0..(*PAGE_SIZE + 2) {
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
    fn reads_threads() -> CrabResult<()> {
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
}
