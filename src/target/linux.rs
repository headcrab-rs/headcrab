mod memory;
mod readmem;

use crate::target::thread::Thread;
use crate::target::unix::{self, UnixTarget};
use nix::unistd::{getpid, Pid};
use procfs::process::{Process, Task};
use procfs::ProcError;
use std::{
    ffi::CString,
    fs::File,
    io::{BufRead, BufReader},
};

pub use readmem::ReadMemory;

lazy_static::lazy_static! {
    static ref PAGE_SIZE: usize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
}

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
}

/// This structure is used to pass options to attach
pub struct AttachOptions {
    /// Determines whether process will be killed on debugger exit or crash.
    pub kill_on_exit: bool,
}

impl UnixTarget for LinuxTarget {
    /// Provides the Pid of the debuggee process
    fn pid(&self) -> Pid {
        self.pid
    }
}

impl LinuxTarget {
    /// Launches a new debuggee process
    pub fn launch(
        path: &str,
    ) -> Result<(LinuxTarget, nix::sys::wait::WaitStatus), Box<dyn std::error::Error>> {
        let (pid, status) = unix::launch(CString::new(path)?)?;
        let target = LinuxTarget { pid };
        target.kill_on_exit()?;
        Ok((target, status))
    }

    /// Attaches process as a debuggee.
    pub fn attach(
        pid: Pid,
        options: AttachOptions,
    ) -> Result<(LinuxTarget, nix::sys::wait::WaitStatus), Box<dyn std::error::Error>> {
        let status = unix::attach(pid)?;
        let target = LinuxTarget { pid };

        if options.kill_on_exit {
            target.kill_on_exit()?;
        }

        Ok((target, status))
    }

    /// Uses this process as a debuggee.
    pub fn me() -> LinuxTarget {
        LinuxTarget { pid: getpid() }
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
                    is_writable: perms.next() == Some('w'),
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
            let target = LinuxTarget { pid: getpid() };
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
}
