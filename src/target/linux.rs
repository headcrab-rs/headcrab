use crate::target::thread::Thread;
use crate::target::unix::{self, UnixTarget};
use nix::unistd::{getpid, Pid};
use procfs::process::Process;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    marker::PhantomData,
    mem,
};

struct LinuxThread {
    name: String,
    id: i32,
}

impl LinuxThread {
    fn new(name: impl Into<String>, id: i32) -> LinuxThread {
        LinuxThread {
            name: name.into(),
            id,
        }
    }
}

impl Thread for LinuxThread {
    type ThreadId = i32;

    fn name(&self) -> Option<String> {
        Some(self.name.clone())
    }

    fn thread_id(&self) -> Self::ThreadId {
        self.id
    }
}

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
    pub fn launch(path: &str) -> Result<LinuxTarget, Box<dyn std::error::Error>> {
        let pid = unix::launch(path)?;
        Ok(LinuxTarget { pid })
    }

    /// Attaches process as a debugee.
    pub fn attach(pid: Pid) -> Result<LinuxTarget, Box<dyn std::error::Error>> {
        unix::attach(pid)?;
        Ok(LinuxTarget { pid })
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

    /// Returns the current snapshot view of this debugee process threads.
    pub fn threads(
        &self,
    ) -> Result<Vec<Box<dyn Thread<ThreadId = i32>>>, Box<dyn std::error::Error>> {
        let tasks: Vec<_> = Process::new(self.pid.as_raw())?
            .tasks()?
            .flatten()
            .collect();

        let mut result: Vec<Box<dyn Thread<ThreadId = i32>>> = vec![];
        for task in tasks {
            let t_stat = task.stat()?;
            let thread = LinuxThread::new(&t_stat.comm, task.tid);
            result.push(Box::new(thread))
        }
        Ok(result)
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
        self.read_ops.push(ReadOp {
            remote_base,
            len: mem::size_of::<T>(),
            local_ptr: val as *mut T as *mut libc::c_void,
        });

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

        if bytes_read == -1 {
            // fixme: return a proper error type
            return Err(Box::new(nix::Error::last()));
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
    use super::*;

    use nix::unistd::getpid;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use std::alloc::{alloc_zeroed, dealloc, Layout};

    use nix::sys::mman::{mprotect, ProtFlags};

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
        let mut read_var_op: usize = 0;

        unsafe {
            let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();
            let ptr = alloc_zeroed(layout);

            *(ptr as *mut usize) = 9921;

            mprotect(
                ptr as *mut std::ffi::c_void,
                PAGE_SIZE,
                ProtFlags::PROT_NONE,
            )
            .expect("Failed to mprotect");

            let res = ReadMemory::new(getpid())
                .read(&mut read_var_op, ptr as *const _ as usize)
                .apply();

            // Expected to fail when reading read-protected memory.
            // FIXME: Change when reading read-protected memory is handled properly
            match res {
                Ok(()) => panic!("Unexpected result: reading protected memory succeeded"),
                Err(_) => (),
            }

            mprotect(
                ptr as *mut std::ffi::c_void,
                PAGE_SIZE,
                ProtFlags::PROT_WRITE,
            )
            .expect("Failed to mprotect");
            dealloc(ptr, layout);
        }
    }

    #[test]
    fn read_cross_page_memory() {
        let mut read_var_op = [0u32; 2];

        unsafe {
            let layout = Layout::from_size_align(PAGE_SIZE * 2, PAGE_SIZE).unwrap();
            let ptr = alloc_zeroed(layout);

            let array_ptr = (ptr as usize + PAGE_SIZE - std::mem::size_of::<u32>()) as *mut u8;
            *(array_ptr as *mut [u32; 2]) = [123, 456];

            let second_page_ptr = (ptr as usize + PAGE_SIZE) as *mut std::ffi::c_void;

            mprotect(second_page_ptr, PAGE_SIZE, ProtFlags::PROT_NONE).expect("Failed to mprotect");

            ReadMemory::new(getpid())
                .read(&mut read_var_op, array_ptr as *const _ as usize)
                .apply()
                .expect("Failed to apply memop");

            // Expected result because of cross page read
            // FIXME: Change when cross page read is handled correctly
            assert_eq!([123, 0], read_var_op);

            mprotect(second_page_ptr, PAGE_SIZE, ProtFlags::PROT_WRITE)
                .expect("Failed to mprotect");
            dealloc(ptr, layout);
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
            .map(|t| (t.name().unwrap().clone(), t.thread_id()))
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
