use super::memory::{split_protected, MemoryOp};
use super::LinuxTarget;
use nix::{sys::ptrace, unistd::Pid};
use std::{cmp, marker::PhantomData, mem, slice};

const WORD_SIZE: usize = mem::size_of::<usize>();

/// Write operations don't have any unique properties at this time.
/// If needed, later this can be replaced with `struct WriteOp(MemoryOp, <extra props>)`.
type WriteOp = MemoryOp;

/// Allows to write data to different locations in debuggee's memory as a single operation.
/// This implementation can select different strategies for different memory pages.
pub struct WriteMemory<'a> {
    target: &'a LinuxTarget,
    write_ops: Vec<WriteOp>,
    /// We need only an immutable reference because we don't rewrite values of variables in `WriteOp`.
    _marker: PhantomData<&'a ()>,
}

impl<'a> WriteMemory<'a> {
    pub(super) fn new(target: &'a LinuxTarget) -> Self {
        WriteMemory {
            target,
            write_ops: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Writes a value of type `T` into debuggee's memory at location `remote_base`.
    /// The value will be read from the provided variable `val`.
    /// You should call `apply` in order to execute the memory write operation.
    /// The lifetime of the variable `val` is bound to the lifetime of `WriteMemory`.
    pub fn write<T: ?Sized>(mut self, val: &'a T, remote_base: usize) -> Self {
        WriteOp::split_on_page_boundary(
            &WriteOp {
                remote_base,
                local_ptr: val as *const T as *mut libc::c_void,
                local_ptr_len: mem::size_of_val(val),
            },
            &mut self.write_ops,
        );
        self
    }

    /// Writes a slice of type `T` into debuggee's memory at location `remote_base`.
    /// The entries will be read from the provided slice `val`.
    /// You should call `apply` in order to execute the memory write operation.
    /// The lifetime of the variable `val` is bound to the lifetime of `WriteMemory`.
    pub fn write_slice<T>(mut self, val: &'a [T], remote_base: usize) -> Self {
        WriteOp::split_on_page_boundary(
            &WriteOp {
                remote_base,
                local_ptr: val.as_ptr() as *mut libc::c_void,
                local_ptr_len: val.len() * mem::size_of::<T>(),
            },
            &mut self.write_ops,
        );
        self
    }

    /// Executes the memory write operation.
    ///
    /// # Remote safety
    ///
    /// It's a user's responsibility to ensure that debuggee memory addresses are valid.
    /// This function only reads memory from the local process.
    pub fn apply(self) -> Result<(), Box<dyn std::error::Error>> {
        let protected_maps = self
            .target
            .memory_maps()?
            .into_iter()
            .filter(|map| !map.is_writable)
            .collect::<Vec<_>>();

        let (protected, writable) = split_protected(&protected_maps, self.write_ops.into_iter())?;

        // Break write operations into word groups.
        let protected_groups = protected
            .into_iter()
            .flat_map(|op| op.into_word_sized_ops());

        unsafe {
            if !writable.is_empty() {
                write_process_vm(self.target.pid, &writable)?;
            }
            write_ptrace(self.target.pid, protected_groups)?;
        }

        Ok(())
    }

    /// Executes memory writing operations using ptrace only.
    /// This function should be used only for testing purposes.
    #[cfg(test)]
    unsafe fn apply_ptrace(self) -> Result<(), Box<dyn std::error::Error>> {
        write_ptrace(
            self.target.pid,
            self.write_ops
                .into_iter()
                .flat_map(|op| op.into_word_sized_ops()),
        )?;
        Ok(())
    }
}

/// Breaks the memory write operation into groups of words suitable for writing
/// with `ptrace::write`.
///
/// ptrace(PTRACE_POKETEXT) can write only a single word (usize) to the destination address.
/// So if we want to write e.g. 1 byte, we need to read 8 bytes at the destination address
/// first, replace the first byte, and overwrite it at the destination address again.
/// Obviously, this is very inefficient since it requires a lot of context switches,
/// but sometimes it's the only way to overwrite the target's memory.
struct WordSizedOps {
    mem_op: WriteOp,
}

impl WriteOp {
    /// Converts this memory operation into an iterator that returns word-sized memory operations.
    /// This is required for ptrace which is not capable of writing data larger than a single word
    /// (which is equal to usize - or 8 bytes - on x86_64).
    fn into_word_sized_ops(self) -> WordSizedOps {
        WordSizedOps { mem_op: self }
    }
}

impl Iterator for WordSizedOps {
    type Item = WriteOp;

    /// Produces a next word for writing to debuggee's memory.
    ///
    /// # Safety
    ///
    /// This function doesn't guarantee safety of produced pointers.
    /// It's a user's responsibility to ensure the validity of provided memory addresses and sizes.
    fn next(&mut self) -> Option<MemoryOp> {
        if self.mem_op.local_ptr_len == 0 {
            return None;
        }

        let group_size = cmp::min(WORD_SIZE, self.mem_op.local_ptr_len);

        let output = WriteOp {
            remote_base: self.mem_op.remote_base,
            local_ptr: self.mem_op.local_ptr,
            local_ptr_len: group_size,
        };

        self.mem_op.local_ptr_len -= group_size;
        self.mem_op.local_ptr = unsafe { self.mem_op.local_ptr.offset(group_size as isize) };
        self.mem_op.remote_base += group_size;

        Some(output)
    }
}

/// Allows to write to write-protected pages.
/// On Linux, this will result in multiple system calls and it's inefficient.
pub(crate) unsafe fn write_ptrace(
    pid: Pid,
    write_ops: impl Iterator<Item = MemoryOp>,
) -> Result<(), Box<dyn std::error::Error>> {
    for op in write_ops {
        assert!(op.local_ptr_len <= WORD_SIZE);

        if op.local_ptr_len < WORD_SIZE {
            // Write op is smaller than a single word, so we should read memory before rewriting it.
            let mut word = ptrace::read(pid, op.remote_base as *mut _)?.to_ne_bytes();
            let src_bytes: &[u8] =
                slice::from_raw_parts(op.local_ptr as *const _, op.local_ptr_len);

            for offset in 0..op.local_ptr_len {
                word[offset] = src_bytes[offset];
            }

            ptrace::write(
                pid,
                op.remote_base as *mut _,
                usize::from_ne_bytes(word) as *mut usize as *mut _,
            )?;
        } else {
            let word = op.local_ptr.cast::<usize>().read();
            ptrace::write(pid, op.remote_base as *mut _, word as *mut _)?;
        }
    }

    Ok(())
}

/// Allows to write data to different locations in debuggee's memory as a single operation.
/// It requires a memory page to be writable.
pub(crate) unsafe fn write_process_vm(
    pid: Pid,
    write_ops: &[WriteOp],
) -> Result<(), Box<dyn std::error::Error>> {
    // Create a list of `IoVec`s and remote `IoVec`s
    let remote_iov = write_ops
        .iter()
        .map(WriteOp::as_remote_iovec)
        .collect::<Vec<_>>();

    let local_iov = write_ops
        .iter()
        .map(WriteOp::as_local_iovec)
        .collect::<Vec<_>>();

    let bytes_written = libc::process_vm_writev(
        pid.into(),
        local_iov.as_ptr(),
        local_iov.len() as libc::c_ulong,
        remote_iov.as_ptr(),
        remote_iov.len() as libc::c_ulong,
        0,
    );

    if bytes_written == -1 {
        // fixme: return a proper error type
        return Err(Box::new(nix::Error::last()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{write_process_vm, WriteMemory, WriteOp};
    use crate::target::linux::memory::PAGE_SIZE;
    use crate::target::LinuxTarget;
    use libc::c_void;
    use nix::{
        sys::{
            mman::{mprotect, ProtFlags},
            ptrace, wait,
        },
        unistd::{self, fork, getppid, ForkResult},
    };
    use std::{
        alloc::{alloc_zeroed, dealloc, Layout},
        mem, ptr,
    };

    #[test]
    fn write_memory_proc_vm() {
        let var: usize = 52;
        let var2: u8 = 128;

        let write_var_op: usize = 0;
        let write_var2_op: u8 = 0;

        let target = LinuxTarget::me();

        let write_mem = WriteMemory::new(&target)
            .write(&var, &write_var_op as *const _ as usize)
            .write(&var2, &write_var2_op as *const _ as usize);

        unsafe {
            write_process_vm(target.pid, &write_mem.write_ops).expect("Failed to write memory")
        };

        unsafe {
            assert_eq!(ptr::read_volatile(&write_var_op), var);
            assert_eq!(ptr::read_volatile(&write_var2_op), var2);
        }
    }

    #[test]
    fn write_memory_ptrace() {
        let var: usize = 52;
        let var2: u8 = 128;
        let dyn_array = vec![1, 2, 3, 4];

        let write_var_op: usize = 0;
        let write_var2_op: u8 = 0;
        let write_array = [0u8; 4];

        // Use a pipe for synchronization between parent & child processes.
        let (read_pipe, write_pipe) = unistd::pipe().unwrap();

        // ptrace::attach() is not allowed to be called on its own process, so we do a fork.
        // child process writes to the parent's memory instead of the other way around because it's easier to
        // check results with assert_eq! this way.
        match fork() {
            Ok(ForkResult::Child) => {
                let parent = getppid();
                let (target, _wait_stat) = LinuxTarget::attach(parent, Default::default()).unwrap();

                // Write memory to parent's process
                let write_mem = target
                    .write()
                    .write(&var, &write_var_op as *const _ as usize)
                    .write(&var2, &write_var2_op as *const _ as usize)
                    .write_slice(&dyn_array, &write_array as *const _ as usize);

                unsafe { write_mem.apply_ptrace().expect("Failed to write memory") };

                // Close the write end of the pipe for synchronization with the parent.
                unistd::close(write_pipe).unwrap();

                ptrace::detach(parent, None).unwrap();
            }
            Ok(ForkResult::Parent { .. }) => {
                // Sleep & wait for the child to send us SIGCONT
                unistd::close(write_pipe).unwrap();
                let _ = unistd::read(read_pipe, &mut [0]).unwrap();

                unsafe {
                    assert_eq!(ptr::read_volatile(&write_var_op), var);
                    assert_eq!(ptr::read_volatile(&write_var2_op), var2);
                    assert_eq!(&ptr::read_volatile(&write_array), dyn_array.as_slice());
                }
            }
            Err(x) => panic!(x),
        }
    }

    #[test]
    fn write_protected_memory() {
        let var: usize = 101;
        let var2: u8 = 102;

        // Allocate an empty page and make it read-only
        let layout = Layout::from_size_align(2 * *PAGE_SIZE, *PAGE_SIZE).unwrap();
        let (write_protected_ptr, write_protected_ptr2) = unsafe {
            let ptr = alloc_zeroed(layout);
            mprotect(
                ptr as *mut std::ffi::c_void,
                *PAGE_SIZE,
                ProtFlags::PROT_READ,
            )
            .expect("Failed to mprotect");

            (
                ptr as *const usize,
                ptr.offset(mem::size_of::<usize>() as _),
            )
        };

        // Use a pipe for synchronization between parent & child processes.
        let (read_pipe, write_pipe) = unistd::pipe().unwrap();

        // ptrace::attach() is not allowed to be called on its own process, so we do a fork.
        // child process writes to the parent's memory instead of the other way around because it's easier to
        // check results with assert_eq! this way.
        match fork() {
            Ok(ForkResult::Child) => {
                let parent = getppid();
                let (target, _wait_stat) = LinuxTarget::attach(parent, Default::default()).unwrap();

                // Write memory to parent's process
                let write_mem = target
                    .write()
                    .write(&var, write_protected_ptr as usize)
                    .write(&var2, write_protected_ptr2 as usize);

                unsafe {
                    // FIXME: we deliberately use `apply_ptrace()` instead of `apply()` because `apply()` depends on
                    // `lazy_static` to read the debuggee memory maps, and `lazy_static` uses
                    // `std::sync::Once` which can have undefined behaviour in a forked process:
                    // https://github.com/rust-lang/rust/issues/43448
                    // This can be fixed by either _not_ using fork or not using `lazy_static` while
                    // reading memory maps.
                    write_mem.apply_ptrace().expect("Failed to write memory");
                }

                // Close the write end of the pipe for synchronization with the parent.
                unistd::close(write_pipe).unwrap();

                ptrace::detach(parent, None).unwrap();
            }
            Ok(ForkResult::Parent { child, .. }) => unsafe {
                // Synchronize with the child - the read end of the pipe will be blocked until it's closed by the child process.
                unistd::close(write_pipe).unwrap();
                let _ = unistd::read(read_pipe, &mut [0]).unwrap();

                assert_eq!(ptr::read_volatile(write_protected_ptr), var);
                assert_eq!(ptr::read_volatile(write_protected_ptr2), var2);

                // 'Unprotect' memory so that it can be deallocated
                mprotect(
                    write_protected_ptr as *mut _,
                    *PAGE_SIZE,
                    ProtFlags::PROT_WRITE | ProtFlags::PROT_READ,
                )
                .expect("Failed to mprotect");
                dealloc(write_protected_ptr as *mut _, layout);

                wait::waitpid(child, None).unwrap();
            },
            Err(x) => panic!(x),
        };
    }

    /// Tests transformation of `WriteOp` into groups of words suitable for use in `ptrace::write`.
    #[test]
    fn ptrace_write_groups() {
        let arr = [42u64, 64u64];

        let write_op = WriteOp {
            remote_base: 0x100,
            local_ptr: &arr[0] as *const _ as *mut c_void,
            local_ptr_len: mem::size_of_val(&arr),
        };

        assert_eq!(
            &write_op.into_word_sized_ops().collect::<Vec<_>>()[..],
            &[
                WriteOp {
                    remote_base: 0x100,
                    local_ptr: &arr[0] as *const _ as *mut c_void,
                    local_ptr_len: mem::size_of::<u64>(),
                },
                WriteOp {
                    remote_base: 0x100 + mem::size_of::<u64>(),
                    local_ptr: &arr[1] as *const _ as *mut c_void,
                    local_ptr_len: mem::size_of::<u64>(),
                }
            ][..]
        );
    }

    /// Tests transformation of `WriteOp` into groups suitable for use in `ptrace::write`.
    /// Check that the uneven-sized write operations break down into correct groups.
    #[test]
    fn ptrace_write_groups_packed() {
        #[repr(packed(2))]
        struct PackedStruct {
            v1: u64,
            v2: u16,
        }
        let val = PackedStruct { v1: 42, v2: 256 };

        let write_op = WriteOp {
            remote_base: 0x100,
            local_ptr: &val as *const _ as *mut c_void,
            local_ptr_len: mem::size_of_val(&val),
        };

        unsafe {
            assert_eq!(
                &write_op.into_word_sized_ops().collect::<Vec<_>>()[..],
                &[
                    WriteOp {
                        remote_base: 0x100,
                        local_ptr: &val.v1 as *const _ as *mut c_void,
                        local_ptr_len: mem::size_of::<u64>(),
                    },
                    WriteOp {
                        remote_base: 0x100 + mem::size_of::<u64>(),
                        local_ptr: &val.v2 as *const _ as *mut c_void,
                        local_ptr_len: mem::size_of::<u16>(),
                    }
                ][..]
            );
        }
    }
}
