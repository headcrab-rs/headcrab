use super::memory::{split_protected, MemoryOp};
use super::LinuxTarget;
use nix::{sys::ptrace, unistd::Pid};
use std::{cmp, marker::PhantomData, mem, slice};

const WORD_SIZE: usize = mem::size_of::<usize>();

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
    ///
    /// # Safety
    ///
    /// The type `T` must not have any invalid values.
    /// For example `T` must not be a `bool`, as `transmute::<u8, bool>(2)` is not a valid value for a bool.
    /// In case of doubt, wrap the type in [`mem::MaybeUninit`].
    pub fn write<T: ?Sized>(mut self, val: &'a T, remote_base: usize) -> Self {
        self.write_ops.push(WriteOp {
            remote_base,
            source_len: mem::size_of_val(val),
            source_ptr: val as *const T as *const libc::c_void,
        });
        self
    }

    /// Executes the memory write operation.
    pub unsafe fn apply(self) -> Result<(), Box<dyn std::error::Error>> {
        let protected_maps = self
            .target
            .memory_maps()?
            .into_iter()
            .filter(|map| !map.is_writable)
            .collect::<Vec<_>>();

        let (protected, writable) = split_protected(&protected_maps, self.write_ops.into_iter())?;

        write_process_vm(self.target.pid, &writable)?;
        write_ptrace(self.target.pid, &protected)?;

        Ok(())
    }
}

/// A single memory write operation.
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub(crate) struct WriteOp {
    /// Remote destation location.
    remote_base: usize,
    /// Pointer to a source.
    source_ptr: *const libc::c_void,
    /// Size of `source_ptr`.
    source_len: usize,
}

impl MemoryOp for WriteOp {
    fn remote_base(&self) -> usize {
        self.remote_base
    }
}

impl WriteOp {
    /// Converts the memory write operation into a remote IoVec.
    fn as_remote_iovec(&self) -> libc::iovec {
        libc::iovec {
            iov_base: self.remote_base as *const libc::c_void as *mut _,
            iov_len: self.source_len,
        }
    }

    /// Converts the memory write operation into a local IoVec.
    fn as_local_iovec(&self) -> libc::iovec {
        libc::iovec {
            iov_base: self.source_ptr as *mut _,
            iov_len: self.source_len,
        }
    }

    /// Breaks the memory write operation into groups of words suitable for writing
    /// with `ptrace::write`.
    unsafe fn as_ptrace(&self) -> Vec<WriteOp> {
        let mut output = Vec::with_capacity((self.source_len + WORD_SIZE - 1) / WORD_SIZE);

        let WriteOp {
            mut source_len,
            mut source_ptr,
            mut remote_base,
        } = self;

        while source_len > 0 {
            let group_size = cmp::min(WORD_SIZE, source_len);

            output.push(WriteOp {
                remote_base,
                source_ptr,
                source_len: group_size,
            });

            source_len -= group_size;
            source_ptr = source_ptr.offset(group_size as isize);
            remote_base += group_size;
        }

        output
    }
}

/// Allows to write to write-protected pages.
/// On Linux, this will result in multiple system calls and it's inefficient.
pub(crate) unsafe fn write_ptrace(
    pid: Pid,
    write_ops: &[WriteOp],
) -> Result<(), Box<dyn std::error::Error>> {
    // ptrace(PTRACE_POKETEXT) can write only a single word (usize) to the destination address.
    // So if we want to write e.g. 1 byte, we need to read 8 bytes at the destination address
    // first, replace the first byte, and overwrite it at the destination address again.
    // Obviously, this is very inefficient since it requires a lot of context switches,
    // but sometimes it's the only way to overwrite the target's memory.

    // Break write ops into groups of <usize> bytes.
    let write_op_groups = write_ops.iter().flat_map(|op| op.as_ptrace());

    for op in write_op_groups {
        assert!(op.source_len <= WORD_SIZE);

        if op.source_len < WORD_SIZE {
            // Write op is smaller than a single word, so we should read memory before rewriting it.
            let mut word = ptrace::read(pid, op.remote_base as *mut _)?.to_ne_bytes();
            let src_bytes: &[u8] = slice::from_raw_parts(op.source_ptr as *const _, op.source_len);

            for offset in 0..op.source_len {
                word[offset] = src_bytes[offset];
            }

            ptrace::write(
                pid,
                op.remote_base as *mut _,
                usize::from_ne_bytes(word) as *mut usize as *mut _,
            )?;
        } else {
            let word = op.source_ptr.cast::<usize>().read();
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
    use super::{write_process_vm, write_ptrace, WriteMemory, WriteOp};
    use crate::target::LinuxTarget;
    use libc::c_void;
    use nix::{
        sys::{ptrace, signal, wait},
        unistd::{fork, getppid, ForkResult},
    };
    use std::{mem, ptr};

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

        let write_var_op: usize = 0;
        let write_var2_op: u8 = 0;

        // ptrace::attach() is not allowed to be called on its own process, so we do a fork.
        // child process writes to the parent's memory instead of the other way around because it's easier to
        // check results with assert_eq! this way.
        match fork() {
            Ok(ForkResult::Child) => {
                let parent = getppid();
                let (target, _wait_stat) = LinuxTarget::attach(parent, Default::default()).unwrap();

                let write_mem = WriteMemory::new(&target)
                    .write(&var, &write_var_op as *const _ as usize)
                    .write(&var2, &write_var2_op as *const _ as usize);

                unsafe {
                    write_ptrace(target.pid, &write_mem.write_ops).expect("Failed to write memory")
                };

                ptrace::cont(parent, Some(signal::Signal::SIGCONT)).unwrap();
            }
            Ok(ForkResult::Parent { child, .. }) => {
                wait::waitpid(child, None).unwrap();

                unsafe {
                    assert_eq!(ptr::read_volatile(&write_var_op), var);
                    assert_eq!(ptr::read_volatile(&write_var2_op), var2);
                }
            }
            Err(x) => panic!(x),
        }
    }

    /// Tests transformation of `WriteOp` into groups of words suitable for use in `ptrace::write`.
    #[test]
    fn ptrace_write_groups() {
        let arr = [42u64, 64u64];

        let write_op = WriteOp {
            remote_base: 0x100,
            source_len: mem::size_of_val(&arr),
            source_ptr: &arr[0] as *const _ as *const c_void,
        };

        assert_eq!(
            unsafe { &write_op.as_ptrace()[..] },
            &[
                WriteOp {
                    remote_base: 0x100,
                    source_len: mem::size_of::<u64>(),
                    source_ptr: &arr[0] as *const _ as *const c_void,
                },
                WriteOp {
                    remote_base: 0x100 + mem::size_of::<u64>(),
                    source_len: mem::size_of::<u64>(),
                    source_ptr: &arr[1] as *const _ as *const c_void,
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
            source_len: mem::size_of_val(&val),
            source_ptr: &val as *const _ as *const c_void,
        };

        unsafe {
            assert_eq!(
                &write_op.as_ptrace()[..],
                &[
                    WriteOp {
                        remote_base: 0x100,
                        source_len: mem::size_of::<u64>(),
                        source_ptr: &val.v1 as *const _ as *const c_void,
                    },
                    WriteOp {
                        remote_base: 0x100 + mem::size_of::<u64>(),
                        source_len: mem::size_of::<u16>(),
                        source_ptr: &val.v2 as *const _ as *const c_void,
                    }
                ][..]
            );
        }
    }
}
