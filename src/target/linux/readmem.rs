use super::{
    memory::{split_protected, MemoryOp},
    LinuxTarget,
};
use crate::CrabResult;
use nix::{sys::ptrace, unistd::Pid};
use std::{marker::PhantomData, mem};

/// Read operations don't have any unique properties at this time.
/// If needed, later this can be replaced with `struct ReadOp(MemoryOp, <extra props>)`.
type ReadOp = MemoryOp;

/// Allows to read memory from different locations in debuggee's memory as a single operation.
pub struct ReadMemory<'a> {
    target: &'a LinuxTarget,
    read_ops: Vec<ReadOp>,
    /// This requires a mutable reference because we rewrite values of variables in `ReadOp`.
    _marker: PhantomData<&'a mut ()>,
}

impl<'a> ReadMemory<'a> {
    pub(in crate::target) fn new(target: &'a LinuxTarget) -> Self {
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
    /// For example, `T` must not be a `bool`, as `transmute::<u8, bool>(2)` is not a valid value for a bool.
    /// In case of doubt, wrap the type in [`mem::MaybeUninit`].
    // todo: further document mem safety - e.g., what happens in the case of partial read
    pub unsafe fn read<T>(mut self, val: &'a mut T, remote_base: usize) -> Self {
        MemoryOp::split_on_page_boundary(
            &MemoryOp {
                remote_base,
                local_ptr: val as *mut T as *mut libc::c_void,
                local_ptr_len: mem::size_of::<T>(),
            },
            &mut self.read_ops,
        );
        self
    }

    /// Reads a value of type `*mut T` from debuggee's memory at location `remote_base`.
    /// This value will be written to the provided pointer `ptr`.
    /// You should call `apply` in order to execute the memory read operation.
    /// The provided pointer `ptr` can't be accessed until either `apply` is called or `self` is
    /// dropped.
    ///
    /// # Safety
    ///
    /// Memory location at `ptr` must be of valid size and must not be outlived by `ReadMem`.
    /// You need to ensure the lifetime guarantees, and generally you should prefer using `read<T>(&mut val)`.
    // todo: further document mem safety - e.g., what happens in the case of partial read
    pub unsafe fn read_ptr<T>(mut self, ptr: *mut T, remote_base: usize) -> Self {
        MemoryOp::split_on_page_boundary(
            &MemoryOp {
                remote_base,
                local_ptr: ptr as *mut _,
                local_ptr_len: mem::size_of::<T>(),
            },
            &mut self.read_ops,
        );
        self
    }

    /// Reads a slice of type `&mut [T]` from debuggee's memory at location `remote_base`.
    /// This value will be written to the provided slice `val`.
    /// You should call `apply` in order to execute the memory read operation.
    /// The provided value `val` can't be accessed until either `apply` is called or `self` is
    /// dropped.
    ///
    /// # Safety
    ///
    /// The type `T` must not have any invalid values.
    /// For example, `T` must not be a `bool`, as `transmute::<u8, bool>(2)` is not a valid value for a bool.
    /// In case of doubt, wrap the type in [`mem::MaybeUninit`].
    // todo: further document mem safety - e.g., what happens in the case of partial read
    pub unsafe fn read_slice<T>(mut self, val: &'a mut [T], remote_base: usize) -> Self {
        MemoryOp::split_on_page_boundary(
            &MemoryOp {
                remote_base,
                local_ptr: val.as_mut_ptr() as *mut _,
                local_ptr_len: val.len() * mem::size_of::<T>(),
            },
            &mut self.read_ops,
        );
        self
    }

    /// Reads a `u8` byte slice from debuggee's memory at location `remote_base`.
    /// This value will be written to the provided slice `val`.
    /// You should call `apply` in order to execute the memory read operation.
    pub fn read_byte_slice<T>(mut self, val: &'a mut [u8], remote_base: usize) -> Self {
        MemoryOp::split_on_page_boundary(
            &MemoryOp {
                remote_base,
                local_ptr: val.as_mut_ptr() as *mut _,
                local_ptr_len: val.len(),
            },
            &mut self.read_ops,
        );
        self
    }

    /// Executes the memory read operation.
    pub fn apply(self) -> CrabResult<()> {
        let pid = self.target.pid;
        let read_len = self
            .read_ops
            .iter()
            .fold(0, |sum, read_op| sum + read_op.local_ptr_len);

        if read_len > isize::MAX as usize {
            panic!("Read size too big");
        };

        // FIXME: Probably a better way to do this - see if we can get info about pages protection from
        // cache and predict whether this operation will require ptrace or plain read_process_vm would work.
        let result = Self::read_process_vm(pid, &self.read_ops);

        if result.is_err() && result.unwrap_err() == nix::Error::Sys(nix::errno::Errno::EFAULT)
            || result.is_ok() && result.unwrap() != read_len as isize
        {
            let protected_maps = self
                .target
                .memory_maps()?
                .into_iter()
                .filter(|map| !map.is_readable)
                .collect::<Vec<_>>();

            let (protected, readable) = split_protected(&protected_maps, self.read_ops.into_iter());

            Self::read_process_vm(pid, &readable)?;
            Self::read_ptrace(pid, &protected)?;
        }
        Ok(())
    }

    /// Allows to read from several different locations with one system call.
    /// It will error on pages that are not readable. Returns number of bytes read at granularity of ReadOps.
    fn read_process_vm(pid: Pid, read_ops: &[ReadOp]) -> Result<isize, nix::Error> {
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
                pid.into(),
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

    /// Allows to read from protected memory pages.
    /// This operation results in multiple system calls and is inefficient.
    fn read_ptrace(pid: Pid, read_ops: &[MemoryOp]) -> CrabResult<()> {
        let long_size = std::mem::size_of::<std::os::raw::c_long>();

        for read_op in read_ops {
            let mut offset: usize = 0;
            // Read until all of the data is read
            while offset < read_op.local_ptr_len {
                let data =
                    ptrace::read(pid, (read_op.remote_base + offset) as *mut std::ffi::c_void)?;

                // Read full word. No need to preserve other data
                if (read_op.local_ptr_len - offset) >= long_size {
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
                            read_op.local_ptr_len - offset,
                        );
                        let data_bytes = data.to_ne_bytes();

                        previous_bytes[0..(read_op.local_ptr_len - offset)]
                            .clone_from_slice(&data_bytes[0..(read_op.local_ptr_len - offset)]);
                    }
                }
                offset += long_size;
            }
        }
        Ok(())
    }
}
