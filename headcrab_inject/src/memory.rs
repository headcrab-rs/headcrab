// Based on https://github.com/bytecodealliance/wasmtime/blob/48fab12142c971405ab1c56fdceadf78bc2bbff4/cranelift/simplejit/src/memory.rs

use std::mem;

use headcrab::{target::LinuxTarget, CrabResult};

/// Round `size` up to the nearest multiple of `page_size`.
fn round_up_to_page_size(size: u64, page_size: u64) -> u64 {
    (size + (page_size - 1)) & !(page_size - 1)
}

/// A simple struct consisting of a pointer and length.
struct PtrLen {
    ptr: u64,
    len: u64,
}

impl PtrLen {
    /// Create a new empty `PtrLen`.
    fn new() -> Self {
        Self { ptr: 0, len: 0 }
    }

    /// Create a new `PtrLen` pointing to at least `size` bytes of memory,
    /// suitably sized and aligned for memory protection.
    fn with_size(target: &LinuxTarget, size: u64, prot: libc::c_int) -> CrabResult<Self> {
        let page_size = *headcrab::target::PAGE_SIZE as u64;
        let alloc_size = round_up_to_page_size(size, page_size);
        let ptr = target.mmap(
            0 as *mut _,
            alloc_size as usize,
            prot,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            0,
            0,
        )?;
        Ok(Self {
            ptr,
            len: alloc_size,
        })
    }
}

impl Drop for PtrLen {
    fn drop(&mut self) {
        if self.ptr != 0 {
            todo!("unmap")
        }
    }
}

/// JIT memory manager. This manages pages of suitably aligned and
/// accessible memory. Memory will be leaked by default to have
/// function pointers remain valid for the remainder of the
/// program's life.
pub struct Memory {
    prot: libc::c_int,
    allocations: Vec<PtrLen>,
    current: PtrLen,
    position: u64,
}

impl Memory {
    pub fn new_executable() -> Self {
        Self {
            prot: libc::PROT_READ | libc::PROT_EXEC,
            allocations: Vec::new(),
            current: PtrLen::new(),
            position: 0,
        }
    }

    pub fn new_readonly() -> Self {
        Self {
            prot: libc::PROT_READ,
            allocations: Vec::new(),
            current: PtrLen::new(),
            position: 0,
        }
    }

    pub fn new_writable() -> Self {
        Self {
            prot: libc::PROT_READ | libc::PROT_WRITE,
            allocations: Vec::new(),
            current: PtrLen::new(),
            position: 0,
        }
    }

    pub fn allocate(&mut self, target: &LinuxTarget, size: u64, align: u64) -> CrabResult<u64> {
        if self.position % align != 0 {
            self.position += align - self.position % align;
            debug_assert!(self.position % align as u64 == 0);
        }

        if size <= self.current.len - self.position {
            // TODO: Ensure overflow is not possible.
            let ptr = self.current.ptr + self.position;
            self.position += size;
            return Ok(ptr);
        }

        // Finish current
        self.allocations
            .push(mem::replace(&mut self.current, PtrLen::new()));
        self.position = 0;

        // TODO: Allocate more at a time.
        self.current = PtrLen::with_size(target, size, self.prot)?;
        self.position = size;
        Ok(self.current.ptr)
    }

    /// Frees all allocated memory regions that would be leaked otherwise.
    /// Likely to invalidate existing function pointers, causing unsafety.
    pub unsafe fn free_memory(&mut self) {
        self.allocations.clear();
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        // leak memory to guarantee validity of function pointers
        mem::take(&mut self.allocations)
            .into_iter()
            .for_each(mem::forget);
        mem::forget(mem::replace(&mut self.current, PtrLen::new()));
    }
}
