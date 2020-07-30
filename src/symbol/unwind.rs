/// This is a naive stack unwinder that returns all words that could be interpreted as return
/// address for a known function.
pub fn naive_unwinder<'a>(
    debuginfo: &'a super::RelocatedDwarf,
    stack: &'a [usize],
    rip: usize,
) -> impl Iterator<Item = usize> + 'a {
    std::iter::once(rip).chain(stack.iter().cloned().filter(move |addr| {
        debuginfo.get_address_symbol_kind(*addr) == Some(object::SymbolKind::Text)
    }))
}

struct FramePointerUnwinder<'a> {
    stack: &'a [usize],
    stack_offset: usize,
    rbp: usize,
}

impl Iterator for FramePointerUnwinder<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        println!("stack_offset={:x} rbp={:x}", self.stack_offset, self.rbp);
        if self.rbp >= self.stack_offset && self.rbp < self.stack_offset + self.stack.len() * 8 {
            let ip = self.stack[(self.rbp - self.stack_offset) / 8 + 1];
            println!("ip={:x}", ip);
            self.rbp = self.stack[(self.rbp - self.stack_offset) / 8];
            Some(ip)
        } else {
            None
        }
    }
}

/// This is a frame pointer based unwinder. It expects the frame pointer to form a linked list.
/// May require `-Cforce-frame-pointers=yes`.
pub fn frame_pointer_unwinder<'a>(
    _debuginfo: &'a super::RelocatedDwarf,
    stack: &'a [usize],
    rip: usize,
    stack_offset: usize,
    rbp: usize,
) -> impl Iterator<Item = usize> + 'a {
    std::iter::once(rip).chain(FramePointerUnwinder {
        stack,
        stack_offset,
        rbp,
    })
}
