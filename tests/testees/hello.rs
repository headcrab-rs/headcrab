static STATICVAR: &str = "Hello, world!\n";

#[no_mangle]
#[inline(never)]
fn breakpoint() {
    // This will be patched by the debugger to be a breakpoint
    unsafe { core::arch::x86_64::_mm_pause(); }
}


pub fn main() {
    breakpoint();
    println!("{}", STATICVAR);
}
