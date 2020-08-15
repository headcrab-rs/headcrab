static STATICVAR: &str = "Hello, world!\n";

#[no_mangle]
#[inline(never)]
fn breakpoint() {
    // This will be patched by the debugger to be a breakpoint
    unsafe { core::arch::x86_64::_mm_pause(); }
}

#[inline(never)]
fn black_box<T>(v: T) {
    unsafe { std::ptr::read_volatile(&v); }
}

pub fn main() {
    let var = 42usize;
    let reg_var = 43usize;
    {
        let mut temp = 100usize;
        black_box(&mut temp);
    }
    black_box(reg_var);
    breakpoint();
    black_box(reg_var);
    println!("{} {}", STATICVAR, var);
}
