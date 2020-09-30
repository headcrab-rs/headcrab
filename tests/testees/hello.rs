static STATICVAR: &str = "Hello, world!\n";

#[no_mangle]
#[inline(never)]
fn breakpoint() {
    unsafe {
        core::arch::x86_64::_mm_pause();
    }
}

#[inline(never)]
fn black_box<T>(v: T) {
    unsafe {
        std::ptr::read_volatile(&v);
    }
}

struct A {
    b: u8,
    c: &'static u8,
}

pub fn main() {
    let var = 42usize;
    let reg_var = 43usize;
    {
        let mut temp = 100usize;
        black_box(&mut temp);
    }
    black_box(reg_var);
    let a = A { b: 42, c: &43 };
    black_box(&a);
    breakpoint();
    black_box(reg_var);
    println!("{} {}", STATICVAR, var);
}
