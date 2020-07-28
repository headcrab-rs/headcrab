static STATICVAR: &str = "Hello, world!\n";

#[no_mangle]
#[inline(never)]
fn a_function() {}

pub fn main() {
    a_function();
    println!("{}", STATICVAR);
}
