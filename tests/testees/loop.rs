#[inline(never)]
#[no_mangle]
fn breakpoint(counter: u8) -> () {
    println!("- {} -", counter);
}

fn main() {
    for i in 0..8 {
        breakpoint(i);
    }
}
