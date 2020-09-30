#[inline(never)]
#[no_mangle]
fn breakpoint(counter: u8) -> () {
    println!("- {} -", counter);
}

fn main() {
    let breaks = 8;
    for i in 0..breaks {
        breakpoint(i);
    }
    println!("Called `breakpoint` {} times.", breaks);
}
