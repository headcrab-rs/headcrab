static STATICVAR: &str = "Hello, world!\n";

pub fn main() {

    use std::{thread, time};
    thread::sleep(time::Duration::from_millis(100));

    println!("{}", STATICVAR);
}
