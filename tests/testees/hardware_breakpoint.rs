#[no_mangle]
static mut STATICVAR: u8 = 100;

pub fn main() {
    unsafe {
        STATICVAR = 200;
    }
}
