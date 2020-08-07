#[no_mangle]
static mut STATICVAR: u8 = 100;
#[no_mangle]
static mut STATICVAR2: u8 = 100;
#[no_mangle]
static mut STATICVAR3: u8 = 100;

pub fn main() {
    unsafe {
        STATICVAR = 200;
        STATICVAR2 = 200;
        STATICVAR3 = 200;
    }
}
