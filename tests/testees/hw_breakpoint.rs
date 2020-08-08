#[no_mangle]
static mut STATICVAR: u8 = 100;
#[no_mangle]
static mut STATICVAR2: u8 = 100;
#[no_mangle]
static mut STATICVAR3: u8 = 100;

pub fn main() {
    unsafe {
        std::ptr::write_volatile(&mut STATICVAR, 200);
        std::ptr::write_volatile(&mut STATICVAR2, 200);
        std::ptr::write_volatile(&mut STATICVAR3, 200);
    }
}
