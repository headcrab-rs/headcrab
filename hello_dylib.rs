#![crate_type = "cdylib"]
#![no_std]

extern "C" {
    fn puts(_: *const u8);
}

#[panic_handler]
fn panic_handler(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
unsafe extern "C" fn __headcrab_command() {
    puts("Hello World from dylib!\0" as *const str as *const u8);
}
