#![no_std]
#![no_main]

#[panic_handler]
fn handle_panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "stdcall" fn my_main() {}
