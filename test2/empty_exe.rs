#![no_std]
#![no_main]
#![windows_subsystem = "console"]

#[panic_handler]
fn handle_panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "stdcall" fn mainCRTStartup() -> u32 {
    42
}
