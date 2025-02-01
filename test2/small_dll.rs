#![no_std]
#![crate_type = "cdylib"]
#![windows_subsystem = "console"]

#[panic_handler]
fn handle_panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn my_export() -> u32 {
    43
}

#[no_mangle]
pub extern "stdcall" fn _DllMainCRTStartup() -> u32 {
    0
}
