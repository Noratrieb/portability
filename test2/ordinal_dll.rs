#![no_std]
#![crate_type = "cdylib"]
#![windows_subsystem = "console"]

#[panic_handler]
fn handle_panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn my_export_ordinal_1() -> u32 {
    1
}

#[no_mangle]
pub extern "C" fn my_export_ordinal_2() -> u32 {
    2
}

#[no_mangle]
pub extern "C" fn my_export_named() -> u32 {
    5
}

#[no_mangle]
pub extern "stdcall" fn _DllMainCRTStartup() -> u32 {
    0
}
