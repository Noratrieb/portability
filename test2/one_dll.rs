#![no_std]
#![no_main]
#![windows_subsystem = "console"]

#[link(name = "small_dll", kind = "raw-dylib")]
unsafe extern "C" {
    safe fn my_export() -> u32;
}

#[panic_handler]
fn handle_panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "stdcall" fn mainCRTStartup() -> u32 {
    my_export()
}
