#![no_std]
#![no_main]
#![windows_subsystem = "console"]

#[link(name = "small_dll", kind = "raw-dylib")]
unsafe extern "C" {
    safe fn my_export() -> u32;
}

#[link(name = "ordinal_dll", kind = "raw-dylib")]
unsafe extern "C" {
    #[link_ordinal(1)]
    safe fn my_export_ordinal_1() -> u32;
    #[link_ordinal(2)]
    safe fn my_export_ordinal_2() -> u32;
    safe fn my_export_named() -> u32;
}

#[panic_handler]
fn handle_panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "stdcall" fn mainCRTStartup() -> u32 {
    my_export()
        .wrapping_add(my_export_ordinal_1())
        .wrapping_add(my_export_ordinal_2())
        .wrapping_add(my_export_named())
}
