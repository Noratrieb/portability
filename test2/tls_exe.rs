#![feature(thread_local)]
#![no_std]
#![no_main]
#![windows_subsystem = "console"]

#[panic_handler]
fn handle_panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[thread_local]
static mut A_THREAD_LOCAL: u32 = 50;
#[thread_local]
static mut ANOTHER_THREAD_LOCAL: u32 = 55;

#[inline(never)]
fn set_tls(value: u32) {
    unsafe { A_THREAD_LOCAL = value; }
    unsafe { ANOTHER_THREAD_LOCAL = value; }
}

#[no_mangle]
pub extern "stdcall" fn mainCRTStartup() -> u32 {
    // Use some indirection to actually force TLS to happen
    set_tls(14);
    unsafe { A_THREAD_LOCAL + ANOTHER_THREAD_LOCAL }
}

#[no_mangle]
pub extern "stdcall" fn _tls_index() {}
