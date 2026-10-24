#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {

    loop {}
}

#[no_mangle]
#[link_section = "lsm/task_kill"]
pub extern "C" fn task_kill(_ctx: *mut core::ffi::c_void) -> i32 {
    0
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
