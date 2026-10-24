#[cfg(target_os = "windows")]
pub fn fill(buf: &mut [u8]) -> Result<(), String> {
    use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};

    for chunk in buf.chunks_mut(u32::MAX as usize) {

        let status = unsafe {
            BCryptGenRandom(core::ptr::null_mut(), chunk.as_mut_ptr(), chunk.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
        };
        if status != 0 {
            return Err(format!("BCryptGenRandom returned {status:#x}"));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn fill(_buf: &mut [u8]) -> Result<(), String> {
    Err("this binary was not built for Windows".into())
}
