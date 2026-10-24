use std::ffi::CString;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

pub fn used_fraction(path: &Path) -> std::io::Result<f64> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "a NUL in the path"))?;

    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };

    let rc = unsafe { libc::statvfs(c.as_ptr(), core::ptr::addr_of_mut!(st)) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fraction(u64::from(st.f_blocks), u64::from(st.f_bfree), u64::from(st.f_bavail)))
}

fn fraction(blocks: u64, free: u64, avail: u64) -> f64 {
    let used = blocks.saturating_sub(free);
    let usable = used.saturating_add(avail);
    if usable == 0 {

        return 1.0;
    }
    used as f64 / usable as f64
}
