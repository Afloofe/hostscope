use std::io;

const URANDOM: &str = "/dev/urandom";

pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    match getrandom(buf) {
        Ok(()) => Ok(()),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) => from_device(buf),
        Err(e) => Err(e),
    }
}

fn getrandom(buf: &mut [u8]) -> io::Result<()> {
    let mut done = 0;
    while let Some(rest) = buf.get_mut(done..).filter(|r| !r.is_empty()) {

        let n = unsafe { libc::syscall(libc::SYS_getrandom, rest.as_mut_ptr().cast::<libc::c_void>(), rest.len(), 0_u32) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        match usize::try_from(n) {
            Ok(k) if k > 0 && k <= rest.len() => done += k,
            _ => return Err(io::Error::other(format!("getrandom(2) returned {n} for {} byte(s)", rest.len()))),
        }
    }
    Ok(())
}

fn from_device(buf: &mut [u8]) -> io::Result<()> {
    use std::io::Read as _;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _};
    let mut f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(URANDOM)?;

    let m = f.metadata()?;
    urandom_device(m.file_type().is_char_device(), m.rdev()).map_err(|why| io::Error::new(io::ErrorKind::InvalidData, why))?;
    f.read_exact(buf)
}

fn urandom_device(is_char: bool, rdev: u64) -> Result<(), String> {
    let (major, minor) = (libc::major(rdev), libc::minor(rdev));
    if is_char && (major, minor) == (1, 9) {
        return Ok(());
    }
    Err(if is_char {
        format!(
            "{URANDOM} is character device {major}:{minor}, not the kernel's urandom (1:9) — refusing \
             to make key material from it"
        )
    } else {
        format!("{URANDOM} is not a character device — refusing to make key material from it")
    })
}
