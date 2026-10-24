pub fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(target_os = "linux")]
pub struct Sealed {
    fd: std::os::fd::OwnedFd,
    digest: String,
    len: usize,
}

#[cfg(target_os = "linux")]
impl core::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sealed")
            .field("digest", &self.digest)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
impl Sealed {

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.fd.as_fd()
    }

    pub fn new(bytes: &[u8]) -> Result<Self, String> {
        use std::os::fd::{FromRawFd as _, OwnedFd};

        if bytes.is_empty() {
            return Err("refusing to seal an empty image: there would be nothing to relaunch".into());
        }

        let name = c"hemostat-image";

        let raw = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        if raw < 0 {
            return Err(format!("memfd_create failed: {}", std::io::Error::last_os_error()));
        }

        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let mut written = 0usize;
        while written < bytes.len() {
            let chunk = bytes.get(written..).unwrap_or_default();

            let n = unsafe {
                libc::write(
                    std::os::fd::AsRawFd::as_raw_fd(&fd),
                    chunk.as_ptr().cast(),
                    chunk.len(),
                )
            };
            if n <= 0 {
                return Err(format!(
                    "writing the image into the memfd failed after {written} of {} bytes: {}",
                    bytes.len(),
                    std::io::Error::last_os_error()
                ));
            }
            written += n as usize;
        }

        let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

        let rc = unsafe {
            libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&fd), libc::F_ADD_SEALS, seals)
        };
        if rc != 0 {
            return Err(format!("sealing the image failed: {}", std::io::Error::last_os_error()));
        }

        Ok(Sealed { fd, digest: digest(bytes), len: bytes.len() })
    }

    pub fn from_path(path: &std::path::Path) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("could not read {} to seal it: {e}", path.display()))?;
        Self::new(&bytes)
    }

    pub fn sealed(&self) -> bool {

        let got = unsafe {
            libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&self.fd), libc::F_GET_SEALS)
        };
        got >= 0 && (got & libc::F_SEAL_WRITE) != 0 && (got & libc::F_SEAL_SEAL) != 0
    }
}
