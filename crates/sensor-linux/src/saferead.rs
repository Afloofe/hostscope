use std::fs;
use std::path::Path;

pub const MAX_SCAN_BYTES: u64 = 4 * 1024 * 1024;

pub fn read_scan_target(path: &Path) -> Option<String> {
    read_scan_target_bounded(path).map(|(text, _)| text)
}

pub fn read_scan_target_bounded(path: &Path) -> Option<(String, bool)> {
    use std::io::Read as _;

    let (f, md) = open_regular(path, NOT_REGULAR).ok()?;
    let mut buf = Vec::new();
    (&f).take(MAX_SCAN_BYTES).read_to_end(&mut buf).ok()?;

    let truncated = md.len() > MAX_SCAN_BYTES;
    Some((String::from_utf8_lossy(&buf).into_owned(), truncated))
}

pub fn read_whole_file(path: &Path, max: u64) -> Option<Vec<u8>> {
    use std::io::Read as _;

    let (f, md) = open_regular(path, NOT_REGULAR).ok()?;
    if md.len() > max {
        return None;
    }
    let mut buf = Vec::with_capacity(usize::try_from(md.len()).ok()?);
    (&f).take(max).read_to_end(&mut buf).ok()?;
    Some(buf)
}

pub const MAX_HASH_BYTES: u64 = 1 << 30;

pub fn sha256_file(path: &Path) -> Option<[u8; 32]> {
    sha256_of(path).ok()
}

pub fn sha256_of(path: &Path) -> std::io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use std::io::{Error, ErrorKind, Read as _};
    let (f, md) = open_regular(path, NOT_REGULAR)?;
    let over = |len: u64| {
        Error::new(ErrorKind::InvalidData, format!("{len} bytes, over the {MAX_HASH_BYTES}-byte hash cap"))
    };
    if md.len() > MAX_HASH_BYTES {
        return Err(over(md.len()));
    }

    let mut f = (&f).take(MAX_HASH_BYTES + 1);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut seen = 0u64;
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                seen += n as u64;
                h.update(buf.get(..n).unwrap_or_default());
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    if seen > MAX_HASH_BYTES {
        return Err(over(seen));
    }
    Ok(h.finalize().into())
}

pub const NOT_REGULAR: &str = "not a regular file — a named pipe, socket or device is never opened";

pub fn open_regular(path: &Path, refusal: &str) -> std::io::Result<(fs::File, fs::Metadata)> {
    use std::io::{Error, ErrorKind};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let at = open_o_path(path)?;
    let md = at.metadata()?;
    if !md.is_file() {
        return Err(Error::new(ErrorKind::InvalidInput, refusal.to_string()));
    }
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(format!("/proc/self/fd/{}", at.as_raw_fd()))
        .map_err(|e| {

            if e.kind() == ErrorKind::NotFound {
                Error::other(format!("not reopened through /proc/self/fd ({e})"))
            } else {
                e
            }
        })?;
    Ok((f, md))
}

pub fn open_o_path(path: &Path) -> std::io::Result<fs::File> {
    use std::os::fd::{FromRawFd as _, OwnedFd};

    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL"))?;

    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

fn sha256_stream(r: impl std::io::Read, limit: u64) -> Option<([u8; 32], u64)> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;
    let mut r = r.take(limit);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                h.update(buf.get(..n)?);
                total = total.saturating_add(n as u64);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    Some((h.finalize().into(), total))
}

pub fn image_id(path: &Path) -> Option<(u64, [u8; 32])> {
    let (f, _) = open_regular(path, NOT_REGULAR).ok()?;
    let (digest, len) = sha256_stream(&f, MAX_HASH_BYTES)?;
    Some((len, digest))
}

pub fn is_image(path: &Path, ours: &(u64, [u8; 32])) -> bool {
    open_regular(path, NOT_REGULAR).is_ok_and(|(f, md)| md.len() == ours.0 && reads_as_image(&f, ours))
}

fn reads_as_image(r: impl std::io::Read, ours: &(u64, [u8; 32])) -> bool {
    sha256_stream(r, ours.0.saturating_add(1)).is_some_and(|(digest, n)| n == ours.0 && digest == ours.1)
}

pub const MAX_PROC_BYTES: u64 = 1024 * 1024;

pub fn read_proc(path: &Path, cap: u64) -> std::io::Result<(Vec<u8>, bool)> {
    read_bounded(fs::File::open(path)?, cap)
}

pub(crate) fn read_bounded(mut r: impl std::io::Read, cap: u64) -> std::io::Result<(Vec<u8>, bool)> {
    let limit = usize::try_from(cap).unwrap_or(usize::MAX).saturating_add(1);
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0_u8; 64 * 1024];
    while buf.len() < limit {
        let want = chunk.len().min(limit - buf.len());
        let Some(into) = chunk.get_mut(..want) else { break };
        let n = match r.read(into) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let Some(got) = chunk.get(..n) else { break };
        if buf.capacity() - buf.len() < n {
            buf.reserve_exact(buf.capacity().max(n).min(limit - buf.len()));
        }
        buf.extend_from_slice(got);
    }
    let truncated = buf.len() as u64 > cap;
    buf.truncate(usize::try_from(cap).unwrap_or(usize::MAX));
    Ok((buf, truncated))
}

pub fn read_kernel_text(path: impl AsRef<Path>) -> std::io::Result<String> {
    fs::read(path).map(|b| String::from_utf8_lossy(&b).into_owned())
}

pub const MAX_MAPS_BYTES: u64 = 64 * 1024 * 1024;

pub fn read_kernel_text_capped(path: impl AsRef<Path>, cap: u64) -> std::io::Result<(String, bool)> {
    let (mut buf, truncated) = read_proc(path.as_ref(), cap)?;
    if truncated {
        let whole = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        buf.truncate(whole);
    }
    let text = String::from_utf8(buf)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
    Ok((text, truncated))
}

pub fn read_text(path: &Path) -> std::io::Result<String> {
    use std::io::{Error, ErrorKind, Read as _};

    let (f, md) = open_regular(
        path,
        "not a regular file — a named pipe, socket or device cannot be read as \
         configuration, and opening one is how this sweep is made to wait forever",
    )?;
    if md.len() > MAX_SCAN_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("{} bytes, over the {MAX_SCAN_BYTES}-byte cap", md.len()),
        ));
    }
    let mut buf = Vec::new();
    (&f).take(MAX_SCAN_BYTES).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

pub fn read_bytes(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind, Read as _};

    let (f, md) = open_regular(
        path,
        "not a regular file — a named pipe, socket or device cannot be read as content, \
         and opening one is how this is made to wait forever",
    )?;
    if md.len() > max {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("{} bytes, over the {max}-byte cap", md.len()),
        ));
    }
    let mut buf = Vec::with_capacity(usize::try_from(md.len()).unwrap_or(0));
    (&f).take(max).read_to_end(&mut buf)?;
    Ok(buf)
}
