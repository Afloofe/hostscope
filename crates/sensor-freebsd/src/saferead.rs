use std::fs;
use std::io::{Error, ErrorKind, Read as _};
use std::path::Path;

pub const MAX_SCAN_BYTES: u64 = 4 * 1024 * 1024;

pub const MAX_HASH_BYTES: u64 = 1 << 30;

pub const NOT_REGULAR: &str =
    "not a regular file — a symlink, named pipe, socket or device is never read";

#[cfg(unix)]
fn no_follow_flags() -> i32 {
    libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY
}

#[cfg(unix)]
pub fn open_regular(path: &Path, refusal: &str) -> std::io::Result<(fs::File, fs::Metadata)> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file() {
        return Err(Error::new(ErrorKind::InvalidInput, refusal.to_string()));
    }
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(no_follow_flags())
        .open(path)
        .map_err(|e| {

            if e.kind() == ErrorKind::NotFound {
                e
            } else {
                Error::new(e.kind(), format!("{refusal} ({e})"))
            }
        })?;
    let md = f.metadata()?;
    if !md.is_file() || md.dev() != before.dev() || md.ino() != before.ino() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("{refusal} (the path changed between the check and the open)"),
        ));
    }
    Ok((f, md))
}

#[cfg(unix)]
pub fn read_scan_target_bounded(path: &Path) -> Option<(String, bool)> {
    let (f, md) = open_regular(path, NOT_REGULAR).ok()?;
    let mut buf = Vec::new();
    (&f).take(MAX_SCAN_BYTES).read_to_end(&mut buf).ok()?;
    Some((String::from_utf8_lossy(&buf).into_owned(), md.len() > MAX_SCAN_BYTES))
}

#[cfg(unix)]
pub fn read_text(path: &Path) -> std::io::Result<String> {
    let bytes = read_bytes(path, MAX_SCAN_BYTES)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(unix)]
pub fn read_bytes(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    let (f, md) = open_regular(path, NOT_REGULAR)?;
    read_open(&f, &md, max)
}

#[cfg(unix)]
pub fn read_whole_file(path: &Path, max: u64) -> Option<Vec<u8>> {
    read_bytes(path, max).ok()
}

#[cfg(unix)]
pub(crate) fn read_open(f: &fs::File, md: &fs::Metadata, max: u64) -> std::io::Result<Vec<u8>> {
    let over = |n: u64| Error::new(ErrorKind::InvalidData, format!("{n} bytes, over the {max}-byte cap"));
    if md.len() > max {
        return Err(over(md.len()));
    }
    let mut buf = Vec::with_capacity(usize::try_from(md.len()).unwrap_or(0));
    f.take(max.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(over(buf.len() as u64));
    }
    Ok(buf)
}

#[cfg(unix)]
pub fn sha256_of(path: &Path) -> std::io::Result<[u8; 32]> {
    let (f, md) = open_regular(path, NOT_REGULAR)?;
    if md.len() > MAX_HASH_BYTES {
        return Err(Error::new(ErrorKind::InvalidData, format!("{} bytes, over the hash cap", md.len())));
    }
    let mut t = Throttle::unlimited();
    sha256_reader(&f, MAX_HASH_BYTES, &mut t)
}

pub(crate) fn sha256_reader(r: impl std::io::Read, limit: u64, t: &mut Throttle) -> std::io::Result<[u8; 32]> {
    use sha2::{Digest as _, Sha256};
    let mut r = r.take(limit.saturating_add(1));
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut seen = 0u64;
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                seen = seen.saturating_add(n as u64);
                h.update(buf.get(..n).unwrap_or_default());
                t.spent(n as u64);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    if seen > limit {
        return Err(Error::new(ErrorKind::InvalidData, format!("over the {limit}-byte hash cap")));
    }
    Ok(h.finalize().into())
}

pub(crate) fn sha256_bytes(bytes: &[u8], t: &mut Throttle) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    for chunk in bytes.chunks(256 * 1024) {
        h.update(chunk);
        t.spent(chunk.len() as u64);
    }
    h.finalize().into()
}

pub const HASH_BYTES_PER_SEC: u64 = 32 * 1024 * 1024;

#[derive(Debug)]
pub struct Throttle {
    rate: u64,
    start: std::time::Instant,
    burst: u64,
    total: u64,
}

impl Throttle {

    pub fn new(rate: u64) -> Self {
        Throttle { rate, start: std::time::Instant::now(), burst: 0, total: 0 }
    }

    pub fn unlimited() -> Self {
        Throttle::new(0)
    }

    pub fn spent(&mut self, n: u64) {
        self.total = self.total.saturating_add(n);
        if self.rate == 0 {
            return;
        }
        let budget = |bytes: u64| std::time::Duration::from_secs_f64(bytes as f64 / self.rate as f64);
        if self.start.elapsed() > budget(self.burst) + std::time::Duration::from_secs(1) {
            self.start = std::time::Instant::now();
            self.burst = 0;
        }
        self.burst = self.burst.saturating_add(n);
        let due = budget(self.burst);
        let elapsed = self.start.elapsed();
        if due > elapsed {
            std::thread::sleep(due - elapsed);
        }
    }

    pub fn bytes(&self) -> u64 {
        self.total
    }
}
