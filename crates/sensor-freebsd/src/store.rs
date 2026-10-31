use std::path::{Path, PathBuf};

use crate::tools::{Invocation, RunError, Runner, Tool};

pub const STORE_DIR: &str = "/root/hemostat";

pub const QUOTA_BYTES: u64 = 256 * 1024 * 1024;

pub const RESERVED_BYTES: u64 = 32 * 1024 * 1024;

pub const SHARED_BYTES: u64 = QUOTA_BYTES - RESERVED_BYTES;

pub const DISK_FILESYSTEMS: &[&str] = &["ufs", "zfs"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {

    pub device: String,

    pub mountpoint: String,

    pub fstype: String,
}

pub fn parse_mount_p(text: &str) -> Result<Vec<Mount>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let (Some(dev), Some(mp), Some(ty)) = (f.first(), f.get(1), f.get(2)) else {
            return Err(format!("mount -p line {} is not an fstab line: {line:?}", n + 1));
        };
        if f.len() > 6 || !mp.starts_with('/') {
            return Err(format!("mount -p line {} is not an fstab line: {line:?}", n + 1));
        }
        out.push(Mount { device: unescape(dev), mountpoint: unescape(mp), fstype: (*ty).to_string() });
    }
    Ok(out)
}

fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        let oct = b.get(i + 1..i + 4).filter(|d| c == b'\\' && d.iter().all(|x| (b'0'..=b'7').contains(x)));
        match oct.and_then(|d| u8::from_str_radix(core::str::from_utf8(d).ok()?, 8).ok()) {
            Some(v) => {
                out.push(v);
                i += 4;
            }
            None => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn covering<'a>(mounts: &'a [Mount], path: &str) -> Option<&'a Mount> {
    let under = |mp: &str| {
        mp == "/" || path == mp || path.strip_prefix(mp).is_some_and(|rest| rest.starts_with('/'))
    };
    mounts
        .iter()
        .enumerate()
        .filter(|(_, m)| under(&m.mountpoint))
        .max_by_key(|(i, m)| (m.mountpoint.len(), *i))
        .map(|(_, m)| m)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {

    MountTable(String),

    NoMount,

    NotDisk(Mount),

    MemoryDisk(Mount),

    Disagrees(Mount),

    NotADirectory(String),

    Mode(String, u32),

    Io(String),
}

impl core::fmt::Display for Refused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Refused::MountTable(why) => write!(f, "the mount table could not be read: {why}"),
            Refused::NoMount => f.write_str("no mount covers the store path"),
            Refused::NotDisk(m) => write!(
                f,
                "{} is {} on {}, not a disk: a reboot would delete the evidence",
                m.mountpoint, m.fstype, m.device
            ),
            Refused::MemoryDisk(m) => {
                write!(f, "{} is on {}, a memory disk: a reboot would delete the evidence", m.mountpoint, m.device)
            }
            Refused::Disagrees(m) => {
                write!(f, "mount -p puts it on {} ({}), and the filesystem says otherwise", m.mountpoint, m.device)
            }
            Refused::NotADirectory(p) => write!(f, "{p} is not a plain directory"),
            Refused::Mode(p, m) => write!(
                f,
                "{p} is mode {m:o}, open to group or other, and a store must sit in a directory only its \
                 owner can open. If {p} is HEMOSTAT's own, `chmod 700 {p}` fixes it (look at what is in it \
                 first: something opened it); otherwise name a private directory with --store"
            ),
            Refused::Io(why) => f.write_str(why),
        }
    }
}

pub fn judge_mount(m: &Mount) -> Result<(), Refused> {
    if !DISK_FILESYSTEMS.contains(&m.fstype.as_str()) {
        return Err(Refused::NotDisk(m.clone()));
    }
    let md = m.device.strip_prefix("/dev/md").is_some_and(|n| n.bytes().next().is_some_and(|b| b.is_ascii_digit()));
    if md {
        return Err(Refused::MemoryDisk(m.clone()));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {

    pub dir: String,

    pub mount: Mount,

    pub exists: bool,
}

pub fn place(runner: &mut dyn Runner, root: &Path, dir: &str) -> Result<Placement, Refused> {
    let out = runner
        .run(&Invocation::new(Tool::Mount, &["-p"]).max_output(1024 * 1024))
        .map_err(|e: RunError| Refused::MountTable(e.to_string()))?;
    if !out.success() {
        return Err(Refused::MountTable(format!("mount -p exited {:?}", out.status)));
    }
    let mounts = parse_mount_p(&out.text()).map_err(Refused::MountTable)?;
    let mount = covering(&mounts, dir).ok_or(Refused::NoMount)?.clone();
    judge_mount(&mount)?;
    placed_on(root, dir, mount)
}

#[cfg(unix)]
fn placed_on(root: &Path, dir: &str, mount: Mount) -> Result<Placement, Refused> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let full = root.join(dir.trim_start_matches('/'));
    let exists = match std::fs::symlink_metadata(&full) {
        Ok(md) if md.file_type().is_dir() => {
            let mode = md.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(Refused::Mode(dir.into(), mode));
            }
            true
        }
        Ok(_) => return Err(Refused::NotADirectory(dir.into())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(Refused::Io(e.to_string())),
    };
    let mut probe: PathBuf = full.clone();
    while !probe.exists() {
        if !probe.pop() {
            return Err(Refused::NoMount);
        }
    }
    let here = std::fs::metadata(&probe).map_err(|e| Refused::Io(e.to_string()))?;
    let mp = std::fs::metadata(root.join(mount.mountpoint.trim_start_matches('/')))
        .map_err(|e| Refused::Io(e.to_string()))?;
    if here.dev() != mp.dev() {
        return Err(Refused::Disagrees(mount));
    }
    Ok(Placement { dir: dir.into(), mount, exists })
}

#[cfg(not(unix))]
fn placed_on(_root: &Path, dir: &str, _mount: Mount) -> Result<Placement, Refused> {
    Err(Refused::NotADirectory(dir.into()))
}

#[cfg(unix)]
pub fn create_private(path: &Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let is_dir = |p: &Path| match std::fs::symlink_metadata(p) {
        Ok(md) if md.file_type().is_dir() => Ok(true),
        Ok(_) => Err(Error::new(ErrorKind::InvalidInput, format!("{} is not a plain directory", p.display()))),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    };
    let mut missing = Vec::new();
    let mut p = path;
    while !p.as_os_str().is_empty() && !is_dir(p)? {
        missing.push(p);
        p = p.parent().unwrap_or(Path::new(""));
    }
    for d in missing.into_iter().rev() {
        match std::fs::DirBuilder::new().mode(0o700).create(d) {
            Ok(()) => {}

            Err(e) if e.kind() == ErrorKind::AlreadyExists && is_dir(d)? => continue,
            Err(e) => return Err(e),
        }
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(d)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn create_private(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

#[cfg(unix)]
pub fn used(dir: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)? {
            let e = e?;
            let md = std::fs::symlink_metadata(e.path())?;
            if md.file_type().is_dir() {
                stack.push(e.path());
            } else if md.file_type().is_file() {
                total = total.saturating_add(md.len());
            }
        }
    }
    Ok(total)
}

#[derive(Debug)]
pub struct Store {

    pub placement: Placement,
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverQuota {

    pub used: u64,

    pub wanted: u64,

    pub limit: u64,
}

impl core::fmt::Display for OverQuota {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.limit < QUOTA_BYTES {
            write!(
                f,
                "the store holds {} bytes; {} more would reach into its last {} MiB, which are kept for the seals \
                 fw block, fw confirm and undo make before a config write. Ship or copy the older stores under \
                 {STORE_DIR} off the box, then remove them, to make room",
                self.used,
                self.wanted,
                RESERVED_BYTES / (1024 * 1024)
            )
        } else {
            write!(f, "the store holds {} bytes; {} more would pass its {QUOTA_BYTES}-byte quota", self.used, self.wanted)
        }
    }
}

#[cfg(unix)]
impl Store {

    pub fn open(runner: &mut dyn Runner, root: &Path) -> Result<Store, Refused> {
        let placement = place(runner, root, STORE_DIR)?;
        let path = root.join(STORE_DIR.trim_start_matches('/'));
        if !placement.exists {
            create_private(&path).map_err(|e| Refused::Io(format!("{}: {e}", path.display())))?;
        }
        Ok(Store { placement, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn admit(&self, wanted: u64) -> Result<(), OverQuota> {
        admitted(self.held(), wanted, SHARED_BYTES)
    }

    pub fn admit_reserved(&self, wanted: u64) -> Result<(), OverQuota> {
        admitted(self.held(), wanted, QUOTA_BYTES)
    }

    pub fn room(&self) -> u64 {
        SHARED_BYTES.saturating_sub(self.held())
    }

    fn held(&self) -> u64 {
        used(&self.path).unwrap_or(u64::MAX)
    }
}

#[cfg(unix)]
fn admitted(used: u64, wanted: u64, limit: u64) -> Result<(), OverQuota> {
    if used.saturating_add(wanted) > limit {
        return Err(OverQuota { used, wanted, limit });
    }
    Ok(())
}
