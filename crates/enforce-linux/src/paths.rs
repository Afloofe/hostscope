use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::action::ProcVerb;

pub(crate) fn exe_suffix(exe: &Option<String>) -> String {
    match exe {
        Some(e) => format!(" ({e})"),
        None => String::new(),
    }
}

pub(crate) fn verb_word(v: ProcVerb) -> &'static str {
    match v {
        ProcVerb::Kill => "kill",
        ProcVerb::Suspend => "suspend",
    }
}

pub(crate) fn sig_name(sig: libc::c_int) -> &'static str {
    match sig {
        libc::SIGKILL => "SIGKILL",
        libc::SIGSTOP => "SIGSTOP",
        libc::SIGCONT => "SIGCONT",
        _ => "signal",
    }
}

pub(crate) const DECLARED_PROTECT_FILE: &str = "/etc/hemostat/protect";

pub(crate) fn read_declarations() -> Option<String> {
    match hemostat_sensor_linux::saferead::read_text(std::path::Path::new(DECLARED_PROTECT_FILE)) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(String::new()),
        Err(_) => None,
    }
}

pub(crate) fn declarations_unreadable() -> bool {
    read_declarations().is_none()
        || hemostat_sensor_linux::services::declarations_unreadable()
}

pub(crate) fn read_declared_users() -> BTreeSet<String> {
    read_declarations()
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix("user:"))
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .collect()
}

pub(crate) fn read_declared_protections() -> BTreeSet<String> {
    let mut out: BTreeSet<String> = read_declarations()
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))

        .filter(|l| !l.starts_with("user:"))
        .map(str::to_string)
        .collect();

    let resolved: Vec<String> = out
        .iter()
        .filter(|d| d.starts_with('/'))
        .filter_map(|d| {
            let trailing = d.ends_with('/');
            let c = std::fs::canonicalize(d.trim_end_matches('/')).ok()?;
            let c = c.to_string_lossy().into_owned();
            Some(if trailing { format!("{c}/") } else { c })
        })
        .collect();
    out.extend(resolved);
    out.extend(hemostat_sensor_linux::services::protected_names(
        &hemostat_sensor_linux::services::declarations(),
    ));
    out
}

pub fn udev_reload() -> Result<(), String> {
    let Some(udevadm) = resolve_tool(&["/usr/bin/udevadm", "/bin/udevadm", "/sbin/udevadm"]) else {
        return Err("udevadm not found".into());
    };
    run_tool(&udevadm, &["control", "--reload-rules"])
}

pub fn daemon_reload() -> Result<(), String> {
    let Some(systemctl) = resolve_tool(&["/usr/bin/systemctl", "/bin/systemctl"]) else {
        return Err("systemctl not found".into());
    };
    run_tool(&systemctl, &["daemon-reload"])
}

pub(crate) fn path_refusal(path: &Path) -> Option<String> {
    if path.as_os_str().is_empty() || path == Path::new("/") {
        return Some("the path is empty or the root directory".into());
    }

    let mut views = Vec::new();
    match canonical_parent(path) {
        Some(p) => views.push(p),
        None => {
            return Some(
                "the path's directory could not be resolved; refusing rather than acting \
                 on an unverified target"
                    .into(),
            )
        }
    }
    if let Ok(full) = fs::canonicalize(path) {
        views.push(full);
    }

    for v in &views {
        let p = v.to_string_lossy();
        for guarded in ["/proc/", "/sys/", "/dev/"] {
            if p.starts_with(guarded) {
                return Some(format!("{guarded} is a pseudo-filesystem and must not be moved"));
            }
        }
        if p == "/" {
            return Some("the path is empty or the root directory".into());
        }
    }

    if same_file(path, Path::new("/proc/self/exe")) {
        return Some("that is the agent's own executable".into());
    }
    None
}

pub(crate) fn canonical_parent(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?;
    let parent = path.parent()?;
    let base = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    Some(fs::canonicalize(base).ok()?.join(name))
}

pub(crate) fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
        _ => false,
    }
}

pub fn open_unredirected(path: &Path) -> std::io::Result<fs::File> {
    use std::ffi::{CString, OsString};
    use std::io::{Error, ErrorKind};
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Component;

    fn open_at(dir: &fs::File, name: &CString, flags: libc::c_int) -> std::io::Result<fs::File> {

        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(Error::last_os_error());
        }

        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    fn push_components(todo: &mut Vec<OsString>, p: &Path) {
        let names = p.components().filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
        });
        let names: Vec<OsString> = names.collect();
        todo.extend(names.into_iter().rev());
    }

    const MAX_LINKS: usize = 40;
    const DIR: libc::c_int = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    const FILE: libc::c_int = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;

    if !path.is_absolute() {
        return Err(Error::new(ErrorKind::InvalidInput, "not an absolute path"));
    }

    let root = || {

        let fd = unsafe { libc::open(c"/".as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(Error::last_os_error());
        }

        Ok(unsafe { fs::File::from_raw_fd(fd) })
    };

    let mut dirs: Vec<fs::File> = vec![root()?];
    let mut todo: Vec<OsString> = Vec::new();
    push_components(&mut todo, path);
    let mut links = 0usize;

    while let Some(name) = todo.pop() {
        let last = todo.is_empty();
        if name == ".." {
            if dirs.len() > 1 {
                dirs.pop();
            }
            if last {
                return Err(Error::new(ErrorKind::InvalidInput, "the path names a directory"));
            }
            continue;
        }
        let Some(dir) = dirs.last() else {
            return Err(Error::other("lost the directory being walked"));
        };
        let cname = CString::new(name.as_bytes())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "NUL in a path component"))?;
        let err = match open_at(dir, &cname, if last { FILE } else { DIR }) {
            Ok(f) if last => return Ok(f),
            Ok(f) => {
                dirs.push(f);
                continue;
            }
            Err(e) => e,
        };
        if last {
            return Err(if err.raw_os_error() == Some(libc::ELOOP) {
                Error::new(
                    ErrorKind::PermissionDenied,
                    "it is a symlink, which is refused outright, not followed",
                )
            } else {
                err
            });
        }
        if !matches!(err.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP)) {
            return Err(err);
        }

        let link = open_at(dir, &cname, libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)?;
        let lmd = link.metadata()?;
        if !lmd.file_type().is_symlink() {
            return Err(err);
        }
        let dmd = dir.metadata()?;
        let only_root_can_replace =
            dmd.uid() == 0 && (dmd.mode() & 0o022 == 0 || dmd.mode() & 0o1000 != 0);
        if lmd.uid() != 0 || !only_root_can_replace {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "`{}` on the way to it is a link that someone other than root could have \
                     put there, and it is not followed",
                    name.to_string_lossy()
                ),
            ));
        }
        links += 1;
        if links > MAX_LINKS {
            return Err(Error::from_raw_os_error(libc::ELOOP));
        }
        let mut buf = vec![0u8; 4096];

        let n = unsafe {
            libc::readlinkat(link.as_raw_fd(), c"".as_ptr(), buf.as_mut_ptr().cast(), buf.len())
        };
        let n = usize::try_from(n).map_err(|_| Error::last_os_error())?;
        if n >= buf.len() {
            return Err(Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        buf.truncate(n);
        let target = PathBuf::from(OsString::from_vec(buf));
        if target.is_absolute() {
            dirs.truncate(1);
        }
        push_components(&mut todo, &target);
    }
    Err(Error::new(ErrorKind::InvalidInput, "the path names no file"))
}

pub(crate) fn resolve_tool(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(|s| PathBuf::from(*s))
        .find(|p| p.exists())
}

pub(crate) fn run_tool(tool: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new(tool)
        .args(args)
        .env_clear()
        .output()
        .map_err(|e| format!("could not run {}: {e}", tool.display()))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let code = output.status.code().map_or_else(|| "signal".to_string(), |c| c.to_string());
        Err(format!(
            "{} exited with status {code}: {}",
            tool.display(),
            stderr.trim()
        ))
    }
}

pub(crate) fn ensure_vault(vault_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(vault_dir)
        .map_err(|e| format!("could not create the vault {}: {e}", vault_dir.display()))
}

pub(crate) fn vault_dest(vault_dir: &Path, src: &Path) -> PathBuf {
    let base = src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    vault_dir.join(format!("{base}.{}.{nonce}", std::process::id()))
}

pub(crate) fn move_into_vault(src: &Path, vault_dir: &Path) -> Result<(PathBuf, Vec<String>), String> {
    ensure_vault(vault_dir)?;
    let dest = vault_dest(vault_dir, src);
    let lost = move_file(src, &dest)?;
    Ok((dest, lost))
}

pub fn snapshot(original: &Path, content: &str, vault_dir: &Path) -> Result<PathBuf, String> {
    snapshot_into_vault(original, content, vault_dir)
}

pub(crate) fn snapshot_into_vault(src: &Path, content: &str, vault_dir: &Path) -> Result<PathBuf, String> {
    ensure_vault(vault_dir)?;
    let dest = vault_dest(vault_dir, src);
    fs::write(&dest, content).map_err(|e| format!("could not snapshot into the vault: {e}"))?;
    Ok(dest)
}

pub(crate) struct Pinned {
    dir: std::os::fd::OwnedFd,
    name: std::ffi::CString,
}

const MAX_LINK_HOPS: u32 = 40;

pub(crate) fn pin_parent(path: &Path) -> Result<Pinned, String> {
    use std::collections::VecDeque;
    use std::ffi::{CString, OsString};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Component;

    let parts = |p: &Path| -> VecDeque<OsString> {
        p.components()
            .filter_map(|c| match c {
                Component::Normal(n) => Some(n.to_os_string()),
                Component::ParentDir => Some(OsString::from("..")),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
            })
            .collect()
    };
    let name = path.file_name().ok_or_else(|| format!("{} names no file", path.display()))?;
    let name = CString::new(name.as_bytes())
        .map_err(|_| format!("{} contains a NUL byte", path.display()))?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let parent = if parent.is_absolute() {
        parent
    } else {
        std::env::current_dir()
            .map_err(|e| format!("{} is relative and the working directory is unreadable: {e}", path.display()))?
            .join(parent)
    };

    let mut dir = open_dir_at(None, c"/").map_err(|e| format!("could not open /: {e}"))?;
    let mut here = PathBuf::from("/");
    let mut todo = parts(&parent);
    let mut hops = 0u32;
    while let Some(part) = todo.pop_front() {
        let c = CString::new(part.as_bytes())
            .map_err(|_| format!("{} contains a NUL byte", path.display()))?;
        let at = here.join(&part);
        let st = stat_at(&dir, &c).map_err(|e| format!("{}: {e}", at.display()))?;
        if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
            let holder = stat_fd(&dir).map_err(|e| format!("{}: {e}", here.display()))?;
            let target = read_link_at(&dir, &c).map_err(|e| format!("{}: {e}", at.display()))?;
            if holder.st_uid != 0 || holder.st_mode & 0o022 != 0 {
                return Err(format!(
                    "{} is a link to {}, in a directory an account other than root can write, \
                     so where it leads is not this path's to decide. A link on the way to {} \
                     is refused, not followed",
                    at.display(),
                    target.display(),
                    path.display()
                ));
            }
            hops += 1;
            if hops > MAX_LINK_HOPS {
                return Err(format!("{}: too many levels of links", path.display()));
            }
            if target.is_absolute() {
                dir = open_dir_at(None, c"/").map_err(|e| format!("could not open /: {e}"))?;
                here = PathBuf::from("/");
            }
            let mut next = parts(&target);
            next.extend(todo);
            todo = next;
            continue;
        }
        dir = open_dir_at(Some(&dir), &c).map_err(|e| format!("{}: {e}", at.display()))?;
        if part == ".." {
            here.pop();
        } else {
            here = at;
        }
    }
    Ok(Pinned { dir, name })
}

fn open_dir_at(dir: Option<&std::os::fd::OwnedFd>, name: &std::ffi::CStr) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    let at = dir.map_or(libc::AT_FDCWD, |d| d.as_raw_fd());

    let fd = unsafe {
        libc::openat(
            at,
            name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

fn stat_at(dir: &std::os::fd::OwnedFd, name: &std::ffi::CStr) -> std::io::Result<libc::stat> {
    use std::os::fd::AsRawFd as _;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();

    let rc = unsafe {
        libc::fstatat(dir.as_raw_fd(), name.as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW)
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(unsafe { st.assume_init() })
}

fn stat_fd(fd: &std::os::fd::OwnedFd) -> std::io::Result<libc::stat> {
    use std::os::fd::AsRawFd as _;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();

    let rc = unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(unsafe { st.assume_init() })
}

fn read_link_at(dir: &std::os::fd::OwnedFd, name: &std::ffi::CStr) -> std::io::Result<PathBuf> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStringExt as _;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];

    let n = unsafe {
        libc::readlinkat(dir.as_raw_fd(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len())
    };
    let Ok(n) = usize::try_from(n) else {
        return Err(std::io::Error::last_os_error());
    };
    buf.truncate(n);
    Ok(PathBuf::from(std::ffi::OsString::from_vec(buf)))
}

impl Pinned {

    pub(crate) fn dir_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd as _;
        self.dir.as_raw_fd()
    }

    pub(crate) fn name(&self) -> &std::ffi::CStr {
        &self.name
    }

    pub(crate) fn stat(&self) -> std::io::Result<libc::stat> {
        stat_at(&self.dir, &self.name)
    }

    pub(crate) fn kind(&self) -> std::io::Result<libc::mode_t> {
        stat_at(&self.dir, &self.name).map(|st| st.st_mode & libc::S_IFMT)
    }

    pub(crate) fn open(&self, flags: libc::c_int, mode: libc::c_uint) -> std::io::Result<fs::File> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                self.name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
}

pub(crate) fn move_file(from: &Path, to: &Path) -> Result<Vec<String>, String> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::MetadataExt as _;

    let src = pin_parent(from).map_err(|e| format!("refused to move {}: {e}", from.display()))?;
    let dst = pin_parent(to).map_err(|e| format!("refused to move to {}: {e}", to.display()))?;

    match src.kind() {
        Ok(k) if k == libc::S_IFREG || k == libc::S_IFLNK => {}
        Ok(_) => return Err(format!("refused to move {}: it is not a regular file", from.display())),
        Err(e) => return Err(format!("moving {} failed: {e}", from.display())),
    }

    let rc = unsafe {
        libc::renameat(src.dir.as_raw_fd(), src.name.as_ptr(), dst.dir.as_raw_fd(), dst.name.as_ptr())
    };
    if rc == 0 {
        return Ok(Vec::new());
    }
    let (lost, copied) = copy_preserving(&src, from, &dst, to)?;

    match stat_at(&src.dir, &src.name) {
        Ok(st) if st.st_dev == copied.dev() && st.st_ino == copied.ino() => {}
        _ => {
            return Err(format!(
                "{} changed while it was being copied to {}; the copy is there and nothing \
                 was removed",
                from.display(),
                to.display()
            ))
        }
    }

    let rc = unsafe { libc::unlinkat(src.dir.as_raw_fd(), src.name.as_ptr(), 0) };
    if rc != 0 {
        return Err(format!(
            "removing {} after copy failed: {}",
            from.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(lost)
}

fn copy_preserving(
    src_at: &Pinned,
    from: &Path,
    dst_at: &Pinned,
    to: &Path,
) -> Result<(Vec<String>, fs::Metadata), String> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mut src = src_at.open(libc::O_RDONLY | libc::O_NONBLOCK, 0).map_err(|e| {
        format!(
            "copy {} failed: {e} (a symlink here is refused outright, not followed)",
            from.display()
        )
    })?;
    let md = src.metadata().map_err(|e| format!("copy {} failed: {e}", from.display()))?;
    if !md.is_file() {
        return Err(format!("copy {} failed: it is not a regular file", from.display()));
    }

    let mut dst = dst_at
        .open(
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            md.permissions().mode() & 0o7777,
        )
        .map_err(|e| format!("copy {} -> {} failed: {e}", from.display(), to.display()))?;

    std::io::copy(&mut src, &mut dst)
        .map_err(|e| format!("copy {} -> {} failed: {e}", from.display(), to.display()))?;
    dst.sync_all().map_err(|e| format!("copy to {} failed to flush: {e}", to.display()))?;

    let mut lost = Vec::new();

    let rc = unsafe { libc::fchown(dst.as_raw_fd(), md.uid(), md.gid()) };
    if rc != 0 {
        lost.push(format!(
            "owner (uid {} gid {}: {})",
            md.uid(),
            md.gid(),
            std::io::Error::last_os_error()
        ));
    }

    let times = [
        libc::timespec { tv_sec: md.atime(), tv_nsec: md.atime_nsec() },
        libc::timespec { tv_sec: md.mtime(), tv_nsec: md.mtime_nsec() },
    ];

    let rc = unsafe { libc::futimens(dst.as_raw_fd(), times.as_ptr()) };
    if rc != 0 {
        lost.push(format!("timestamps (mtime {}: {})", md.mtime(), std::io::Error::last_os_error()));
    }

    Ok((lost, md))
}
