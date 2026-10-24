use std::ffi::CString;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};

pub const WATCHED: u64 = libc::FAN_CLOSE_WRITE | libc::FAN_MODIFY | libc::FAN_OPEN_EXEC;

pub const WATCHED_CANARY: u64 = libc::FAN_OPEN | libc::FAN_ACCESS;

pub fn arm_files(files: &[PathBuf]) -> Result<Watch, ArmError> {

    let raw = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
            (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
        )
    };
    if raw < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(ArmError::Init { errno: e, because: explain_init_errno(e) });
    }

    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut marked = Vec::new();
    let mut skipped = Vec::new();
    for f in files {
        if !f.is_file() {
            skipped.push((f.clone(), "not a file on this host".to_string()));
            continue;
        }
        let Ok(c) = CString::new(f.as_os_str().as_encoded_bytes()) else {
            skipped.push((f.clone(), "the path contains a NUL byte".to_string()));
            continue;
        };

        let rc = unsafe {
            libc::fanotify_mark(
                fd.as_raw_fd(),
                libc::FAN_MARK_ADD,
                WATCHED_CANARY,
                libc::AT_FDCWD,
                c.as_ptr(),
            )
        };
        if rc == 0 {
            marked.push(f.clone());
        } else {
            skipped.push((f.clone(), std::io::Error::last_os_error().to_string()));
        }
    }
    if marked.is_empty() {
        return Err(ArmError::NothingMarked { failures: skipped });
    }
    Ok(Watch { fd, marked, skipped, noun: "file(s)", overflows: std::cell::Cell::new(0) })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArmError {

    Init {

        errno: i32,

        because: String,
    },

    NothingMarked {

        failures: Vec<(PathBuf, String)>,
    },
}

impl ArmError {

    pub fn message(&self) -> String {
        match self {
            ArmError::Init { errno, because } => {
                format!("the filesystem sensor could not start (errno {errno}): {because}")
            }
            ArmError::NothingMarked { failures } => format!(
                "the filesystem sensor started but could not watch ANY of the {} requested \
                 director(ies), so it would report nothing and mean nothing: {}",
                failures.len(),
                failures
                    .iter()
                    .map(|(p, why)| format!("{} ({why})", p.display()))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        }
    }
}

pub fn explain_init_errno(errno: i32) -> String {
    match errno {
        libc::EPERM => "fanotify needs CAP_SYS_ADMIN. Run as root, and note that root inside a \
                        container usually does not have it — check CapEff in \
                        /proc/self/status before concluding the kernel lacks the feature"
            .to_string(),
        libc::ENOSYS => "this kernel was built without fanotify (CONFIG_FANOTIFY). There is no \
                         flag that changes this; the scan-based checks are what this host has"
            .to_string(),
        libc::EINVAL => "the kernel rejected the flags. FAN_OPEN_EXEC needs Linux 5.0 or newer; \
                         on an older kernel this sensor cannot report executions"
            .to_string(),
        libc::EMFILE => "this process has hit its open-file limit, so no notification group \
                         could be created"
            .to_string(),
        other => format!("errno {other}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {

    pub mask: u64,

    pub pid: u32,

    pub path: PathBuf,
}

pub fn describe(mask: u64) -> String {
    let mut parts = Vec::new();
    if mask & libc::FAN_OPEN_EXEC != 0 {
        parts.push("executed");
    }
    if mask & libc::FAN_CLOSE_WRITE != 0 {
        parts.push("written and closed");
    } else if mask & libc::FAN_MODIFY != 0 {
        parts.push("being written");
    }
    if mask & (libc::FAN_OPEN | libc::FAN_ACCESS) != 0 && parts.is_empty() {

        parts.push("READ");
    }
    if parts.is_empty() {
        return format!("event mask {mask:#x}");
    }
    parts.join(" and ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {

    Wrote,

    Executed,

    RanAfterWrite,
}

pub fn classify(ev: &Event, written: &std::collections::BTreeSet<PathBuf>) -> Kind {
    let is_exec = ev.mask & libc::FAN_OPEN_EXEC != 0;
    let is_write = ev.mask & (libc::FAN_CLOSE_WRITE | libc::FAN_MODIFY) != 0;
    if is_exec && written.contains(&ev.path) {
        Kind::RanAfterWrite
    } else if is_write {
        Kind::Wrote
    } else {
        Kind::Executed
    }
}

impl Kind {

    pub const fn worth_printing_by_default(self) -> bool {
        matches!(self, Kind::Wrote | Kind::RanAfterWrite)
    }

    pub const fn phrase(self) -> &'static str {
        match self {
            Kind::Wrote => "written",
            Kind::Executed => "executed",
            Kind::RanAfterWrite => "EXECUTED AFTER BEING WRITTEN DURING THIS WATCH",
        }
    }
}

#[derive(Debug)]
pub struct Watch {
    fd: OwnedFd,
    marked: Vec<PathBuf>,
    skipped: Vec<(PathBuf, String)>,

    noun: &'static str,

    overflows: std::cell::Cell<u32>,
}

impl Watch {

    pub fn marked(&self) -> &[PathBuf] {
        &self.marked
    }

    pub fn skipped(&self) -> &[(PathBuf, String)] {
        &self.skipped
    }

    pub fn overflowed(&self) -> u32 {
        self.overflows.get()
    }

    pub fn coverage(&self) -> String {
        let mut s = format!(
            "watching {} {} for {}",
            self.marked.len(),
            self.noun,
            if self.noun == "file(s)" { "reads" } else { "writes and executions" }
        );
        if !self.skipped.is_empty() {
            s.push_str(&format!(
                " — NOT watching {}, so anything that happens there will not appear below: {}",
                self.skipped.len(),
                self.skipped
                    .iter()
                    .map(|(p, why)| format!("{} ({why})", p.display()))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        s
    }
}

pub fn arm(dirs: &[PathBuf]) -> Result<Watch, ArmError> {

    let raw = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
            (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
        )
    };
    if raw < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(ArmError::Init { errno: e, because: explain_init_errno(e) });
    }

    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut marked = Vec::new();
    let mut skipped = Vec::new();
    for dir in dirs {
        match mark_one(fd.as_raw_fd(), dir) {
            Ok(()) => marked.push(dir.clone()),
            Err(why) => skipped.push((dir.clone(), why)),
        }
    }
    if marked.is_empty() {
        return Err(ArmError::NothingMarked { failures: skipped });
    }
    Ok(Watch { fd, marked, skipped, noun: "director(ies)", overflows: std::cell::Cell::new(0) })
}

fn mark_one(fd: i32, dir: &Path) -> Result<(), String> {
    if !dir.is_dir() {
        return Err("not a directory on this host".into());
    }
    let Ok(c) = CString::new(dir.as_os_str().as_encoded_bytes()) else {
        return Err("the path contains a NUL byte".into());
    };

    let rc = unsafe {
        libc::fanotify_mark(
            fd,
            libc::FAN_MARK_ADD | libc::FAN_MARK_ONLYDIR,
            WATCHED | libc::FAN_EVENT_ON_CHILD,
            libc::AT_FDCWD,
            c.as_ptr(),
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    Err(match e.raw_os_error() {
        Some(libc::ENOTDIR) => "not a directory".to_string(),
        Some(libc::ENOENT) => "does not exist on this host".to_string(),
        Some(libc::ENOSPC) => {
            "the per-user mark limit is full (fs.fanotify.max_user_marks)".to_string()
        }
        Some(libc::EINVAL) => {
            "the kernel rejected the event mask — FAN_OPEN_EXEC needs Linux 5.0".to_string()
        }
        _ => e.to_string(),
    })
}

impl Watch {

    pub fn drain(&self, timeout_ms: i32) -> Vec<Event> {
        let mut pfd = libc::pollfd { fd: self.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };

        let ready = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
        if ready <= 0 {
            return Vec::new();
        }

        let mut buf = [0_u8; 8192];

        let n = unsafe {
            libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast::<libc::c_void>(), buf.len())
        };
        if n <= 0 {
            return Vec::new();
        }
        self.parse(&buf[..n as usize])
    }

    fn parse(&self, mut data: &[u8]) -> Vec<Event> {
        const META: usize = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut out = Vec::new();
        while data.len() >= META {

            let meta: libc::fanotify_event_metadata =
                unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
            let len = meta.event_len as usize;
            if len < META || len > data.len() {
                break;
            }

            if meta.mask & libc::FAN_Q_OVERFLOW != 0 {
                self.overflows.set(self.overflows.get().saturating_add(1));
            }
            if meta.vers == libc::FANOTIFY_METADATA_VERSION && meta.fd >= 0 {

                let path = std::fs::read_link(format!("/proc/self/fd/{}", meta.fd))
                    .unwrap_or_else(|_| PathBuf::from("<unresolved>"));
                out.push(Event {
                    mask: meta.mask,
                    pid: u32::try_from(meta.pid).unwrap_or(0),
                    path,
                });
            }
            if meta.fd >= 0 {

                unsafe { libc::close(meta.fd) };
            }
            data = &data[len..];
        }
        out
    }
}

pub fn default_loci() -> Vec<PathBuf> {

    let mut dirs: Vec<PathBuf> = crate::persist::watched_directories()
        .into_iter()
        .chain(crate::snapshot::watched_directories())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs.dedup();
    dirs
}
