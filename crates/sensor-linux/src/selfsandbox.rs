use std::ffi::CString;
use std::path::{Path, PathBuf};

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;

const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;

const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

const WRITE_ACCESSES_ABI1: u64 = (1 << 1)
    | (1 << 4)
    | (1 << 5)
    | (1 << 6)
    | (1 << 7)
    | (1 << 8)
    | (1 << 9)
    | (1 << 10)
    | (1 << 11)
    | (1 << 12);

const ACCESS_REFER: u64 = 1 << 13;

const ACCESS_TRUNCATE: u64 = 1 << 14;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {

    Abi(u32),

    Absent,

    Refused(i32),
}

impl Support {

    pub fn message(self) -> String {
        match self {
            Support::Abi(v) => format!(
                "Landlock ABI {v}. The agent's own write access is restricted to its evidence \
                 store for the rest of this run"
            ),
            Support::Absent => "this kernel has no Landlock (it arrived in 5.13), so the agent \
                                runs unrestricted. That is the same reach every other tool on \
                                this host has, and it is stated rather than assumed"
                .to_string(),
            Support::Refused(e) => format!(
                "the Landlock version query was refused (errno {e}), so the agent runs \
                 unrestricted"
            ),
        }
    }

    pub const fn is_available(self) -> bool {
        matches!(self, Support::Abi(_))
    }
}

pub fn support() -> Support {

    let rc = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<RulesetAttr>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if rc > 0 {
        return Support::Abi(u32::try_from(rc).unwrap_or(1));
    }
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if e == libc::ENOSYS || e == libc::EOPNOTSUPP {
        Support::Absent
    } else {
        Support::Refused(e)
    }
}

pub const fn handled_for(abi: u32) -> u64 {
    let mut a = WRITE_ACCESSES_ABI1;
    if abi >= 2 {
        a |= ACCESS_REFER;
    }
    if abi >= 3 {
        a |= ACCESS_TRUNCATE;
    }
    a
}

#[derive(Debug)]
pub struct Sandbox {
    fd: i32,
    abi: u32,
    writable: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {

    Unsupported(Support),

    MissingWritable(PathBuf),

    Syscall {

        what: &'static str,

        errno: i32,
    },
}

impl Error {

    pub fn message(&self) -> String {
        match self {
            Error::Unsupported(s) => s.message(),
            Error::MissingWritable(p) => format!(
                "{} does not exist, and the sandbox will not be applied without it. Landlock \
                 cannot be widened once set, so a ruleset missing the evidence store is an \
                 agent that cannot write its own output — and it would find that out at the \
                 moment it had something to write",
                p.display()
            ),
            Error::Syscall { what, errno } => {
                format!("{what} failed (errno {errno}); the agent runs unrestricted")
            }
        }
    }
}

impl Sandbox {

    pub fn build(writable: &[PathBuf]) -> Result<Sandbox, Error> {
        let s = support();
        let Support::Abi(abi) = s else {
            return Err(Error::Unsupported(s));
        };
        for p in writable {
            if !p.exists() {
                return Err(Error::MissingWritable(p.clone()));
            }
        }
        let fd = create_ruleset(handled_for(abi), 0)?;
        let sb = Sandbox { fd, abi, writable: writable.to_vec() };
        for p in writable {
            add_rule(sb.fd, p, handled_for(sb.abi))?;
        }
        Ok(sb)
    }

    pub fn apply(self) -> Result<Applied, Error> {
        restrict(self.fd)?;
        Ok(Applied { abi: self.abi, writable: self.writable })
    }
}

fn create_ruleset(fs: u64, net: u64) -> Result<i32, Error> {
    let attr = RulesetAttr {
        handled_access_fs: fs,
        handled_access_net: net,
        scoped: 0,
    };

    let fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::addr_of!(attr),
            std::mem::size_of::<RulesetAttr>(),
            0_u32,
        )
    };
    let fd = i32::try_from(fd).unwrap_or(-1);
    if fd < 0 {
        return Err(Error::Syscall {
            what: "landlock_create_ruleset",
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }
    Ok(fd)
}

fn add_rule(fd: i32, path: &Path, access: u64) -> Result<(), Error> {
    let Ok(c) = CString::new(path.as_os_str().as_encoded_bytes()) else {
        return Err(Error::Syscall { what: "path contains a NUL", errno: libc::EINVAL });
    };

    let parent = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if parent < 0 {
        return Err(Error::Syscall {
            what: "open(O_PATH) on a writable path",
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }
    let attr = PathBeneathAttr {
        allowed_access: access,
        parent_fd: parent,
    };

    let rc = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            fd,
            LANDLOCK_RULE_PATH_BENEATH,
            std::ptr::addr_of!(attr),
            0_u32,
        )
    };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);

    unsafe { libc::close(parent) };
    if rc != 0 {
        return Err(Error::Syscall { what: "landlock_add_rule", errno: e });
    }
    Ok(())
}

fn restrict(fd: i32) -> Result<(), Error> {

    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(Error::Syscall {
            what: "prctl(PR_SET_NO_NEW_PRIVS)",
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }

    let rc = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0_u32) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);

    unsafe { libc::close(fd) };
    if rc != 0 {
        return Err(Error::Syscall { what: "landlock_restrict_self", errno: e });
    }
    Ok(())
}

const READ_ACCESSES: u64 = (1 << 0) | (1 << 2) | (1 << 3);

const FILE_ONLY_ACCESSES: u64 = (1 << 0) | (1 << 1) | (1 << 2) | ACCESS_TRUNCATE;

const NET_TCP: u64 = (1 << 0) | (1 << 1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confined {

    pub abi: u32,

    pub writable: Vec<PathBuf>,

    pub readable: Vec<PathBuf>,

    pub net_denied: bool,
}

impl Confined {

    pub fn summary(&self) -> String {
        let list = |v: &[PathBuf]| v.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ");
        format!(
            "Landlock ABI {} in force for the rest of this process: it reads and writes only beneath {}, \
             reads only beneath {}, and executes nothing. {}",
            self.abi,
            list(&self.writable),
            list(&self.readable),
            if self.net_denied {
                "TCP bind and connect are refused, so it cannot open a connection or another port"
            } else {
                "This kernel's Landlock predates network rules (ABI 4), so TCP is not restricted"
            }
        )
    }
}

pub fn confine(writable: &[PathBuf], readable: &[PathBuf]) -> Result<Confined, Error> {
    let s = support();
    let Support::Abi(abi) = s else {
        return Err(Error::Unsupported(s));
    };
    for p in writable.iter().chain(readable) {
        if !p.exists() {
            return Err(Error::MissingWritable(p.clone()));
        }
    }
    let fs = handled_for(abi) | READ_ACCESSES;
    let net = if abi >= 4 { NET_TCP } else { 0 };
    let fd = create_ruleset(fs, net)?;
    let rule = |p: &Path, want: u64| -> Result<(), Error> {
        let access = if p.is_dir() { want } else { want & FILE_ONLY_ACCESSES & fs };
        add_rule(fd, p, access).inspect_err(|_| {

            unsafe { libc::close(fd) };
        })
    };
    for p in writable {
        rule(p, fs & !(1 << 0))?;
    }
    for p in readable {
        rule(p, (1 << 2) | (1 << 3))?;
    }
    restrict(fd)?;
    Ok(Confined { abi, writable: writable.to_vec(), readable: readable.to_vec(), net_denied: net != 0 })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {

    pub abi: u32,

    pub writable: Vec<PathBuf>,
}

impl Applied {

    pub fn summary(&self) -> String {
        format!(
            "Landlock ABI {} in force for the rest of this process: it can WRITE only beneath \
             {}. Reads are not restricted — a sensor that cannot read is not a sensor, and a \
             read allowlist that got one path wrong would produce a blinded sweep that still \
             prints output. The restriction is inherited across fork and exec, so anything \
             this process starts is refused the same writes, and refused mount outright. Not \
             restricted: the network (nft speaks netlink) or asking PID 1 to act (systemctl), \
             so a compromised process can still have systemd run something outside it. \
             Containment runs from a separate `hemostat` invocation, which this does not \
             touch, so it is a blast-radius reduction for a compromised parser rather than a \
             limit on what the tool can do.",
            self.abi,
            self.writable
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trial {

    Refused {

        errno: i32,

        abi: u32,
    },

    NotRefused {

        abi: u32,
    },

    NotApplied(String),

    Inconclusive(String),
}

impl Trial {

    pub fn message(&self) -> String {
        match self {
            Trial::Refused { errno, abi } => format!(
                "measured: with Landlock ABI {abi} applied, a write outside the evidence store \
                 was refused with errno {errno}. The restriction is real on this kernel"
            ),
            Trial::NotRefused { abi } => format!(
                "MEASURED AND FAILED: Landlock ABI {abi} reported itself applied and a write \
                 outside the evidence store went through anyway. Do not rely on the \
                 self-sandbox on this kernel — it is reporting a restriction it is not \
                 enforcing"
            ),
            Trial::NotApplied(why) => format!("not applied, so nothing was measured: {why}"),
            Trial::Inconclusive(why) => format!(
                "the trial itself could not run ({why}), so this says NOTHING about whether \
                 the sandbox works here"
            ),
        }
    }

    pub const fn proves_it_works(&self) -> bool {
        matches!(self, Trial::Refused { .. })
    }
}

pub fn trial(writable: &Path) -> Trial {
    if !writable.is_dir() {
        return Trial::Inconclusive(format!("{} is not a directory", writable.display()));
    }
    let s = support();
    if !s.is_available() {
        return Trial::NotApplied(s.message());
    }
    let Support::Abi(abi) = s else {
        return Trial::NotApplied(s.message());
    };

    let outside = std::env::temp_dir().join(format!("hemostat-ls-trial-{}", std::process::id()));

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Trial::Inconclusive("fork failed".into());
    }
    if pid == 0 {

        let code = match Sandbox::build(&[writable.to_path_buf()]).and_then(Sandbox::apply) {
            Ok(_) => match std::fs::write(&outside, b"x") {

                Ok(()) => 1,
                Err(e) => {
                    let errno = e.raw_os_error().unwrap_or(0);

                    if errno == libc::EACCES {
                        0
                    } else {
                        3
                    }
                }
            },
            Err(_) => 2,
        };

        unsafe { libc::_exit(code) };
    }

    let mut status = 0_i32;

    let got = unsafe { libc::waitpid(pid, std::ptr::addr_of_mut!(status), 0) };
    let _ = std::fs::remove_file(&outside);
    if got != pid {
        return Trial::Inconclusive("the child could not be reaped".into());
    }

    let code = (status >> 8) & 0xff;
    match code {
        0 => Trial::Refused { errno: libc::EACCES, abi },
        1 => Trial::NotRefused { abi },
        2 => Trial::NotApplied("the ruleset would not apply in the child".into()),
        other => Trial::Inconclusive(format!("the write failed for another reason (code {other})")),
    }
}
