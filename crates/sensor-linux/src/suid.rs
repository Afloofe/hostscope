use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::rootkit::{Finding, Severity};

const S_ISUID: u32 = 0o4000;

const S_ISGID: u32 = 0o2000;

const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;

const FS_IMMUTABLE_FL: i64 = 0x0000_0010;

const FS_APPEND_FL: i64 = 0x0000_0020;

const MAX_FILES: usize = 150_000;

const MAX_DEPTH: usize = 8;

const SCAN_ROOTS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",

    "/usr/lib",
    "/usr/libexec",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
];

const WRITABLE_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];

const INTERPRETERS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "ash", "busybox", "env",
    "python", "python2", "python3", "perl", "ruby", "php", "lua", "luajit",
    "node", "nodejs", "tclsh", "expect", "awk", "gawk", "mawk", "nawk",
    "vim", "vi", "nvim", "nano", "emacs", "less", "more", "man", "find",
];

const ESCALATORS: &[&str] = &[

    "nice", "ionice", "chrt", "taskset", "timeout", "stdbuf", "nohup", "setsid",
    "setarch", "xargs", "flock", "unshare", "nsenter", "chroot", "capsh",
    "run-parts", "start-stop-daemon", "watch", "time", "strace", "ltrace", "gdb",
    "make", "docker", "systemctl", "script", "logsave", "socat", "ip", "ssh",
    "git", "sqlite3", "openssl",

    "ld.so", "ld-linux.so.2", "ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1",
    "ld-linux-armhf.so.3",

    "sed", "ed", "rsync", "tar", "zip", "cpio", "cp", "mv", "dd", "tee", "install",
    "chmod", "chown", "wget", "curl",

    "cat", "tac", "head", "tail", "base64", "base32", "xxd", "od", "hexdump",
    "strings",
];

const SUID_ALLOWLIST: &[&str] = &[

    "sudo", "su", "sudoedit", "pkexec", "newgrp", "gpasswd", "passwd", "chsh",
    "chfn", "expiry", "chage", "vlock", "unix_chkpwd", "pam_extrausers_chkpwd",

    "mount", "umount", "fusermount", "fusermount3", "ntfs-3g", "mount.nfs",
    "mount.cifs", "pmount", "pumount",

    "ping", "ping6", "traceroute", "traceroute6", "traceroute6.iputils",
    "mtr", "mtr-packet", "arping", "netreport",

    "dbus-daemon-launch-helper", "polkit-agent-helper-1", "ssh-keysign",
    "chrome-sandbox", "Xorg.wrap", "snap-confine", "vmware-user-suid-wrapper",
    "gnome-keyring-daemon", "spice-client-glib-usb-acl-helper", "xf86-video-intel-backlight-helper",
    "utempter", "kismet_cap_linux_wifi", "kismet_cap_linux_bluetooth",

    "wall", "write", "bsd-write", "sg", "at", "crontab", "dotlockfile",
    "mlocate", "locate", "ssh-agent", "screen", "wall.ul", "mail-lock",
    "mail-unlock", "mail-touchlock", "dotlock.mailutils",
];

const CAP_ALLOWLIST: &[&str] = &[
    "ping", "ping6", "arping", "mtr-packet", "fping", "fping6", "clockdiff",
    "dumpcap", "traceroute6.iputils", "gnome-keyring-daemon", "sshd",
    "rlogin", "rsh", "rcp", "systemd-network-generator",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {

    Interpreter,

    Escalator,

    WritablePath,

    Unknown,

    Allowlisted,

    Packaged,
}

impl Verdict {

    pub fn severity(self) -> Severity {
        match self {
            Verdict::Interpreter | Verdict::WritablePath | Verdict::Escalator => Severity::Critical,
            Verdict::Unknown => Severity::Warn,
            Verdict::Allowlisted | Verdict::Packaged => Severity::Note,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,

    pub files_scanned: usize,

    pub suid_count: usize,

    pub cap_count: usize,

    pub capped: bool,

    pub depth_pruned: usize,
}

fn under_any(path: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|p| path.starts_with(p.as_str()))
}

fn interpreter_fingerprints() -> Vec<(u64, String, &'static str)> {
    const DIRS: &[&str] = &["/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin"];
    let mut out = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for name in INTERPRETERS {
        for dir in DIRS {
            let p = PathBuf::from(dir).join(name);
            let Ok(md) = fs::metadata(&p) else { continue };
            if !md.is_file() {
                continue;
            }

            let Some(d) = file_digest(&p) else { continue };
            if seen.insert(d.clone()) {
                out.push((md.len(), d, *name));
            }
        }
    }
    out
}

fn file_digest(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};

    const MAX_SUID_BYTES: u64 = 256 * 1024 * 1024;
    let bytes = crate::saferead::read_whole_file(path, MAX_SUID_BYTES)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn interpreter_by_content(
    path: &Path,
    len: u64,
    prints: &[(u64, String, &'static str)],
) -> Option<&'static str> {
    if !prints.iter().any(|(l, _, _)| *l == len) {
        return None;
    }
    let d = file_digest(path)?;
    prints.iter().find(|(l, h, _)| *l == len && *h == d).map(|(_, _, n)| *n)
}

fn is_interpreter(basename: &str) -> bool {
    INTERPRETERS.contains(&basename)
}

pub fn classify(basename: &str, is_writable: bool, allowlist: &[&str]) -> Verdict {
    if is_interpreter(basename) {
        Verdict::Interpreter
    } else if is_writable {
        Verdict::WritablePath
    } else if ESCALATORS.contains(&basename) {
        Verdict::Escalator
    } else if allowlist.contains(&basename) {
        Verdict::Allowlisted
    } else {
        Verdict::Unknown
    }
}

fn setid_bits(mode: u32) -> (bool, bool) {
    (mode & S_ISUID != 0, mode & S_ISGID != 0)
}

fn setid_tag(suid: bool, sgid: bool) -> &'static str {
    match (suid, sgid) {
        (true, true) => "SUID+SGID",
        (true, false) => "SUID",
        (false, true) => "SGID",
        (false, false) => "",
    }
}

fn immutable_flags(flags: i64) -> (bool, bool) {
    (flags & FS_IMMUTABLE_FL != 0, flags & FS_APPEND_FL != 0)
}

fn cap_permitted_mask(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 8 {
        return None;
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let rev = magic & 0xFF00_0000;
    let word = |off: usize| -> u64 {
        u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]) as u64
    };
    match rev {

        0x0100_0000 if bytes.len() >= 8 => Some(word(4)),

        0x0200_0000 | 0x0300_0000 if bytes.len() >= 16 => Some(word(4) | (word(12) << 32)),
        _ => None,
    }
}

fn basename(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| path.display().to_string())
}

fn read_capability(path: &Path) -> Option<Vec<u8>> {
    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;

    const NAME: &[u8] = b"security.capability\0";

    let len = unsafe {
        libc::lgetxattr(cpath.as_ptr(), NAME.as_ptr().cast(), std::ptr::null_mut(), 0)
    };
    if len <= 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];

    let got = unsafe {
        libc::lgetxattr(
            cpath.as_ptr(),
            NAME.as_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if got <= 0 {
        return None;
    }
    buf.truncate(got as usize);
    Some(buf)
}

fn read_inode_flags(path: &Path) -> Option<i64> {
    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;

    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY,
        )
    };
    if fd < 0 {
        return None;
    }
    let mut attr: libc::c_long = 0;

    let rc = unsafe { libc::ioctl(fd, FS_IOC_GETFLAGS as _, &mut attr as *mut libc::c_long) };

    unsafe { libc::close(fd) };
    if rc != 0 {
        return None;
    }
    Some(attr as i64)
}

fn home_dirs_with_gap() -> (Vec<PathBuf>, Option<String>) {
    let (text, gap) = match crate::saferead::read_scan_target_bounded(Path::new("/etc/passwd")) {
        None => return (Vec::new(), Some("/etc/passwd (unreadable — no home directory was scanned)".into())),
        Some((t, true)) => (t, Some("/etc/passwd (read only in part — later homes were not scanned)".into())),
        Some((t, false)) => (t, None),
    };
    (parse_suid_homes(&text), gap)
}

fn parse_suid_homes(text: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut f = line.split(':');
        let (Some(_user), Some(_pw), Some(uid), Some(_gid), Some(_gecos), Some(home)) =
            (f.next(), f.next(), f.next(), f.next(), f.next(), f.next())
        else {
            continue;
        };

        let Ok(uid) = uid.parse::<u32>() else { continue };
        if uid < 1000 || uid == 65534 {
            continue;
        }
        if home.is_empty() || home == "/" || home == "/nonexistent" || home == "/dev/null" {
            continue;
        }

        if ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/var", "/run", "/dev", "/opt", "/etc",
            "/proc", "/sys", "/boot"]
            .iter()
            .any(|p| home == *p || home.starts_with(&format!("{p}/")))
        {
            continue;
        }
        out.push(PathBuf::from(home));
    }
    out.sort();
    out.dedup();
    out
}

fn writable_prefixes(homes: &[PathBuf]) -> Vec<String> {
    let mut out: Vec<String> = WRITABLE_PREFIXES.iter().map(|s| s.to_string()).collect();
    for h in homes {
        let mut s = h.display().to_string();
        if !s.ends_with('/') {
            s.push('/');
        }
        out.push(s);
    }
    out
}

fn settle(verdict: Verdict, path: &Path, packages: Option<&crate::pkg::Manager>) -> Verdict {
    match (verdict, packages) {
        (Verdict::Unknown, Some(m)) if m.owns(path) => Verdict::Packaged,
        _ => verdict,
    }
}

fn setid_finding(display: &str, tag: &str, owner: &str, verdict: Verdict) -> Finding {
    match verdict {
        Verdict::Interpreter => Finding {
            severity: Severity::Critical,
            subject: format!("SUID backdoor `{display}`"),
            what: format!("is a {tag}-{owner} copy of a shell or interpreter"),
            why: "a setuid shell or interpreter hands a root shell to anyone who runs it and is \
                  never something a distribution ships — this is the textbook on-disk root \
                  backdoor. Remove the setuid bit and treat the host as compromised until you \
                  know who placed it"
                .into(),
        },
        Verdict::WritablePath => Finding {
            severity: Severity::Critical,
            subject: format!("SUID backdoor `{display}`"),
            what: format!("is a {tag}-{owner} binary under a user-writable path"),
            why: "a setuid-root binary in a directory any local user can write is a privilege \
                  escalation by construction: whoever controls that path controls what runs as \
                  root. No distribution places setuid binaries there"
                .into(),
        },
        Verdict::Escalator => Finding {
            severity: Severity::Critical,
            subject: format!("SUID backdoor `{display}`"),
            what: format!(
                "is a {tag}-{owner} binary that runs any command it is given, or reads or \
                 writes any file it is pointed at"
            ),
            why: "no distribution ships this binary set-id, and with the bit it hands its \
                  owner's identity to anyone who runs it — a root shell, or root's read or \
                  write of /etc/shadow. A package owning the file vouches for the file, not the \
                  bit: `chmod u+s` leaves the package record untouched. Clear the bit and find \
                  out who set it"
                .into(),
        },
        Verdict::Unknown => Finding {
            severity: Severity::Warn,
            subject: format!("unrecognised setuid binary `{display}`"),
            what: format!("is a {tag}-{owner} binary that is not on the known-good allowlist"),
            why: "an unrecognised setuid/setgid-root binary is worth a look — it may be a \
                  legitimate third-party or distribution tool the allowlist does not name (ksu, \
                  newuidmap, …), or an escalation backdoor. A LEAD to verify by provenance, not a \
                  verdict; a setuid SHELL, or one under a writable path, is the Critical"
                .into(),
        },
        Verdict::Packaged => Finding {
            severity: Severity::Note,
            subject: format!("setuid helper `{display}`"),
            what: format!("is a {tag}-{owner} binary the package manager owns"),
            why: "not a name the allowlist carries, but the distribution's own package database claims this file — which is what the allowlist was approximating. Postfix, CUPS and the container runtimes each ship set-id helpers no list names. Inventory only. Ownership vouches for the file, not the bit: a `chmod u+s` leaves the record untouched, and dpkg keeps no modes to verify against (rpm -V and pacman -Qkk do), so if anything else on the host is suspect, ask whether this package ships it set-id"
                .into(),
        },
        Verdict::Allowlisted => Finding {
            severity: Severity::Note,
            subject: format!("setuid helper `{display}`"),
            what: format!("is a {tag}-{owner} binary on the known-good distribution allowlist"),
            why: "a recognised distribution setuid helper in a standard path. Listed for \
                  inventory; confirm the file itself was not swapped if anything else on the host \
                  is suspect"
                .into(),
        },
    }
}

fn cap_finding(display: &str, mask: u64, verdict: Verdict) -> Finding {
    let masktxt = format!("permitted mask 0x{mask:016x}");
    match verdict {
        Verdict::Interpreter => Finding {
            severity: Severity::Critical,
            subject: format!("capability backdoor `{display}`"),
            what: format!("is a shell/interpreter carrying file capabilities ({masktxt})"),
            why: "a capability on an interpreter is a root shell with no setuid bit for ls to \
                  show — a stealthier form of the setuid-shell backdoor. Never a stock binary"
                .into(),
        },
        Verdict::WritablePath => Finding {
            severity: Severity::Critical,
            subject: format!("capability backdoor `{display}`"),
            what: format!("carries file capabilities under a user-writable path ({masktxt})"),
            why: "a capability-bearing binary any local user can overwrite grants a slice of root \
                  to attacker-controlled code, and leaves no setuid bit to notice"
                .into(),
        },
        Verdict::Escalator => Finding {
            severity: Severity::Warn,
            subject: format!("capability on `{display}`"),
            what: format!(
                "carries file capabilities on a binary that runs any command, or reads or \
                 writes any file, it is given ({masktxt})"
            ),
            why: "no distribution grants this binary a capability, and on it one is a slice of \
                  root for anyone who runs it. A backup job given read access this way is \
                  something an administrator does, so this is a lead, not a verdict — but its \
                  package owning the file says nothing about the capability, which is set apart \
                  from the package record"
                .into(),
        },
        Verdict::Unknown => Finding {
            severity: Severity::Warn,
            subject: format!("unrecognised capability binary `{display}`"),
            what: format!("carries file capabilities and is not on the known-good allowlist ({masktxt})"),
            why: "file capabilities grant root powers with no setuid bit — worth confirming — but \
                  distributions ship capability-bearing binaries the allowlist may not name \
                  (newuidmap, newgidmap, ping, …), so this is a LEAD to verify by provenance, not \
                  a verdict. A capability on a SHELL, or under a writable path, is the Critical"
                .into(),
        },
        Verdict::Packaged => Finding {
            severity: Severity::Note,
            subject: format!("capability helper `{display}`"),
            what: format!("carries file capabilities and the package manager owns it ({masktxt})"),
            why: "not a name the allowlist carries, but the distribution's own package database claims this file. Inventory only. Ownership vouches for the file, not the capability, which is set apart from the package record — if anything else on the host is suspect, ask whether this package grants it one"
                .into(),
        },
        Verdict::Allowlisted => Finding {
            severity: Severity::Note,
            subject: format!("capability helper `{display}`"),
            what: format!("is a known-good binary carrying file capabilities ({masktxt})"),
            why: "a recognised distribution binary that legitimately uses a capability instead of \
                  a setuid bit (ping and friends). Inventory only"
                .into(),
        },
    }
}

fn is_systemd_private_tmp(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("systemd-private-"))
}

fn owner_label(suid: bool, uid: u32, gid: u32) -> String {
    if suid {
        if uid == 0 { "root".into() } else { format!("uid{uid}") }
    } else if gid == 0 {
        "root".into()
    } else {
        format!("gid{gid}")
    }
}

#[derive(Clone, Copy)]
struct ScanTarget<'a> {
    path: &'a Path,
    mode: u32,
    uid: u32,
    gid: u32,

    writable: bool,
    len: u64,
}

fn scan_file(
    target: ScanTarget<'_>,
    packages: Option<&crate::pkg::Manager>,
    prints: &[(u64, String, &'static str)],
    report: &mut Report,
) {
    let ScanTarget { path, mode, uid, gid, writable, len } = target;
    let display = path.display().to_string();
    let mut base = basename(path);

    if !is_interpreter(&base) {
        if let Some(real) = interpreter_by_content(path, len, prints) {
            base = real.to_string();
        }
    }

    let (suid, sgid) = setid_bits(mode);
    if suid || sgid {
        report.suid_count += 1;
        let verdict = settle(classify(&base, writable, SUID_ALLOWLIST), path, packages);
        let tag = setid_tag(suid, sgid);
        let owner = owner_label(suid, uid, gid);
        report
            .findings
            .push(setid_finding(&display, tag, &owner, verdict));
    }

    if let Some(bytes) = read_capability(path) {
        if let Some(mask) = cap_permitted_mask(&bytes) {
            report.cap_count += 1;
            let verdict = settle(classify(&base, writable, CAP_ALLOWLIST), path, packages);
            report.findings.push(cap_finding(&display, mask, verdict));
        }
    }

    if writable {
        if let Some(flags) = read_inode_flags(path) {
            let (imm, app) = immutable_flags(flags);
            if imm || app {
                let which = if imm && app {
                    "immutable and append-only (chattr +i +a)"
                } else if imm {
                    "immutable (chattr +i)"
                } else {
                    "append-only (chattr +a)"
                };
                report.findings.push(Finding {
                    severity: Severity::Warn,
                    subject: format!("immutable file `{display}`"),
                    what: format!("is marked {which} in a user-writable location"),
                    why: "the immutable/append-only inode flag makes a file survive `rm` until \
                          someone runs `chattr -i` first — a resist-removal marker a rootkit sets \
                          on the files it drops. It is legitimate on a few system files, so this \
                          is a lead, not a verdict; here it sits somewhere a distribution would \
                          not set it, which is why it is worth explaining"
                        .into(),
                });
            }
        }
    }
}

pub fn report() -> Report {
    let (homes, homes_gap) = home_dirs_with_gap();
    let prefixes = writable_prefixes(&homes);

    let mut roots: Vec<PathBuf> = SCAN_ROOTS.iter().map(PathBuf::from).collect();
    roots.extend(homes.iter().cloned());

    let packages = crate::pkg::manager();

    let prints = interpreter_fingerprints();

    let mut report = Report::default();
    let mut readable_any = false;
    let mut refused: Vec<String> = Vec::new();

    if let Some(gap) = homes_gap {
        refused.push(gap);
    }

    let mut visited: BTreeSet<PathBuf> = BTreeSet::new();

    for root in &roots {

        match fs::read_dir(root) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                refused.push(root.display().to_string());
                continue;
            }
        }
        readable_any = true;
        walk(root, &prefixes, packages.as_ref(), &prints, &mut report, &mut refused, &mut visited);
        if report.capped {
            break;
        }
    }

    let (private_tmp, other): (Vec<&String>, Vec<&String>) =
        refused.iter().partition(|d| is_systemd_private_tmp(d));
    for dir in other {
        report.findings.push(Finding {
            severity: Severity::Warn,
            subject: format!("unreadable path `{dir}`"),
            what: "exists but could not be read while scanning for setuid/capability files".into(),
            why: "this path is NOT clean, it is unchecked — a setuid backdoor here would be \
                  invisible to this pass. Re-run as root; until then treat it as unexamined"
                .into(),
        });
    }
    if !private_tmp.is_empty() {
        report.findings.push(Finding {
            severity: Severity::Warn,
            subject: format!("{} per-service private /tmp director(ies) unreadable", private_tmp.len()),
            what: "systemd `PrivateTmp=` directories, root-only by construction, were not scanned"
                .into(),
            why: "these are still unchecked, not clean — a setuid file inside one would be \
                  invisible to this pass. They are grouped because there is one per service \
                  using PrivateTmp and an unprivileged run can never read any of them, so the \
                  count is a fact about the privilege this ran with rather than about the host. \
                  Re-run as root to scan them"
                .into(),
        });
    }

    if report.capped {
        report.findings.push(Finding {
            severity: Severity::Note,
            subject: "scan bound reached".into(),
            what: format!("stopped after examining {MAX_FILES} files — the walk was capped"),
            why: "the file cap bounds the agent against a hostile deep directory. The surface is \
                  therefore only partially covered: absence of a finding beyond this point is not \
                  evidence of absence. Narrow the roots or raise the bound to finish the sweep"
                .into(),
        });
    }

    if report.depth_pruned > 0 {
        report.findings.push(Finding {
            severity: Severity::Note,
            subject: "scan depth bound reached".into(),
            what: format!(
                "{} director(y/ies) deeper than {MAX_DEPTH} levels were not entered",
                report.depth_pruned
            ),
            why: "the depth bound keeps a hostile nested tree from holding the walk, and it \
                  means anything below it was not examined — a setuid binary buried deep in a \
                  writable tree is the shape an attacker would choose"
                .into(),
        });
    }

    report.findings.sort_by_key(|f| std::cmp::Reverse(f.severity));

    if !readable_any {
        report.available = false;
        report.reason = Some(if refused.is_empty() {
            "none of the setuid scan roots exist on this host".into()
        } else {
            "none of the setuid scan roots could be read (all refused) — re-run as root".into()
        });
        return report;
    }

    report.available = true;
    report
}

#[allow(clippy::too_many_arguments)]
fn walk(
    root: &Path,
    prefixes: &[String],
    packages: Option<&crate::pkg::Manager>,
    prints: &[(u64, String, &'static str)],
    report: &mut Report,
    refused: &mut Vec<String>,
    visited: &mut BTreeSet<PathBuf>,
) {
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            report.depth_pruned += 1;
            continue;
        }

        let key = dir.canonicalize().unwrap_or_else(|_| dir.clone());
        if !visited.insert(key) {
            continue;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                refused.push(dir.display().to_string());
                continue;
            }
        };
        for entry in entries.flatten() {
            if report.files_scanned >= MAX_FILES {
                report.capped = true;
                return;
            }
            let path = entry.path();

            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            let ft = meta.file_type();
            if ft.is_dir() {
                stack.push((path, depth + 1));
            } else if ft.is_file() {
                report.files_scanned += 1;
                let display = path.display().to_string();
                let writable = under_any(&display, prefixes);
                scan_file(
                    ScanTarget {
                        path: &path,
                        mode: meta.mode(),
                        uid: meta.uid(),
                        gid: meta.gid(),
                        writable,
                        len: meta.len(),
                    },
                    packages,
                    prints,
                    report,
                );
            }
        }
    }
}
