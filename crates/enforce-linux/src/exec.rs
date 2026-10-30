use std::path::{Path, PathBuf};

use crate::paths::same_file;
use crate::{
    path_refusal, ApplyOptions, Failure, Outcome, Plan, ProtectSet, RefuseCause,
    Refusal, UndoKind, UndoRecord,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {

    BindMount,

    ClearExecBits,
}

impl Mechanism {

    pub const fn token(self) -> &'static str {
        match self {
            Mechanism::BindMount => "bind-mount",
            Mechanism::ClearExecBits => "clear-exec-bits",
        }
    }
}

pub const fn judge_mechanism(can_mount: bool) -> Mechanism {
    if can_mount {
        Mechanism::BindMount
    } else {
        Mechanism::ClearExecBits
    }
}

pub const NEVER_BLOCKED: &[&str] = &[
    "/bin/sh",
    "/usr/bin/sh",
    "/bin/bash",
    "/usr/bin/bash",
    "/bin/dash",
    "/usr/bin/dash",
    "/bin/busybox",
    "/usr/bin/busybox",
    "/bin/mount",
    "/usr/bin/mount",
    "/bin/umount",
    "/usr/bin/umount",
    "/bin/su",
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/bin/sudo",
    "/usr/bin/env",
    "/bin/env",
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/sbin/sshd",
    "/usr/lib/openssh/sshd-session",
    "/usr/libexec/openssh/sshd-session",
    "/usr/lib/ssh/sshd-session",
    "/usr/libexec/sshd-session",
    "/usr/lib/openssh/sshd-auth",
    "/usr/libexec/openssh/sshd-auth",
    "/usr/lib/ssh/sshd-auth",
    "/usr/libexec/sshd-auth",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceImages {

    pub listeners: Vec<(u32, PathBuf)>,

    pub declared: Vec<(String, PathBuf)>,

    pub scored: Vec<(String, PathBuf, String)>,
}

pub fn service_images(protect: &ProtectSet) -> Result<ServiceImages, String> {
    let listeners = protect
        .listener_pids
        .iter()
        .filter_map(|pid| {
            std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|exe| (*pid, image_name(exe)))
        })
        .collect();
    let declared = hemostat_sensor_linux::services::declared_exec_paths(
        &hemostat_sensor_linux::services::declarations(),
    )?;

    let held: Vec<hemostat_sensor_linux::services::Declared> = protect
        .scored_units
        .keys()
        .map(|unit| hemostat_sensor_linux::services::Declared { unit: unit.clone(), paths: Vec::new() })
        .collect();
    let scored = hemostat_sensor_linux::services::declared_exec_paths(&held)?
        .into_iter()
        .filter_map(|(unit, exe)| {
            let service = protect.scored_service(&unit)?.to_string();
            Some((unit, exe, service))
        })
        .collect();
    Ok(ServiceImages { listeners, declared, scored })
}

pub fn image_name(link: PathBuf) -> PathBuf {
    match link.to_str().and_then(|s| s.strip_suffix(" (deleted)")) {
        Some(s) => PathBuf::from(s),
        None => link,
    }
}

pub fn is_never_blocked(path: &Path) -> bool {
    NEVER_BLOCKED.iter().any(|p| Path::new(p) == path)
}

pub fn resolve(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

pub fn refusal_for(
    path: &Path,
    protect: &ProtectSet,
    pid1_exe: Option<&Path>,
    session_images: &[(u32, PathBuf)],
    services: &ServiceImages,
) -> Option<Refusal> {
    let say = |cause: RefuseCause, message: String| {
        Some(Refusal {
            action: format!("block execution of {}", path.display()),
            cause,
            message,
            suggested_alternative: None,
        })
    };

    if let Some(reason) = path_refusal(path) {
        return say(
            RefuseCause::InvalidTarget(reason.clone()),
            format!("refused to block {}: {reason}", path.display()),
        );
    }
    if !path.exists() {
        return say(
            RefuseCause::InvalidTarget("the path does not exist".into()),
            format!(
                "{} does not exist. A bind mount needs something to mount over, and blocking a \
                 name that is not there would report a containment that is not in place",
                path.display()
            ),
        );
    }

    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        let target = resolve(path);
        return say(
            RefuseCause::InvalidTarget("the path is a symlink".into()),
            format!(
                "refused to block {}: it is a symbolic link to {}, and the block would land on \
                 that file, not on the link. Name that file if it is the one you mean",
                path.display(),
                target.display()
            ),
        );
    }
    let same = |p: &Path| p == path || same_file(p, path);
    if let Some(r) = identity_refusal(path, same, pid1_exe, session_images, services) {
        return Some(r);
    }

    if !protect.listener_map_complete {
        return say(
            RefuseCause::UnverifiedProtectSet,
            format!(
                "refused to block {}: the listening-socket map is incomplete, so this cannot be \
                 shown not to be a scored service's binary. Re-run as root",
                path.display()
            ),
        );
    }
    if let Some(reason) = protect.path_reason(path) {
        return say(
            RefuseCause::Protected(reason.clone()),
            format!("refused to block {}: {}", path.display(), reason.describe()),
        );
    }
    None
}

fn identity_refusal(
    path: &Path,
    is: impl Fn(&Path) -> bool,
    pid1_exe: Option<&Path>,
    session_images: &[(u32, PathBuf)],
    services: &ServiceImages,
) -> Option<Refusal> {
    let say = |cause: RefuseCause, message: String| {
        Some(Refusal {
            action: format!("block execution of {}", path.display()),
            cause,
            message,
            suggested_alternative: None,
        })
    };
    if is(Path::new("/proc/self/exe")) {
        return say(
            RefuseCause::InvalidTarget("that is the agent's own executable".into()),
            format!("refused to block {}: that is the agent's own executable", path.display()),
        );
    }
    if NEVER_BLOCKED.iter().any(|p| is(Path::new(p))) {
        return say(
            RefuseCause::InvalidTarget("recovery path".into()),
            format!(
                "refused to block {}: it is part of the path back onto this host. `umount` is \
                 how this very action is reversed, sshd is how a responder reaches the host, \
                 and a shell is how anything is run at all — blocking one turns a reversible \
                 containment into a rebuild",
                path.display()
            ),
        );
    }

    if pid1_exe.is_some_and(&is) {
        return say(
            RefuseCause::InvalidTarget("pid 1".into()),
            format!(
                "refused to block {}: it is the executable pid 1 is running. The host would \
                 come up to nothing at the next boot, and the cause would not be visible until \
                 then",
                path.display()
            ),
        );
    }

    for (pid, exe) in session_images {
        if is(exe) {
            return say(
                RefuseCause::Protected(crate::ProtectReason::OperatorSession),
                format!(
                    "refused to block {}: pid {pid} is running it, and that pid is on the \
                     session chain this agent was launched from. Blocking it cuts the \
                     responder off the host at their next command",
                    path.display()
                ),
            );
        }
    }

    for (pid, exe) in &services.listeners {
        if is(exe) {
            return say(
                RefuseCause::Protected(crate::ProtectReason::ServiceListener),
                format!(
                    "refused to block {}: pid {pid} runs it and holds a listening socket, and a \
                     scored service whose binary is blocked fails at its next start. If it is a \
                     bind shell, stop it first (`remediate --allow-listener <unit>` for one a \
                     unit runs, or by hand) and block the file once nothing listening runs it",
                    path.display()
                ),
            );
        }
    }

    for (unit, exe, service) in &services.scored {
        if is(exe) {
            return say(
                RefuseCause::Protected(crate::ProtectReason::ScoredService(service.clone())),
                format!(
                    "refused to block {}: {unit} starts it, and {unit} runs the packet's scored \
                     service on this box: {service}. The service would fail at its next start, \
                     `services --restore` included — fix the unit by hand (restore it from its \
                     package, or take the added line out), then block the file if it is still \
                     wanted",
                    path.display()
                ),
            );
        }
    }
    for (unit, exe) in &services.declared {
        if is(exe) {
            return say(
                RefuseCause::Protected(crate::ProtectReason::OperatorDeclared),
                format!(
                    "refused to block {}: {unit}, declared in /etc/hemostat/critical, starts it, \
                     and the service would fail at its next start",
                    path.display()
                ),
            );
        }
    }
    None
}

pub fn session_images(protect: &ProtectSet) -> Vec<(u32, PathBuf)> {
    protect
        .session_pids
        .iter()
        .filter_map(|pid| {
            std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|exe| (*pid, exe))
        })
        .collect()
}

pub fn caveat() -> &'static str {
    "This stops the NEXT start, not a process already running from this image — contain that \
     with a kill or a suspend. It also does not survive a reboot."
}

pub fn apply(
    path: &Path,
    opts: &ApplyOptions,
    protect: &ProtectSet,
    mechanism: Mechanism,
) -> Outcome {
    let pid1 = std::fs::read_link("/proc/1/exe").ok();
    let images = session_images(protect);
    let services = match service_images(protect) {
        Ok(s) => s,
        Err(why) => {
            return Outcome::Refused(Refusal {
                action: format!("block execution of {}", path.display()),
                cause: RefuseCause::UnverifiedProtectSet,
                message: format!(
                    "refused to block {}: {why}, so this cannot be shown not to be the binary \
                     of a declared service or of a scored service held under HEMOSTAT_GOLDEN",
                    path.display()
                ),
                suggested_alternative: None,
            })
        }
    };
    if let Some(r) = refusal_for(path, protect, pid1.as_deref(), &images, &services) {
        return Outcome::Refused(r);
    }

    if !opts.armed {
        return Outcome::Planned(Plan {
            summary: format!("block execution of {}", path.display()),
            detail: match mechanism {
                Mechanism::BindMount => format!(
                    "Bind-mount /dev/null over {}. The file is not written to at all — its \
                     bytes, its mode and its timestamps stay exactly as they are, which is what \
                     an examiner will be asked about. While the block is on, that PATH reads as \
                     /dev/null, so the digest is taken first and recorded. {}",
                    path.display(),
                    caveat()
                ),
                Mechanism::ClearExecBits => format!(
                    "Clear every execute bit on {}. This WRITES to the inode: the mode changes \
                     and the ctime moves, so the file is no longer in the state the adversary \
                     left it in. The previous mode goes in the undo journal. Used because a \
                     bind mount is not available here. {}",
                    path.display(),
                    caveat()
                ),
            },
            undo: match mechanism {
                Mechanism::BindMount => format!("umount {}", path.display()),
                Mechanism::ClearExecBits => "restore the recorded mode".into(),
            },
            reversible: true,
            prefer_instead: None,
        });
    }

    let held = match pin(path, pid1.as_deref(), &images, &services) {
        Ok(f) => f,
        Err(o) => return *o,
    };
    match mechanism {
        Mechanism::BindMount => bind_mount(path, &held),
        Mechanism::ClearExecBits => clear_exec_bits(path, &held),
    }
}

fn pin(
    path: &Path,
    pid1_exe: Option<&Path>,
    session_images: &[(u32, PathBuf)],
    services: &ServiceImages,
) -> Result<std::fs::File, Box<Outcome>> {
    use std::os::unix::fs::MetadataExt as _;
    let failed = |reason: String| {
        Box::new(Outcome::Failed(Failure {
            action: format!("block execution of {}", path.display()),
            reason: format!("{reason}. Nothing was changed"),
        }))
    };
    let held = crate::paths::open_unredirected(path)
        .map_err(|e| failed(format!("could not open {}: {e}", path.display())))?;
    let md = held.metadata().map_err(|e| failed(format!("could not examine {}: {e}", path.display())))?;
    if !md.is_file() {
        return Err(failed(format!("{} is not a regular file", path.display())));
    }
    let is_held = |p: &Path| std::fs::metadata(p).is_ok_and(|m| m.dev() == md.dev() && m.ino() == md.ino());
    if let Some(mut r) = identity_refusal(path, is_held, pid1_exe, session_images, services) {
        r.message.push_str(
            ". It was not that file when the name was judged a moment earlier, so something \
             changed it in between",
        );
        return Err(Box::new(Outcome::Refused(r)));
    }
    Ok(held)
}

const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;

fn digest_before_blocking(held: &std::fs::File) -> String {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;
    let len = match held.metadata() {
        Ok(m) => m.len(),
        Err(e) => return format!("not hashed (the file could not be stat'd: {e})"),
    };
    if len > MAX_HASH_BYTES {
        return format!("not hashed ({len} bytes, over the {MAX_HASH_BYTES} cap)");
    }
    let mut bytes = Vec::new();

    if let Err(e) = held.take(MAX_HASH_BYTES + 1).read_to_end(&mut bytes) {
        return format!("not hashed ({e})");
    }
    if bytes.len() as u64 > MAX_HASH_BYTES {
        return format!("not hashed (it grew past the {MAX_HASH_BYTES} cap while being read)");
    }
    let mut h = Sha256::new();
    h.update(&bytes);
    format!("sha256 {:x}, {} bytes", h.finalize(), bytes.len())
}

fn bind_mount(path: &Path, held: &std::fs::File) -> Outcome {

    let digest = digest_before_blocking(held);
    match mount_dev_null_over(held) {
        Ok(()) => Outcome::Applied(UndoRecord {
            did: format!(
                "blocked execution of {} by bind-mounting /dev/null over it — the file itself \
                 is unchanged, and was {} immediately before the mount went on. {}",
                path.display(),
                digest,
                caveat()
            ),
            undo: UndoKind::UnmountExecBlock { path: path.to_path_buf() },
            reversible: true,
        }),
        Err(e) => Outcome::Failed(Failure {
            action: format!("block execution of {}", path.display()),
            reason: format!(
                "bind-mounting /dev/null over {} failed: {e}. Nothing was changed — a failed \
                 bind mount leaves no partial state",
                path.display()
            ),
        }),
    }
}

fn mount_dev_null_over(held: &std::fs::File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let target = std::ffi::CString::new(format!("/proc/self/fd/{}", held.as_raw_fd()))
        .map_err(std::io::Error::other)?;

    let rc = unsafe {
        libc::mount(
            c"/dev/null".as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn clear_exec_bits(path: &Path, held: &std::fs::File) -> Outcome {
    use std::os::unix::fs::PermissionsExt as _;
    let md = match held.metadata() {
        Ok(m) => m,
        Err(e) => {
            return Outcome::Failed(Failure {
                action: format!("block execution of {}", path.display()),
                reason: format!("could not read the mode of {}: {e}", path.display()),
            })
        }
    };
    let was = md.permissions().mode() & 0o7777;

    let now = was & !0o7111;
    if let Err(e) = held.set_permissions(std::fs::Permissions::from_mode(now)) {
        return Outcome::Failed(Failure {
            action: format!("block execution of {}", path.display()),
            reason: format!("could not change the mode of {}: {e}", path.display()),
        });
    }
    Outcome::Applied(UndoRecord {
        did: format!(
            "blocked execution of {} by clearing its execute bits ({was:04o} -> {now:04o}). \
             This wrote to the inode, so its ctime has moved. {}",
            path.display(),
            caveat()
        ),
        undo: UndoKind::RestoreMode { path: path.to_path_buf(), mode: was },
        reversible: true,
    })
}

pub fn undo_unmount(path: &Path, opts: &ApplyOptions) -> Outcome {
    if !opts.armed {
        return Outcome::Planned(Plan {
            summary: format!("unblock {}", path.display()),
            detail: format!(
                "Unmount the /dev/null over {} — `umount`, through its directory held open so \
                 a link swapped in on the way is not followed.",
                path.display()
            ),
            undo: "Block it again if needed.".into(),
            reversible: true,
            prefer_instead: None,
        });
    }
    match unmount_at(path) {
        Ok(()) => Outcome::Applied(UndoRecord {
            did: format!("unblocked {}: the bind mount is gone", path.display()),
            undo: UndoKind::Irreversible { note: "unmounting is the undo".into() },
            reversible: false,
        }),
        Err(e) => Outcome::Failed(Failure {
            action: format!("unblock {}", path.display()),
            reason: format!(
                "could not unmount {}: {e}. The block is STILL IN PLACE — execution is still \
                 refused",
                path.display()
            ),
        }),
    }
}

fn unmount_at(path: &Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(Error::new(ErrorKind::InvalidInput, "the path names no file"));
    };
    let dir = if dir == Path::new("/") {
        std::fs::File::open("/")?
    } else {
        crate::paths::open_unredirected(dir)?
    };
    let mut target = format!("/proc/self/fd/{}/", dir.as_raw_fd()).into_bytes();
    target.extend_from_slice(name.as_bytes());
    let target = std::ffi::CString::new(target)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "NUL in a path component"))?;

    let rc = unsafe { libc::umount2(target.as_ptr(), libc::UMOUNT_NOFOLLOW) };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

pub fn can_bind_mount() -> bool {
    has_sys_admin()
}

fn has_sys_admin() -> bool {
    const CAP_SYS_ADMIN: u64 = 21;
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        })
        .is_some_and(|caps| caps & (1 << CAP_SYS_ADMIN) != 0)
}

pub fn evidence_note(path: &Path, mechanism: Mechanism) -> String {
    match mechanism {
        Mechanism::BindMount => format!(
            "EVIDENCE: the original bytes are intact on the inode, but they are NOT reachable \
             through {} while the block is on — that name now resolves to /dev/null, so \
             `sha256sum` there returns the hash of an empty file and `stat` reports the \
             character device. The digest taken immediately before the mount is in the record \
             above; to reach the bytes again, lift the block with `--lift`. `findmnt {}` shows \
             the block is in place.",
            path.display(),
            path.display()
        ),
        Mechanism::ClearExecBits => format!(
            "The contents of {} are unchanged, but its mode is not: this route writes to the \
             inode. Hash it from the vault copy rather than from disk if the ctime matters.",
            path.display()
        ),
    }
}

pub fn block(path: &Path, opts: &ApplyOptions, protect: &ProtectSet) -> Outcome {
    apply(path, opts, protect, judge_mechanism(can_bind_mount()))
}

pub fn image_of(pid: u32) -> Result<PathBuf, String> {
    let link = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|e| format!("could not read the image of pid {pid}: {e}"))?;
    let s = link.to_string_lossy().into_owned();
    if let Some(stripped) = s.strip_suffix(" (deleted)") {
        return Err(format!(
            "pid {pid} is running {stripped}, which has already been unlinked. There is no \
             path to block: the next start would have to come from somewhere else, and that \
             somewhere is what to look for"
        ));
    }
    Ok(link)
}
