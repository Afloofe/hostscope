use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};

use crate::{ApplyOptions, Failure, Outcome, Plan, UndoKind, UndoRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {

    Image {

        path: PathBuf,

        deleted: bool,
    },

    AnonymousExec {

        start: u64,

        end: u64,

        perms: String,
    },
}

impl Subject {

    pub fn size(&self, pid: u32) -> Option<u64> {
        match self {
            Subject::Image { .. } => {
                std::fs::metadata(format!("/proc/{pid}/exe")).ok().map(|m| m.len())
            }
            Subject::AnonymousExec { start, end, .. } => Some(end.saturating_sub(*start)),
        }
    }

    pub fn filename(&self, pid: u32) -> String {
        match self {
            Subject::Image { path, .. } => {
                let base = path
                    .file_name()
                    .map_or_else(|| "image".to_string(), |n| n.to_string_lossy().into_owned());
                format!("pid{pid}-image-{base}")
            }
            Subject::AnonymousExec { start, end, .. } => {
                format!("pid{pid}-anon-{start:016x}-{end:016x}.bin")
            }
        }
    }

    pub fn why(&self) -> &'static str {
        match self {
            Subject::Image { deleted: true, .. } => {
                "the file has been unlinked, so this is the ONLY copy of the image in existence \
                 and it stops being readable the moment the process exits"
            }
            Subject::Image { deleted: false, .. } => {
                "the file is still on disk, so this is a convenience rather than a rescue — the \
                 same bytes can be collected from the filesystem at any time"
            }
            Subject::AnonymousExec { .. } => {
                "executable memory with no file behind it, which is code that was never loaded \
                 from disk. There is nothing on the filesystem to collect instead"
            }
        }
    }
}

pub const MAX_REGION_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acquired {

    pub path: PathBuf,

    pub subject: Subject,

    pub bytes: u64,

    pub sha256: String,
}

pub fn sensitivity_notice() -> &'static str {
    "SENSITIVE: this is process memory. It may contain passwords typed into that process, \
     session tokens, private keys and whatever the user was working on. A region boundary is \
     not a guarantee about content. Handle it as the most sensitive artefact of the engagement \
     — do not forward it to a third party without deciding that deliberately."
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Survey {

    pub subjects: Vec<Subject>,

    pub gap: Option<String>,
}

pub fn survey(pid: u32) -> Result<Survey, String> {
    survey_capped(pid, MAX_MAPS_BYTES)
}

const MAX_MAPS_BYTES: u64 = hemostat_sensor_linux::saferead::MAX_MAPS_BYTES;

fn survey_capped(pid: u32, cap: u64) -> Result<Survey, String> {
    let mut out = Vec::new();

    match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(link) => {
            let s = link.to_string_lossy().into_owned();
            let deleted = s.ends_with(" (deleted)");
            out.push(Subject::Image {
                path: PathBuf::from(s.trim_end_matches(" (deleted)")),
                deleted,
            });
        }
        Err(e) => {
            return Err(format!(
                "pid {pid}'s image could not be read ({e}). Either it has exited, or this run \
                 is not privileged enough to look — and those lead to opposite conclusions, so \
                 neither is assumed"
            ))
        }
    }

    let (maps, truncated) =
        hemostat_sensor_linux::saferead::read_kernel_text_capped(format!("/proc/{pid}/maps"), cap)
            .map_err(|e| format!("pid {pid}'s mappings could not be read ({e})"))?;
    out.extend(anonymous_exec_in(&maps));
    let gap = truncated.then(|| map_cut_gap(pid, cap));
    Ok(Survey { subjects: out, gap })
}

fn map_cut_gap(pid: u32, cap: u64) -> String {
    format!(
        "pid {pid}'s memory map is over the {} MiB read cap and was NOT examined in full: an \
         anonymous executable region past that point is not offered here. A map that size is \
         itself anomalous. `grep -E ' ..x[ps] ' /proc/{pid}/maps` lists every executable mapping",
        cap / (1024 * 1024)
    )
}

const KERNEL_MAPPINGS: &[&str] =
    &["[vdso]", "[vvar]", "[vvar_vclock]", "[vsyscall]", "[uprobes]", "[sigpage]", "[vectors]"];

pub fn anonymous_exec_in(maps: &str) -> Vec<Subject> {
    let mut out = Vec::new();
    for line in maps.lines() {
        let f: Vec<&str> = line.splitn(6, char::is_whitespace).collect();
        if f.len() < 5 {
            continue;
        }
        let perms = f[1];
        if !perms.contains('x') {
            continue;
        }
        let path = f.get(5).map(|p| p.trim()).filter(|p| !p.is_empty());
        if path.is_some_and(|p| !p.starts_with('[') || KERNEL_MAPPINGS.contains(&p)) {
            continue;
        }
        let Some((a, b)) = f[0].split_once('-') else { continue };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16)) else {
            continue;
        };
        out.push(Subject::AnonymousExec { start, end, perms: perms.to_string() });
    }
    out
}

pub fn apply(pid: u32, subject: &Subject, dir: &Path, opts: &ApplyOptions) -> Outcome {
    let size = subject.size(pid);
    if let Some(n) = size {
        if n > MAX_REGION_BYTES {
            let (mb, cap) = (n / (1024 * 1024), MAX_REGION_BYTES / (1024 * 1024));
            return Outcome::Refused(crate::Refusal {
                action: format!("acquire {} from pid {pid}", subject.filename(pid)),
                cause: crate::RefuseCause::InvalidTarget("too large".into()),
                message: match subject {

                    Subject::Image { .. } => format!(
                        "this image is {mb} MB, over the {cap} MB cap on a single read, and \
                         reading it whole is an unbounded pause on a host somebody is trying to \
                         keep up. If it is the only copy, keep it by hand before the process \
                         exits: `cp /proc/{pid}/exe` into a private directory reads the same \
                         inode this would have"
                    ),
                    Subject::AnonymousExec { .. } => format!(
                        "this is {mb} MB, over the {cap} MB cap. Injected code is measured in \
                         kilobytes and a read this size is an unbounded pause on a host somebody \
                         is trying to keep up. If you genuinely want it, take a full image with a \
                         tool built for that"
                    ),
                },
                suggested_alternative: None,
            });
        }
    }

    match realtime_class(pid) {
        Ok(None) => {}
        Ok(Some(class)) => {
            return Outcome::Refused(crate::Refusal {
                action: format!("acquire {} from pid {pid}", subject.filename(pid)),
                cause: crate::RefuseCause::InvalidTarget(format!("scheduled {class}")),
                message: format!(
                    "pid {pid} is scheduled {class}, a real-time class; reading it competes with \
                     a process that has deadlines. Take it with a tool built for that, at a \
                     time the process can afford"
                ),
                suggested_alternative: None,
            });
        }
        Err(why) => {
            return Outcome::Refused(crate::Refusal {
                action: format!("acquire {} from pid {pid}", subject.filename(pid)),
                cause: crate::RefuseCause::InvalidTarget(why.clone()),
                message: format!("refused: {why}, so it cannot be shown not to be real-time"),
                suggested_alternative: None,
            });
        }
    }

    if !opts.armed {
        let mut detail = format!(
            "Read {} from pid {pid} into {}. {}",
            match subject {
                Subject::Image { path, deleted } => format!(
                    "the image at {}{}",
                    path.display(),
                    if *deleted { " (UNLINKED)" } else { "" }
                ),
                Subject::AnonymousExec { start, end, perms } =>
                    format!("the {perms} mapping {start:#x}-{end:#x}"),
            },
            dir.display(),
            subject.why()
        );
        if matches!(subject, Subject::AnonymousExec { .. }) {
            detail.push_str("\n\n  ");
            detail.push_str(sensitivity_notice());
        }
        return Outcome::Planned(Plan {
            summary: format!("acquire {} from pid {pid}", subject.filename(pid)),
            detail,
            undo: "delete the artefact. Acquiring reads and changes nothing on the host".into(),

            reversible: false,
            prefer_instead: None,
        });
    }

    let bytes = match subject {
        Subject::Image { .. } => read_image(pid),
        Subject::AnonymousExec { start, end, .. } => read_region(pid, *start, *end),
    };
    let bytes = match bytes {
        Ok(b) => b,
        Err(reason) => {
            return Outcome::Failed(Failure {
                action: format!("acquire from pid {pid}"),
                reason,
            })
        }
    };

    if let Err(reason) = private_dir(dir) {
        return Outcome::Failed(Failure { action: format!("acquire from pid {pid}"), reason });
    }
    let path = dir.join(subject.filename(pid));
    if let Err(e) = write_private(&path, &bytes) {
        return Outcome::Failed(Failure {
            action: format!("acquire from pid {pid}"),
            reason: format!("could not write {}: {e}", path.display()),
        });
    }

    let sha = sha256_hex(&bytes);
    let mut did = format!(
        "acquired {} byte(s) from pid {pid} into {} (sha256 {sha}) — {}",
        bytes.len(),
        path.display(),
        subject.why()
    );
    if matches!(subject, Subject::AnonymousExec { .. }) {
        did.push(' ');
        did.push_str(sensitivity_notice());
    }

    Outcome::Applied(UndoRecord {
        did,

        undo: UndoKind::Nothing,
        reversible: false,
    })
}

fn realtime_class(pid: u32) -> Result<Option<&'static str>, String> {
    let stat = std::fs::read(format!("/proc/{pid}/stat"))
        .map_err(|e| format!("could not read pid {pid}'s scheduling class ({e})"))?;

    let stat = String::from_utf8_lossy(&stat);
    realtime_class_in(&stat).ok_or_else(|| format!("pid {pid}'s stat has no scheduling class"))
}

fn realtime_class_in(stat: &str) -> Option<Option<&'static str>> {

    let policy: u32 = stat.rsplit_once(')')?.1.split_whitespace().nth(38)?.parse().ok()?;
    Some(match policy {
        1 => Some("SCHED_FIFO"),
        2 => Some("SCHED_RR"),
        6 => Some("SCHED_DEADLINE"),
        _ => None,
    })
}

fn private_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    let md = std::fs::symlink_metadata(dir).map_err(|e| format!("could not examine {}: {e}", dir.display()))?;
    if !md.is_dir() {
        return Err(format!("{} is not a directory (a symlink is refused, not followed)", dir.display()));
    }
    let me = std::fs::metadata("/proc/self").map_err(|e| format!("could not read this process's uid: {e}"))?;
    if md.uid() != me.uid() {
        return Err(format!("{} belongs to uid {}, not to this process; pick another --into", dir.display(), md.uid()));
    }
    if md.mode() & 0o077 != 0 {
        return Err(format!(
            "{} is mode {:o}, readable by others, and an acquisition holds whatever the \
             process had in memory; `chmod 700` it or pick another --into",
            dir.display(),
            md.mode() & 0o7777
        ));
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

fn read_image(pid: u32) -> Result<Vec<u8>, String> {

    let f = std::fs::File::open(format!("/proc/{pid}/exe"))
        .map_err(|e| format!("could not read pid {pid}'s image: {e}"))?;

    let len = f.metadata().map_err(|e| format!("could not stat pid {pid}'s image: {e}"))?.len();
    let too_big = || {
        format!(
            "pid {pid}'s image is over the {} MB cap on a single read, so nothing was read or \
             written",
            MAX_REGION_BYTES / (1024 * 1024)
        )
    };
    if len > MAX_REGION_BYTES {
        return Err(too_big());
    }
    let mut buf = Vec::new();
    (&f).take(MAX_REGION_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("could not read pid {pid}'s image: {e}"))?;
    if buf.len() as u64 > MAX_REGION_BYTES {
        return Err(too_big());
    }
    Ok(buf)
}

fn read_region(pid: u32, start: u64, end: u64) -> Result<Vec<u8>, String> {
    let len = usize::try_from(end.saturating_sub(start))
        .map_err(|_| "the region is larger than this machine can address".to_string())?;
    let mut f = std::fs::File::open(format!("/proc/{pid}/mem")).map_err(|e| {
        format!(
            "could not open pid {pid}'s memory ({e}). This needs root or CAP_SYS_PTRACE, and on \
             a host with `kernel.yama.ptrace_scope` raised it needs to be root"
        )
    })?;
    f.seek(SeekFrom::Start(start))
        .map_err(|e| format!("could not seek to {start:#x}: {e}"))?;
    let mut buf = vec![0_u8; len];

    f.read_exact(&mut buf).map_err(|e| {
        format!(
            "could not read {len} bytes at {start:#x} ({e}). The mapping may have been unmapped \
             between the survey and the read — nothing was written"
        )
    })?;
    Ok(buf)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

pub fn manifest_line(a: &Acquired, pid: u32) -> String {
    format!(
        "{}\t{}\t{}\tpid {pid}\t{}\n",
        a.path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
        a.bytes,
        a.sha256,
        a.subject.why()
    )
}
