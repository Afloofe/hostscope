use std::fs;
use std::path::Path;

use hs_core::event::{fields, FieldMap, FieldValue};
use hs_core::{Event, EventKind, Origin, Provenance, Stamp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcSnapshot {

    pub pid: u32,

    pub ppid: u32,

    pub uid: u32,

    pub exe: Option<String>,

    pub cmdline: Option<String>,

    pub starttime_ticks: u64,
}

impl ProcSnapshot {

    pub fn to_event(&self, seq: u64, stamp: Stamp, origin: Origin) -> Event {
        let mut f = FieldMap::new();
        if let Some(exe) = &self.exe {
            f.insert(fields::IMAGE, FieldValue::Str(exe.clone()));
        }
        if let Some(cmd) = &self.cmdline {
            f.insert(fields::COMMAND_LINE, FieldValue::Str(cmd.clone()));
        }
        f.insert(fields::USER, FieldValue::U64(u64::from(self.uid)));
        f.insert(PID, FieldValue::U64(u64::from(self.pid)));
        f.insert(PPID, FieldValue::U64(u64::from(self.ppid)));

        Event {
            seq,
            stamp,
            origin,
            lane: EventKind::ProcessCreate.default_lane(),
            kind: EventKind::ProcessCreate,
            provenance: Provenance::Procfs,
            fields: f,
        }
    }
}

use hs_core::event::FieldName;

pub const PID: FieldName = fields::PROCESS_ID;

pub const PPID: FieldName = fields::PARENT_PROCESS_ID;

const MAX_STAT_BYTES: u64 = 64 * 1024;

const NOT_PROCFS: &str = "not a regular file on procfs — something is mounted over this process's \
     entry, and it is neither opened nor read";

fn read_pid_file(path: &Path, cap: u64) -> std::io::Result<(Vec<u8>, bool)> {
    use std::os::fd::AsRawFd as _;
    let refuse = || std::io::Error::new(std::io::ErrorKind::InvalidInput, NOT_PROCFS);
    let at = crate::saferead::open_o_path(path)?;
    let md = at.metadata()?;
    if !md.is_file() {
        return Err(refuse());
    }
    let asked = match on_procfs(&at) {
        Ok(true) => true,
        Ok(false) => return Err(refuse()),
        Err(e) if e.raw_os_error() == Some(libc::EBADF) => false,
        Err(e) => return Err(e),
    };
    let pinned = format!("/proc/self/fd/{}", at.as_raw_fd());
    let (f, _) = crate::saferead::open_regular(Path::new(&pinned), NOT_PROCFS)?;
    if !asked && !on_procfs(&f)? {
        return Err(refuse());
    }

    crate::saferead::read_bounded(&f, cap)
}

fn on_procfs(f: &fs::File) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd as _;

    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };

    let rc = unsafe { libc::fstatfs(f.as_raw_fd(), &mut sfs) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(is_proc_magic(sfs.f_type))
}

fn is_proc_magic(f_type: impl Into<i128>) -> bool {
    f_type.into() == i128::from(libc::PROC_SUPER_MAGIC)
}

pub fn read_process(pid: u32) -> Option<ProcSnapshot> {
    let base = format!("/proc/{pid}");
    let (stat, cut) = read_pid_file(&Path::new(&base).join("stat"), MAX_STAT_BYTES).ok()?;
    if cut {
        return None;
    }
    let stat = String::from_utf8_lossy(&stat).into_owned();

    let close = stat.rfind(')')?;
    let rest: Vec<&str> = stat.get(close + 1..)?.split_whitespace().collect();

    let ppid = rest.first().and_then(|_| rest.get(1))?.parse().ok()?;
    let starttime_ticks = rest.get(19).and_then(|v| v.parse().ok()).unwrap_or(0);

    let (status, _) = read_pid_file(&Path::new(&base).join("status"), MAX_STAT_BYTES).ok()?;
    let status = String::from_utf8_lossy(&status).into_owned();
    let uid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())?;

    let exe = fs::read_link(Path::new(&base).join("exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());

    let cmdline = read_pid_file(&Path::new(&base).join("cmdline"), crate::saferead::MAX_PROC_BYTES)
        .ok()
        .map(|(raw, _)| raw)
        .map(|raw| {
        raw.split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(String::from_utf8_lossy)
            .collect::<Vec<_>>()
            .join(" ")
    });

    Some(ProcSnapshot {
        pid,
        ppid,
        uid,
        exe,
        cmdline: cmdline.filter(|c| !c.is_empty()),
        starttime_ticks,
    })
}

pub fn walk() -> Vec<ProcSnapshot> {
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut out: Vec<ProcSnapshot> = dir
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(read_process)
        .collect();
    out.sort_by_key(|p| p.pid);
    out
}
