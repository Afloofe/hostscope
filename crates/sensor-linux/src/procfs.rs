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

    pub cmdline_cut: bool,

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

fn read_pid_file(path: &Path, cap: u64) -> std::io::Result<(Vec<u8>, bool)> {
    crate::saferead::read_procfs(path, cap)
}

pub const MAX_CMDLINE_KEPT: usize = 64 * 1024;

pub const MAX_WALK_CMDLINE_BYTES: usize = 32 * 1024 * 1024;

const MAX_CMDLINE_FLOOR: usize = 2 * hs_core::MAX_FIELD_BYTES;

pub(crate) fn keep_ends(s: String, keep: usize) -> (String, bool) {
    use hs_core::event::CUT_MARK;
    if s.len() <= keep {
        return (s, false);
    }
    let half = keep / 2;
    let mut head = half;
    while head > 0 && !s.is_char_boundary(head) {
        head -= 1;
    }
    let mut tail = s.len().saturating_sub(half);
    while tail < s.len() && !s.is_char_boundary(tail) {
        tail += 1;
    }
    let mut out = String::with_capacity(head + CUT_MARK.len() + (s.len() - tail));
    out.push_str(s.get(..head).unwrap_or_default());
    out.push_str(CUT_MARK);
    out.push_str(s.get(tail..).unwrap_or_default());
    (out, true)
}

pub(crate) fn charge_cmdline(budget: &mut usize, cmd: &mut String) -> bool {
    if cmd.len() <= *budget {
        *budget -= cmd.len();
        return false;
    }
    *budget = 0;
    let (kept, cut) = keep_ends(std::mem::take(cmd), MAX_CMDLINE_FLOOR);
    *cmd = kept;
    cut
}

pub fn cmdline_gap(procs: &[ProcSnapshot]) -> Option<String> {
    let cut: Vec<u32> = procs.iter().filter(|p| p.cmdline_cut).map(|p| p.pid).collect();
    if cut.is_empty() {
        return None;
    }
    let shown: Vec<String> = cut.iter().take(10).map(u32::to_string).collect();
    let more = cut.len() - shown.len();
    Some(format!(
        "{} of {} process(es) have a command line longer than the walk keeps of it ({} KiB each, {} MiB over every \
         process) — pid {}{}. Only its head and tail were examined, so a rule or a match keyed on text in the cut \
         middle has not been evaluated for those",
        cut.len(),
        procs.len(),
        MAX_CMDLINE_KEPT / 1024,
        MAX_WALK_CMDLINE_BYTES / (1024 * 1024),
        shown.join(", "),
        if more > 0 { format!(" and {more} more") } else { String::new() }
    ))
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

    let mut cmdline_cut = false;
    let cmdline = read_pid_file(&Path::new(&base).join("cmdline"), crate::saferead::MAX_PROC_BYTES)
        .ok()
        .map(|(raw, read_cut)| {
            let joined = raw
                .split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(String::from_utf8_lossy)
                .collect::<Vec<_>>()
                .join(" ");
            let (kept, kept_cut) = keep_ends(joined, MAX_CMDLINE_KEPT);
            cmdline_cut = read_cut || kept_cut;
            kept
        });

    Some(ProcSnapshot {
        pid,
        ppid,
        uid,
        exe,
        cmdline: cmdline.filter(|c| !c.is_empty()),
        cmdline_cut,
        starttime_ticks,
    })
}

pub fn walk() -> Vec<ProcSnapshot> {
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut pids: Vec<u32> =
        dir.flatten().filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok()).collect();
    pids.sort_unstable();
    let mut budget = MAX_WALK_CMDLINE_BYTES;
    pids.into_iter()
        .filter_map(read_process)
        .map(|mut p| {
            if let Some(cmd) = p.cmdline.as_mut() {
                p.cmdline_cut |= charge_cmdline(&mut budget, cmd);
            }
            p
        })
        .collect()
}
