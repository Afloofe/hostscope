use std::collections::{BTreeMap, BTreeSet};

use crate::procfs::ProcSnapshot;
use crate::rootkit::{Finding, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Supervisor {

    Unit(String),

    UserUnit {

        manager: String,

        unit: String,
    },

    Adopted {

        manager: String,

        pid: u32,
    },

    Parent {

        pid: u32,

        ident: String,
    },

    Supervised {

        supervisor: String,

        service: String,

        pid: u32,
    },

    Orphaned,

    None_,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Respawn {

    pub ident: String,

    pub was_pid: u32,

    pub now_pid: u32,

    pub by: Supervisor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {

    Ordinary,

    Irregular,

    SurvivedRemoval,
}

const INTERPRETERS: &[&str] =
    &["sh", "bash", "dash", "zsh", "ksh", "python", "python2", "python3", "perl", "ruby", "php"];

pub fn script_of(p: &ProcSnapshot) -> Option<String> {
    script_in(p.exe.as_deref()?, p.cmdline.as_deref()?)
}

fn script_in(exe: &str, cmd: &str) -> Option<String> {
    let base = exe.rsplit('/').next()?;
    let base = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if !INTERPRETERS.contains(&base) && !INTERPRETERS.contains(&exe.rsplit('/').next()?) {
        return None;
    }
    let mut toks = cmd.split_whitespace();
    let _argv0 = toks.next()?;
    for t in toks {
        if t == "-c" {
            return None;
        }
        if t.starts_with('-') {
            continue;
        }
        if t.starts_with('/') && t.len() > 1 {
            return Some(t.to_string());
        }

        return None;
    }
    None
}

pub fn identity(p: &ProcSnapshot) -> String {
    if let Some(script) = script_of(p) {
        return script;
    }
    match (&p.exe, &p.cmdline) {
        (Some(e), _) if !e.is_empty() => e.clone(),
        (_, Some(c)) if !c.is_empty() => c.clone(),
        _ => format!("pid:{}", p.pid),
    }
}

const MAX_SCRIPT: usize = 64 * 1024;

pub fn program_text(p: &ProcSnapshot) -> String {
    let mut text = p.cmdline.clone().unwrap_or_default();
    if let Some(script) = script_of(p) {
        let path = std::path::Path::new(&script);

        use std::io::Read as _;
        if let Ok((f, _)) = crate::saferead::open_regular(path, crate::saferead::NOT_REGULAR) {
            let mut body = Vec::new();
            if (&f).take(MAX_SCRIPT as u64).read_to_end(&mut body).is_ok() {
                text.push('\n');
                text.push_str(&String::from_utf8_lossy(&body));
            }
        }
    }
    text
}

pub fn unit_from_cgroup(text: &str) -> Option<String> {
    match cgroup_unit(text)? {
        CgroupUnit::System(u) => Some(u),
        CgroupUnit::User { .. } => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CgroupUnit {

    System(String),

    User { manager: String, unit: String },
}

pub fn cgroup_path(line: &str) -> Option<&str> {
    line.splitn(3, ':').nth(2)
}

fn cgroup_unit(text: &str) -> Option<CgroupUnit> {
    let is_manager = |c: &str| c.starts_with("user@") && c.ends_with(".service");
    let mut found = None;
    for line in text.lines() {
        let Some(path) = cgroup_path(line) else { continue };
        let path: Vec<&str> = path.split('/').collect();
        let Some(at) = path.iter().rposition(|c| c.ends_with(".service") || c.ends_with(".scope")) else {
            continue;
        };
        let leaf = *path.get(at)?;
        if leaf.ends_with(".scope") || is_manager(leaf) {
            return None;
        }
        let manager = path.get(..at).and_then(|above| above.iter().rfind(|c| is_manager(c)));
        found = Some(match manager {
            Some(m) => CgroupUnit::User { manager: (*m).to_string(), unit: leaf.to_string() },
            None => CgroupUnit::System(leaf.to_string()),
        });
    }
    found
}

pub fn loop_respawner(text: &str, own: &[String], is_program: &dyn Fn(&str) -> bool) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let looping = lower.contains("while ")
        || lower.contains("until ")
        || lower.contains("for(;;)")
        || lower.contains("for (;;)");
    let sleeping = lower.contains("sleep ");
    if !(looping && sleeping) {
        return None;
    }
    text.split_whitespace()
        .map(|t| t.trim_matches(|c| c == '"' || c == '\'' || c == ';' || c == '`' || c == '('))
        .find(|t| {
            t.starts_with('/') && t.len() > 1 && !is_interpreter(t) && !own.iter().any(|o| o == t) && is_program(t)
        })
        .map(|s| s.to_string())
}

fn program_check<'a>(procs: &[ProcSnapshot], is_exec: &'a dyn Fn(&str) -> bool) -> impl Fn(&str) -> bool + 'a {
    let live: BTreeSet<String> = procs.iter().map(identity).collect();
    move |t: &str| live.contains(t) || live.contains(&format!("{t} (deleted)")) || is_exec(t)
}

pub fn guard_pairs(procs: &[ProcSnapshot]) -> Vec<(u32, u32)> {
    pairs_with(procs, &program_text, &is_executable_file)
}

pub fn pairs_with(
    procs: &[ProcSnapshot],
    text: &dyn Fn(&ProcSnapshot) -> String,
    is_exec: &dyn Fn(&str) -> bool,
) -> Vec<(u32, u32)> {
    let read: Vec<(u32, Option<String>, BTreeSet<String>)> = procs
        .iter()
        .map(|p| (p.pid, pair_name(p).filter(|n| is_exec(n)), names_in(&text(p), &own_names(p))))
        .collect();
    pairs_from(&read)
}

pub fn pairs_from(procs: &[(u32, Option<String>, BTreeSet<String>)]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for (i, (apid, aname, anames)) in procs.iter().enumerate() {
        let Some(aname) = aname else { continue };
        for (bpid, bname, bnames) in procs.iter().skip(i + 1) {
            let Some(bname) = bname else { continue };
            if aname == bname {
                continue;
            }
            if anames.contains(bname) && bnames.contains(aname) {
                out.push((*apid, *bpid));
            }
        }
    }
    out
}

pub fn pair_name(p: &ProcSnapshot) -> Option<String> {
    let name = match script_of(p) {
        Some(_) if reads_program_elsewhere(p) => return None,
        Some(script) => script,
        None => {
            let exe = p.exe.as_deref()?;
            if is_interpreter(exe) {
                return None;
            }
            exe.to_string()
        }
    };
    let plain = name.len() > 1
        && name.starts_with('/')
        && !name.contains(|c: char| c.is_whitespace() || WORD_BREAKS.contains(&c));
    plain.then_some(name)
}

const WORD_BREAKS: &[char] = &['"', '\'', '`', ';', '|', '&', '<', '>', '(', ')', '{', '}', '[', ']', ',', '='];

pub fn names_in(text: &str, own: &[String]) -> BTreeSet<String> {
    text.split(|c: char| c.is_whitespace() || WORD_BREAKS.contains(&c))
        .filter(|w| w.len() > 1 && w.starts_with('/') && !own.iter().any(|o| o == w))
        .map(str::to_string)
        .collect()
}

pub fn own_names(p: &ProcSnapshot) -> Vec<String> {
    let mut own: Vec<String> = Vec::new();
    if let Some(argv0) = p.cmdline.as_deref().and_then(|c| c.split_whitespace().next()) {
        own.push(argv0.to_string());
    }
    own.extend(p.exe.clone());
    own.extend(script_of(p));
    own
}

fn reads_program_elsewhere(p: &ProcSnapshot) -> bool {
    let (Some(exe), Some(cmd)) = (p.exe.as_deref(), p.cmdline.as_deref()) else { return false };
    reads_elsewhere(exe, cmd)
}

fn reads_elsewhere(exe: &str, cmd: &str) -> bool {
    let full = exe.rsplit('/').next().unwrap_or(exe);
    let (shell, inline): (bool, &[char]) = match full.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.') {
        "sh" | "bash" | "dash" | "zsh" | "ksh" => (true, &['s', 'c']),
        "python" => (false, &['c']),
        "perl" => (false, &['e', 'E']),
        "ruby" => (false, &['e']),
        "php" => (false, &['r']),
        _ => (false, &[]),
    };
    for t in cmd.split_whitespace().skip(1) {

        let Some(flags) = t.strip_prefix('-') else { return false };
        if flags.is_empty() || (shell && (t == "--rcfile" || t == "--init-file")) {
            return true;
        }
        if !flags.starts_with('-') && flags.contains(inline) {
            return true;
        }
    }
    false
}

pub(crate) fn is_interpreter(path: &str) -> bool {
    let full = path.rsplit('/').next().unwrap_or(path);
    let base = full.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INTERPRETERS.contains(&base) || INTERPRETERS.contains(&full)
}

fn is_executable_file(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

pub fn respawns(before: &[ProcSnapshot], after: &[ProcSnapshot]) -> Vec<Respawn> {
    let group = |set: &[ProcSnapshot]| -> BTreeMap<String, BTreeSet<u32>> {
        let mut m: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
        for p in set {
            m.entry(identity(p)).or_default().insert(p.pid);
        }
        m
    };
    let (b, a) = (group(before), group(after));

    let mut out = Vec::new();
    for (ident, old) in &b {
        let Some(new) = a.get(ident) else { continue };

        if old.iter().any(|p| new.contains(p)) {
            continue;
        }
        let (Some(&was), Some(&now)) = (old.iter().next(), new.iter().next()) else {
            continue;
        };
        out.push(Respawn { ident: ident.clone(), was_pid: was, now_pid: now, by: Supervisor::None_ });
    }
    out
}

pub fn supervisor_program(ident: &str, cmdline: Option<&str>) -> Option<(String, String)> {

    const SUPERVISORS: &[&str] = &[
        "runsv",
        "s6-supervise",
        "supervise",
    ];

    let program = ident.split_whitespace().next()?;
    let base = program.rsplit('/').next().unwrap_or(program);
    if !SUPERVISORS.contains(&base) {
        return None;
    }

    let service = cmdline
        .and_then(|c| c.split_whitespace().nth(1))
        .map(|a| a.trim_end_matches('/').rsplit('/').next().unwrap_or(a).to_string())
        .unwrap_or_default();
    Some((base.to_string(), service))
}

pub fn attribute(p: &ProcSnapshot, unit: Option<&str>, procs: &[ProcSnapshot]) -> Supervisor {
    if let Some(u) = unit {
        return Supervisor::Unit(u.to_string());
    }
    if p.ppid <= 1 {
        return Supervisor::Orphaned;
    }
    match procs.iter().find(|q| q.pid == p.ppid) {
        Some(parent) => match supervisor_program(&identity(parent), parent.cmdline.as_deref()) {
            Some((supervisor, service)) => {
                Supervisor::Supervised { supervisor, service, pid: parent.pid }
            }
            None => Supervisor::Parent { pid: parent.pid, ident: identity(parent) },
        },

        None => Supervisor::Orphaned,
    }
}

pub fn supervisor_of(p: &ProcSnapshot, procs: &[ProcSnapshot]) -> Supervisor {
    let text = crate::saferead::read_pid_text(format!("/proc/{}/cgroup", p.pid)).unwrap_or_default();
    attribute_cgroup(p, &text, procs)
}

fn attribute_cgroup(p: &ProcSnapshot, cgroup: &str, procs: &[ProcSnapshot]) -> Supervisor {
    match cgroup_unit(cgroup) {
        Some(CgroupUnit::User { manager, unit }) => Supervisor::UserUnit { manager, unit },
        Some(CgroupUnit::System(u)) => attribute(p, Some(&u), procs),
        None => match (attribute(p, None, procs), user_manager(cgroup)) {
            (Supervisor::Parent { pid, ident }, Some(manager))
                if ident.split_whitespace().next().is_some_and(|e| e.rsplit('/').next() == Some("systemd")) =>
            {
                Supervisor::Adopted { manager, pid }
            }
            (by, _) => by,
        },
    }
}

fn user_manager(cgroup: &str) -> Option<String> {
    cgroup
        .lines()
        .filter_map(cgroup_path)
        .flat_map(|p| p.split('/'))
        .find(|c| c.starts_with("user@") && c.ends_with(".service"))
        .map(str::to_string)
}

pub fn weigh(by: &Supervisor, packaged: bool, after_removal: bool) -> Verdict {
    if after_removal {
        return Verdict::SurvivedRemoval;
    }
    match by {

        Supervisor::Unit(_) | Supervisor::UserUnit { .. } | Supervisor::Supervised { .. } => {
            Verdict::Ordinary
        }
        _ if packaged => Verdict::Ordinary,
        Supervisor::Parent { .. }
        | Supervisor::Adopted { .. }
        | Supervisor::Orphaned
        | Supervisor::None_ => Verdict::Irregular,
    }
}

pub fn describe(by: &Supervisor) -> String {
    match by {
        Supervisor::Unit(u) => format!("systemd unit {u} (stop and disable it before killing the process)"),
        Supervisor::UserUnit { manager, unit } => format!(
            "systemd user unit {unit} of {manager} (stop and disable it with `systemctl --user`, as \
             that user, before killing the process — the system manager does not own it)"
        ),
        Supervisor::Supervised { supervisor, service, pid } if !service.is_empty() => format!(
            "{supervisor} pid {pid} supervising {service} (`sv down {service}` — or remove the \
             service directory — before killing the process, or it comes straight back)"
        ),
        Supervisor::Supervised { supervisor, pid, .. } => format!(
            "{supervisor} pid {pid} (stop the supervised service before killing the process)"
        ),
        Supervisor::Adopted { manager, pid } => format!(
            "adopted by {manager} (pid {pid}), the user's service manager, which reaps it and does \
             not restart it — do not kill the manager; look for what launched it again: a user \
             timer, an autostart entry, a cron line"
        ),
        Supervisor::Parent { pid, ident } => format!("parent pid {pid} ({ident}) — kill it in the same freeze, or it restarts this one"),
        Supervisor::Orphaned => "nothing in the process tree — it was double-forked, so look for a unit, a cron line or a timer".to_string(),
        Supervisor::None_ => "not determined".to_string(),
    }
}

pub fn findings(
    seen: &[Respawn],
    packaged: &dyn Fn(&str) -> bool,
    after_removal: &dyn Fn(&str) -> bool,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for r in seen {
        let v = weigh(&r.by, packaged(&r.ident), after_removal(&r.ident));
        let (sev, why) = match v {
            Verdict::SurvivedRemoval => (
                Severity::Critical,
                "this agent killed it and it is running again, so something on this host is \
                 putting it back. Removing the payload alone will not hold — the supervisor \
                 named above has to go in the same action."
                    .to_string(),
            ),
            Verdict::Irregular => (
                Severity::Warn,
                "it was replaced without the service manager being involved, which is how a \
                 minder keeps a payload alive. It may equally be a wrapper script; confirm \
                 what the supervisor is before acting on it."
                    .to_string(),
            ),
            Verdict::Ordinary => (
                Severity::Note,
                "restarted by the service manager that owns it — this is what a working host \
                 does, recorded so that a later respawn has something to compare against."
                    .to_string(),
            ),
        };
        out.push(Finding {
            severity: sev,
            subject: r.ident.clone(),
            what: format!(
                "restarted: pid {} replaced pid {}; kept alive by {}",
                r.now_pid,
                r.was_pid,
                describe(&r.by)
            ),
            why,
        });
    }
    out
}

pub fn group_for(pid: u32, procs: &[ProcSnapshot], unit: Option<&str>) -> (Vec<u32>, Vec<String>) {
    group_with(pid, procs, unit, &program_text, &is_executable_file)
}

pub fn group_with(
    pid: u32,
    procs: &[ProcSnapshot],
    unit: Option<&str>,
    text: &dyn Fn(&ProcSnapshot) -> String,
    is_exec: &dyn Fn(&str) -> bool,
) -> (Vec<u32>, Vec<String>) {
    let mut members: BTreeSet<u32> = BTreeSet::new();
    members.insert(pid);

    let Some(target) = procs.iter().find(|p| p.pid == pid) else {
        return (vec![pid], unit.into_iter().map(|s| s.to_string()).collect());
    };
    let target_id = identity(target);

    for (a, b) in pairs_with(procs, text, is_exec) {
        if a == pid {
            members.insert(b);
        } else if b == pid {
            members.insert(a);
        }
    }

    let is_program = program_check(procs, is_exec);
    for p in procs {
        if p.pid == pid || p.pid <= 1 {
            continue;
        }
        if let Some(relaunches) = loop_respawner(&text(p), &own_names(p), &is_program) {
            if relaunches == target_id {
                members.insert(p.pid);
            }
        }
    }

    members.remove(&1);
    (members.into_iter().collect(), unit.into_iter().map(|s| s.to_string()).collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pinned {

    pub pid: u32,

    pub start: u64,
}

impl Pinned {

    pub fn seed(procs: &[&ProcSnapshot]) -> Vec<Pinned> {
        let mut out: Vec<Pinned> = Vec::new();
        for p in procs {
            let pin = Pinned { pid: p.pid, start: p.starttime_ticks };
            if pin.pid > 1 && pin.start > 0 && !out.contains(&pin) {
                out.push(pin);
            }
        }
        out
    }

    pub fn is(&self, p: &ProcSnapshot) -> bool {
        p.pid == self.pid && p.starttime_ticks == self.start
    }

    pub fn list(seed: &[Pinned]) -> String {
        seed.iter().map(|s| format!("{}@{}", s.pid, s.start)).collect::<Vec<_>>().join(",")
    }

    pub fn parse_list(s: &str) -> Option<Vec<Pinned>> {
        let number = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
        s.split(',')
            .map(|e| {
                let (pid, start) = e.split_once('@')?;
                if !number(pid) || !number(start) {
                    return None;
                }
                let pin = Pinned { pid: pid.parse().ok()?, start: start.parse().ok()? };
                (pin.pid > 1 && pin.start > 0).then_some(pin)
            })
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub available: bool,

    pub reason: Option<String>,

    pub findings: Vec<Finding>,

    pub seeds: Vec<Vec<Pinned>>,
}

impl Report {

    pub fn seed(&self, i: usize) -> Option<&[Pinned]> {
        self.seeds.get(i).map(Vec::as_slice)
    }
}

pub fn report() -> Report {
    let procs = crate::procfs::walk();

    if procs.is_empty() {
        return Report {
            available: false,
            reason: Some(
                "/proc yielded no processes, so no guard pair or restart loop could be \
                 seen — this is a refusal to read, not an absence of watchdogs"
                    .into(),
            ),
            findings: Vec::new(),
            seeds: Vec::new(),
        };
    }
    let packages = crate::pkg::manager();
    let owned = |exe: &str| -> bool {
        packages.as_ref().is_some_and(|m| m.owns(std::path::Path::new(exe)))
    };

    let mut out: Vec<(Finding, Vec<Pinned>)> = Vec::new();

    for (a, b) in guard_pairs(&procs) {
        let (Some(pa), Some(pb)) = (
            procs.iter().find(|p| p.pid == a),
            procs.iter().find(|p| p.pid == b),
        ) else {
            continue;
        };
        let (ia, ib) = (identity(pa), identity(pb));

        if owned(&ia) && owned(&ib) {
            continue;
        }
        out.push(pair_finding(pa, &ia, pb, &ib));
    }

    let is_program = program_check(&procs, &is_executable_file);
    for p in &procs {

        let text = program_text(p);
        let Some(target) = loop_respawner(&text, &own_names(p), &is_program) else { continue };

        if target == identity(p) {
            continue;
        }

        let live = procs.iter().find(|q| identity(q) == target);
        if owned(&target) {
            continue;
        }
        let unit = supervisor_of(p, &procs);
        out.push(loop_finding(p, &target, live, &unit));
    }

    out.extend(cmdline_note(&procs).map(|f| (f, Vec::new())));

    let (findings, seeds): (Vec<Finding>, Vec<Vec<Pinned>>) = out.into_iter().unzip();
    Report { available: true, reason: None, findings, seeds }
}

fn cmdline_note(procs: &[ProcSnapshot]) -> Option<Finding> {
    let what = crate::procfs::cmdline_gap(procs)?;
    Some(Finding {
        severity: Severity::Note,
        subject: "command-line coverage".to_string(),
        what,
        why: "a command line padded past what the walk keeps costs the agent its head and tail and no more, so \
              one process cannot spend the console's memory; a guard-pair partner or a restart loop's target named \
              only in the middle is not in this sweep. `tr '\\0' ' ' < /proc/PID/cmdline` shows the whole of one"
            .to_string(),
    })
}

fn pair_finding(pa: &ProcSnapshot, ia: &str, pb: &ProcSnapshot, ib: &str) -> (Finding, Vec<Pinned>) {
    let (a, b) = (pa.pid, pb.pid);
    let finding = Finding {
        severity: Severity::Critical,
        subject: format!("{ia} + {ib}"),
        what: format!(
            "mutual guard pair: pid {a} ({ia}) and pid {b} ({ib}) each name the other, so each will restart the other"
        ),
        why: "killing either one alone will not hold — the survivor restarts it, usually within seconds, and a responder who kills them one at a time will be told both times that it worked. Remove them in a single frozen action."
            .to_string(),
    };
    (finding, Pinned::seed(&[pa, pb]))
}

fn loop_finding(p: &ProcSnapshot, target: &str, live: Option<&ProcSnapshot>, unit: &Supervisor) -> (Finding, Vec<Pinned>) {
    let finding = Finding {
        severity: if live.is_some() { Severity::Warn } else { Severity::Note },
        subject: target.to_string(),
        what: match live {
            Some(q) => format!(
                "pid {} is a restart loop for {target}, which is running as pid {}",
                p.pid, q.pid
            ),
            None => format!("pid {} is a restart loop for {target}, which is not running", p.pid),
        },
        why: format!(
            "supervision that does not go through the service manager. Kept alive by {}. This shape is also used by some vendor wrapper scripts, so confirm what the loop is before removing it — but a loop relaunching an unpackaged binary out of a writable directory is how an implant survives being killed.",
            describe(unit)
        ),
    };
    let seed = match live {
        Some(q) => Pinned::seed(&[p, q]),
        None => Pinned::seed(&[p]),
    };
    (finding, seed)
}

pub fn watch(secs: u64) -> Vec<Finding> {
    let before = crate::procfs::walk();
    std::thread::sleep(std::time::Duration::from_secs(secs));
    let after = crate::procfs::walk();

    let mut seen = respawns(&before, &after);
    for r in &mut seen {
        if let Some(p) = after.iter().find(|p| p.pid == r.now_pid) {
            r.by = supervisor_of(p, &after);
        }
    }

    let packages = crate::pkg::manager();
    let owned = |exe: &str| packages.as_ref().is_some_and(|m| m.owns(std::path::Path::new(exe)));
    let mut out = findings(&seen, &owned, &|_| false);
    out.extend(cmdline_note(&after).or_else(|| cmdline_note(&before)));
    out
}
