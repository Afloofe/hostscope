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
    let exe = p.exe.as_deref()?;
    let base = exe.rsplit('/').next()?;
    let base = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if !INTERPRETERS.contains(&base) && !INTERPRETERS.contains(&exe.rsplit('/').next()?) {
        return None;
    }
    let cmd = p.cmdline.as_deref()?;
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

fn cgroup_unit(text: &str) -> Option<CgroupUnit> {
    let is_manager = |c: &str| c.starts_with("user@") && c.ends_with(".service");
    let mut found = None;
    for line in text.lines() {
        let path: Vec<&str> = line.rsplit(':').next().unwrap_or("").split('/').collect();
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

pub fn loop_respawner(cmdline: &str) -> Option<String> {
    let lower = cmdline.to_ascii_lowercase();
    let looping = lower.contains("while ")
        || lower.contains("until ")
        || lower.contains("for(;;)")
        || lower.contains("for (;;)");
    let sleeping = lower.contains("sleep ");
    if !(looping && sleeping) {
        return None;
    }
    cmdline
        .split_whitespace()
        .map(|t| t.trim_matches(|c| c == '"' || c == '\'' || c == ';' || c == '`' || c == '('))
        .find(|t| t.starts_with('/') && t.len() > 1 && !t.starts_with("/bin/sh") && !t.starts_with("/bin/bash"))
        .map(|s| s.to_string())
}

pub fn guard_pairs(procs: &[ProcSnapshot]) -> Vec<(u32, u32)> {
    pairs_from(&procs.iter().map(|p| (p.pid, identity(p), program_text(p))).collect::<Vec<_>>())
}

pub fn pairs_from(procs: &[(u32, String, String)]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for (i, (apid, aid, atext)) in procs.iter().enumerate() {
        for (bpid, bid, btext) in procs.iter().skip(i + 1) {
            if aid == bid {
                continue;
            }
            if atext.contains(bid.as_str()) && btext.contains(aid.as_str()) {
                out.push((*apid, *bpid));
            }
        }
    }
    out
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
    let text = std::fs::read_to_string(format!("/proc/{}/cgroup", p.pid)).unwrap_or_default();
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
        .filter_map(|l| l.rsplit(':').next())
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
    let mut members: BTreeSet<u32> = BTreeSet::new();
    members.insert(pid);

    let Some(target) = procs.iter().find(|p| p.pid == pid) else {
        return (vec![pid], unit.into_iter().map(|s| s.to_string()).collect());
    };
    let target_id = identity(target);

    for (a, b) in guard_pairs(procs) {
        if a == pid {
            members.insert(b);
        } else if b == pid {
            members.insert(a);
        }
    }

    for p in procs {
        if p.pid == pid || p.pid <= 1 {
            continue;
        }
        if let Some(relaunches) = loop_respawner(&program_text(p)) {
            if relaunches == target_id {
                members.insert(p.pid);
            }
        }
    }

    members.remove(&1);
    (members.into_iter().collect(), unit.into_iter().map(|s| s.to_string()).collect())
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub available: bool,

    pub reason: Option<String>,

    pub findings: Vec<Finding>,
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
        };
    }
    let packages = crate::pkg::manager();
    let owned = |exe: &str| -> bool {
        packages.as_ref().is_some_and(|m| m.owns(std::path::Path::new(exe)))
    };

    let mut out = Vec::new();

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
        out.push(Finding {
            severity: Severity::Critical,
            subject: format!("{ia} + {ib}"),
            what: format!(
                "mutual guard pair: pid {a} ({ia}) and pid {b} ({ib}) each name the other, so each will restart the other"
            ),
            why: "killing either one alone will not hold — the survivor restarts it, usually within seconds, and a responder who kills them one at a time will be told both times that it worked. Remove them in a single frozen action."
                .to_string(),
        });
    }

    for p in &procs {

        let text = program_text(p);
        let Some(target) = loop_respawner(&text) else { continue };

        if target == identity(p) {
            continue;
        }

        let live = procs.iter().find(|q| identity(q) == target);
        if owned(&target) {
            continue;
        }
        let unit = supervisor_of(p, &procs);
        out.push(Finding {
            severity: if live.is_some() { Severity::Warn } else { Severity::Note },
            subject: target.clone(),
            what: match live {
                Some(q) => format!(
                    "pid {} is a restart loop for {target}, which is running as pid {}",
                    p.pid, q.pid
                ),
                None => format!("pid {} is a restart loop for {target}, which is not running", p.pid),
            },
            why: format!(
                "supervision that does not go through the service manager. Kept alive by {}. This shape is also used by some vendor wrapper scripts, so confirm what the loop is before removing it — but a loop relaunching an unpackaged binary out of a writable directory is how an implant survives being killed.",
                describe(&unit)
            ),
        });
    }

    Report { available: true, reason: None, findings: out }
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
    findings(&seen, &owned, &|_| false)
}
