use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::{ApplyOptions, Outcome, ProtectSet, RemovalAction, UndoRecord};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Group {

    pub members: Vec<u32>,

    pub units: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupOutcome {

    pub steps: Vec<String>,

    pub undo: Vec<UndoRecord>,

    pub survivors: Vec<u32>,

    pub removed: bool,

    pub aborted: Option<String>,

    pub left_units: Vec<LeftUnit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftUnit {

    pub unit: String,

    pub outside: Vec<u32>,
}

impl LeftUnit {

    pub fn why(&self) -> String {
        match self.outside.as_slice() {
            [] => "nothing could be found running in it, so nothing shows it is this group's to \
                   stop"
                .into(),
            pids => format!(
                "it also runs pid(s) {}, which are not in this group, and masking it would stop \
                 them too",
                pids.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
            ),
        }
    }
}

fn alive(pid: u32) -> bool {

    let Ok(stat) = std::fs::read(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let stat = String::from_utf8_lossy(&stat);

    let Some(rest) = stat.rsplit_once(')') else { return false };
    !matches!(rest.1.split_whitespace().next(), Some("Z") | None)
}

fn still_running(pid: u32) -> bool {
    for _ in 0..20 {
        if !alive(pid) {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    alive(pid)
}

fn suspend_for(pid: u32) -> Option<RemovalAction> {
    let snap = hemostat_sensor_linux::procfs::read_process(pid)?;
    Some(RemovalAction::SuspendProcess {
        pid,
        start_time: snap.starttime_ticks,
        exe: snap.exe,
    })
}

fn kill_for(pid: u32) -> Option<RemovalAction> {
    let snap = hemostat_sensor_linux::procfs::read_process(pid)?;
    Some(RemovalAction::KillProcess { pid, start_time: snap.starttime_ticks, exe: snap.exe })
}

fn unfreeze(frozen: &[UndoRecord], opts: &ApplyOptions, steps: &mut Vec<String>) {
    for rec in frozen.iter().rev() {
        match crate::undo(rec, opts) {
            Outcome::Applied(_) | Outcome::Planned(_) => {
                steps.push(format!("  resumed: {}", rec.did));
            }
            other => steps.push(format!(
                "  COULD NOT RESUME {} ({other:?}) — check this pid by hand, it may still be stopped",
                rec.did
            )),
        }
    }
}

fn pid_starttimes() -> BTreeSet<(u32, u64)> {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return BTreeSet::new();
    };
    dir.flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(|pid| {
            let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
            let stat = String::from_utf8_lossy(&stat);
            let tail = stat.rsplit_once(')')?.1;

            let start = tail.split_whitespace().nth(19)?.parse::<u64>().ok()?;
            Some((pid, start))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UnitCall {

    Mask,

    Outside(Vec<u32>),

    Empty,
}

fn unit_call(
    in_unit: &BTreeSet<u32>,
    members: &BTreeSet<u32>,
    parent: &BTreeMap<u32, u32>,
) -> UnitCall {
    if in_unit.is_empty() {
        return UnitCall::Empty;
    }
    let outside: Vec<u32> = in_unit
        .iter()
        .copied()
        .filter(|p| !members.contains(p) && !descends_from(*p, members, parent))
        .collect();
    if outside.is_empty() {
        UnitCall::Mask
    } else {
        UnitCall::Outside(outside)
    }
}

fn descends_from(pid: u32, members: &BTreeSet<u32>, parent: &BTreeMap<u32, u32>) -> bool {
    let mut seen = BTreeSet::new();
    let mut at = pid;
    for _ in 0..256 {
        if !seen.insert(at) {
            return false;
        }
        let Some(&up) = parent.get(&at) else { return false };
        if up <= 1 {
            return false;
        }
        if members.contains(&up) {
            return true;
        }
        at = up;
    }
    false
}

fn cgroup_in_unit(text: &str, names: &[String]) -> bool {
    text.lines()
        .filter_map(hemostat_sensor_linux::watchdog::cgroup_path)
        .any(|path| path.split('/').any(|c| names.iter().any(|n| n == c)))
}

fn unit_census(names: &[String]) -> (BTreeSet<u32>, BTreeMap<u32, u32>) {
    use hemostat_sensor_linux::saferead::{read_proc, MAX_PROC_BYTES};
    let mut in_unit = BTreeSet::new();
    let mut parent = BTreeMap::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return (in_unit, parent);
    };
    for pid in dir.flatten().filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok()) {
        if let Some(up) = ppid_of(pid) {
            parent.insert(pid, up);
        }
        let held = match read_proc(Path::new(&format!("/proc/{pid}/cgroup")), MAX_PROC_BYTES) {
            Ok((text, cut)) => cut || cgroup_in_unit(&String::from_utf8_lossy(&text), names),

            Err(_) => Path::new(&format!("/proc/{pid}")).exists(),
        };
        if held {
            in_unit.insert(pid);
        }
    }
    (in_unit, parent)
}

fn ppid_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    let stat = String::from_utf8_lossy(&stat);
    stat.rsplit_once(')')?.1.split_whitespace().nth(1)?.parse().ok()
}

fn left_step(left: &LeftUnit, armed: bool) -> String {
    let did = if armed { "LEFT" } else { "would LEAVE" };
    format!(
        "  {did} {} running, NOT masked: {}. Only the group's own processes are frozen and \
         killed; if this unit restarts one of them, stop it by hand once you have seen what \
         else it runs",
        left.unit,
        left.why()
    )
}

fn owner_uids(pid: u32) -> Option<Vec<u32>> {
    use hemostat_sensor_linux::saferead::{read_proc, MAX_PROC_BYTES};
    let (status, _) = read_proc(Path::new(&format!("/proc/{pid}/status")), MAX_PROC_BYTES).ok()?;
    let (real, effective) = crate::account::status_uids(&String::from_utf8_lossy(&status))?;
    let login = read_proc(Path::new(&format!("/proc/{pid}/loginuid")), 64)
        .ok()
        .and_then(|(b, _)| crate::account::login_uid(&String::from_utf8_lossy(&b)));
    let mut uids = vec![real, effective];
    uids.extend(login);
    Some(uids)
}

fn newcomer_owner_reason(
    uids: Option<&[u32]>,
    passwd: Option<&str>,
    protect: &ProtectSet,
) -> Option<String> {
    let Some(passwd) = passwd else {
        return Some(
            "could not be checked for whose it is: /etc/passwd could not be read".into(),
        );
    };
    let Some(uids) = uids else {
        return Some("could not be checked for whose it is: its status could not be read".into());
    };
    for &uid in uids {
        let names: Vec<&str> = passwd
            .lines()
            .filter_map(|l| {
                let mut f = l.split(':');
                let (name, _, id) = (f.next()?, f.next()?, f.next()?);
                (!name.is_empty() && id.parse::<u32>().ok() == Some(uid)).then_some(name)
            })
            .collect();
        if names.is_empty() {
            return Some(format!(
                "runs as uid {uid}, which has no entry in /etc/passwd, so whose it is cannot be \
                 checked"
            ));
        }
        if let Some((name, why)) = names.iter().find_map(|n| protect.user_reason(n).map(|r| (*n, r))) {
            return Some(format!("runs as {name} (uid {uid}): {}", why.describe()));
        }
    }
    None
}

pub fn remove(group: &Group, opts: &ApplyOptions, protect: &ProtectSet) -> GroupOutcome {
    remove_journaling(group, opts, protect, &mut |_| {})
}

pub fn remove_journaling(
    group: &Group,
    opts: &ApplyOptions,
    protect: &ProtectSet,
    journal: &mut dyn FnMut(&UndoRecord),
) -> GroupOutcome {
    let mut steps = Vec::new();
    let mut undo: Vec<UndoRecord> = Vec::new();

    let mut members: Vec<u32> =
        group.members.iter().copied().collect::<BTreeSet<_>>().into_iter().collect();
    if members.is_empty() {
        return GroupOutcome {
            steps: vec!["nothing to remove: the group has no members".into()],
            undo,
            survivors: Vec::new(),
            removed: false,
            aborted: Some("empty group".into()),
            left_units: Vec::new(),
        };
    }

    let pre_existing = pid_starttimes();

    let member_ids: BTreeSet<String> = members
        .iter()
        .filter_map(|p| hemostat_sensor_linux::procfs::read_process(*p))
        .map(|s| hemostat_sensor_linux::watchdog::identity(&s))
        .collect();

    let mut held: BTreeSet<u32> = BTreeSet::new();
    steps.push(format!("freezing {} process(es) so none can restart another", members.len()));
    for &pid in &members {
        let Some(action) = suspend_for(pid) else {

            steps.push(format!(
                "  pid {pid} exited before the freeze reached it; its identity is still watched"
            ));
            continue;
        };
        match action.apply(opts, protect) {
            Outcome::Applied(rec) => {
                steps.push(format!("  frozen: pid {pid}"));
                journal(&rec);
                undo.push(rec);
                held.insert(pid);
            }
            Outcome::Planned(plan) => {
                steps.push(format!("  would freeze: pid {pid} ({})", plan.detail));
                held.insert(pid);
            }
            Outcome::Refused(r) => {
                steps.push(format!("  REFUSED: {}", r.message));
                unfreeze(&undo, opts, &mut steps);
                return GroupOutcome {
                    steps,
                    undo,
                    survivors: members.iter().copied().filter(|p| alive(*p)).collect(),
                    removed: false,
                    aborted: Some(format!(
                        "the protect-set refused pid {pid}, so the group cannot be taken as a \
                         whole; nothing was changed. {}",
                        r.message
                    )),
                    left_units: Vec::new(),
                };
            }
            other => {
                steps.push(format!("  FAILED to freeze pid {pid}: {other:?}"));
                unfreeze(&undo, opts, &mut steps);
                return GroupOutcome {
                    steps,
                    undo,
                    survivors: members.iter().copied().filter(|p| alive(*p)).collect(),
                    removed: false,
                    aborted: Some(format!("could not freeze pid {pid}; nothing was changed")),
                    left_units: Vec::new(),
                };
            }
        }
    }

    if opts.armed {

        let frozen_ids = &member_ids;

        let passwd = hemostat_sensor_linux::saferead::read_scan_target(Path::new("/etc/passwd"));

        let mut extra: Vec<u32> = Vec::new();
        let mut settled = false;
        for _ in 0..8 {
            let newcomers: Vec<u32> = hemostat_sensor_linux::procfs::walk()
                .into_iter()
                .filter(|s| {
                    !members.contains(&s.pid)
                        && !extra.contains(&s.pid)

                        && !pre_existing.contains(&(s.pid, s.starttime_ticks))
                        && frozen_ids.contains(&hemostat_sensor_linux::watchdog::identity(s))
                })
                .map(|s| s.pid)
                .collect();
            if newcomers.is_empty() {
                settled = true;
                break;
            }
            for pid in newcomers {
                let Some(action) = suspend_for(pid) else { continue };

                if let Some(why) =
                    newcomer_owner_reason(owner_uids(pid).as_deref(), passwd.as_deref(), protect)
                {
                    steps.push(format!(
                        "  LEFT ALONE: pid {pid}, spawned during the freeze, {why}; it is never \
                         frozen or killed"
                    ));
                    unfreeze(&undo, opts, &mut steps);
                    return GroupOutcome {
                        steps,
                        undo,
                        survivors: members.iter().copied().filter(|p| alive(*p)).collect(),
                        removed: false,
                        aborted: Some(format!(
                            "pid {pid}, spawned during the freeze running a member's program, \
                             {why}, so it is left alone, and killing the group without it would \
                             not hold; the frozen members were resumed and nothing was changed"
                        )),
                        left_units: Vec::new(),
                    };
                }
                match action.apply(opts, protect) {
                    Outcome::Applied(rec) => {
                        steps.push(format!(
                            "  frozen: pid {pid} — spawned during the freeze, same program as a \
                             member; it would have restarted the group"
                        ));
                        journal(&rec);
                        undo.push(rec);
                        extra.push(pid);
                        held.insert(pid);
                    }
                    Outcome::Refused(r) => {

                        steps.push(format!("  REFUSED a newcomer: {}", r.message));
                        unfreeze(&undo, opts, &mut steps);
                        return GroupOutcome {
                            steps,
                            undo,
                            survivors: members.iter().copied().filter(|p| alive(*p)).collect(),
                            removed: false,
                            aborted: Some(format!(
                                "a process spawned during the freeze could not be frozen ({}), so \
                                 killing the group would not hold; nothing was changed",
                                r.message
                            )),
                            left_units: Vec::new(),
                        };
                    }
                    other => steps.push(format!("  could not freeze newcomer {pid}: {other:?}")),
                }
            }
        }
        members.extend(extra);
        if !settled {
            steps.push(
                "the group kept spawning new members faster than they could be frozen; \
                 proceeding, but expect survivors"
                    .into(),
            );
        }
    }

    let mut left_units: Vec<LeftUnit> = Vec::new();
    for unit in &group.units {
        steps.push(format!("disarming supervisor unit {unit}"));

        let mut names = vec![unit.clone()];
        names.extend(hemostat_sensor_linux::services::unit_names(std::slice::from_ref(unit)));
        let (in_unit, parent) = unit_census(&names);
        let outside = match unit_call(&in_unit, &held, &parent) {
            UnitCall::Mask => None,
            UnitCall::Outside(pids) => Some(pids),
            UnitCall::Empty => Some(Vec::new()),
        };
        if let Some(outside) = outside {
            let left = LeftUnit { unit: unit.clone(), outside };
            steps.push(left_step(&left, opts.armed));
            left_units.push(left);
            continue;
        }
        match (RemovalAction::MaskService { unit: unit.clone() }).apply(opts, protect) {
            Outcome::Applied(rec) => {
                steps.push(format!("  masked: {unit}"));
                journal(&rec);
                undo.push(rec);
            }
            Outcome::Planned(p) => steps.push(format!("  would mask: {unit} ({})", p.detail)),
            Outcome::Refused(r) => {

                steps.push(format!(
                    "  REFUSED: {} — the kill below will probably not hold, because this unit \
                     can still restart what it owns",
                    r.message
                ));
            }
            other => steps.push(format!("  FAILED to mask {unit}: {other:?}")),
        }
    }

    steps.push("killing the frozen processes".into());
    for &pid in &members {
        let Some(action) = kill_for(pid) else {
            steps.push(format!("  pid {pid} exited while frozen; nothing to kill"));
            continue;
        };
        match action.apply(opts, protect) {
            Outcome::Applied(rec) => {
                steps.push(format!("  killed: pid {pid}"));
                journal(&rec);
                undo.push(rec);
            }
            Outcome::Planned(p) => steps.push(format!("  would kill: pid {pid} ({})", p.detail)),
            Outcome::Refused(r) => steps.push(format!("  REFUSED: {}", r.message)),
            other => steps.push(format!("  FAILED to kill pid {pid}: {other:?}")),
        }
    }

    if !opts.armed {
        steps.push("dry run: nothing was signalled. Re-run armed to apply.".into());
        return GroupOutcome {
            steps,
            undo,
            survivors: Vec::new(),
            removed: false,
            aborted: None,
            left_units,
        };
    }

    let survivors: Vec<u32> = members.iter().copied().filter(|p| still_running(*p)).collect();
    if survivors.is_empty() {
        steps.push("verified: every member of the group is gone".into());
    } else {
        steps.push(format!(
            "STILL ALIVE after the kill: {survivors:?} — something not in this group is \
             restarting them. Look for a unit, a timer, a cron line, or another process \
             holding the same payload path.",
        ));
    }
    let removed = survivors.is_empty();
    GroupOutcome { steps, undo, survivors, removed, aborted: None, left_units }
}
