use std::collections::BTreeSet;

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
        };
    }

    let pre_existing = pid_starttimes();

    let member_ids: BTreeSet<String> = members
        .iter()
        .filter_map(|p| hemostat_sensor_linux::procfs::read_process(*p))
        .map(|s| hemostat_sensor_linux::watchdog::identity(&s))
        .collect();

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
            }
            Outcome::Planned(plan) => {
                steps.push(format!("  would freeze: pid {pid} ({})", plan.detail));
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
                };
            }
        }
    }

    if opts.armed {

        let frozen_ids = &member_ids;

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
                match action.apply(opts, protect) {
                    Outcome::Applied(rec) => {
                        steps.push(format!(
                            "  frozen: pid {pid} — spawned during the freeze, same program as a \
                             member; it would have restarted the group"
                        ));
                        journal(&rec);
                        undo.push(rec);
                        extra.push(pid);
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

    for unit in &group.units {
        steps.push(format!("disarming supervisor unit {unit}"));
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
        return GroupOutcome { steps, undo, survivors: Vec::new(), removed: false, aborted: None };
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
    GroupOutcome { steps, undo, survivors, removed, aborted: None }
}
