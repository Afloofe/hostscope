use std::path::{Path, PathBuf};

use crate::{resolve_tool, run_tool, ApplyOptions, Failure, Outcome, Plan, UndoKind, UndoRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace {

    pub path: PathBuf,

    pub what: &'static str,

    pub removable: bool,

    pub note: Option<String>,
}

const AGENT_PATHS: &[(&str, &str)] = &[
    ("/usr/local/bin/hemostat", "the agent binary"),
    ("/opt/hemostat/hemostat", "the agent binary"),
    ("/etc/systemd/system/hemostat-console.service", "a systemd unit that starts the console"),
    ("/etc/systemd/system/hemostat.service", "a systemd unit that starts the agent"),
    ("/etc/sv/hemostat", "a runit service directory"),
    ("/var/service/hemostat", "a runit service link"),
    ("/etc/service/hemostat", "a runit service link"),
];

const RUNIT_SERVICE_DIRS: &[&str] = &[
    "/etc/service",
    "/run/runit/service",
    "/var/service",
    "/service",
    "/etc/runit/runsvdir/current",
];

const SENTINEL_SERVICE: &str = "hemostat-sentinel";

use hemostat_sensor_linux::enablement::SENTINEL_UNIT_PREFIX;

pub const EVIDENCE_PREFIXES: &[&str] = &[
    "/var/lib/hemostat",
    "/var/log/hemostat",
];

#[derive(Debug, Clone, Default)]
pub struct Survey {

    pub traces: Vec<Trace>,

    pub evidence: Vec<(PathBuf, u64)>,

    pub stuck: Vec<Trace>,

    pub manages_services: bool,

    pub root: PathBuf,
}

impl Survey {

    pub fn is_empty(&self) -> bool {
        self.traces.is_empty() && self.stuck.is_empty()
    }

    pub fn evidence_note(&self) -> String {
        if self.evidence.is_empty() {
            return "No evidence store or undo journal was found on this host, so nothing is \
                    being left behind."
                .to_string();
        }
        let total = self.evidence.iter().fold(0u64, |t, (_, n)| t.saturating_add(*n));

        let size = if total < 1024 {
            format!("{total} bytes")
        } else {
            format!("{} KiB", total / 1024)
        };
        format!(
            "LEFT IN PLACE ({} path(s), {size}): the evidence store, the undo journals and the \
             file snapshots those journals point at. They are the output of this engagement, \
             not part of the agent, and an uninstall that swept them up would destroy the \
             artefact somebody is going to be asked about. Remove them deliberately if that is \
             what you want: {}",
            self.evidence.len(),
            self.evidence
                .iter()
                .map(|(p, _)| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

pub fn survey() -> Survey {

    survey_in(Path::new("/"), false)
}

pub fn survey_in(root: &Path, selfprotect_armed: bool) -> Survey {
    let mut s = Survey {
        manages_services: root == Path::new("/"),
        root: root.to_path_buf(),
        ..Survey::default()
    };

    for (rel, what) in AGENT_PATHS {
        let p = root.join(rel.trim_start_matches('/'));
        if p.exists() {
            s.traces.push(Trace {
                path: p,
                what,
                removable: true,
                note: None,
            });
        }
    }

    s.traces.extend(sentinel_traces(root));
    s.traces.extend(canary_traces(root));

    if let Ok(me) = std::fs::read_link("/proc/self/exe") {
        let known = AGENT_PATHS.iter().any(|(p, _)| Path::new(p) == me);
        if !known && me.exists() && root == Path::new("/") {
            s.stuck.push(Trace {
                path: me.clone(),
                what: "the running agent binary, in a location this did not put it",
                removable: false,
                note: Some(format!(
                    "this is the image this process is running from, and it is not one of the \
                     paths an install uses. It is not removed automatically — deleting a file \
                     this tool is not sure it created is the one thing it refuses everywhere \
                     else. Remove it by hand once this process has exited: rm {}",
                    me.display()
                )),
            });
        }
    }

    for prefix in EVIDENCE_PREFIXES {
        let p = root.join(prefix.trim_start_matches('/'));
        if p.exists() {
            s.evidence.push((p.clone(), tree_bytes(&p)));
        }
    }

    if selfprotect_armed {
        s.stuck.push(Trace {
            path: PathBuf::from("(kernel)"),
            what: "an armed task_kill self-protection",
            removable: false,
            note: Some(
                "an eBPF program denying signals to this process is attached in the kernel and \
                 outlives the code that attached it. It goes when this process exits, and not \
                 before — so run the uninstall, then stop the agent, and do not report the host \
                 as clean while a program nobody can kill is still running on it"
                    .into(),
            ),
        });
    }

    s
}

fn sentinel_traces(root: &Path) -> Vec<Trace> {
    let mut out: Vec<Trace> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for dir in RUNIT_SERVICE_DIRS {
        let p = root.join(dir.trim_start_matches('/')).join(SENTINEL_SERVICE);
        if p.symlink_metadata().is_err() {
            continue;
        }

        if !seen.insert(std::fs::canonicalize(&p).unwrap_or_else(|_| p.clone())) {
            continue;
        }
        out.push(Trace { path: p, what: "the sentinel's runit service", removable: true, note: None });
    }
    if let Ok(rd) = std::fs::read_dir(root.join("run/systemd/transient")) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with(SENTINEL_UNIT_PREFIX) && name.ends_with(".service") {
                out.push(Trace { path: e.path(), what: "a transient sentinel unit", removable: true, note: None });
            }
        }
    }
    out
}

fn canary_traces(root: &Path) -> Vec<Trace> {
    let passwd = hemostat_sensor_linux::saferead::read_scan_target(&root.join("etc/passwd")).unwrap_or_default();
    let homes: Vec<PathBuf> = passwd
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            let uid: u32 = f.get(2)?.parse().ok()?;
            if !(1000..60_000).contains(&uid) {
                return None;
            }
            f.get(5).map(PathBuf::from)
        })
        .collect();
    crate::deceive::catalogue(&homes)
        .into_iter()
        .map(|t| root.join(t.path.strip_prefix("/").unwrap_or(&t.path)))
        .filter(|p| {
            hemostat_sensor_linux::saferead::read_scan_target(p).is_some_and(|c| crate::deceive::is_our_token(&c))
        })
        .map(|path| Trace { path, what: "a planted canary", removable: true, note: None })
        .collect()
}

fn transient_unit(t: &Trace) -> Option<String> {
    let name = t.path.file_name()?.to_str()?;
    (t.path.parent()?.ends_with("run/systemd/transient") && name.starts_with(SENTINEL_UNIT_PREFIX))
        .then(|| name.to_string())
}

fn tree_bytes(p: &Path) -> u64 {
    let Ok(md) = std::fs::metadata(p) else { return 0 };
    if md.is_file() {
        return md.len();
    }
    entries_bytes(p)
}

fn entries_bytes(dir: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    rd.flatten().fold(0u64, |total, e| {

        let n = match e.file_type() {
            Ok(t) if t.is_dir() => entries_bytes(&e.path()),
            Ok(t) if t.is_file() => e.metadata().map_or(0, |m| m.len()),
            _ => 0,
        };
        total.saturating_add(n)
    })
}

pub fn apply(s: &Survey, opts: &ApplyOptions) -> Outcome {
    if s.is_empty() {
        return Outcome::Planned(Plan {
            summary: "nothing to uninstall".into(),
            detail: format!(
                "No agent binary, unit or service directory was found in the places an install \
                 puts them. {}",
                s.evidence_note()
            ),
            undo: "nothing was changed".into(),
            reversible: false,
            prefer_instead: None,
        });
    }

    if !opts.armed {
        let mut detail = format!(
            "Remove {} path(s): {}.",
            s.traces.len(),
            s.traces
                .iter()
                .map(|t| format!("{} ({})", t.path.display(), t.what))
                .collect::<Vec<_>>()
                .join(", ")
        );
        if !s.stuck.is_empty() {
            detail.push_str("\n\n  CANNOT BE REMOVED FROM HERE:");
            for t in &s.stuck {
                detail.push_str(&format!(
                    "\n    {} — {}",
                    t.path.display(),
                    t.note.as_deref().unwrap_or(t.what)
                ));
            }
        }
        detail.push_str("\n\n  ");
        detail.push_str(&s.evidence_note());
        return Outcome::Planned(Plan {
            summary: "take the agent off this host".into(),
            detail,
            undo: "there is no undo: drop the agent again to reinstall it. The EVIDENCE is not \
                   touched and does not need one"
                .into(),
            reversible: false,
            prefer_instead: None,
        });
    }

    let mut done: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();

    if s.manages_services {
    if let Some(systemctl) = resolve_tool(&["/usr/bin/systemctl", "/bin/systemctl"]) {
        for unit in ["hemostat-console.service", "hemostat.service"] {
            if s.traces.iter().any(|t| t.path.to_string_lossy().contains(unit)) {
                let _ = run_tool(&systemctl, &["disable", "--now", unit]);
            }
        }
    }
    if let Some(sv) = resolve_tool(&["/usr/bin/sv", "/bin/sv"]) {
        if s.traces.iter().any(|t| t.path.to_string_lossy().contains("/hemostat")) {
            let _ = run_tool(&sv, &["down", "hemostat"]);
        }

        for t in s.traces.iter().filter(|t| t.path.ends_with(SENTINEL_SERVICE)) {
            let _ = run_tool(&sv, &["down", &t.path.to_string_lossy()]);
        }
    }

    if let Some(systemctl) = resolve_tool(&["/usr/bin/systemctl", "/bin/systemctl"]) {
        for unit in s.traces.iter().filter_map(transient_unit) {
            let _ = run_tool(&systemctl, &["stop", &unit]);
        }
    }
    }

    for t in &s.traces {
        let r = if t.path.is_dir() {
            std::fs::remove_dir_all(&t.path)
        } else {
            std::fs::remove_file(&t.path)
        };
        match r {
            Ok(()) => done.push(t.path.display().to_string()),

            Err(e) if e.kind() == std::io::ErrorKind::NotFound => done.push(t.path.display().to_string()),
            Err(e) => failed.push(format!("{} ({e})", t.path.display())),
        }
    }

    if s.manages_services {
        if let Some(systemctl) = resolve_tool(&["/usr/bin/systemctl", "/bin/systemctl"]) {
            let _ = run_tool(&systemctl, &["daemon-reload"]);
        }
    }

    for t in survey_in(&s.root, false).traces {
        failed.push(format!("{} ({}) is still present after removal", t.path.display(), t.what));
    }

    let mut did = format!("removed {} of {} agent path(s)", done.len(), s.traces.len());
    if !s.stuck.is_empty() {
        did.push_str(&format!(
            " — {} thing(s) could NOT be removed from here: {}",
            s.stuck.len(),
            s.stuck
                .iter()
                .map(|t| format!("{} ({})", t.path.display(), t.what))
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    did.push_str(" — ");
    did.push_str(&s.evidence_note());

    if failed.is_empty() {
        Outcome::Applied(UndoRecord {
            did,

            undo: UndoKind::Nothing,
            reversible: false,
        })
    } else {
        Outcome::Failed(Failure {
            action: "uninstall".into(),
            reason: format!(
                "{} path(s) could not be removed: {}. {did}",
                failed.len(),
                failed.join("; ")
            ),
        })
    }
}
