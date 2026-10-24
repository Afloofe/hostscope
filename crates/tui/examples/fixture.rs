use std::io::Write as _;

use std::time::Instant;

use hemostat_tui::queue::{QCommand, QueueModel, QueueRow};
use hemostat_tui::verbs::registry::REGISTRY;
use hemostat_tui::verbs::{Kind, Platform};
use hemostat_tui::{
    Confidence, ConsoleModel, FindingRow, Outcome, PostureModel, Remedy, Risk, Row, RunRequest, Running, Sev,
    VerbHost, VerbItem, Verbs,
};

fn log(line: &str) {
    if let Ok(p) = std::env::var("HEMOSTAT_FIXTURE_LOG") {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
            let _ = writeln!(f, "{line}");
        }
    }
}

fn findings() -> ConsoleModel {
    let rows = (0..14)
        .map(|i| FindingRow {
            severity: if i < 3 { Sev::Critical } else if i < 8 { Sev::Warn } else { Sev::Note },
            source: "persistence".into(),
            subject: format!("cron · /etc/cron.d/fixture-{i:02}"),
            what: "a job that runs a shell out of /dev/shm".into(),
            why: "cron jobs do not normally execute from tmpfs".into(),
            remedy: (i % 2 == 0).then(|| Remedy {
                what: format!("move /etc/cron.d/fixture-{i:02} into the vault"),
                risk: Risk::MayBreak,
                note: "FIXTURE: nothing is applied by this binary".into(),
                undo: "hemostat undo <journal>".into(),
                id: format!("fixture:{i}"),
            }),
            evidence: (0..40).map(|k| format!("/etc/cron.d/fixture-{i:02} evidence line {k:02}")).collect(),
        })
        .collect();
    ConsoleModel::new("fixture-host".into(), "fixture".into(), rows)
}

fn queue_model(status: &[String]) -> QueueModel {
    let rows = (0..20)
        .map(|i| QueueRow {
            id: format!("fx{i:04}"),
            severity: if i < 4 { Sev::Critical } else { Sev::Warn },
            current: None,
            host: format!("host-{:02}", i % 5),
            variant: "it-full".into(),
            source: "accounts".into(),
            subject: format!("fixture subject {i:02}"),
            sightings: 1,
            state: status.get(i).cloned().unwrap_or_else(|| "new".into()),
            owner: String::new(),
            age: "1m".into(),
            absent: false,
            detail: (0..50).map(|k| format!("fixture detail line {k:02}")).collect(),
        })
        .collect();
    QueueModel {
        title: "fixture engagement".into(),
        actor: "uid=1000(fixture)".into(),
        rows,
        hosts: (0..50).map(|k| format!("host-{k:02} last heard 1m ago")).collect(),
        cluster: vec!["fixture cluster: 3 hosts share subject 00".into()],
        ..QueueModel::default()
    }
}

struct FakeRun {
    started: Instant,
    sent: usize,
    lines: Vec<String>,
    code: i32,
    forever: bool,
    stopped: bool,
}

impl Running for FakeRun {
    fn poll(&mut self) -> (Vec<String>, Option<Outcome>) {
        let due = (self.started.elapsed().as_millis() / 200) as usize;
        let mut out = Vec::new();
        while self.sent < due && (self.forever || self.sent < self.lines.len()) {
            out.push(self.lines.get(self.sent).cloned().unwrap_or_else(|| format!("fixture watch line {}", self.sent)));
            self.sent += 1;
        }
        if self.stopped {
            log("STOPPED");
            return (out, Some(Outcome { code: None, label: "killed by a signal".into(), plan_ok: false }));
        }
        if !self.forever && self.sent >= self.lines.len() {
            let label = match self.code {
                5 => "exit 5 · DRY RUN: the plan printed and nothing was applied".to_string(),
                c => format!("exit {c} · ran (FIXTURE: nothing was touched)"),
            };
            return (out, Some(Outcome { code: Some(self.code), label, plan_ok: self.code == 0 || self.code == 5 }));
        }
        (out, None)
    }
    fn stop(&mut self) {
        self.stopped = true;
    }
}

struct FakeHost;

impl VerbHost for FakeHost {
    fn start(&mut self, req: &RunRequest) -> Result<Box<dyn Running>, String> {
        log(&format!("RUN armed={} ticket={:?} {}", req.armed, req.ticket, req.argv.join(" ")));
        let spec = REGISTRY.iter().find(|s| req.argv.first().map(String::as_str) == s.argv.first().copied());
        let acts = spec.is_some_and(|s| s.kind == Kind::Act);
        let forever = spec.is_some_and(|s| s.kind == Kind::Watch);
        let code = if acts && !req.armed { 5 } else { 0 };
        let mut lines: Vec<String> =
            (0..3).map(|i| format!("fixture output {i} for hemostat {}", req.argv.join(" "))).collect();
        if code == 5 {
            lines.push("Nothing was changed. Add --arm to load it.".into());
        }
        Ok(Box::new(FakeRun { started: Instant::now(), sent: 0, lines, code, forever, stopped: false }))
    }
    fn choices(&mut self, key: &str) -> Vec<String> {
        log(&format!("CHOICES {key}"));
        (0..8).map(|i| format!("/fixture/{key}-{i}")).collect()
    }
    fn inherited_ticket(&self) -> Option<String> {
        None
    }
}

fn verbs() -> Verbs {
    let names = ["rootkit", "watch", "snapshot", "uninstall", "exec-block", "network", "undo"];
    let items = names
        .iter()
        .filter_map(|n| REGISTRY.iter().find(|s| s.name == *n && s.platforms.contains(&Platform::Linux)))
        .map(|spec| VerbItem {
            spec,
            disabled: None,
            help: format!("FIXTURE: `hemostat {}` is not run by this binary", spec.name),
            preset: Vec::new(),
        })
        .chain(REGISTRY.iter().find(|s| s.name == "scan").map(|spec| VerbItem {
            spec,
            disabled: Some("mod-scan-yara: NOT-BUILT in variant fixture".into()),
            help: "FIXTURE: a verb this image does not have".into(),
            preset: Vec::new(),
        }))
        .collect();
    Verbs { items, host: Box::new(FakeHost) }
}

fn main() -> std::io::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("console") => hemostat_tui::run_console(
            findings(),
            findings,
            |id| {
                log(&format!("APPLY {id}"));
                Err("fixture: nothing is applied".into())
            },
            verbs(),
        ),
        Some("queue") => {
            let mut states: Vec<String> = Vec::new();
            hemostat_tui::run_queue(queue_model(&states), |cmd| {
                log(&format!("{cmd:?}"));
                if let QCommand::Resolve(id, k, _) = cmd {
                    let i: usize = id.trim_start_matches("fx").parse().unwrap_or(0);
                    states.resize(states.len().max(i + 1), "new".into());
                    if let Some(s) = states.get_mut(i) {
                        *s = format!("resolved:{k}");
                    }
                }
                Ok((queue_model(&states), format!("fixture recorded {cmd:?}")))
            }, verbs())
        }
        Some("posture") => {
            let m = || PostureModel {
                variant: "fixture".into(),
                version: "0.0.0".into(),
                tier: "L2".into(),
                tier_meaning: "fixture posture".into(),
                rows: vec![Row { label: "trial attach".into(), value: "ok".into(), confidence: Confidence::Measured, note: String::new() }],
                warnings: vec!["fixture warning".into()],
                hooks: vec![],
            };
            hemostat_tui::run(m(), || {
                log("REPROBE");
                m()
            }, verbs())
        }
        _ => {
            eprintln!("usage: fixture console|queue|posture");
            std::process::exit(2);
        }
    }
}
