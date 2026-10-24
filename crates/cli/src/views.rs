#[cfg(all(target_os = "linux", feature = "mod-tui"))]
use crate::remedy::linux_remedy;
#[cfg(all(target_os = "windows", feature = "mod-tui"))]
use crate::remedy::windows_remedy;

#[cfg(all(target_os = "linux", feature = "mod-tui", feature = "mod-scan-yara"))]
use crate::analysis::scan_targets;

#[cfg(all(any(target_os = "linux", target_os = "windows"), feature = "mod-tui"))]
use crate::MANIFEST;

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    Rootkit,
    Suid,
    Inventory,
    SysMap,
    KptrHooks,
    Sshd,
    Sysctl,
    Watchdog,
    Accounts,
    Overview,
    Persistence,
    Systemd,
    Injected,
    Kwalk,
    KernelPosture,
    Trust,
    Scan,
}

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    Probe,
    Persistence,
    Accounts,
    Overview,
    Evtlog,
    Sysmon,
    Usn,
    Wmi,
    Com,
    DllHijack,
    Modules,
    Streams,
    Trust,
    Detect,
}

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
impl Source {

    pub(crate) const ALL: [Source; 14] = [
        Source::Probe,
        Source::Persistence,
        Source::Accounts,
        Source::Overview,
        Source::Evtlog,
        Source::Sysmon,
        Source::Usn,
        Source::Wmi,
        Source::Com,
        Source::DllHijack,
        Source::Modules,
        Source::Streams,
        Source::Trust,
        Source::Detect,
    ];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Source::Probe => "probe",
            Source::Persistence => "persistence",
            Source::Accounts => "accounts",
            Source::Overview => "overview",
            Source::Evtlog => "evtlog",
            Source::Sysmon => "sysmon",
            Source::Usn => "usn",
            Source::Wmi => "wmi",
            Source::Com => "com",
            Source::DllHijack => "dll-hijack",
            Source::Modules => "modules",
            Source::Streams => "streams",
            Source::Trust => "trust",
            Source::Detect => "detect",
        }
    }
}

#[cfg(all(any(target_os = "linux", target_os = "windows"), feature = "mod-tui"))]
pub(crate) enum Ran {

    Yes,

    No(String),

    InPart(String),
}

#[cfg(all(any(target_os = "linux", target_os = "windows"), feature = "mod-tui"))]
impl From<crate::coverage::Covered> for Ran {
    fn from(c: crate::coverage::Covered) -> Self {
        use crate::coverage::Covered;
        match c {
            Covered::Fully => Ran::Yes,
            Covered::NotAtAll(why) => Ran::No(why),
            Covered::InPart(why) => Ran::InPart(why),
        }
    }
}

#[cfg(all(any(target_os = "linux", target_os = "windows"), feature = "mod-tui"))]
pub(crate) struct Coverage {
    pub(crate) gaps: Vec<hemostat_tui::Gap>,
    pub(crate) asked: Vec<Source>,
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn console_model() -> hemostat_tui::ConsoleModel {
    use hemostat_sensor_linux::rootkit::{Finding as RFinding, Severity as RSev};
    use hemostat_tui::{FindingRow, Sev};

    pub(crate) fn rsev(s: RSev) -> Sev {
        match s {
            RSev::Critical => Sev::Critical,
            RSev::Warn => Sev::Warn,
            RSev::Note => Sev::Note,
        }
    }
    pub(crate) fn push(rows: &mut Vec<FindingRow>, source: Source, findings: &[RFinding]) {
        let source = source.name();
        for f in findings {
            rows.push(FindingRow {
                severity: rsev(f.severity),
                source: source.to_string(),
                subject: f.subject.clone(),
                what: f.what.clone(),
                why: f.why.clone(),
                remedy: linux_remedy(source, &f.subject, &f.what, "", rsev(f.severity)),
                evidence: artefacts(&f.subject, &f.what),
            });
        }
    }

    let mut rows: Vec<FindingRow> = Vec::new();

    let mut cov = Coverage::new();

    let rk = hemostat_sensor_linux::rootkit_report();
    cov.note(Source::Rootkit, crate::coverage::rootkit(&rk).into());
    push(&mut rows, Source::Rootkit, &rk.findings);

    let suid = hemostat_sensor_linux::suid::report();
    cov.note_flag(Source::Suid, suid.available, &suid.reason);
    push(&mut rows, Source::Suid, &suid.findings);

    let inv = hemostat_sensor_linux::inventory::report_with(crate::vendor::manifest_for("console").as_deref());
    cov.note_flag(Source::Inventory, inv.available, &inv.reason);
    push(&mut rows, Source::Inventory, &inv.findings);

    let sm = hemostat_sensor_linux::sysmap::report();
    cov.note_flag(Source::SysMap, sm.available, &sm.reason);
    push(&mut rows, Source::SysMap, &sm.findings);

    let kp = hemostat_sensor_linux::kptrhooks::report();
    cov.note_flag(Source::KptrHooks, kp.available, &kp.reason);
    push(&mut rows, Source::KptrHooks, &kp.findings);

    let ssh = hemostat_sensor_linux::sshd::report();
    cov.note_flag(Source::Sshd, ssh.available, &ssh.reason);
    push(&mut rows, Source::Sshd, &ssh.findings);

    let sysctl = hemostat_sensor_linux::sysctlpolicy::report();
    cov.note_flag(Source::Sysctl, sysctl.available, &sysctl.reason);
    push(&mut rows, Source::Sysctl, &sysctl.findings);

    let wd = hemostat_sensor_linux::watchdog::report();
    cov.note_flag(Source::Watchdog, wd.available, &wd.reason);
    push(&mut rows, Source::Watchdog, &wd.findings);

    let acc = hemostat_sensor_linux::account_report();

    cov.note(Source::Accounts, crate::coverage::accounts(&acc).into());
    for f in &acc.findings {
        let severity = match f.severity {
            hemostat_sensor_linux::Severity::Critical => Sev::Critical,
            hemostat_sensor_linux::Severity::Warn => Sev::Warn,
            _ => Sev::Note,
        };
        rows.push(FindingRow {
            severity,
            source: Source::Accounts.name().into(),
            subject: f.subject.clone(),
            what: f.what.clone(),
            why: f.why.clone(),
            remedy: linux_remedy(Source::Accounts.name(), &f.subject, &f.what, "", severity),
            evidence: artefacts(&f.subject, &f.what),
        });
    }

    use hemostat_sensor_linux::{TriageFinding, TriageSeverity};
    pub(crate) fn tsev(s: TriageSeverity) -> Sev {
        match s {
            TriageSeverity::Critical => Sev::Critical,
            TriageSeverity::Warn => Sev::Warn,
            _ => Sev::Note,
        }
    }
    pub(crate) fn push_t(rows: &mut Vec<FindingRow>, source: Source, findings: &[TriageFinding]) {
        let source = source.name();
        for f in findings {
            if matches!(f.severity, TriageSeverity::Info) {
                continue;
            }
            let subject = if f.locus.is_empty() {
                f.subject.clone()
            } else {
                format!("{} · {}", f.subject, f.locus)
            };
            rows.push(FindingRow {
                severity: tsev(f.severity),
                source: source.to_string(),
                subject,
                what: f.what.clone(),
                why: f.why.clone(),
                remedy: linux_remedy(source, &f.subject, &f.what, &f.locus, tsev(f.severity)),

                evidence: if f.locus.is_empty() { Vec::new() } else { vec![f.locus.clone()] },
            });
        }
    }
    let ov = hemostat_sensor_linux::overview_report();
    cov.note(Source::Overview, crate::coverage::overview(&ov).into());
    push_t(&mut rows, Source::Overview, &ov.findings);

    let pr = hemostat_sensor_linux::persist_report();
    cov.note(Source::Persistence, crate::coverage::persistence(&pr).into());
    push_t(&mut rows, Source::Persistence, &pr.findings);

    let sd = hemostat_sensor_linux::enablement::report();
    cov.note(Source::Systemd, crate::coverage::enablement(&sd).into());
    push_t(&mut rows, Source::Systemd, &sd.findings);

    let inj = hemostat_sensor_linux::hooked_report();
    cov.note(Source::Injected, crate::coverage::injected(&inj).into());
    push_t(&mut rows, Source::Injected, &inj.findings);

    let kw = hemostat_sensor_linux::kwalk_report();
    cov.note(Source::Kwalk, crate::coverage::kwalk(&kw).into());
    push_t(&mut rows, Source::Kwalk, &kw.findings);

    let kpo = hemostat_sensor_linux::kernposture_report();
    cov.note(Source::KernelPosture, crate::coverage::kernel_posture(&kpo).into());
    push_t(&mut rows, Source::KernelPosture, &kpo.findings);

    let tr = hemostat_sensor_linux::trust::report_with(&crate::snapshot::anchor_baseline(crate::snapshot::DEFAULT_STORE));
    cov.note(Source::Trust, crate::coverage::trust(&tr).into());
    push_t(&mut rows, Source::Trust, &tr.findings);

    #[cfg(feature = "mod-scan-yara")]
    {
        let (targets, mut notes) = scan_targets();
        let o = hemostat_scan::scan_files(&targets, hemostat_scan::rules_dir(None).as_deref());
        notes.extend(o.skipped.iter().map(|(p, why)| format!("{}: {why}", p.display())));
        cov.note(Source::Scan, crate::coverage::scan(&o, &notes, targets.len()).into());
        rows.extend(o.hits.iter().map(scan_row));
    }
    #[cfg(not(feature = "mod-scan-yara"))]
    cov.note(
        Source::Scan,
        Ran::No(
            "the content scanner is not in this image — `mod-scan-yara` was not compiled in, \
             so no file's content was examined at all"
                .into(),
        ),
    );

    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown-host".into());

    let when = {
        use std::time::{SystemTime, UNIX_EPOCH};
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => {
                let s = d.as_secs();
                format!("{:02}:{:02}:{:02} UTC", (s / 3600) % 24, (s / 60) % 60, s % 60)
            }
            Err(_) => String::new(),
        }
    };

    debug_assert!(
        cov.unanswered().is_empty(),
        "console source(s) contributed rows without reporting coverage: {:?} — a source \
         missing here is one `source_ran` answers yes for unconditionally",
        cov.unanswered()
    );

    hemostat_tui::ConsoleModel::new(host, when, rows).with_gaps(cov.gaps)
}

#[cfg(all(target_os = "linux", feature = "mod-tui", feature = "mod-scan-yara"))]
fn scan_row(hit: &hemostat_scan::Hit) -> hemostat_tui::FindingRow {
    use hemostat_tui::{FindingRow, Sev};

    if hit.own_image {
        return FindingRow {
            severity: Sev::Note,
            source: Source::Scan.name().into(),
            subject: hit.path.display().to_string(),
            what: format!("HEMOSTAT's own running image matches `{}`", hit.rule),
            why: "this is the file this agent is running from — the same device and inode as \
                  /proc/self/exe — and it carries the text of its own built-in rules, which is \
                  what matched. A copy of it at another path, or another file put at this path, \
                  is not this file and is judged as any file is"
                .to_string(),
            remedy: None,
            evidence: vec![hit.path.display().to_string()],
        };
    }
    FindingRow {

        severity: Sev::Critical,
        source: Source::Scan.name().into(),
        subject: hit.path.display().to_string(),
        what: format!("matches `{}`", hit.rule),
        why: if hit.note.is_empty() {
            "a YARA rule matched this file's content. Every other row on this page is about \
             shape — where a file lives, what starts it, who owns it — and this one is about \
             what the file *is*"
                .to_string()
        } else {
            format!(
                "{}. Every other row on this page is about shape; this one is about what the \
                 file is. Rules loaded from {} are the operator's own and carry the operator's \
                 judgement, not ours",
                hit.note,
                hemostat_scan::RULES_DIR
            )
        },
        remedy: linux_remedy(Source::Scan.name(), &hit.path.display().to_string(), "", "", Sev::Critical),
        evidence: vec![hit.path.display().to_string()],
    }
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn artefacts(subject: &str, what: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for text in [subject, what] {
        let mut words = text.split_whitespace().peekable();
        while let Some(w) = words.next() {
            let t = w.trim_matches(|c: char| "`'\"(),;:".contains(c));
            if t.starts_with('/') && t.len() > 1 {
                out.push(t.to_string());
            } else if t == "pid" {
                if let Some(n) = words.peek() {
                    let n = n.trim_matches(|c: char| "`'\"(),;:".contains(c));
                    if n.chars().all(|c| c.is_ascii_digit()) && !n.is_empty() {
                        out.push(format!("pid {n}  (ls -l /proc/{n}/exe, cat /proc/{n}/cmdline)"));
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn pids_in(what: &str) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    let toks: Vec<&str> = what.split_whitespace().collect();
    for w in toks.windows(2) {
        if w[0] == "pid" {
            if let Ok(n) = w[1].trim_matches(|c: char| !c.is_ascii_digit()).parse::<u32>() {
                if n > 1 && !out.contains(&n) {
                    out.push(n);
                }
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]

pub(crate) fn journal_one(rec: &hemostat_enforce_linux::UndoRecord) -> Result<String, String> {
    use hemostat_enforce_linux::journal;
    use std::io::Write as _;
    let dir = std::path::Path::new(hemostat_enforce_linux::DEFAULT_VAULT);
    let body = journal::encode(std::slice::from_ref(rec));
    let failed = |why: String| format!("{} — WARNING: the undo journal could not be written ({why})", rec.did);
    std::fs::create_dir_all(dir).map_err(|e| failed(e.to_string()))?;
    for _ in 0..16 {
        let path = journal::unique_path(dir);
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                return f
                    .write_all(body.as_bytes())
                    .and_then(|()| f.sync_all())
                    .map(|()| format!("{} — undo: hemostat undo {}", rec.did, path.display()))
                    .map_err(|e| failed(e.to_string()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(failed(e.to_string())),
        }
    }
    Err(failed("no free journal name after 16 attempts".into()))
}

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
pub(crate) fn posture_model() -> hemostat_tui::PostureModel {
    use hemostat_sensor_win::Flag;
    use hemostat_tui::{Confidence, PostureModel, Row};

    let p = hemostat_sensor_win::report();

    let conf = |f: Flag| match f {
        Flag::Unreadable => Confidence::Unknown,
        _ => Confidence::Inferred,
    };
    let row = |label: &str, f: Flag, note: &str| Row {
        label: label.to_string(),
        value: f.token().to_string(),
        confidence: conf(f),
        note: note.to_string(),
    };

    let f = &p.facts;
    let rows = vec![
        Row {
            label: "agent reaches".into(),
            value: p.agent.token().to_string(),
            confidence: Confidence::Measured,
            note: "from this process's own token".into(),
        },
        Row {
            label: "adversary reaches".into(),
            value: p.adversary.token().to_string(),
            confidence: Confidence::Inferred,
            note: "from the barriers below".into(),
        },
        row("Secure Boot", f.secure_boot, "firmware; cannot be changed from Windows"),
        row("HVCI / Memory Integrity", f.hvci, "hypervisor-enforced code integrity"),
        row("VBS", f.vbs, "virtualisation-based security"),
        row(
            "vulnerable-driver blocklist",
            f.driver_blocklist,
            if f.driver_blocklist_basis.is_some() {
                "the BYOVD backstop — INFERRED from the build, not read"
            } else {
                "the BYOVD backstop"
            },
        ),
        row("LSA protected process", f.lsa_ppl, "credential exposure"),
        row("WDigest plaintext caching", f.wdigest_plaintext, "credential exposure"),
        row("Defender real-time protection", f.defender_rtp, "read only — §1.4a"),
        row("Defender tamper protection", f.defender_tamper, "read only — §1.4a"),
    ];

    PostureModel {
        variant: MANIFEST.variant.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        tier: p.standing.token().to_string(),
        tier_meaning: p.standing.meaning().to_string(),
        rows,

        warnings: f.notes.clone(),

        hooks: Vec::new(),
    }
}

#[cfg(all(target_os = "windows", feature = "mod-tui"))]
pub(crate) fn console_model() -> hemostat_tui::ConsoleModel {
    use hemostat_sensor_win::Severity as WSev;
    use hemostat_tui::{FindingRow, Sev};

    let mut rows: Vec<FindingRow> = Vec::new();
    let mut cov = Coverage::new();
    for source in Source::ALL {
        let (findings, covered) = crate::sensors_win::swept(source);
        cov.note(source, covered.into());
        for f in findings {
            rows.push(FindingRow {
                severity: match f.severity {
                    WSev::Critical => Sev::Critical,
                    WSev::Warn => Sev::Warn,
                    WSev::Note => Sev::Note,
                },
                source: source.name().to_string(),
                subject: f.subject.clone(),
                what: f.what.clone(),

                why: match &f.fix {
                    Some(fix) => format!("{}  —  fix: {fix}", f.why),
                    None => f.why.clone(),
                },
                remedy: windows_remedy(&f.subject),

                evidence: f
                    .fix
                    .iter()
                    .filter(|x| x.contains("HKLM") || x.contains('\\'))
                    .cloned()
                    .collect(),
            });
        }
    }

    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown-host".into());

    let when = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => {
            let s = d.as_secs();
            format!("{:02}:{:02}:{:02} UTC", (s / 3600) % 24, (s / 60) % 60, s % 60)
        }
        Err(_) => String::new(),
    };
    debug_assert!(
        cov.unanswered().is_empty(),
        "console source(s) never reported coverage: {:?}",
        cov.unanswered()
    );

    #[cfg(feature = "mod-detect-sigma")]
    crate::win_detect::console_live_rows(&mut rows, &mut cov.gaps);
    hemostat_tui::ConsoleModel::new(host, when, rows).with_gaps(cov.gaps)
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
pub(crate) fn posture_model() -> hemostat_tui::PostureModel {
    use hemostat_tui::{Confidence, PostureModel, Row};

    let r = hemostat_sensor_linux::probe();
    let hooks = hemostat_sensor_linux::hook_report();
    let usable = hooks.iter().filter(|h| h.state.usable()).count();
    let undetermined = hooks
        .iter()
        .filter(|h| h.state == hemostat_sensor_linux::HookState::Undetermined)
        .count();

    let mut rows = vec![Row {
        label: "trial attach".into(),
        value: match &r.trial {
            Some(hemostat_sensor_linux::TrialAttach::Attached) => "attached".into(),
            Some(hemostat_sensor_linux::TrialAttach::Refused { .. }) => "refused".into(),
            None => "not attempted".into(),
        },

        confidence: if r.trial.is_some() { Confidence::Measured } else { Confidence::Inferred },
        note: r.trial.as_ref().map(|t| t.detail()).unwrap_or_default(),
    }];

    rows.push(Row {
        label: "boot line (lsm=)".into(),
        value: match &r.lsm_boot_line {
            hemostat_sensor_linux::LsmBootLine::Default => "kernel default".into(),
            hemostat_sensor_linux::LsmBootLine::Complete => "complete".into(),
            hemostat_sensor_linux::LsmBootLine::Narrowed { .. } => "NARROWED".into(),
            hemostat_sensor_linux::LsmBootLine::Unknown => "unknown".into(),
        },
        confidence: match r.lsm_boot_line {
            hemostat_sensor_linux::LsmBootLine::Unknown => Confidence::Unknown,
            _ => Confidence::Measured,
        },
        note: match &r.lsm_boot_line {
            hemostat_sensor_linux::LsmBootLine::Narrowed { dropped } => {
                format!("boot line excludes {}", dropped.join(", "))
            }
            _ => String::new(),
        },
    });

    rows.push(Row {
        label: "LSM hooks usable".into(),
        value: format!("{usable} of {}", hooks.len()),
        confidence: if undetermined > 0 { Confidence::Unknown } else { Confidence::Measured },
        note: if undetermined > 0 {
            format!("{undetermined} undetermined — the BTF walk did not finish")
        } else {
            "read from this kernel's own BTF".into()
        },
    });

    rows.push(Row {
        label: "process ceiling".into(),
        value: r.process_can.to_string(),
        confidence: if r.capabilities_known { Confidence::Measured } else { Confidence::Unknown },
        note: if r.limited_by_privilege() {
            "the ceiling is privilege, not the host".into()
        } else {
            String::new()
        },
    });

    let mut warnings = Vec::new();
    if let Some(w) = r.lsm_boot_line.warning() {
        warnings.push(w.lines().next().unwrap_or_default().to_string());
    }
    if r.limited_by_privilege() {
        warnings.push(format!("re-run elevated to reach {}", r.host_supports));
    }

    let hook_lines = hooks
        .iter()
        .map(|h| hemostat_tui::HookLine {
            name: h.name.to_string(),
            state: match &h.state {
                hemostat_sensor_linux::HookState::Available { variant, params }
                    if *variant == "single" => format!("ok ({params} args)"),
                hemostat_sensor_linux::HookState::Available { variant, .. } => {
                    format!("ok [{variant}]")
                }
                hemostat_sensor_linux::HookState::UnknownPrototype { params } => {
                    format!("SHAPE? ({params})")
                }
                hemostat_sensor_linux::HookState::Missing => "absent".into(),
                hemostat_sensor_linux::HookState::Undetermined => "unknown".into(),
            },
            buys: h.capability.to_string(),
            usable: h.state.usable(),
        })
        .collect();

    PostureModel {
        hooks: hook_lines,
        variant: MANIFEST.variant.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        tier: r.effective().to_string(),
        tier_meaning: r.effective().describe().to_string(),
        rows,
        warnings,
    }
}

#[cfg(all(target_os = "linux", feature = "mod-tui"))]
impl Source {

    pub(crate) const ALL: [Source; 17] = [
        Source::Rootkit,
        Source::Suid,
        Source::Inventory,
        Source::SysMap,
        Source::KptrHooks,
        Source::Sshd,
        Source::Sysctl,
        Source::Watchdog,
        Source::Accounts,
        Source::Overview,
        Source::Persistence,
        Source::Systemd,
        Source::Injected,
        Source::Kwalk,
        Source::KernelPosture,
        Source::Trust,
        Source::Scan,
    ];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Source::Rootkit => "rootkit",
            Source::Suid => "suid",
            Source::Inventory => "inventory",
            Source::SysMap => "sysmap",
            Source::KptrHooks => "kptr-hooks",
            Source::Sshd => "sshd",
            Source::Sysctl => "sysctl",
            Source::Watchdog => "watchdog",
            Source::Accounts => "accounts",
            Source::Overview => "overview",
            Source::Persistence => "persistence",
            Source::Systemd => "systemd",
            Source::Injected => "injected",
            Source::Kwalk => "kwalk",
            Source::KernelPosture => "kernel-posture",
            Source::Trust => "trust",
            Source::Scan => "scan",
        }
    }
}

#[cfg(all(any(target_os = "linux", target_os = "windows"), feature = "mod-tui"))]
impl Coverage {
    pub(crate) fn new() -> Self {
        Coverage { gaps: Vec::new(), asked: Vec::new() }
    }

    pub(crate) fn note(&mut self, source: Source, ran: Ran) {
        self.asked.push(source);
        match ran {
            Ran::Yes => {}
            Ran::No(why) => self.gaps.push(hemostat_tui::Gap::did_not_run(source.name(), why)),
            Ran::InPart(why) => self.gaps.push(hemostat_tui::Gap::partial(source.name(), why)),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn note_flag(&mut self, source: Source, available: bool, reason: &Option<String>) {
        self.note(source, crate::coverage::from_flag(available, reason).into());
    }

    pub(crate) fn unanswered(&self) -> Vec<&'static str> {
        Source::ALL
            .iter()
            .filter(|s| !self.asked.contains(s))
            .map(|s| s.name())
            .collect()
    }
}
