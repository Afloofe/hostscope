use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::persist::suspicion;
use crate::pkg;
use crate::triage::{Finding, Severity};

pub const DECLARATION: &str = "/etc/hemostat/critical";

pub const BASELINE: &str = "/var/lib/hemostat/services-baseline.tsv";

const WORLD_WRITABLE: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declared {

    pub unit: String,

    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceState {

    pub unit: String,

    pub active: String,

    pub enabled: String,

    pub loaded: String,

    pub fragment: Option<PathBuf>,

    pub dropins: Vec<PathBuf>,

    pub exec: Option<PathBuf>,

    pub id: String,

    pub triggered_by: String,

    pub wanted_by: String,

    pub kind: String,

    pub result: String,
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub services: Vec<ServiceState>,

    pub declared: usize,

    pub available: bool,

    pub reason: Option<String>,

    pub declaration_unreadable: bool,

    pub packager: Option<String>,

    pub baseline_compared: bool,

    pub baseline_rows: usize,

    pub baseline_digest: String,
}

pub fn parse_line(line: &str) -> Option<Declared> {
    let t = line.split('#').next().unwrap_or("").trim();
    if t.is_empty() {
        return None;
    }
    let mut words = t.split_whitespace();
    let raw = words.next()?;

    if raw.starts_with('/') {
        return None;
    }
    let unit = normalise_unit(raw);
    let paths = words.filter(|w| w.starts_with('/')).map(PathBuf::from).collect();
    Some(Declared { unit, paths })
}

pub const UNIT_SUFFIXES: &[&str] = &[
    ".service", ".socket", ".device", ".mount", ".automount", ".swap", ".target", ".path",
    ".timer", ".slice", ".scope",
];

pub fn normalise_unit(name: &str) -> String {
    if name.is_empty() || UNIT_SUFFIXES.iter().any(|s| name.ends_with(s)) {
        name.to_string()
    } else {
        format!("{name}.service")
    }
}

pub fn unit_names(units: &[String]) -> Vec<String> {
    let units: Vec<&String> = units.iter().filter(|u| is_unit_name(u)).collect();
    if units.is_empty() {
        return Vec::new();
    }
    let Some(systemctl) = resolve(&["/usr/bin/systemctl", "/bin/systemctl"]) else {
        return Vec::new();
    };
    let ask = |names: &[&String]| {
        let mut args = vec!["--property=Id,Names", "--"];
        args.extend(names.iter().map(|n| n.as_str()));
        show_within(&systemctl, &args)
    };
    match ask(&units) {
        Ok(out) if out.status.success() => parse_unit_names(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => Vec::new(),
        Ok(_) => {
            let mut names = Vec::new();
            for u in &units {
                match ask(&[*u]) {
                    Ok(out) if out.status.success() => {
                        names.extend(parse_unit_names(&String::from_utf8_lossy(&out.stdout)));
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            names
        }
    }
}

pub const SHOW_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

pub fn show_within(systemctl: &Path, args: &[&str]) -> Result<std::process::Output, String> {
    let mut cmd = Command::new(systemctl);
    cmd.arg("show").args(args).env_clear().env("LC_ALL", "C");
    match crate::sshd::output_within(&mut cmd, std::process::Stdio::null(), SHOW_LIMIT) {
        Ok(Some(out)) => Ok(out),
        Ok(None) => Err(format!(
            "`systemctl show` had not answered after {} seconds (a wedged systemd or D-Bus)",
            SHOW_LIMIT.as_secs()
        )),
        Err(e) => Err(format!("could not run {}: {e}", systemctl.display())),
    }
}

pub fn parse_unit_names(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let Some(v) = line.strip_prefix("Id=").or_else(|| line.strip_prefix("Names=")) else {
            continue;
        };
        for n in v.split_whitespace() {
            if !out.iter().any(|o| o == n) {
                out.push(n.to_string());
            }
        }
    }
    out
}

fn is_unit_name(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 255
        && !u.starts_with('-')
        && u.bytes().all(|b| b.is_ascii_alphanumeric() || b":_.\\@-".contains(&b))
}

pub fn declarations() -> Vec<Declared> {
    parse_declaration(
        &crate::saferead::read_scan_target(std::path::Path::new(DECLARATION)).unwrap_or_default(),
    )
}

pub fn declarations_unreadable() -> bool {
    match crate::saferead::read_text(std::path::Path::new(DECLARATION)) {
        Ok(_) => false,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

pub fn parse_declaration(text: &str) -> Vec<Declared> {
    let mut out: Vec<Declared> = Vec::new();
    for line in text.lines() {
        let Some(d) = parse_line(line) else { continue };

        match out.iter_mut().find(|k| k.unit == d.unit) {
            Some(k) => k.paths.extend(d.paths),
            None => out.push(d),
        }
    }
    out
}

pub fn protected_names(declared: &[Declared]) -> Vec<String> {
    let mut out = Vec::new();
    for d in declared {
        out.push(d.unit.clone());
        out.extend(d.paths.iter().map(|p| p.to_string_lossy().into_owned()));
    }
    out
}

fn resolve(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

fn capture(tool: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new(tool).args(args).env_clear().env("LC_ALL", "C").output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn exec_path(rendered: &str) -> Option<PathBuf> {
    let at = rendered.find("path=")? + "path=".len();
    let rest = &rendered[at..];
    let end = rest.find([';', ' ']).unwrap_or(rest.len());
    let p = rest[..end].trim();
    (!p.is_empty()).then(|| PathBuf::from(p))
}

pub fn declared_exec_paths(declared: &[Declared]) -> Result<Vec<(String, PathBuf)>, String> {
    if declared.is_empty() {
        return Ok(Vec::new());
    }

    if init_other_than_systemd().is_some() {
        return Ok(Vec::new());
    }
    let Some(systemctl) = resolve(&["/usr/bin/systemctl", "/bin/systemctl"]) else {
        return Err("systemctl not found — what the declared services start cannot be asked".into());
    };
    let mut found = Vec::new();
    for d in declared {
        let out = show_within(
            &systemctl,
            &["--property=ExecCondition,ExecStartPre,ExecStart,ExecStartPost", "--", &d.unit],
        )
        .map_err(|why| format!("{why}, asked what {} starts", d.unit))?;
        if !out.status.success() {
            return Err(format!(
                "`systemctl show {}` failed ({}), so what it starts is not known",
                d.unit,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        found.extend(exec_paths(&text).into_iter().map(|p| (d.unit.clone(), p)));
    }
    Ok(found)
}

fn init_other_than_systemd() -> Option<String> {
    crate::enablement::other_init(
        crate::saferead::read_pid_text("/proc/1/comm").ok().as_deref(),
        fs::read_link("/proc/1/exe").ok().as_deref(),
        Path::new("/run/systemd/system").is_dir(),
    )
}

pub fn exec_paths(text: &str) -> Vec<PathBuf> {
    const AT: &str = "{ path=";
    let mut out = Vec::new();
    for line in text.lines() {
        let mut rest = line;
        while let Some(at) = rest.find(AT) {
            let tail = rest.get(at + AT.len()..).unwrap_or_default();
            let end = tail.find([';', ' ', '}']).unwrap_or(tail.len());
            let p = tail.get(..end).unwrap_or_default().trim();
            if !p.is_empty() {
                out.push(PathBuf::from(p));
            }
            rest = tail.get(end..).unwrap_or_default();
        }
    }
    out
}

fn query(systemctl: &Path, unit: &str) -> ServiceState {
    let mut st = ServiceState { unit: unit.to_string(), ..ServiceState::default() };
    let Some(text) = capture(
        systemctl,
        &[
            "show",
            unit,
            "--property=Id,LoadState,ActiveState,UnitFileState,FragmentPath,DropInPaths,\
             ExecStart,TriggeredBy,WantedBy,RequiredBy,Type,Result",
        ],
    ) else {
        return st;
    };
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.trim();
        match k {
            "LoadState" => st.loaded = v.to_string(),
            "ActiveState" => st.active = v.to_string(),
            "UnitFileState" => st.enabled = v.to_string(),
            "FragmentPath" if !v.is_empty() => st.fragment = Some(PathBuf::from(v)),
            "DropInPaths" if !v.is_empty() => {
                st.dropins = v.split_whitespace().map(PathBuf::from).collect();
            }
            "ExecStart" if !v.is_empty() => st.exec = exec_path(v),
            "Id" => st.id = v.to_string(),
            "TriggeredBy" => st.triggered_by = v.to_string(),

            "WantedBy" | "RequiredBy" if !v.is_empty() => {
                if !st.wanted_by.is_empty() {
                    st.wanted_by.push(' ');
                }
                st.wanted_by.push_str(v);
            }
            "Type" => st.kind = v.to_string(),
            "Result" => st.result = v.to_string(),
            _ => {}
        }
    }
    st
}

fn digest(path: &Path) -> Option<String> {
    crate::saferead::sha256_file(path).map(|d| d.iter().map(|b| format!("{b:02x}")).collect())
}

const MAX_DECLARED_FILES: usize = 500;

const MAX_DECLARED_DEPTH: usize = 8;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Watched {

    pub files: Vec<PathBuf>,

    pub gaps: Vec<(PathBuf, String)>,
}

pub fn watched_files(st: &ServiceState, extra: &[PathBuf]) -> Watched {
    let mut w = Watched::default();
    w.files.extend(st.fragment.clone());
    w.files.extend(st.dropins.iter().cloned());
    w.files.extend(st.exec.clone());
    for p in extra {
        match fs::metadata(p) {
            Ok(md) if md.is_dir() => walk_declared(p, &mut w),
            Ok(_) => w.files.push(p.clone()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                w.gaps.push((p.clone(), "is not there".to_string()));
            }
            Err(e) => w.gaps.push((p.clone(), format!("could not be looked at ({e})"))),
        }
    }
    w.files.sort();
    w.files.dedup();
    w
}

fn walk_declared(root: &Path, w: &mut Watched) {
    let mut taken = 0usize;
    let mut entered: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    let mut too_deep: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let real = dir.canonicalize().unwrap_or_else(|_| dir.clone());
        if entered.contains(&real) {
            continue;
        }

        if depth > MAX_DECLARED_DEPTH {
            too_deep.insert(real);
            continue;
        }
        entered.insert(real);
        let mut entries: Vec<PathBuf> = match fs::read_dir(&dir) {
            Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
            Err(e) => {
                w.gaps.push((dir, format!("could not be listed ({e}), so nothing under it is watched")));
                continue;
            }
        };
        entries.sort();
        for c in entries {
            if c.is_dir() {
                stack.push((c, depth + 1));
            } else if c.is_file() {
                if taken == MAX_DECLARED_FILES {
                    w.gaps.push((
                        root.to_path_buf(),
                        format!("has more than {MAX_DECLARED_FILES} files under it; the rest are not watched"),
                    ));
                    return;
                }
                taken += 1;
                w.files.push(c);
            }
        }
    }
    if too_deep.iter().any(|d| !entered.contains(d)) {
        w.gaps.push((
            root.to_path_buf(),
            format!("has directories more than {MAX_DECLARED_DEPTH} levels down, which are not watched"),
        ));
    }
}

fn under_world_writable(p: &Path) -> Option<&'static str> {
    let s = p.to_string_lossy().into_owned();
    WORLD_WRITABLE.iter().find(|d| s.starts_with(**d)).copied()
}

fn is_admin_dropin(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.starts_with("/etc/systemd/") || s.starts_with("/run/systemd/")
}

pub fn baseline_rows(declared: &[Declared]) -> Result<(BTreeMap<String, String>, Vec<String>), String> {
    let Some(systemctl) = resolve(&["/usr/bin/systemctl", "/bin/systemctl"]) else {
        return Err("systemctl not found — cannot ask systemd which files a unit uses".into());
    };
    let mut rows: BTreeMap<String, String> = BTreeMap::new();
    let mut gaps: Vec<String> = Vec::new();
    for d in declared {
        let st = query(&systemctl, &d.unit);
        let watched = watched_files(&st, &d.paths);
        gaps.extend(
            watched.gaps.iter().map(|(p, why)| format!("declared services: {} {why}", p.display())),
        );
        record_rows(&watched.files, &mut rows, &mut gaps);
    }
    Ok((rows, gaps))
}

fn record_rows(files: &[PathBuf], rows: &mut BTreeMap<String, String>, gaps: &mut Vec<String>) {
    for f in files {

        if is_mask(f) {
            continue;
        }
        match digest(f) {
            Some(h) => {
                rows.insert(f.to_string_lossy().into_owned(), h);
            }
            None => gaps.push(format!("declared services: {}: not read", f.display())),
        }
    }
}

fn usable_baseline<'a>(given: &'a Baseline, r: &mut Report) -> Option<&'a BTreeMap<String, String>> {
    match given {
        Baseline::Absent => None,
        Baseline::Refused(why) => {
            r.findings.push(Finding::flag(
                Severity::Warn,
                "services",
                "arrival snapshot".to_string(),
                format!("present and not used: {why}"),
                "this run compared nothing against it, which is not the same as there being no \
                 baseline — and a snapshot that stopped verifying is itself worth knowing about",
            ));
            None
        }
        Baseline::Snapshot { rows, .. } if rows.is_empty() => {
            r.findings.push(Finding::flag(
                Severity::Warn,
                "services",
                "arrival snapshot".to_string(),
                "records no files for the declared services".to_string(),
                "the services were probably declared after the snapshot was taken. Nothing was \
                 compared; `hemostat snapshot --replace` records them, and moves what counts as \
                 arrival",
            ));
            None
        }
        Baseline::Snapshot { rows, .. } => Some(rows),
    }
}

fn compare(base: &BTreeMap<String, String>, manifest: Option<&crate::vendor::Manifest>, r: &mut Report) {
    for (path, was) in base {
        let p = Path::new(path);
        match digest(p) {
            Some(now) if &now == was => {}

            Some(_) if manifest.and_then(|m| {
                crate::saferead::sha256_file(p).and_then(|d| m.is_vendor(path, &d))
            }) == Some(true) => r.findings.push(Finding::flag(
                Severity::Note,
                "services",
                path.clone(),
                format!(
                    "changed since the arrival snapshot, into a version {} shipped",
                    manifest.map_or("the vendor", |m| m.release.as_str())
                ),
                "the file is not what it was on arrival, and it is byte-for-byte a file the \
                 vendor shipped at this path — a package update, not a replacement",
            )),
            Some(_) => r.findings.push(Finding::flag(
                Severity::Critical,
                "services",
                path.clone(),
                "changed since the arrival snapshot — a declared service depends on it".to_string(),
                "the contents of this file are not what they were on arrival, and no vendor \
                 manifest vouches for what it is now. Unlike the package check this covers \
                 files nobody packaged, which is most of what a team writes during an exercise",
            )),
            None => r.findings.push(Finding::flag(
                Severity::Warn,
                "services",
                path.clone(),
                "in the arrival snapshot, but cannot be read now — a declared service depends on it"
                    .to_string(),
                "a watched file that has been deleted or has become unreadable is a change \
                 this check cannot measure, reported as unknown rather than as clean",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Baseline {

    Absent,

    Snapshot {

        rows: BTreeMap<String, String>,

        anchor: String,

        pinned: bool,
    },

    Refused(String),
}

#[allow(clippy::too_many_lines)]
pub fn check(
    declared: &[Declared],
    given: &Baseline,
    manifest: Option<&crate::vendor::Manifest>,
) -> Report {
    let mut r = Report { declared: declared.len(), ..Report::default() };

    if declarations_unreadable() {
        r.declaration_unreadable = true;
        r.findings.push(Finding::flag(
            Severity::Warn,
            "services",
            DECLARATION.to_string(),
            "the service declaration file could not be read".to_string(),
            "the services it names were not checked, so their absence from this report means \
             nothing",
        ));
    }
    if declared.is_empty() {
        r.available = true;
        r.reason = Some(if r.declaration_unreadable {
            format!(
                "{DECLARATION} could not be read, so no declared service was checked — this is \
                 not a host with nothing declared"
            )
        } else {
            format!(
                "nothing declared — name the services this host is scored on in {DECLARATION}, \
                 one per line, and every run will say whether they are up and whether anything \
                 has touched them"
            )
        });
        return r;
    }
    let Some(systemctl) = resolve(&["/usr/bin/systemctl", "/bin/systemctl"]) else {
        r.reason = Some("systemctl not found — the service state could not be read".into());
        return r;
    };
    r.available = true;

    let manager = pkg::manager();
    r.packager = manager.as_ref().map(|m| m.kind.name().to_string());

    let baseline = usable_baseline(given, &mut r);
    if let Baseline::Snapshot { rows, anchor, pinned } = given {
        r.baseline_rows = rows.len();
        r.baseline_digest = format!("{anchor}{}", if *pinned { " (pinned)" } else { " (NOT pinned)" });
    }
    r.baseline_compared = baseline.is_some();
    if Path::new(BASELINE).exists() {
        r.findings.push(Finding::flag(
            Severity::Note,
            "services",
            BASELINE.to_string(),
            "a baseline file from an earlier version is present and is no longer read".to_string(),
            "the services baseline now comes from the sealed arrival snapshot; this file is a \
             root-writable leftover. Remove it when convenient",
        ));
    }

    let mut verified: BTreeMap<String, Vec<pkg::Drift>> = BTreeMap::new();

    let mut drift_reported: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    let mut by_package: BTreeMap<String, Vec<pkg::Drift>> = BTreeMap::new();

    let mut dir_owned: BTreeMap<PathBuf, bool> = BTreeMap::new();

    for d in declared {
        let st = query(&systemctl, &d.unit);

        check_presence(d, &mut r, &st);
        check_layered_dropins(d, &mut r, &st);
        check_shadowed_unit(&mut r, &st);
        check_start_source(d, &mut r, &st);

        let watched = watched_files(&st, &d.paths);
        for (p, why) in &watched.gaps {
            r.findings.push(Finding::flag(
                Severity::Warn,
                "services",
                p.display().to_string(),
                format!("declared for {}, and {why}", d.unit),
                "nothing there was compared against the package or the arrival snapshot, so \
                 the absence of a finding about it is not a clean result",
            ));
        }
        let files = watched.files;
        let declared_dirs: Vec<&PathBuf> = d.paths.iter().filter(|p| p.is_dir()).collect();
        if let Some(m) = &manager {
            let kind = m.kind.name();
            for f in &files {
                let key = f.to_string_lossy().into_owned();
                if verified.contains_key(&key) {
                    continue;
                }
                let under_declared = declared_dirs.iter().any(|dir| f.starts_with(dir));
                let mut dir_is_owned = |dir: &Path| {
                    *dir_owned.entry(dir.to_path_buf()).or_insert_with(|| m.owner(dir).is_some())
                };
                if known_unowned(m.kind, f, under_declared, &mut dir_is_owned) {
                    continue;
                }
                let Some(owner) = m.owner(f) else { continue };

                let drifts = by_package.entry(owner).or_insert_with_key(|o| m.drift(o)).clone();

                for dr in &drifts {
                    verified.insert(dr.path.to_string_lossy().into_owned(), Vec::new());
                }
                verified.insert(key, drifts.clone());
                for dr in drifts
                    .iter()
                    .filter(|dr| files.contains(&dr.path) && drift_reported.insert(dr.path.clone()))
                {
                    if dr.is_config {
                        r.findings.push(Finding::flag(
                            Severity::Warn,
                            "services",
                            dr.path.display().to_string(),
                            format!("differs from the {kind} package, and is a config file"),
                            "this is exactly what a service somebody configured looks like, and \
                             exactly what a modified config looks like. The package manager \
                             cannot tell them apart and neither can this — read the diff",
                        ));
                    } else {
                        r.findings.push(Finding::flag(
                            Severity::Critical,
                            "services",
                            dr.path.display().to_string(),
                            format!("differs from the {kind} package, and is NOT a config file"),
                            "nobody edits a packaged binary, library or unit file by hand. The \
                             package manager says these bytes are not the bytes it installed",
                        ));
                    }
                }
            }
        }

        if let Some(frag) = &st.fragment {

            let read = crate::saferead::read_scan_target(std::path::Path::new(frag));
            if read.is_none() {
                r.findings.push(unread_unit_file(frag, &d.unit, "the unit file of"));
            }
            if let Some(text) = read {
                if let Some((sev, what, why)) = judge_unit_text(&text, Scope::UnitFile) {
                    r.findings.push(Finding::flag(
                        sev,
                        "services",
                        frag.display().to_string(),
                        format!("{}'s own unit file: {what}", d.unit),
                        why,
                    ));
                }
            }
        }

        r.services.push(st);
    }

    if let Some(base) = baseline {
        compare(base, manifest, &mut r);
    }

    r.findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    r
}

fn judge_directive(
    key: &str,
    value: &str,
    scope: Scope,
) -> Option<(Severity, String, &'static str)> {
    let k = key.trim();
    let v = value.trim();
    let lv = v.to_lowercase();

    if k.starts_with("Environment") {
        for var in ["ld_preload", "ld_audit", "ld_library_path"] {
            if lv.contains(var) {
                return Some((
                    Severity::Critical,
                    format!("sets {} for the service", v.split('=').next().unwrap_or(v)),
                    "a linker variable in a unit's environment loads attacker code into the \
                     service's own address space every time it starts. It needs no Exec line \
                     and survives every check that only reads commands",
                ));
            }
        }
    }

    if scope == Scope::DropIn && (k == "User" || k == "Group") && (lv == "root" || lv == "0") {
        return Some((
            Severity::Critical,
            format!("{k}={v} — the service is made to run as root"),
            "a service that was written to drop privileges being handed root back is a \
             privilege escalation spelled as configuration",
        ));
    }

    const HARDENING: &[&str] = &[
        "ProtectSystem", "ProtectHome", "PrivateTmp", "NoNewPrivileges",
        "PrivateDevices", "ProtectKernelModules", "ProtectKernelTunables",
        "RestrictSUIDSGID", "LockPersonality", "MemoryDenyWriteExecute",
    ];

    if scope == Scope::DropIn
        && HARDENING.contains(&k)
        && matches!(lv.as_str(), "no" | "false" | "off" | "0")
    {
        return Some((
            Severity::Warn,
            format!("{k}={v} — a sandbox the unit shipped with is switched off"),
            "weakening a service's confinement does nothing for the service and everything \
             for whatever runs inside it. Worth knowing who turned it off and why",
        ));
    }

    if k.starts_with("Exec") {
        if let Some(why) = suspicion(v) {
            return Some((
                Severity::Critical,
                format!("{k} runs a command that {why}"),
                "a drop-in adds directives without editing the packaged file, so the unit \
                 itself still verifies clean against the package manager. It is the tidiest \
                 place to attach a command to a service that is certain to run",
            ));
        }

        if scope == Scope::DropIn {
            return Some((
                Severity::Warn,
                format!("{k}={}", clip(v, 90)),
                "a command layered onto this service runs with its privileges every time it \
                 starts. Nothing about this one looks wrong — `ExecStartPre=… -t` to validate \
                 a config is the usual reason to write a drop-in at all — so it is here to be \
                 read, not to be believed",
            ));
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {

    DropIn,

    UnitFile,
}

fn check_presence(d: &Declared, r: &mut Report, st: &ServiceState) {
    if st.loaded == "not-found" || st.loaded.is_empty() {
        r.findings.push(Finding::flag(
            Severity::Warn,
            "services",
            d.unit.clone(),
            "declared critical, but systemd does not know this unit",
            "either the name in the declaration is wrong, or the unit file has been removed \
             from the host entirely. Both are worth a look, and the second is an outage \
             waiting for the next boot",
        ));
    } else {
        if st.enabled == "masked" {
            r.findings.push(Finding::flag(
                Severity::Critical,
                "services",
                d.unit.clone(),
                "declared critical, and MASKED",
                "a masked unit cannot be started at all — not by hand, not by a dependency, \
                 not at boot. Masking a scored service is the quietest way to take it away, \
                 because nothing appears to fail until something tries to start it",
            ));
        }

        if is_down(st) && st.enabled != "masked" {
            r.findings.push(Finding::flag(
                Severity::Critical,
                "services",
                d.unit.clone(),
                format!("declared critical, and {}", if st.active.is_empty() { "not running" } else { &st.active }),
                "this is a service you said this host has to keep. It is not running now",
            ));
        }
        if oneshot_failed(st) {
            r.findings.push(Finding::flag(
                Severity::Critical,
                "services",
                d.unit.clone(),
                format!("declared critical, and its last run ended in `{}`", st.result),
                "a oneshot unit is inactive once it finishes, so its state says nothing. \
                 Whether it *worked* is the thing to read, and this one did not",
            ));
        }

        if will_not_come_back(st) {
            r.findings.push(Finding::flag(
                Severity::Warn,
                "services",
                d.unit.clone(),
                "running now, but nothing will start it after a reboot",
                "it is disabled, no socket or path activates it, and no other unit wants it \
                 — so it survives only until the host restarts. Nothing appears wrong in the \
                 meantime, which is what makes it worth saying out loud. `systemctl enable` \
                 restores the autostart",
            ));
        }
    }
}

fn unread_unit_file(path: &std::path::Path, unit: &str, role: &str) -> Finding {
    Finding::flag(
        Severity::Warn,
        "services",
        path.display().to_string(),
        format!("{role} {unit} could not be read"),
        "what it tells systemd to run was not examined, so the absence of a finding here says \
         nothing about it. Re-run with privilege; a unit file root cannot read is itself odd",
    )
}

fn check_layered_dropins(d: &Declared, r: &mut Report, st: &ServiceState) {
    for dropin in &st.dropins {
        if !is_admin_dropin(dropin) {
            continue;
        }

        let Some((text, truncated)) = crate::saferead::read_scan_target_bounded(std::path::Path::new(dropin)) else {
            r.findings.push(unread_unit_file(dropin, &d.unit, "a drop-in layered onto"));
            continue;
        };
        if truncated {
            r.findings.push(Finding::flag(
                Severity::Warn,
                "services",
                dropin.display().to_string(),
                format!("a drop-in for {} was read only in part", d.unit),
                "it is larger than the read cap, so anything past it — an ExecStartPost=, an \
                 identity change — was not examined. No real drop-in is this size",
            ));
        }
        match judge_unit_text(&text, Scope::DropIn) {
            Some((sev, what, why)) => r.findings.push(Finding::flag(
                sev,
                "services",
                dropin.display().to_string(),
                format!("layered onto {}: {what}", d.unit),
                why,
            )),

            None => r.findings.push(Finding::flag(
                Severity::Note,
                "services",
                dropin.display().to_string(),
                format!("a drop-in configures {} — no command, identity or sandbox change", d.unit),
                "something outside the package has settings layered onto this unit. \
                 Inventory: this is the ordinary way to tune a service, and it is here so \
                 that what runs is never a surprise",
            )),
        }
    }
}

fn known_unowned(
    kind: pkg::Kind,
    f: &Path,
    under_declared: bool,
    dir_is_owned: &mut dyn FnMut(&Path) -> bool,
) -> bool {
    if !under_declared || kind == pkg::Kind::Rpm {
        return false;
    }
    if fs::symlink_metadata(f).map_or(true, |md| md.file_type().is_symlink()) {
        return false;
    }
    f.parent().is_some_and(|dir| !dir_is_owned(dir))
}

fn is_mask(p: &Path) -> bool {
    p.read_link().is_ok_and(|t| t == Path::new("/dev/null"))
}

fn check_shadowed_unit(r: &mut Report, st: &ServiceState) {
    if let Some(frag) = &st.fragment {
        let fs_str = frag.to_string_lossy();

        if fs_str.starts_with("/etc/systemd/system/") && !is_mask(frag) {
            let vendor = ["/usr/lib/systemd/system/", "/lib/systemd/system/"]
                .iter()
                .map(|d| PathBuf::from(format!("{d}{}", d_unit_file(frag))))
                .find(|p| p.exists());
            if let Some(v) = vendor {
                r.findings.push(Finding::flag(
                    Severity::Warn,
                    "services",
                    frag.display().to_string(),
                    format!("this unit file shadows the packaged one at {}", v.display()),
                    "systemd reads /etc before /usr, so the packaged unit is not what runs. \
                     Overriding a unit wholesale is legitimate and also how a service is \
                     quietly replaced — compare the two",
                ));
            }
        }
    }
}

fn check_start_source(d: &Declared, r: &mut Report, st: &ServiceState) {
    if let Some(exec) = &st.exec {
        if let Some(dir) = under_world_writable(exec) {
            r.findings.push(Finding::flag(
                Severity::Critical,
                "services",
                exec.display().to_string(),
                format!("{} starts a binary under {dir}", d.unit),
                "a root service whose executable lives where any local user can replace it \
                 is a privilege escalation with no exploit required — wait for the restart",
            ));
        } else if !exec.exists() {
            r.findings.push(Finding::flag(
                Severity::Critical,
                "services",
                exec.display().to_string(),
                format!("{} starts a binary that is not there", d.unit),
                "the unit names an executable that does not exist, so the service cannot \
                 start. If it is running now, it is running from a file that has since been \
                 deleted or replaced",
            ));
        }
    }
}

pub(crate) fn logical_lines(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut pending: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim_end_matches(['\r']);
        if line.trim_start().starts_with(['#', ';']) {
            continue;
        }
        let trailing = line.len() - line.trim_end_matches('\\').len();
        let continues = trailing % 2 == 1;
        let body = if continues { &line[..line.len() - 1] } else { line };
        match &mut pending {

            Some(acc) => {

                while acc.ends_with(' ') || acc.ends_with('\t') {
                    acc.pop();
                }
                acc.push(' ');
                acc.push_str(body.trim_start());
            }
            None => pending = Some(body.to_string()),
        }
        if !continues {
            if let Some(done) = pending.take() {
                out.push(done);
            }
        }
    }

    if let Some(done) = pending.take() {
        out.push(done);
    }
    out
}

fn judge_unit_text(text: &str, scope: Scope) -> Option<(Severity, String, &'static str)> {
    let mut worst: Option<(Severity, String, &'static str)> = None;
    for line in logical_lines(text) {
        let l = line.trim();
        if l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        let Some((k, v)) = l.split_once('=') else { continue };
        let Some(found) = judge_directive(k, v, scope) else { continue };
        if worst.as_ref().is_none_or(|w| found.0 > w.0) {
            worst = Some(found);
        }
    }
    worst
}

fn is_down(st: &ServiceState) -> bool {
    st.kind != "oneshot" && st.active != "active"
}

fn oneshot_failed(st: &ServiceState) -> bool {
    st.kind == "oneshot" && !st.result.is_empty() && st.result != "success"
}

fn will_not_come_back(st: &ServiceState) -> bool {
    st.active == "active"
        && st.enabled == "disabled"
        && st.triggered_by.is_empty()
        && st.wanted_by.is_empty()
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{head}…")
}

fn d_unit_file(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}
