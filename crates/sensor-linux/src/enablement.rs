use std::collections::BTreeSet;

use crate::triage::{Finding, Severity};

const SWEPT: &[&str] = &["/etc/systemd/", "/usr/lib/systemd/", "/lib/systemd/", "/run/systemd/system/"];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnitFact {

    pub id: String,

    pub load_state: String,

    pub file_state: String,

    pub fragment: String,

    pub transient: bool,

    pub main_pid: u32,

    pub service_type: String,

    pub notify_access: String,

    pub exec_starts: usize,

    pub exec_start: String,

    pub hooks: Vec<String>,

    pub own: Option<Own>,

    pub dbus: Option<DbusActivated>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbusActivated {

    pub name: String,

    pub service_package: String,

    pub program: String,

    pub program_package: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Own {

    Sentinel,

    Rollback,
}

pub const SENTINEL_UNIT_PREFIX: &str = "hemostat-sentinel-";

pub fn own_name(id: &str) -> Option<Own> {
    let unit = id.strip_suffix(".service")?;
    let window = unit
        .strip_prefix(crate::netpolicy::ROLLBACK_UNIT)
        .and_then(|rest| rest.strip_prefix('-'));
    if window.is_some_and(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit())) {
        return Some(Own::Rollback);
    }
    let pid = unit.strip_prefix(SENTINEL_UNIT_PREFIX)?;
    (!pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit())).then_some(Own::Sentinel)
}

const HOOKS: &[&str] =
    &["ExecCondition", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost"];

fn runs_one_command(u: &UnitFact) -> bool {
    u.exec_starts == 1
        && u.hooks.is_empty()
        && matches!(u.service_type.as_str(), "simple" | "exec")
        && u.notify_access == "none"
}

fn loads_code(name: &[u8]) -> bool {
    name.starts_with(b"LD_")
        || name.starts_with(b"BASH_FUNC_")
        || matches!(name, b"GCONV_PATH" | b"BASH_ENV" | b"ENV" | b"SHELLOPTS" | b"BASHOPTS" | b"PS4")
}

fn inert_environment(environ: &[u8]) -> Option<Option<String>> {
    let mut path = None;
    for kv in environ.split(|b| *b == 0).filter(|kv| !kv.is_empty()) {
        let mut split = kv.splitn(2, |b| *b == b'=');
        let (name, value) = (split.next().unwrap_or_default(), split.next().unwrap_or_default());
        if loads_code(name) {
            return None;
        }
        if name == b"PATH" {
            if path.is_some() {
                return None;
            }
            path = Some(std::str::from_utf8(value).ok()?.to_string());
        }
    }
    Some(path)
}

const SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

type FileId = (u64, u64);

fn which(path: &str, name: &str, id: &dyn Fn(&std::path::Path) -> Option<FileId>) -> Option<FileId> {
    for dir in path.split(':') {
        if !dir.starts_with('/') {
            return None;
        }
        if let Some(f) = id(&std::path::Path::new(dir).join(name)) {
            return Some(f);
        }
    }
    None
}

fn sentinel_argv(argv: &[String]) -> bool {
    matches!(argv, [_, verb, flag, _] if verb == "sentinel" && flag == "--watch")
}

const DBUS_SYSTEM_SERVICES: &str = "/usr/share/dbus-1/system-services";

pub fn dbus_unit_name(id: &str) -> Option<&str> {
    let rest = id.strip_suffix(".service")?.strip_prefix("dbus-:")?;
    let (unique, rest) = rest.split_once('-')?;
    if unique.is_empty() || !unique.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    let (name, instance) = rest.rsplit_once('@')?;
    if instance.is_empty() || !instance.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    well_known_bus_name(name).then_some(name)
}

fn well_known_bus_name(name: &str) -> bool {
    name.len() <= 255
        && name.split('.').count() >= 2
        && name.split('.').all(|e| {
            !e.is_empty()
                && !e.starts_with(|c: char| c.is_ascii_digit())
                && e.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DbusService {

    name: String,

    exec: Vec<String>,

    systemd_service: bool,
}

fn parse_dbus_service(text: &str) -> Option<DbusService> {
    let (mut in_section, mut sections) = (false, 0usize);
    let (mut name, mut exec, mut systemd_service) = (None, None, false);
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_section = line == "[D-BUS Service]";
            sections += usize::from(in_section);
            continue;
        }
        let Some((key, value)) = line.split_once('=').filter(|_| in_section) else { continue };
        let value = value.trim().to_string();

        let doubled = match key.trim() {
            "Name" => name.replace(value).is_some(),
            "Exec" => exec.replace(value).is_some(),
            "SystemdService" => {
                systemd_service = true;
                false
            }
            _ => false,
        };
        if doubled {
            return None;
        }
    }
    if sections != 1 {
        return None;
    }
    Some(DbusService { name: name?, exec: plain_command(&exec?)?, systemd_service })
}

fn plain_command(s: &str) -> Option<Vec<String>> {
    const SPECIAL: &[char] = &[
        '"', '\'', '\\', '$', '`', ';', '|', '&', '<', '>', '(', ')', '{', '}', '*', '?', '[', ']',
        '~', '#', '%',
    ];
    if s.contains(SPECIAL) {
        return None;
    }
    let words: Vec<String> = s.split_whitespace().map(str::to_string).collect();
    words.first().is_some_and(|p| p.starts_with('/')).then_some(words)
}

fn exec_start_is(exec_start: &str, argv: &[String]) -> bool {
    let Some(program) = argv.first() else { return false };
    exec_start.starts_with(&format!("{{ path={program} ; argv[]={} ; ", argv.join(" ")))
}

fn bus_runs_one_command(u: &UnitFact) -> bool {
    u.exec_starts == 1
        && u.hooks.is_empty()
        && matches!(u.service_type.as_str(), "simple" | "exec" | "dbus")
        && u.notify_access == "none"
}

fn interpreter_of(first_line: &str) -> Option<&str> {
    let interp = first_line.strip_prefix("#!")?.split_whitespace().next()?;
    interp.starts_with('/').then_some(interp)
}

fn loads_interpreter_code(name: &[u8]) -> bool {
    name.starts_with(b"PYTHON")
        || name.starts_with(b"PERL5")
        || name.starts_with(b"RUBY")
        || matches!(name, b"PERLLIB" | b"NODE_OPTIONS" | b"NODE_PATH")
}

fn inert_for_a_script(environ: &[u8]) -> bool {
    inert_environment(environ).is_some()
        && !environ
            .split(|b| *b == 0)
            .any(|kv| loads_interpreter_code(kv.split(|b| *b == b'=').next().unwrap_or_default()))
}

const USER_HZ: u64 = 100;

const CLOCK_SLACK: i64 = 2;

fn changed_before(changed: i64, started: i64) -> bool {
    changed.saturating_add(CLOCK_SLACK) < started
}

impl UnitFact {

    pub fn is_loaded(&self) -> bool {
        self.load_state == "loaded"
    }

    pub fn fragment_is_swept(&self) -> bool {
        SWEPT.iter().any(|d| self.fragment.starts_with(d))
    }
}

pub fn parse_show(text: &str) -> Vec<UnitFact> {
    let mut out = Vec::new();
    let mut cur = UnitFact::default();
    let mut seen_any = false;

    for line in text.lines() {
        if line.trim().is_empty() {
            if seen_any && !cur.id.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            cur = UnitFact::default();
            seen_any = false;
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        seen_any = true;
        match k {
            "Id" => cur.id = v.to_string(),
            "LoadState" => cur.load_state = v.to_string(),
            "UnitFileState" => cur.file_state = v.to_string(),
            "FragmentPath" => cur.fragment = v.to_string(),
            "Transient" => cur.transient = v == "yes",
            "MainPID" => cur.main_pid = v.parse().unwrap_or(0),
            "Type" => cur.service_type = v.to_string(),
            "NotifyAccess" => cur.notify_access = v.to_string(),

            "ExecStart" if !v.is_empty() => {
                if cur.exec_starts == 0 {
                    cur.exec_start = v.to_string();
                }
                cur.exec_starts += 1;
            }
            _ if HOOKS.contains(&k) && !v.is_empty() && !cur.hooks.iter().any(|h| h == k) => {
                cur.hooks.push(k.to_string());
            }
            _ => {}
        }
    }
    if !cur.id.is_empty() {
        out.push(cur);
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub enabled: BTreeSet<String>,

    pub examined: usize,

    pub available: bool,

    pub reason: Option<String>,

    pub other_init: Option<String>,
}

pub fn judge(units: &[UnitFact]) -> Vec<Finding> {
    let mut f = Vec::new();

    for u in units.iter().filter(|u| u.is_loaded()) {
        if u.transient {
            if let Some(own) = u.own {
                let (what, why) = match own {
                    Own::Sentinel => (
                        format!(
                            "`{}` is HEMOSTAT's own sentinel: its main process (pid {}) is this \
                             agent's image, running `sentinel --watch`",
                            u.id, u.main_pid
                        ),
                        "`sentinel --register` made it, to restart the agent if something kills \
                         it. Recognised by what it runs, not by its name — a unit that only took \
                         the name stays Critical. `hemostat uninstall` removes it",
                    ),
                    Own::Rollback => (
                        format!(
                            "`{}` is HEMOSTAT's own network dead-man switch: its main process \
                             (pid {}) is running exactly the rollback script this agent writes",
                            u.id, u.main_pid
                        ),
                        "`network --arm` scheduled it. It sleeps out the armed window and then \
                         puts the previous ruleset back unless `hemostat network --confirm` was \
                         run, and exits either way. Recognised by what it runs, not by its name \
                         — a unit that only took the name stays Critical",
                    ),
                };
                f.push(Finding::flag(Severity::Info, "HEMOSTAT's own unit", u.id.clone(), what, why));
                continue;
            }
            if let Some(d) = &u.dbus {
                f.push(Finding::flag(
                    Severity::Note,
                    "transient unit",
                    u.id.clone(),
                    format!(
                        "`{}` is the D-Bus activation of `{}`: the bus made it from the service file \
                         `{}` ships, and its main process (pid {}) runs `{}`, which `{}` ships \
                         unchanged",
                        u.id, d.name, d.service_package, u.main_pid, d.program, d.program_package
                    ),
                    "dbus-broker starts a bus service whose file names no systemd unit as a \
                     transient unit called dbus-<bus id>-<service>@<n>.service, so setroubleshoot \
                     after an SELinux denial, or anything else the bus starts on demand, leaves one. \
                     Recognised by what it runs, never by its name: the service file and every file \
                     its command runs or reads are vouched for by the package manager, the unit runs \
                     exactly that command, and the running image is that program or its script's \
                     interpreter. The package database is the host's own and root can rewrite it, \
                     which is why this stays on the page; a unit that only has the name stays \
                     Critical",
                ));
                continue;
            }

            let borrowed = if own_name(&u.id).is_some() {
                " — it has the name of one of HEMOSTAT's own units, and what it runs is not \
                 HEMOSTAT's or could not be read"
            } else {
                ""
            };
            f.push(Finding::flag(
                Severity::Critical,
                "transient unit",
                u.id.clone(),
                format!(
                    "`{}` is a transient unit: systemd was handed it at runtime rather than \
                     reading it from a unit file{borrowed}",
                    u.id
                ),
                "a transient unit is created with `systemd-run`. Its only file is the one \
                 systemd writes under /run/systemd/transient, which is gone at reboot and is \
                 not a directory this tool's persistence catalogue walks, so no filesystem \
                 sweep here finds it. Nothing legitimate on an idle host creates one; check \
                 what it runs with `systemctl cat`",
            ));
            continue;
        }
        if u.fragment.is_empty() {

            f.push(Finding::flag(
                Severity::Warn,
                "unit without a file",
                u.id.clone(),
                format!("`{}` is loaded but systemd reports no unit file for it", u.id),
                "a loaded unit with no fragment is not the ordinary not-found case, which is \
                 excluded above. Worth asking systemd directly what it thinks it is running",
            ));
            continue;
        }
        if !u.fragment_is_swept() {
            f.push(Finding::flag(
                Severity::Warn,
                "unit outside the swept tree",
                u.id.clone(),
                format!("`{}` loads from `{}`", u.id, u.fragment),
                "its unit file is outside the directories the persistence catalogue walks, so \
                 nothing else in this tool has looked at it. Generator output lands here \
                 legitimately — the generator itself is the thing to check, and the catalogue \
                 does sweep those",
            ));
        }
    }
    f
}

#[cfg(target_os = "linux")]
pub fn report() -> Report {
    use std::process::Command;

    if let Some(init) = other_init(
        crate::saferead::read_pid_text("/proc/1/comm").ok().as_deref(),
        std::fs::read_link("/proc/1/exe").ok().as_deref(),
        std::path::Path::new("/run/systemd/system").is_dir(),
    ) {
        return Report {
            available: false,
            reason: Some(format!(
                "PID 1 is `{init}`, not systemd, so there is no systemd to ask and no transient \
                 unit to find; the catalogue covers runit, OpenRC and s6 separately"
            )),
            other_init: Some(init),
            ..Report::default()
        };
    }

    let Some(systemctl) = systemctl_path() else {
        return Report {
            available: false,
            reason: Some(
                "systemctl was not found at /usr/bin, /bin or /usr/sbin, though PID 1 is or may \
                 be systemd, so systemd was not asked what will start"
                    .into(),
            ),
            ..Report::default()
        };
    };

    let listed = Command::new(&systemctl)
        .env_clear()
        .env("LC_ALL", "C")
        .args(["list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager"])
        .output();
    let Ok(listed) = listed else {
        return Report {
            available: false,
            reason: Some("systemctl list-units could not be run".into()),
            ..Report::default()
        };
    };
    let names = match listed_services(listed.status.success(), &listed.stdout, &listed.stderr) {
        Ok(n) => n,
        Err(why) => return Report { available: false, reason: Some(why), ..Report::default() },
    };

    let mut args: Vec<String> = vec![
        "show".into(),
        "--property=Id".into(),
        "--property=LoadState".into(),
        "--property=UnitFileState".into(),
        "--property=FragmentPath".into(),
        "--property=Transient".into(),
        "--property=MainPID".into(),
        "--property=Type".into(),
        "--property=NotifyAccess".into(),
        "--property=ExecStart".into(),
        "--no-pager".into(),
    ];
    args.extend(HOOKS.iter().map(|h| format!("--property={h}")));
    args.extend(names.iter().cloned());
    let Ok(shown) = Command::new(&systemctl).env_clear().env("LC_ALL", "C").args(&args).output()
    else {
        return Report {
            available: false,
            reason: Some("systemctl show could not be run".into()),
            ..Report::default()
        };
    };

    let mut units = parse_show(&String::from_utf8_lossy(&shown.stdout));
    recognise_own(&mut units);
    recognise_dbus(&mut units);
    conclude(names.len(), shown.status.success(), &shown.stderr, units)
}

#[cfg(target_os = "linux")]
fn recognise_dbus(units: &mut [UnitFact]) {
    use crate::saferead::{open_regular, read_bounded, read_proc, read_text, MAX_PROC_BYTES, NOT_REGULAR};
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};

    const MAX_UNITS: usize = 8;
    let regular = |p: &Path| std::fs::metadata(p).ok().filter(std::fs::Metadata::is_file);
    let id_of = |m: &std::fs::Metadata| (m.dev(), m.ino());

    let first_line = |p: &Path| -> Option<String> {
        let (f, _) = open_regular(p, NOT_REGULAR).ok()?;
        let (head, _) = read_bounded(&f, 256).ok()?;
        String::from_utf8_lossy(&head).lines().next().map(str::to_string)
    };
    let boot = crate::persist::boot_time();
    let mut vouching = crate::pkg::Vouching::default();

    let candidates = units
        .iter_mut()
        .filter(|u| u.transient && u.is_loaded() && u.own.is_none() && u.main_pid > 0)
        .filter(|u| dbus_unit_name(&u.id).is_some())
        .take(MAX_UNITS);
    for u in candidates {
        let Some(name) = dbus_unit_name(&u.id).map(str::to_string) else { continue };
        if !bus_runs_one_command(u) {
            continue;
        }
        let service = Path::new(DBUS_SYSTEM_SERVICES).join(format!("{name}.service"));
        let Ok(text) = read_text(&service) else { continue };
        let Some(svc) = parse_dbus_service(&text) else { continue };
        if svc.name != name || svc.systemd_service || !exec_start_is(&u.exec_start, &svc.exec) {
            continue;
        }
        let Some(program) = svc.exec.first().map(PathBuf::from) else { continue };

        let base = PathBuf::from(format!("/proc/{}", u.main_pid));
        if !crate::hooked::shares_our_mount_ns(&base)
            || std::fs::read_link(base.join("root")).ok().as_deref() != Some(Path::new("/"))
        {
            continue;
        }
        let Ok((environ, false)) = read_proc(&base.join("environ"), MAX_PROC_BYTES) else { continue };
        if !inert_for_a_script(&environ) {
            continue;
        }
        let image_now = || std::fs::metadata(base.join("exe")).ok().map(|m| id_of(&m));
        let Some(image) = image_now() else { continue };
        let Some(started) = crate::procfs::read_process(u.main_pid)
            .zip(boot)
            .and_then(|(p, b)| i64::try_from(b.saturating_add(p.starttime_ticks / USER_HZ)).ok())
        else {
            continue;
        };
        let Some(prog) = regular(&program) else { continue };

        let mut runs = program.clone();
        let mut reads: Vec<PathBuf> = svc
            .exec
            .iter()
            .skip(1)
            .filter(|a| a.starts_with('/'))
            .map(PathBuf::from)
            .filter(|p| regular(p).is_some())
            .collect();
        if id_of(&prog) != image {
            let Some(interp) = first_line(&program).as_deref().and_then(interpreter_of).map(PathBuf::from) else {
                continue;
            };
            let Ok(real) = interp.canonicalize() else { continue };

            if regular(&real).map(|m| id_of(&m)) != Some(image) {
                continue;
            }
            runs = real;
            reads.push(program.clone());
        }

        let Some(service_package) = vouching.vouches_for(&service) else { continue };
        let Some(program_package) = vouching.vouches_for(&program) else { continue };
        if !std::iter::once(&runs).chain(reads.iter()).all(|p| vouching.vouches_for(p).is_some()) {
            continue;
        }

        if read_text(&service).ok().as_ref() != Some(&text)
            || image_now() != Some(image)
            || regular(&runs).map(|m| id_of(&m)) != Some(image)
            || !reads.iter().all(|p| regular(p).is_some_and(|m| changed_before(m.ctime(), started)))
        {
            continue;
        }
        u.dbus = Some(DbusActivated {
            name,
            service_package,
            program: program.display().to_string(),
            program_package,
        });
    }
}

#[cfg(target_os = "linux")]
fn recognise_own(units: &mut [UnitFact]) {
    use crate::saferead::{read_proc, sha256_file, MAX_PROC_BYTES};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    let file_id = |p: &Path| std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
    let executable = |p: &Path| {
        std::fs::metadata(p)
            .ok()
            .filter(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .map(|m| (m.dev(), m.ino()))
    };

    let mut this_image: Option<Option<[u8; 32]>> = None;
    for u in units.iter_mut().filter(|u| u.transient && u.main_pid > 0) {
        let Some(own) = own_name(&u.id) else { continue };
        if !runs_one_command(u) {
            continue;
        }
        let base = PathBuf::from(format!("/proc/{}", u.main_pid));
        let Ok((raw, false)) = read_proc(&base.join("cmdline"), MAX_PROC_BYTES) else { continue };
        let argv: Vec<String> = raw
            .strip_suffix(&[0])
            .unwrap_or(&raw)
            .split(|b| *b == 0)
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        let Ok((environ, false)) = read_proc(&base.join("environ"), MAX_PROC_BYTES) else { continue };
        let Some(path) = inert_environment(&environ) else { continue };
        let verified = match own {
            Own::Rollback => {
                let shell = file_id(Path::new(crate::netpolicy::ROLLBACK_SHELL));
                let system_sleep = which(SYSTEM_PATH, "sleep", &executable);
                crate::netpolicy::is_rollback(&argv)
                    && shell.is_some()
                    && file_id(&base.join("exe")) == shell

                    && crate::hooked::shares_our_mount_ns(&base)
                    && system_sleep.is_some()
                    && which(path.as_deref().unwrap_or(SYSTEM_PATH), "sleep", &executable) == system_sleep
            }
            Own::Sentinel => {
                let ours = *this_image.get_or_insert_with(|| sha256_file(Path::new("/proc/self/exe")));
                sentinel_argv(&argv) && ours.is_some() && sha256_file(&base.join("exe")) == ours
            }
        };
        if verified {
            u.own = Some(own);
        }
    }
}

pub(crate) fn other_init(comm: Option<&str>, exe: Option<&std::path::Path>, booted: bool) -> Option<String> {
    let comm = comm.map(str::trim).filter(|c| !c.is_empty());

    let image = exe
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map(|n| n.trim_end_matches(" (deleted)"));
    if booted || comm == Some("systemd") || image == Some("systemd") {
        return None;
    }
    comm.map(str::to_string)
}

fn listed_services(ok: bool, stdout: &[u8], stderr: &[u8]) -> Result<Vec<String>, String> {
    if !ok {
        return Err(format!("systemctl list-units failed: {}", first_line(stderr)));
    }
    let names: Vec<String> = String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| n.ends_with(".service"))
        .map(str::to_string)
        .collect();
    if names.is_empty() {
        return Err("systemctl list-units named no service units at all, which no host booted \
                    with systemd does — nothing was examined, so nothing here is clean"
            .into());
    }
    Ok(names)
}

fn conclude(listed: usize, ok: bool, stderr: &[u8], units: Vec<UnitFact>) -> Report {
    let failed = if ok { String::new() } else { format!(" (systemctl show failed: {})", first_line(stderr)) };
    if units.is_empty() {
        return Report {
            available: false,
            reason: Some(format!("systemd described none of the {listed} service unit(s) it listed{failed}")),
            ..Report::default()
        };
    }
    let reason = (units.len() < listed).then(|| {
        format!(
            "systemd described {} of the {listed} service unit(s) it listed{failed}; the rest \
             were not judged",
            units.len()
        )
    });
    let enabled = units
        .iter()
        .filter(|u| u.file_state == "enabled")
        .map(|u| u.id.clone())
        .collect();

    let mut findings = judge(&units);
    crate::triage::rank(&mut findings);
    Report {
        findings,
        enabled,
        examined: units.len(),
        available: true,
        reason,
        other_init: None,
    }
}

fn first_line(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("it exited non-zero and said nothing")
        .to_string()
}

#[cfg(target_os = "linux")]
fn systemctl_path() -> Option<std::path::PathBuf> {
    ["/usr/bin/systemctl", "/bin/systemctl", "/usr/sbin/systemctl"]
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists())
}
