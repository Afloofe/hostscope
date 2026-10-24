use std::collections::{BTreeMap, BTreeSet};

use hemostat_evcrypto::manifest::Manifest;
use hs_core::severity::Severity;

use crate::configxml::{self, Config};
pub use crate::drift::Finding;
use crate::evidence::{join, Evidence, Judged, Kind, Obs, ToolObs};
use crate::tools::{Invocation, Tool};

pub const CRONTAB: &str = "/etc/crontab";

pub const CRON_D: &[&str] = &["/etc/cron.d", "/usr/local/etc/cron.d"];

pub const CRON_TABS: &str = "/var/cron/tabs";

pub const AT_JOBS: &str = "/var/at/jobs";

pub const RC_D: &[&str] = &["/etc/rc.d", "/usr/local/etc/rc.d"];

pub const RC_CONF_FILES: &[&str] = &["/etc/rc.conf", "/etc/rc.conf.local", "/etc/defaults/rc.conf"];

pub const RC_CONF_DIRS: &[&str] = &["/etc/rc.conf.d", "/usr/local/etc/rc.conf.d"];

pub const PERIODIC: &[&str] = &[
    "/etc/periodic/daily",
    "/etc/periodic/weekly",
    "/etc/periodic/monthly",
    "/etc/periodic/security",
    "/usr/local/etc/periodic/daily",
    "/usr/local/etc/periodic/weekly",
    "/usr/local/etc/periodic/monthly",
    "/usr/local/etc/periodic/security",
];

pub const PERIODIC_CONF: &[&str] = &["/etc/periodic.conf", "/etc/periodic.conf.local", "/etc/defaults/periodic.conf"];

pub const LOADER_FILES: &[&str] = &["/boot/defaults/loader.conf", "/boot/loader.conf", "/boot/loader.conf.local"];

pub const LOADER_D: &str = "/boot/loader.conf.d";

pub const MODULE_PATH: &[&str] = &["/boot/kernel", "/boot/modules"];

pub const DEVD_CONF: &str = "/etc/devd.conf";

pub const DEVD_DIRS: &[&str] = &["/etc/devd", "/usr/local/etc/devd"];

pub const PKG_QUERY: &[&str] = &["query", "-a", "%n\\t%v"];

pub const PACKAGE_RC_SCRIPTS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "pfBlockerNG",
        "pfSense-pkg-pfBlockerNG",
        "3.2.0_8",
        "/usr/local/etc/rc.d/pfb_filter.sh",
        "f6d09bd8c94f0d7d61806e4069f10623e5b56a348a15238f97442c74e1ab630d",
    ),
    (
        "pfBlockerNG",
        "pfSense-pkg-pfBlockerNG",
        "3.2.0_8",
        "/usr/local/etc/rc.d/pfb_dnsbl.sh",
        "4155025f5e27708879fe901819ca78f20977d89b6c208f27541ddbbd96787ddf",
    ),
];

fn package_rc(
    path: &str,
    digest: Option<[u8; 32]>,
    cfg_pkgs: &BTreeSet<String>,
    installed: &BTreeMap<String, String>,
    man: Option<&Manifest>,
) -> Option<&'static str> {
    let hex: String = digest?.iter().map(|b| format!("{b:02x}")).collect();
    PACKAGE_RC_SCRIPTS
        .iter()
        .find(|(name, port, ver, p, sha)| {
            *p == path
                && *sha == hex
                && cfg_pkgs.contains(*name)
                && installed.get(*port).map(String::as_str) == Some(*ver)
                && man.and_then(|m| m.covers_version(port, ver)) == Some(true)
        })
        .map(|(name, ..)| *name)
}

fn installed_packages(ev: &Evidence) -> Option<BTreeMap<String, String>> {
    match ev.tools.get(&crate::evidence::tool_key(&pkg_query())) {
        Some(ToolObs::Ran { status: Some(0), stdout }) => Some(
            String::from_utf8_lossy(stdout)
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    let (n, v) = l.split_once('\t').unwrap_or((l, ""));
                    (n.to_string(), v.to_string())
                })
                .collect(),
        ),
        _ => None,
    }
}

pub const MAX_SCRIPT: u64 = 1024 * 1024;

pub const MAX_MODULES: usize = 256;

pub fn pkg_query() -> Invocation {
    Invocation::new(Tool::PkgStatic, PKG_QUERY)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronLine {

    pub when: Vec<String>,

    pub who: String,

    pub command: String,

    pub raw: String,
}

impl CronLine {

    pub fn is(&self, item: &configxml::CronItem) -> bool {
        self.when.len() == 5
            && self.when.iter().zip(item.when.iter()).all(|(a, b)| a == b.trim())
            && self.who == item.who.trim()
            && self.command == item.command.trim()
    }
}

fn is_env(t: &str) -> bool {
    let name = t.split('=').next().unwrap_or("").trim();
    t.contains('=') && !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !name.starts_with(|c: char| c.is_ascii_digit())
}

pub fn parse_crontab(text: &str, with_user: bool) -> (Vec<CronLine>, Vec<String>) {
    let mut out = Vec::new();
    let mut junk = Vec::new();
    for l in text.lines() {
        let t = l.trim();
        if t.is_empty() || t.starts_with('#') || is_env(t) {
            continue;
        }
        let mut words = t.split_whitespace();
        let n_when = if t.starts_with('@') { 1 } else { 5 };
        let when: Vec<String> = words.by_ref().take(n_when).map(str::to_string).collect();
        let who = if with_user { words.next().unwrap_or_default().to_string() } else { String::new() };

        let mut rest = t;
        for _ in 0..(n_when + usize::from(with_user)) {
            rest = rest.trim_start();
            rest = rest.find(char::is_whitespace).map_or("", |i| rest.get(i..).unwrap_or(""));
        }
        let command = rest.trim().to_string();
        if when.len() != n_when || command.is_empty() || (with_user && who.is_empty()) {
            junk.push(t.to_string());
            continue;
        }
        out.push(CronLine { when, who, command, raw: t.to_string() });
    }
    (out, junk)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderSetting {

    pub key: String,

    pub value: String,
}

pub fn parse_loader(text: &str) -> Vec<LoaderSetting> {
    text.lines()
        .filter_map(|l| {
            let t = l.trim();
            if t.is_empty() || t.starts_with('#') {
                return None;
            }
            let (k, v) = t.split_once('=')?;
            let v = v.trim();
            let v = match v.strip_prefix('"') {
                Some(q) => q.split('"').next().unwrap_or(""),
                None => v.split('#').next().unwrap_or("").trim(),
            };
            Some(LoaderSetting { key: k.trim().to_string(), value: v.to_string() })
        })
        .collect()
}

const LOADER_RISKY: &[&str] = &[
    "init_path",
    "init_script",
    "init_chroot",
    "init_shell",
    "kernel",
    "kernels",
    "bootfile",
    "module_path",
    "loader_conf_files",
    "loader_conf_dirs",
    "local_loader_conf_files",
    "exec",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {

    pub name: String,

    pub candidates: Vec<String>,

    pub named: Option<String>,

    pub from: String,

    pub data: Option<String>,
}

impl Module {

    pub fn is_kld(&self) -> bool {
        self.data.is_none()
    }
}

pub fn loader_modules(files: &[(String, String)]) -> Vec<Module> {
    let mut load: BTreeMap<String, (bool, String)> = BTreeMap::new();
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    let mut types: BTreeMap<String, String> = BTreeMap::new();
    for (path, text) in files {
        for s in parse_loader(text) {
            if let Some(m) = s.key.strip_suffix("_type") {
                types.insert(m.to_string(), s.value.clone());
            } else if let Some(m) = s.key.strip_suffix("_load") {
                load.insert(m.to_string(), (s.value.eq_ignore_ascii_case("yes"), path.clone()));
            } else if let Some(m) = s.key.strip_suffix("_name") {
                names.insert(m.to_string(), s.value.clone());
            }
        }
    }
    load.into_iter()
        .filter(|(_, (on, _))| *on)
        .take(MAX_MODULES)
        .map(|(m, (_, from))| {
            let file = names.get(&m).cloned();
            let base = file.clone().unwrap_or_else(|| m.clone());
            let candidates = if base.starts_with('/') {
                vec![base.clone()]
            } else {
                let f = if base.ends_with(".ko") { base.clone() } else { format!("{base}.ko") };
                MODULE_PATH.iter().map(|d| join(d, &f)).collect()
            };
            let data = types.get(&m).filter(|t| !matches!(t.as_str(), "kld" | "module" | "")).cloned();
            Module { name: m, candidates, named: file, from, data }
        })
        .collect()
}

pub fn loader_texts(ev: &Evidence) -> Vec<(String, String)> {
    let mut files: Vec<String> = LOADER_FILES.iter().map(|s| (*s).to_string()).collect();
    for e in ev.dir(LOADER_D).unwrap_or_default() {
        if e.name.ends_with(".conf") {
            files.push(join(LOADER_D, &e.name));
        }
    }
    files.into_iter().filter_map(|p| ev.text(&p).map(|t| (p, t))).collect()
}

#[cfg(unix)]
pub fn gather(c: &mut crate::evidence::Collector, runner: &mut dyn crate::tools::Runner) {
    c.file(configxml::CONFIG_PATH, configxml::MAX_BYTES);
    c.file(CRONTAB, MAX_SCRIPT);
    for d in CRON_D.iter().chain([CRON_TABS].iter()) {
        c.dir_files(d, MAX_SCRIPT);
    }
    c.list(AT_JOBS);
    for d in RC_D.iter().chain(RC_CONF_DIRS).chain(PERIODIC).chain(DEVD_DIRS) {
        c.dir_files(d, MAX_SCRIPT);
    }
    for f in RC_CONF_FILES.iter().chain(PERIODIC_CONF).chain(LOADER_FILES).chain([DEVD_CONF].iter()) {
        c.file(f, MAX_SCRIPT);
    }
    c.dir_files(LOADER_D, MAX_SCRIPT);
    for m in loader_modules(&loader_texts(&c.ev)).into_iter().filter(Module::is_kld) {
        for p in m.candidates {
            c.hash(&p);
        }
    }
    c.tool(runner, &pkg_query());
}

enum Verdict {
    Vendor,
    Changed,
    Unowned,
    NotJudged,
}

fn verdict(ev: &Evidence, man: Option<&Manifest>, path: &str) -> Verdict {
    let (Some(m), Some(d)) = (man, ev.sha256(path)) else { return Verdict::NotJudged };
    match m.is_vendor(path, &d) {
        Some(true) => Verdict::Vendor,
        Some(false) => Verdict::Changed,
        None => Verdict::Unowned,
    }
}

fn lines_of(text: &str, n: usize) -> String {
    let ls: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    let mut s = ls.iter().take(n).copied().collect::<Vec<_>>().join("\n");
    if ls.len() > n {
        s.push_str(&format!("\n… and {} more line(s)", ls.len() - n));
    }
    s
}

const CONFIRM: &str = "If your team did not put it there, find out who did before removing it; nothing here \
                       changes the box";

pub fn judge(ev: &Evidence, man: Option<&Manifest>) -> Judged {
    let mut j = Judged::default();
    let mut gaps: Vec<String> = Vec::new();
    let mut f = |sev, subject: &str, what: String, why: &str| {
        j.findings.push(Finding { severity: sev, subject: subject.to_string(), what, why: why.to_string() });
    };
    if man.is_none() {
        gaps.push(
            "no signed manifest ($HEMOSTAT_MANIFEST): no script, module or package could be held to what \
             the vendor ships, so none was judged"
                .into(),
        );
    }

    let cfg: Option<Config> = match ev.bytes(configxml::CONFIG_PATH) {
        Some(b) => match configxml::parse(b) {
            Ok(c) => Some(c),
            Err(e) => {
                gaps.push(format!("config.xml was sealed but not read ({e}): /etc/crontab was not compared"));
                None
            }
        },
        None => {
            gaps.push(format!("{}: {}", configxml::CONFIG_PATH, ev.unread(configxml::CONFIG_PATH).unwrap_or_else(|| "absent".into())));
            None
        }
    };

    let items = cfg.as_ref().map(Config::cron_items).unwrap_or_default();
    match ev.text(CRONTAB) {
        Some(t) => {
            let (lines, junk) = parse_crontab(&t, true);
            let mut unmatched: Vec<&configxml::CronItem> = items.iter().collect();
            for l in &lines {
                match unmatched.iter().position(|i| l.is(i)) {
                    Some(i) => {
                        unmatched.remove(i);
                    }
                    None if cfg.is_some() => f(
                        Severity::Critical,
                        CRONTAB,
                        format!("a crontab line with no cron/item: {}", l.raw),
                        &format!(
                            "pfSense writes /etc/crontab from config.xml's cron/item on every save, so a line \
                             config does not hold was added by hand, and runs as {} on schedule. {CONFIRM}",
                            l.who
                        ),
                    ),
                    None => {}
                }
            }
            for i in unmatched {
                f(Severity::Note, CRONTAB, format!("a cron/item not in the file: {}", i.line().replace('\t', " ")), "config holds it and the file does not: the file has not been regenerated since, or the line was removed by hand");
            }
            for l in junk {
                f(Severity::Warn, CRONTAB, format!("a line cron may read and pfSense never writes: {l}"), "not a job, a variable or a comment as pfSense writes them");
            }
        }
        None => match ev.obs.get(CRONTAB) {
            Some(Obs::Absent) => {}
            _ => gaps.push(format!("{CRONTAB}: {}", ev.unread(CRONTAB).unwrap_or_default())),
        },
    }
    for d in CRON_D {
        for (p, e) in entries(ev, d, &mut gaps) {
            if matches!(verdict(ev, man, &p), Verdict::Vendor) {
                continue;
            }
            match (e, ev.text(&p)) {
                (Kind::File, Some(t)) => {
                    for l in parse_crontab(&t, true).0 {
                        f(
                            Severity::Critical,
                            &p,
                            format!("a crontab line with no cron/item: {}", l.raw),
                            &format!(
                                "cron reads every file here, and nothing in config.xml records this one; it runs \
                                 as {} on schedule. {CONFIRM}",
                                l.who
                            ),
                        );
                    }
                }
                _ => other_entry(&mut f, &mut gaps, ev, &p, "cron reads every file here"),
            }
        }
    }
    for (p, e) in entries(ev, CRON_TABS, &mut gaps) {
        let user = p.rsplit('/').next().unwrap_or_default().to_string();
        let body = match (e, ev.text(&p)) {
            (Kind::File, Some(t)) => lines_of(&t, 8),
            _ => "(not read)".into(),
        };
        f(
            Severity::Critical,
            &p,
            format!("a user crontab for {user}:\n{body}"),
            &format!(
                "pfSense keeps every job in /etc/crontab and never writes one here, so this was made with \
                 crontab(1) on the box. It runs as {user}. {CONFIRM}"
            ),
        );
    }
    for (p, _) in entries(ev, AT_JOBS, &mut gaps) {
        f(Severity::Warn, &p, "an at(1) job is queued".into(), "pfSense's crontab does not run atrun, so it waits; whoever queued it expects something to");
    }

    let cfg_pkgs: BTreeSet<String> = cfg.as_ref().map(|c| c.packages().into_iter().map(|p| p.name).collect()).unwrap_or_default();
    let installed = installed_packages(ev).unwrap_or_default();
    for d in RC_D {
        let boot_tree = *d == "/usr/local/etc/rc.d";
        for (p, e) in entries(ev, d, &mut gaps) {
            let name = p.rsplit('/').next().unwrap_or_default();
            if e == Kind::Link {

                if let Some(Obs::Link(t)) = ev.obs.get(&p) {
                    let sib = join(d, t);
                    if !t.contains('/') && matches!(verdict(ev, man, &sib), Verdict::Vendor) {
                        continue;
                    }
                    if man.is_some() {
                        f(Severity::Warn, &p, format!("a service script that is a link to {t}"), "the only links the vendor ships here point at a sibling vendor script");
                    }
                }
                continue;
            }
            match verdict(ev, man, &p) {
                Verdict::Vendor | Verdict::NotJudged if e == Kind::File && ev.sha256(&p).is_some() => {}
                Verdict::Changed => f(
                    Severity::Critical,
                    &p,
                    "a vendor service script, changed".into(),
                    &format!("the manifest records what the vendor shipped at this path, and this is not it. {CONFIRM}"),
                ),
                Verdict::Unowned if package_rc(&p, ev.sha256(&p), &cfg_pkgs, &installed, man).is_some() => {}
                Verdict::Unowned if boot_tree && name.ends_with(".sh") => f(
                    Severity::Critical,
                    &p,
                    format!("a boot script no package ships:\n{}", ev.text(&p).map(|t| lines_of(&t, 6)).unwrap_or_default()),
                    &format!("pfSense runs every *.sh here as root at boot (rc.start_packages). {CONFIRM}"),
                ),
                Verdict::Unowned => f(
                    Severity::Warn,
                    &p,
                    "a service script no package ships".into(),
                    "it runs when something starts it by name; the manifest has no package that put it here",
                ),
                _ => other_entry(&mut f, &mut gaps, ev, &p, "a service script"),
            }
        }
    }

    for p in RC_CONF_FILES.iter().chain(PERIODIC_CONF) {
        settings_file(&mut f, &mut gaps, ev, man, p);
    }
    for d in RC_CONF_DIRS {
        for (p, _) in entries(ev, d, &mut gaps) {
            settings_file(&mut f, &mut gaps, ev, man, &p);
        }
    }
    for d in PERIODIC {
        for (p, e) in entries(ev, d, &mut gaps) {
            if e == Kind::Dir {
                continue;
            }
            vendor_file(&mut f, &mut gaps, ev, man, &p, "a periodic job", "periodic runs it as root from /etc/rc.periodic, on pfSense's own crontab");
        }
    }
    vendor_file(&mut f, &mut gaps, ev, man, DEVD_CONF, "devd's rules", "devd runs each rule's action as root when the device event fires");
    for d in DEVD_DIRS {
        for (p, e) in entries(ev, d, &mut gaps) {
            if e != Kind::Dir {
                vendor_file(&mut f, &mut gaps, ev, man, &p, "a devd rule file", "devd runs each rule's action as root when the device event fires");
            }
        }
    }

    for p in LOADER_FILES {
        match ev.obs.get(*p) {
            Some(Obs::Bytes(_) | Obs::Absent) => {}
            _ => gaps.push(format!("{p}: {}", ev.unread(p).unwrap_or_default())),
        }
    }
    if let Verdict::Changed = verdict(ev, man, "/boot/defaults/loader.conf") {
        f(Severity::Critical, "/boot/defaults/loader.conf", "the loader's defaults, changed".into(), &format!("they say which files the loader reads and what it boots. {CONFIRM}"));
    }
    let texts = loader_texts(ev);
    for (p, t) in texts.iter().filter(|(p, _)| p != "/boot/defaults/loader.conf") {
        for s in parse_loader(t) {
            let risky = LOADER_RISKY.contains(&s.key.as_str()) || ["_before", "_after", "_error"].iter().any(|x| s.key.ends_with(x));
            if risky {
                f(Severity::Warn, p, format!("{}=\"{}\"", s.key, s.value), "it changes what the loader boots or runs, not which module it loads; pfSense sets none of these");
            }
        }
    }
    for m in loader_modules(&texts) {
        if let Some(t) = &m.data {

            if m.from != "/boot/defaults/loader.conf" {
                f(
                    Severity::Warn,
                    &m.from,
                    format!("{}_load=\"YES\" preloads {} as {t}", m.name, m.candidates.join(", ")),
                    "not a kernel module, but data the loader hands the kernel at boot (an md_image can be the \
                     root filesystem); pfSense sets none",
                );
            }
            continue;
        }
        let found: Vec<&String> = m.candidates.iter().filter(|c| ev.sha256(c).is_some()).collect();
        let Some(file) = found.first() else {
            let unread: Vec<String> = m.candidates.iter().filter_map(|c| ev.unread(c).map(|w| format!("{c}: {w}"))).collect();
            if unread.is_empty() {
                f(Severity::Warn, &m.from, format!("{}_load=\"YES\", and no file for it ({})", m.name, m.candidates.join(", ")), "the loader will fail to load it; something expected it to be there");
            } else {
                gaps.extend(unread);
            }
            continue;
        };
        match verdict(ev, man, file) {
            Verdict::Vendor => {}
            Verdict::NotJudged => {}
            v => f(
                Severity::Critical,
                &m.from,
                format!(
                    "{}_load=\"YES\" loads {file}, which is {}",
                    m.name,
                    if matches!(v, Verdict::Changed) { "a vendor module, changed" } else { "no vendor module" }
                ),
                &format!("a kernel module loaded at boot runs in the kernel, below everything this agent can see. {CONFIRM}"),
            ),
        }
    }

    if let Some(c) = &cfg {
        let pkgs: BTreeMap<String, String> = c.packages().into_iter().map(|p| (p.name, p.configurationfile)).collect();
        for s in c.shellcmds() {
            let pkg = crate::drift::PACKAGE_SHELLCMDS
                .iter()
                .find(|(n, file, kind, cmd)| *kind == s.kind && *cmd == s.command && pkgs.get(*n).map(String::as_str) == Some(*file));
            let subject = format!("config.xml system/{}", s.kind.element());
            match pkg {
                Some((n, ..)) => f(Severity::Note, &subject, format!("{}: {}", s.kind.element(), s.command), &format!("the {n} package adds exactly this boot command, and it is installed")),
                None => f(
                    Severity::Warn,
                    &subject,
                    format!("{}: {}", s.kind.element(), s.command),
                    "a boot command runs as root on every boot. `drift` grades one added since arrival as \
                     Critical; one already here when you arrived is for whoever runs the box to explain",
                ),
            }
        }
        if let Some(sc) = c.root().get("installedpackages/shellcmdsettings") {
            let system: BTreeSet<String> = c.shellcmds().into_iter().map(|s| s.command).collect();
            for row in sc.all("config") {
                let cmd = row.text_at("cmd").unwrap_or_default();
                let kind = row.text_at("cmdtype").unwrap_or_default();
                if cmd.is_empty() || system.contains(cmd) {
                    continue;
                }
                f(Severity::Warn, "config.xml shellcmdsettings", format!("a Shellcmd package row ({kind}): {cmd}"), "the package writes its rows into system/*shellcmd on save; this one is not there yet, or is disabled");
            }
        }
    }

    match (installed_packages(ev), ev.tools.get(&crate::evidence::tool_key(&pkg_query()))) {
        (Some(pkgs), _) => {
            if let Some(m) = man {
                for (name, ver) in &pkgs {
                    match m.covers_version(name, ver) {
                        Some(true) => {}
                        Some(false) => f(
                            Severity::Warn,
                            &format!("package {name}"),
                            format!("{name} {ver} is installed; the manifest covers {}", m.versions_of(name).join(", ")),
                            "the vendor ships this package, at another version: its files cannot be held to the \
                             manifest, which is how a package swapped for a rebuilt one would look too",
                        ),
                        None => f(
                            Severity::Critical,
                            &format!("package {name}"),
                            format!("{name} {ver} is installed, and the manifest knows no such package"),
                            &format!(
                                "the manifest was built from pfSense's signed repositories, and this package is in \
                                 none of what it covers. If your team installed it, build the manifest with it \
                                 (vm/manifest/*.pkgs) and run again. {CONFIRM}"
                            ),
                        ),
                    }
                }
            }
        }
        (None, Some(ToolObs::Ran { status, .. })) => gaps.push(format!("pkg-static exited {status:?}: the installed packages were not read")),
        (None, Some(ToolObs::Failed(why))) => gaps.push(format!("pkg-static did not run ({why}): the installed packages were not read")),
        (None, None) => gaps.push("pkg-static was never run: the installed packages were not read".into()),
    }

    j.gaps = gaps;
    j.sort();
    j
}

fn entries(ev: &Evidence, dir: &str, gaps: &mut Vec<String>) -> Vec<(String, Kind)> {
    match ev.obs.get(dir) {
        Some(Obs::Dir(es)) => es.iter().map(|e| (join(dir, &e.name), e.kind)).collect(),
        Some(Obs::Absent) => Vec::new(),
        Some(Obs::Link(t)) => {
            gaps.push(format!("{dir} is a symlink to {t}; not followed, so what is in it was not judged"));
            Vec::new()
        }
        _ => {
            gaps.push(format!("{dir}: {}", ev.unread(dir).unwrap_or_default()));
            Vec::new()
        }
    }
}

type Push<'a> = dyn FnMut(Severity, &str, String, &str) + 'a;

fn other_entry(f: &mut Push<'_>, gaps: &mut Vec<String>, ev: &Evidence, p: &str, place: &str) {
    match ev.obs.get(p) {
        Some(Obs::Link(t)) => f(Severity::Warn, p, format!("a symlink to {t}"), &format!("{place}, and a link was not followed")),
        Some(Obs::Dir(_)) | Some(Obs::Absent) => {}
        _ => gaps.push(format!("{p}: {}", ev.unread(p).unwrap_or_default())),
    }
}

fn settings_file(f: &mut Push<'_>, gaps: &mut Vec<String>, ev: &Evidence, man: Option<&Manifest>, p: &str) {
    match ev.obs.get(p) {
        Some(Obs::Absent) => return,
        Some(Obs::Bytes(_)) => {}
        _ => return other_entry(f, gaps, ev, p, "a settings file"),
    }
    let vendor_path = p == "/etc/rc.conf" || p.starts_with("/etc/defaults/");
    let body = ev.text(p).map(|t| lines_of(&t, 8)).unwrap_or_default();
    match verdict(ev, man, p) {
        Verdict::Vendor => {}
        Verdict::Changed if p.starts_with("/etc/defaults/") => {
            f(Severity::Critical, p, "a vendor defaults file, changed".into(), &format!("every rc script and periodic job reads it. {CONFIRM}"));
        }
        Verdict::NotJudged if vendor_path => {}
        _ if body.is_empty() => {}
        _ => f(Severity::Warn, p, format!("settings no package ships:\n{body}"), "pfSense does not write this file; what it switches on runs with the service it names"),
    }
}

fn vendor_file(f: &mut Push<'_>, gaps: &mut Vec<String>, ev: &Evidence, man: Option<&Manifest>, p: &str, what: &str, why: &str) {
    match ev.obs.get(p) {
        Some(Obs::Absent) => return,
        Some(Obs::Bytes(_) | Obs::Digest { .. }) => {}
        _ => return other_entry(f, gaps, ev, p, what),
    }
    match verdict(ev, man, p) {
        Verdict::Vendor | Verdict::NotJudged => {}
        Verdict::Changed => f(Severity::Critical, p, format!("{what}, changed from the vendor's"), &format!("{why}. {CONFIRM}")),
        Verdict::Unowned => {
            let body = ev.text(p).map(|t| lines_of(&t, 6)).unwrap_or_default();
            f(Severity::Warn, p, format!("{what} no package ships:\n{body}"), why);
        }
    }
}
