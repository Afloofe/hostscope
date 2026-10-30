use std::collections::{BTreeMap, BTreeSet};

use hs_core::severity::Severity;
use hs_core::snapshot::{Change, Snapshot};

use crate::accounts::{self, GroupRead};
use crate::{overview, persist, wmi};

pub const SCOPE: u32 = 3;

pub const IMAGE: &str = "image/";

pub const KIND: &str = "windows-host";

pub const CRITICAL_GROUPS: &[u32] = &[544, 555];

pub const ADVICE: &str = "Advice only: hemostat does not act on account or permission changes. \
                          Taking one back is a manual call from the TUI";

const SETTINGS: &[&str] = &["winrm-listener", "winrm-client", "winrm-service"];

const INTERPRETERS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "powershell_ise.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "msbuild.exe",
    "installutil.exe",
    "forfiles.exe",
    "conhost.exe",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceRow {

    pub name: String,

    pub image: String,

    pub start: Option<u32>,

    pub kind: Option<u32>,

    pub dll: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskRow {

    pub path: String,

    pub actions: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Readings {

    pub persist: persist::Report,

    pub services: Vec<ServiceRow>,

    pub tasks: Vec<TaskRow>,

    pub task_refused: Vec<String>,

    pub wmi: Option<Result<(wmi::Subscriptions, Vec<String>), String>>,

    pub accounts: accounts::Report,

    pub groups: Vec<GroupRead>,

    pub listeners: overview::Report,

    pub shares: Option<Result<Vec<(String, String)>, String>>,

    pub policy: Vec<(String, Result<String, String>)>,

    pub trust: Option<crate::trust::Report>,
}

pub fn unit_of(key: &str) -> String {
    let mut parts = key.splitn(3, '/');
    let kind = parts.next().unwrap_or_default();
    match kind {
        "autorun" | "group" => match parts.next() {
            Some(second) => format!("{kind}/{second}"),
            None => kind.to_string(),
        },

        "policy" => key.to_string(),
        _ => kind.to_string(),
    }
}

fn fields(v: &str) -> BTreeMap<&str, Vec<&str>> {
    let mut out: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for line in v.lines() {
        if let Some((k, val)) = line.split_once('=') {
            out.entry(k).or_default().push(val);
        }
    }
    out
}

fn field<'a>(v: &'a str, k: &str) -> Option<&'a str> {
    v.lines().find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
}

pub fn record(r: &Readings) -> Snapshot {
    let mut s = Snapshot { scope: SCOPE, ..Snapshot::default() };
    let mut covered: BTreeSet<String> = BTreeSet::new();

    let established = |id: &str| r.persist.observations.iter().any(|o| o.id == id && o.coverage.established());
    if established("services") {
        covered.insert("service".into());
    } else {
        s.gaps.push("services: the service list was not read in full".into());
    }
    for row in &r.services {
        let mut v = format!("image={}", row.image);
        if let Some(n) = row.start {
            v.push_str(&format!("\nstart={n}"));
        }
        if let Some(n) = row.kind {
            v.push_str(&format!("\ntype={n}"));
        }
        if let Some(d) = row.dll.as_deref().filter(|d| !d.is_empty()) {
            v.push_str(&format!("\ndll={d}"));
        }
        s.items.insert(format!("service/{}", row.name), v);
    }

    if r.task_refused.is_empty() {
        covered.insert("task".into());
    } else {
        s.gaps.push(format!("scheduled tasks: {} task file(s) or folder(s) would not read: {}", r.task_refused.len(), r.task_refused.join("; ")));
    }
    for t in &r.tasks {
        s.items.insert(format!("task/{}", t.path), t.actions.join("\n"));
    }

    let mut autoruns: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for e in &r.persist.entries {
        if matches!(e.mechanism, "services" | "scheduled-tasks") {
            continue;
        }

        let key = if e.mechanism == "task-cache" {
            format!("autorun/task-cache/{}", e.command)
        } else {
            format!("autorun/{}/{}|{}", e.mechanism, e.locus, e.name)
        };
        autoruns.entry(key).or_default().push(e.command.clone());
    }
    for (k, v) in autoruns {
        s.items.insert(k, v.join("\n"));
    }
    for o in &r.persist.observations {
        if matches!(o.id, "services" | "scheduled-tasks") {
            continue;
        }
        if o.coverage.established() {
            covered.insert(format!("autorun/{}", o.id));
        } else {
            s.gaps.push(format!("{}: not read in full ({})", o.name, o.refused.join("; ")));
        }
    }

    match &r.wmi {
        Some(Ok((subs, gaps))) => {
            if gaps.is_empty() {
                covered.insert("wmi".into());
            } else {
                s.gaps.push(format!("WMI subscriptions: {}", gaps.join("; ")));
            }
            for c in &subs.consumers {
                let mut v = format!("class={}\ncommand={}", c.consumer.class, c.consumer.command);
                let mut filters: Vec<&str> = wmi::bound_filters(subs, c).iter().map(|f| f.query.as_str()).collect();
                filters.sort_unstable();
                for q in filters {
                    v.push_str(&format!("\nfilter={q}"));
                }
                s.items.insert(format!("wmi/{}/{}", c.namespace, c.relpath), v);
            }
        }
        Some(Err(why)) => s.gaps.push(format!("WMI subscriptions: {why}")),
        None => s.gaps.push("WMI subscriptions: not read".into()),
    }

    if r.accounts.available {
        covered.insert("user".into());
        for a in &r.accounts.accounts {
            s.items.insert(
                format!("user/{}", a.name),
                format!("enabled={}\npassword-required={}", u8::from(a.enabled()), u8::from(!a.password_not_required())),
            );
        }
    } else {
        s.gaps.push(format!("local accounts: {}", r.accounts.reason.as_deref().unwrap_or("not read")));
    }

    for g in &r.groups {
        match &g.members {
            Ok(members) => {
                covered.insert(format!("group/{}", g.sid));
                for m in members {
                    let id = m.sid.clone().unwrap_or_else(|| m.name.clone());
                    s.items.insert(format!("group/{}/{id}", g.sid), format!("{} ({})", m.name, g.name));
                }
            }
            Err(why) => s.gaps.push(format!("group {}: {why}", g.name)),
        }
    }

    if r.listeners.complete() {
        covered.insert("listen".into());
    } else {
        let why = r.listeners.reason.clone().into_iter().chain(r.listeners.gaps.iter().cloned()).collect::<Vec<_>>().join("; ");
        s.gaps.push(format!("listeners: {why}"));
    }
    for sock in r.listeners.sockets.iter().filter(|x| x.listening()) {
        s.items.insert(
            format!("listen/{}/{}/{}", sock.proto, sock.port, sock.local),
            sock.image.clone().unwrap_or_else(|| format!("pid {}", sock.pid)),
        );
    }

    match &r.shares {
        Some(Ok(shares)) => {
            covered.insert("share".into());
            for (name, v) in shares {
                s.items.insert(format!("share/{name}"), v.clone());
            }
        }
        Some(Err(why)) => s.gaps.push(format!("shares: {why}")),
        None => s.gaps.push("shares: not read".into()),
    }

    for (name, reading) in &r.policy {
        let key = format!("policy/{name}");
        match reading {
            Ok(v) => {
                covered.insert(key.clone());
                s.items.insert(key, v.clone());
            }
            Err(why) => s.gaps.push(format!("{name}: {why}")),
        }
    }

    match &r.trust {
        Some(t) if t.complete() => {
            covered.insert("cert".into());
        }
        Some(t) if !t.available => s.gaps.push(format!("certificate stores: {}", t.reason.as_deref().unwrap_or("not read"))),
        Some(t) => s.gaps.push(format!("certificate stores: {}", t.unread.join("; "))),
        None => s.gaps.push("certificate stores: not read".into()),
    }
    if let Some(t) = &r.trust {
        s.items.extend(crate::trust::snapshot_items(t));
    }

    for u in covered {
        s.items.insert(format!("covered/{u}"), String::new());
    }
    s
}

pub fn compare(was: &Snapshot, now: &Snapshot) -> Result<(Vec<Change>, Vec<String>), String> {
    if was.scope > SCOPE {
        return Err(format!(
            "the arrival snapshot was taken by a newer build (scope {}) than this one (scope {SCOPE}); run \
             drift with the build that took it",
            was.scope
        ));
    }
    let covered = |s: &Snapshot, u: &str| s.items.contains_key(&format!("covered/{u}"));
    let mut units: BTreeSet<String> = BTreeSet::new();
    for k in was.items.keys().chain(now.items.keys()) {
        match k.strip_prefix("covered/") {
            Some(u) => units.insert(u.to_string()),
            None => units.insert(unit_of(k)),
        };
    }
    let mut changes = Vec::new();
    let mut gaps = Vec::new();

    units.remove("image");
    for u in &units {
        let (a, b) = (covered(was, u), covered(now, u));
        if u == "cert" && was.scope < 3 {
            gaps.push(format!(
                "cert: the certificate stores were not recorded by the earlier build (scope {}) that took the \
                 arrival snapshot, so no certificate can be called added since arrival. `snapshot --replace` \
                 records them from now on",
                was.scope
            ));
            continue;
        }
        if !(a && b) {
            let when = match (a, b) {
                (false, false) => "on arrival or now",
                (false, true) => "on arrival",
                _ => "now",
            };
            gaps.push(format!("{u}: not read in full {when}, so not compared"));
            continue;
        }
        let keys: BTreeSet<&String> = was
            .items
            .keys()
            .chain(now.items.keys())
            .filter(|k| !k.starts_with("covered/") && unit_of(k) == *u)
            .collect();
        for k in keys {
            let (before, after) = (was.items.get(k), now.items.get(k));
            if before != after {
                changes.push(Change { key: k.clone(), before: before.cloned(), after: after.cloned() });
            }
        }
    }
    Ok((changes, gaps))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {

    pub token: &'static str,

    pub valid: bool,

    pub signer: Option<String>,
}

pub trait Host {

    fn exists(&self, path: &str) -> bool;

    fn env(&self, name: &str) -> Option<String>;

    fn signature(&mut self, path: &str) -> Signed;

    fn com_server(&self, clsid: &str) -> Option<String>;

    fn writable_by_users(&self, path: &str) -> Option<bool>;

    fn refuse(&self, path: &str) -> Option<String> {
        crate::localpath::local(path).err()
    }
}

pub fn run_commands(s: &Snapshot) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for (k, v) in &s.items {
        let kind = k.split('/').next().unwrap_or_default();
        match kind {
            "service" => out.extend(v.lines().filter_map(|l| l.strip_prefix("image=").or_else(|| l.strip_prefix("dll="))).map(str::to_string)),
            "task" => out.extend(v.lines().filter_map(|l| l.strip_prefix("exec ").or_else(|| l.strip_prefix("com "))).map(str::to_string)),
            "autorun" => {
                let mech = k.split('/').nth(1).unwrap_or_default();
                if !SETTINGS.contains(&mech) && mech != "task-cache" {
                    out.extend(v.lines().map(str::to_string));
                }
            }
            "wmi" => out.extend(v.lines().filter_map(|l| l.strip_prefix("command=")).map(str::to_string)),
            _ => {}
        }
    }
    out.into_iter().filter(|c| !c.trim().is_empty()).collect()
}

pub fn expand(s: &str, host: &dyn Host) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('%') {
        out.push_str(rest.get(..i).unwrap_or_default());
        let after = rest.get(i + 1..).unwrap_or_default();
        match after.find('%') {
            Some(j) if j > 0 => {
                let name = after.get(..j).unwrap_or_default();
                match host.env(name) {
                    Some(v) => out.push_str(&v),
                    None => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = after.get(j + 1..).unwrap_or_default();
            }
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

pub fn clsid(s: &str) -> Option<&str> {
    let t = s.trim();
    let inner = t.strip_prefix('{')?.strip_suffix('}')?;
    let lens: Vec<usize> = inner.split('-').map(str::len).collect();
    (lens == [8, 4, 4, 4, 12] && inner.chars().all(|c| c == '-' || c.is_ascii_hexdigit())).then_some(t)
}

pub fn resolve(command: &str, host: &dyn Host) -> Option<String> {
    match locate(command, host) {
        Located::File(f) => Some(f),
        Located::Refused(..) | Located::Nothing => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Located {

    File(String),

    Refused(String, String),

    Nothing,
}

pub fn locate(command: &str, host: &dyn Host) -> Located {
    let root = host.env("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let c = expand(command.trim(), host);
    let c = c.trim();
    if let Some(id) = clsid(c) {

        return match host.com_server(id) {
            Some(p) if clsid(expand(p.trim(), host).trim()).is_none() => locate(&p, host),
            _ => Located::Nothing,
        };
    }
    let lc = c.to_ascii_lowercase();

    let c = if let Some(r) = c.get(4..).filter(|r| lc.starts_with(r"\??\") && r.as_bytes().get(1) == Some(&b':')) {
        r.to_string()
    } else if let Some(r) = c.get(12..).filter(|_| lc.starts_with(r"\systemroot\")) {
        format!(r"{root}\{r}")
    } else if lc.starts_with(r"system32\") {
        format!(r"{root}\{c}")
    } else {
        c.to_string()
    };
    let mut refused: Option<(String, String)> = None;
    let candidate = if let Some(rest) = c.strip_prefix('"') {
        rest.split('"').next().unwrap_or_default().to_string()
    } else {
        let words: Vec<&str> = c.split(' ').collect();
        let mut found = None;
        for n in 1..=words.len() {
            let p = words.get(..n).unwrap_or_default().join(" ");
            if p.contains('\\') {
                if let Some(f) = file_at(host, &p, n == 1, &mut refused) {
                    found = Some(f);
                    break;
                }
            }
        }
        match found {
            Some(f) => return Located::File(f),
            None => words.first().copied().unwrap_or_default().trim_end_matches(',').to_string(),
        }
    };
    let found = if candidate.is_empty() {
        None
    } else if candidate.contains('\\') || candidate.contains('/') {
        file_at(host, &candidate, true, &mut refused)
    } else {
        [format!(r"{root}\System32\{candidate}"), format!(r"{root}\{candidate}")]
            .iter()
            .find_map(|p| file_at(host, p, true, &mut refused))
    };
    match (found, refused) {
        (Some(f), _) => Located::File(f),
        (None, Some((p, why))) => Located::Refused(p, why),
        (None, None) => Located::Nothing,
    }
}

fn file_at(host: &dyn Host, p: &str, named: bool, refused: &mut Option<(String, String)>) -> Option<String> {
    let has_ext = p.rsplit(['\\', '/']).next().is_some_and(|n| n.contains('.'));
    let tries = std::iter::once(p.to_string())
        .chain([".exe", ".dll"].iter().filter(|_| !has_ext).map(|e| format!("{p}{e}")));
    for q in tries {
        if let Some(why) = host.refuse(&q) {
            if (named || crate::localpath::local(&q).is_ok()) && refused.is_none() {
                *refused = Some((q, why));
            }
            continue;
        }
        if host.exists(&q) {
            return Some(q);
        }
    }
    None
}

fn leaf(p: &str) -> String {
    p.rsplit(['\\', '/']).next().unwrap_or(p).to_ascii_lowercase()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Graded {

    pub severity: Severity,

    pub binary: Option<String>,

    pub signer: Option<String>,

    pub reason: String,
}

pub fn grade(command: &str, host: &mut dyn Host) -> Graded {
    let bin = match locate(command, host) {
        Located::File(bin) => bin,
        Located::Refused(_, why) => {
            return Graded {
                severity: Severity::Critical,
                binary: None,
                signer: None,
                reason: format!("what it runs was not opened, so nothing vouches for it: {why}"),
            }
        }
        Located::Nothing => {
            return Graded {
                severity: Severity::Critical,
                binary: None,
                signer: None,
                reason: "what it runs does not resolve to a file on this host, so nothing vouches for it".into(),
            }
        }
    };
    let name = leaf(&bin);
    if INTERPRETERS.contains(&name.as_str()) {
        return Graded {
            severity: Severity::Critical,
            binary: Some(bin),
            signer: None,
            reason: format!(
                "it runs {name}, a command interpreter: the signature covers the interpreter, not the command \
                 it is given"
            ),
        };
    }
    let sig = host.signature(&bin);
    match (sig.valid, sig.signer.clone()) {
        (true, Some(signer)) => {

            let dir = bin.rsplit_once(['\\', '/']).map_or(bin.as_str(), |(d, _)| d).to_string();

            let writable =
                [bin.as_str(), dir.as_str()].map(|p| if host.refuse(p).is_some() { None } else { host.writable_by_users(p) });
            if let Some(p) = [&bin, &dir].into_iter().zip(writable).find_map(|(p, w)| (w == Some(true)).then_some(p)) {
                return Graded {
                    severity: Severity::Critical,
                    binary: Some(bin.clone()),
                    signer: Some(signer.clone()),
                    reason: format!(
                        "{bin} is signed by {signer}, but {p} can be written by unprivileged users, so what runs \
                         from there is not vouched for"
                    ),
                };
            }
            let unread = if writable.contains(&None) { "; whether unprivileged users can write it was not read" } else { "" };
            Graded {
                severity: Severity::Warn,
                binary: Some(bin.clone()),
                signer: Some(signer.clone()),
                reason: format!("{bin} is signed by {signer}{unread}"),
            }
        }
        (true, None) => Graded {
            severity: Severity::Critical,
            binary: Some(bin.clone()),
            signer: None,
            reason: format!("{bin} is signed, and the signer could not be named"),
        },
        (false, _) => Graded {
            severity: Severity::Critical,
            binary: Some(bin.clone()),
            signer: None,
            reason: format!("{bin} is {}", sig.token),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {

    pub severity: Severity,

    pub subject: String,

    pub what: String,

    pub why: String,
}

fn verb(c: &Change) -> &'static str {
    match (&c.before, &c.after) {
        (None, Some(_)) => "added",
        (Some(_), None) => "removed",
        _ => "changed",
    }
}

fn new_lines<'a>(before: Option<&str>, after: &'a str) -> Vec<&'a str> {
    let was: BTreeSet<&str> = before.map(|b| b.lines().collect()).unwrap_or_default();
    after.lines().filter(|l| !l.is_empty() && !was.contains(l)).collect()
}

fn grade_lines(new: &[String], old: &[String], host: &mut dyn Host) -> (Severity, Vec<String>, bool) {
    let mut worst = Severity::Note;
    let mut reasons = Vec::new();
    let mut signers_after = Vec::new();
    for l in new {
        let g = grade(l, host);
        worst = worst.max(g.severity);
        signers_after.push(g.signer.clone());
        reasons.push(format!("{l}: {}", g.reason));
    }
    let old_signers: BTreeSet<String> = old.iter().filter_map(|l| grade(l, host).signer).collect();
    let in_place = worst == Severity::Warn
        && !old.is_empty()
        && signers_after.iter().all(|s| s.as_ref().is_some_and(|s| old_signers.contains(s)));
    (if in_place { Severity::Note } else { worst }, reasons, in_place)
}

fn start_name(n: &str) -> &'static str {
    match n {
        "0" => "boot",
        "1" => "system",
        "2" => "automatic",
        "3" => "on demand",
        "4" => "disabled",
        _ => "unknown",
    }
}

fn service_target(v: &str) -> Option<String> {
    let image = field(v, "image")?;
    let dll = field(v, "dll").filter(|d| !d.is_empty());
    match dll {
        Some(d) if image.to_ascii_lowercase().contains("svchost.exe") => Some(d.to_string()),
        _ => Some(image.to_string()),
    }
}

pub fn judge(c: &Change, now: &Snapshot, host: &mut dyn Host) -> Finding {
    let (kind, rest) = c.key.split_once('/').unwrap_or((c.key.as_str(), ""));
    let v = verb(c);
    let mk = |severity, what: String, why: &str| Finding { severity, subject: c.key.clone(), what, why: why.to_string() };
    let before = c.before.as_deref();
    let after = c.after.as_deref();
    const RUNS: &str = "something set to run since arrival is either your team's change or the adversary's; a \
                        signature names who built the binary, not who installed it";
    match kind {
        "service" => match (before, after) {
            (_, None) => mk(Severity::Note, format!("service removed since arrival (was {})", before.unwrap_or_default().replace('\n', ", ")), RUNS),
            (None, Some(a)) => {
                let g = grade(&service_target(a).unwrap_or_default(), host);
                mk(g.severity, format!("new service since arrival: {}\n{}", a.replace('\n', ", "), g.reason), RUNS)
            }
            (Some(b), Some(a)) => {
                let (tb, ta) = (service_target(b), service_target(a));
                if tb != ta {
                    let new = vec![ta.unwrap_or_default()];
                    let old: Vec<String> = tb.into_iter().collect();
                    let (sev, reasons, in_place) = grade_lines(&new, &old, host);
                    let tail = if in_place { "; the same signer signed what it ran before, so this reads as an update" } else { "" };
                    mk(sev, format!("service now runs something else: {} → {}\n{}{tail}", b.replace('\n', ", "), a.replace('\n', ", "), reasons.join("\n")), RUNS)
                } else {
                    let (sb, sa) = (field(b, "start").unwrap_or("?"), field(a, "start").unwrap_or("?"));
                    let sooner = matches!((sb.parse::<u32>(), sa.parse::<u32>()), (Ok(x), Ok(y)) if y < x);
                    mk(
                        if sooner { Severity::Warn } else { Severity::Note },
                        format!(
                            "service settings changed: {} → {} (start: {} → {})",
                            b.replace('\n', ", "),
                            a.replace('\n', ", "),
                            start_name(sb),
                            start_name(sa)
                        ),
                        "a service that now starts by itself runs at the next boot whether or not anyone asks for it",
                    )
                }
            }
        },
        "task" | "autorun" | "wmi" => {
            let mech = if kind == "autorun" { rest.split('/').next().unwrap_or_default() } else { "" };
            if after.is_none() {
                let what = match kind {
                    "task" => "scheduled task",
                    "wmi" => "WMI consumer",
                    _ => mech,
                };
                return mk(Severity::Note, format!("{what} {v} since arrival (was {})", before.unwrap_or_default().replace('\n', " | ")), RUNS);
            }
            let a = after.unwrap_or_default();
            if SETTINGS.contains(&mech) {
                return mk(Severity::Warn, format!("setting {v} since arrival: {}", a.replace('\n', " | ")), "a remote-management setting changed after the responders arrived");
            }
            if mech == "task-cache" {
                let path = a.lines().next().unwrap_or_default();
                if now.items.contains_key(&format!("task/{path}")) {
                    return mk(Severity::Note, format!("the Task Scheduler's registry entry for {path} {v}; its actions are graded under task/"), RUNS);
                }
                return mk(Severity::Warn, format!("a task is registered in the Task Scheduler's registry with no task file: {path}"), RUNS);
            }

            let runnable = |v: &str| -> Vec<String> {
                if kind == "wmi" {
                    let f = fields(v);
                    let class = f.get("class").and_then(|c| c.first()).copied().unwrap_or_default();
                    let cmd = f.get("command").and_then(|c| c.first()).copied().unwrap_or_default();
                    match class {
                        "CommandLineEventConsumer" => vec![cmd.to_string()],
                        "ActiveScriptEventConsumer" => vec![format!("script {cmd}")],
                        _ => Vec::new(),
                    }
                } else if kind == "task" {
                    v.lines().map(|l| l.strip_prefix("exec ").or_else(|| l.strip_prefix("com ")).unwrap_or(l).to_string()).collect()
                } else {

                    let name = rest.rsplit('|').next().unwrap_or_default();
                    v.lines()
                        .map(|l| if clsid(l).is_none() && clsid(name).is_some() { name.to_string() } else { l.to_string() })
                        .collect()
                }
            };
            let old = before.map(runnable).unwrap_or_default();
            let mut new: Vec<String> = runnable(a).into_iter().filter(|l| !l.is_empty() && !old.contains(l)).collect();
            new.dedup();
            if new.is_empty() {

                let trigger = kind == "wmi" && !runnable(a).is_empty();
                let what = if trigger {
                    format!("WMI consumer {v} since arrival; its command is unchanged and its trigger is now: {}", new_lines(before, a).join(" | "))
                } else {
                    format!("{kind} {v} since arrival; nothing new runs: {}", a.replace('\n', " | "))
                };
                return mk(if trigger { Severity::Warn } else { Severity::Note }, what, RUNS);
            }
            let mut scripts = Vec::new();
            let mut binaries = Vec::new();
            for l in new {
                if l.starts_with("script ") { scripts.push(l) } else { binaries.push(l) }
            }
            let (mut sev, mut reasons, mut in_place) = grade_lines(&binaries, &old, host);
            for s in &scripts {
                sev = Severity::Critical;
                in_place = false;
                reasons.push(format!("{s}: a script consumer runs script text, which no signature covers"));
            }
            let label = match kind {
                "task" => format!("scheduled task {v} since arrival"),
                "wmi" => format!("WMI consumer {v} since arrival ({})", fields(a).get("class").and_then(|c| c.first()).copied().unwrap_or_default()),
                _ => format!("{mech} entry {v} since arrival"),
            };
            let tail = if in_place { "\nthe same signer signed what it ran before, so this reads as an update" } else { "" };
            mk(sev, format!("{label}\n{}{tail}", reasons.join("\n")), RUNS)
        }
        "user" => {
            let sev = match (before, after) {
                (Some(b), Some(a)) => {
                    let enabled = field(b, "enabled") == Some("0") && field(a, "enabled") == Some("1");
                    let pw = field(b, "password-required") == Some("1") && field(a, "password-required") == Some("0");
                    if enabled || pw { Severity::Warn } else { Severity::Note }
                }
                _ => Severity::Warn,
            };
            let what = match (before, after) {
                (None, Some(a)) => format!("new local account since arrival: {}", a.replace('\n', ", ")),
                (Some(b), None) => format!("local account removed since arrival (was {})", b.replace('\n', ", ")),
                (Some(b), Some(a)) => format!("local account changed since arrival: {} → {}", b.replace('\n', ", "), a.replace('\n', ", ")),
                (None, None) => String::new(),
            };
            mk(sev, what, ADVICE)
        }
        "group" => {
            let sid = rest.split('/').next().unwrap_or_default();
            let rid = sid.strip_prefix("S-1-5-32-").and_then(|r| r.parse::<u32>().ok());
            let critical = rid.is_some_and(|r| CRITICAL_GROUPS.contains(&r));
            match (before, after) {
                (None, Some(a)) => mk(
                    if critical { Severity::Critical } else { Severity::Warn },
                    format!("joined since arrival: {a}"),
                    ADVICE,
                ),
                (Some(b), None) => mk(Severity::Warn, format!("left since arrival: {b}"), ADVICE),
                _ => mk(Severity::Note, format!("member renamed since arrival: {} → {}", before.unwrap_or_default(), after.unwrap_or_default()), ADVICE),
            }
        }
        "listen" => match (before, after) {
            (_, None) => mk(Severity::Note, format!("listener closed since arrival (was {})", before.unwrap_or_default()), "a port that was open when the responders arrived is not now; if it was a scored service, it is down"),
            (None, Some(a)) => mk(Severity::Warn, format!("new listener since arrival: {a}"), "a port that opened after the responders arrived was opened by something running now"),
            (Some(b), Some(a)) => mk(Severity::Warn, format!("listener now served by {a} (was {b})"), "the same port answered by a different program is how a service gets impersonated"),
        },
        "share" => match (before, after) {
            (_, None) => mk(Severity::Note, format!("share removed since arrival (was {})", before.unwrap_or_default().replace('\n', ", ")), ADVICE),
            (None, Some(a)) => mk(Severity::Warn, format!("new share since arrival: {}", a.replace('\n', ", ")), ADVICE),
            (Some(b), Some(a)) => mk(Severity::Warn, format!("share changed since arrival: {} → {}", b.replace('\n', ", "), a.replace('\n', ", ")), ADVICE),
        },
        "policy" => {
            let weaker = weakened(rest, before.unwrap_or_default(), after.unwrap_or_default());
            mk(
                if weaker { Severity::Warn } else { Severity::Note },
                format!("{rest} {v} since arrival: {} → {}", before.unwrap_or("(none)"), after.unwrap_or("(none)")),
                if weaker { "a protection or a record that was on when the responders arrived is weaker now" } else { "recorded on arrival and different now" },
            )
        }
        "cert" => {
            let store = rest.rsplit_once('/').map_or(rest, |(s, _)| s).replace('|', "\\");
            let shown = after.or(before).and_then(|x| field(x, "subject")).unwrap_or("?").to_string();
            match (before, after) {
                (None, Some(a)) if field(a, "shipped") != Some("no") => mk(
                    Severity::Note,
                    format!("certificate added to {store} since arrival: {shown}, shipped by {}", field(a, "shipped").unwrap_or("?")),
                    "Microsoft's own roots arrive with updates and the root program's on first use; this one is theirs by thumbprint",
                ),
                (None, Some(a)) => mk(
                    if field(a, "signs") == Some("any") { Severity::Critical } else { Severity::Warn },
                    format!("certificate ADDED to {store} since arrival, not one Microsoft ships: {shown}"),
                    "a CA put in a trust store after the responders arrived, that can sign for any name, lets whoever \
                     holds its key read this host's TLS. `hemostat trust` grades it; taking it out is a person's \
                     decision in certlm.msc or certmgr.msc",
                ),
                (Some(_), None) => mk(
                    Severity::Note,
                    format!("certificate removed from {store} since arrival: {shown}"),
                    "a certificate trusted when the responders arrived is not now; if your team did not remove it, \
                     what relied on it stops working",
                ),
                _ => mk(Severity::Note, format!("certificate in {store} changed since arrival: {shown}"), "the same thumbprint, read differently"),
            }
        }
        _ => mk(Severity::Warn, format!("{v} since arrival"), "recorded on arrival and different now"),
    }
}

pub fn weakened(name: &str, before: &str, after: &str) -> bool {
    if name.starts_with("usn/") {
        return before != after;
    }
    if name == "wdigest-plaintext" {
        return before == "off" && after == "on";
    }
    if name == "audit/process-creation" {
        return before == "audited" && after != "audited";
    }
    if let Some(_channel) = name.strip_prefix("evtlog/") {
        let num = |v: &str, k: &str| v.split(' ').find_map(|p| p.strip_prefix(k).and_then(|x| x.strip_prefix('=')).map(str::to_string));
        let off = num(before, "enabled").as_deref() == Some("1") && num(after, "enabled").as_deref() != Some("1");
        let gone = before != "absent" && after == "absent";
        let smaller = matches!(
            (num(before, "max").and_then(|x| x.parse::<u64>().ok()), num(after, "max").and_then(|x| x.parse::<u64>().ok())),
            (Some(b), Some(a)) if a < b
        );
        return off || gone || smaller;
    }
    before == "on" && after != "on"
}

pub fn judge_all(changes: &[Change], now: &Snapshot, host: &mut dyn Host) -> Vec<Finding> {
    let mut out: Vec<Finding> = changes.iter().map(|c| judge(c, now, host)).collect();
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.subject.cmp(&b.subject)));
    out
}

pub fn com_handlers(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<ComHandler>") {
        let after = rest.get(i + "<ComHandler>".len()..).unwrap_or_default();
        let end = after.find("</ComHandler>").unwrap_or(after.len());
        let block = after.get(..end).unwrap_or_default();
        if let Some(id) = block.find("<ClassId>").and_then(|a| {
            let from = block.get(a + "<ClassId>".len()..)?;
            Some(from.get(..from.find("</ClassId>")?)?.trim().to_string())
        }) {
            out.push(id);
        }
        rest = after.get(end..).unwrap_or_default();
    }
    out
}

pub fn task_actions(xml: &str) -> Vec<String> {
    persist::task_commands(xml)
        .into_iter()
        .map(|c| format!("exec {c}"))
        .chain(com_handlers(xml).into_iter().map(|c| format!("com {c}")))
        .collect()
}

pub fn fact_readings(f: &crate::facts::Facts) -> Vec<(String, Result<String, String>)> {
    use crate::facts::Flag;
    [
        ("secure-boot", f.secure_boot),
        ("vbs", f.vbs),
        ("hvci", f.hvci),
        ("driver-blocklist", f.driver_blocklist),
        ("lsa-ppl", f.lsa_ppl),
        ("wdigest-plaintext", f.wdigest_plaintext),
        ("defender-rtp", f.defender_rtp),
        ("defender-tamper", f.defender_tamper),
    ]
    .into_iter()
    .map(|(n, v)| {
        (
            n.to_string(),
            match v {
                Flag::Unreadable => Err("could not be read".to_string()),
                other => Ok(other.token().to_string()),
            },
        )
    })
    .collect()
}

#[cfg(target_os = "windows")]
pub use read::{read, LiveHost};

#[cfg(not(target_os = "windows"))]
pub fn read(policy: Vec<(String, Result<String, String>)>) -> Readings {
    Readings { policy, ..Readings::default() }
}

#[cfg(target_os = "windows")]
mod read {
    use std::collections::HashMap;

    use super::{task_actions, Host, Readings, ServiceRow, Signed, TaskRow};

    const TASK_ROOT: &str = r"C:\Windows\System32\Tasks";

    pub fn read(mut policy: Vec<(String, Result<String, String>)>) -> Readings {
        let persist = crate::persist::report();
        let services = persist
            .entries
            .iter()
            .filter(|e| e.mechanism == "services")
            .map(|e| {
                let key = format!(r"SYSTEM\CurrentControlSet\Services\{}", e.name);
                let dll = crate::reg::hklm_values_read(&format!(r"{key}\Parameters"))
                    .ok()
                    .and_then(|v| v.into_iter().find(|(n, _)| n.eq_ignore_ascii_case("ServiceDll")).map(|(_, d)| d));
                ServiceRow {
                    name: e.name.clone(),
                    image: e.command.clone(),
                    start: crate::reg::hklm_dword(&key, "Start"),
                    kind: crate::reg::hklm_dword(&key, "Type"),
                    dll,
                }
            })
            .collect();
        let (mut tasks, mut task_refused) = (Vec::new(), Vec::new());
        walk(std::path::Path::new(TASK_ROOT), &mut tasks, &mut task_refused, 0);
        tasks.sort_by(|a: &TaskRow, b| a.path.cmp(&b.path));
        let mut all = super::fact_readings(&crate::acquire::facts());
        all.append(&mut policy);
        Readings {
            persist,
            services,
            tasks,
            task_refused,
            wmi: Some(crate::wmi::live_query()),
            accounts: crate::accounts::report(),
            groups: crate::accounts::privileged_groups(),
            listeners: crate::overview::report(),
            shares: Some(shares()),
            policy: all,
            trust: Some(crate::trust::report()),
        }
    }

    fn walk(dir: &std::path::Path, out: &mut Vec<TaskRow>, refused: &mut Vec<String>, depth: usize) {
        if depth > 8 {
            refused.push(format!("{}: deeper than this walk goes", dir.display()));
            return;
        }
        let rd = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) => {
                refused.push(format!("{}: {e}", dir.display()));
                return;
            }
        };
        for e in rd.flatten() {
            let p = e.path();
            match std::fs::symlink_metadata(&p) {
                Ok(md) if md.is_dir() => walk(&p, out, refused, depth + 1),
                Ok(md) if md.is_file() => match std::fs::read(&p) {
                    Ok(bytes) => {
                        let rel = p.display().to_string();
                        let rel = rel.get(TASK_ROOT.len()..).unwrap_or(&rel).to_string();
                        out.push(TaskRow { path: rel, actions: task_actions(&crate::persist::decode_task(&bytes)) });
                    }
                    Err(e) => refused.push(format!("{}: {e}", p.display())),
                },
                Ok(_) => {}
                Err(e) => refused.push(format!("{}: {e}", p.display())),
            }
        }
    }

    fn shares() -> Result<Vec<(String, String)>, String> {
        use windows_sys::Win32::NetworkManagement::NetManagement::{NetApiBufferFree, MAX_PREFERRED_LENGTH};
        use windows_sys::Win32::Storage::FileSystem::{NetShareEnum, SHARE_INFO_2};
        const ERROR_MORE_DATA: u32 = 234;
        let mut out = Vec::new();
        let mut resume: u32 = 0;
        loop {
            let mut buf: *mut u8 = core::ptr::null_mut();
            let (mut read, mut total) = (0u32, 0u32);

            let rc = unsafe {
                NetShareEnum(
                    core::ptr::null(),
                    2,
                    core::ptr::addr_of_mut!(buf),
                    MAX_PREFERRED_LENGTH,
                    core::ptr::addr_of_mut!(read),
                    core::ptr::addr_of_mut!(total),
                    core::ptr::addr_of_mut!(resume),
                )
            };
            if rc != 0 && rc != ERROR_MORE_DATA {
                return Err(format!("NetShareEnum returned {rc}"));
            }
            if !buf.is_null() {

                let items = unsafe { core::slice::from_raw_parts(buf.cast::<SHARE_INFO_2>(), read as usize) };
                for s in items {

                    let (name, path) = unsafe { (pwstr(s.shi2_netname), pwstr(s.shi2_path)) };
                    out.push((name, format!("type={:#x}\npath={path}", s.shi2_type)));
                }

                unsafe { NetApiBufferFree(buf.cast()) };
            }
            if rc != ERROR_MORE_DATA {
                out.sort();
                return Ok(out);
            }
        }
    }

    unsafe fn pwstr(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0usize;

        while unsafe { *p.add(len) } != 0 && len < 32_768 {
            len += 1;
        }

        String::from_utf16_lossy(unsafe { core::slice::from_raw_parts(p, len) })
    }

    #[derive(Default)]
    pub struct LiveHost {
        seen: HashMap<String, Signed>,
    }

    impl Host for LiveHost {
        fn exists(&self, path: &str) -> bool {
            matches!(crate::localpath::vet(path), Ok(Some((_, md))) if md.is_file())
        }
        fn refuse(&self, path: &str) -> Option<String> {
            crate::localpath::vet(path).err()
        }
        fn env(&self, name: &str) -> Option<String> {
            std::env::var(name).ok()
        }
        fn signature(&mut self, path: &str) -> Signed {
            let k = path.to_ascii_lowercase();
            if let Some(s) = self.seen.get(&k) {
                return s.clone();
            }

            let (trust, signer) = crate::authenticode::verify_signer(path);
            let s = Signed { token: trust.token(), valid: trust.is_valid(), signer };
            self.seen.insert(k, s.clone());
            s
        }
        fn com_server(&self, clsid: &str) -> Option<String> {
            ["InprocServer32", "LocalServer32"].iter().find_map(|sub| {
                crate::reg::default_value(crate::reg::Hive::Machine, &format!(r"SOFTWARE\Classes\CLSID\{clsid}\{sub}"))
                    .filter(|v| !v.trim().is_empty())
            })
        }
        fn writable_by_users(&self, path: &str) -> Option<bool> {

            let (p, _) = crate::localpath::vet(path).ok()??;
            crate::acl::dacl_of_read(&p).ok().map(|aces| crate::acl::grants_unprivileged_write(&aces))
        }
    }
}
