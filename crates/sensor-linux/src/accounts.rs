use std::collections::BTreeMap;
use std::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {

    pub name: String,

    pub uid: u32,

    pub gid: u32,

    pub shell: String,

    pub home: String,
}

impl Account {

    pub fn can_login(&self) -> bool {
        let name = self.shell.rsplit('/').next().unwrap_or("");
        !matches!(name, "nologin" | "false" | "true" | "sync")
    }

    fn shell_shown(&self) -> &str {
        if self.shell.is_empty() {
            "/bin/sh (the field is empty)"
        } else {
            &self.shell
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {

    Note,

    Warn,

    Critical,
}

impl Severity {

    pub fn tag(self) -> &'static str {
        match self {
            Severity::Note => "note",
            Severity::Warn => "WARN",
            Severity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {

    pub severity: Severity,

    pub subject: String,

    pub what: String,

    pub why: String,
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub accounts: Vec<Account>,

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,

    pub unread: Vec<String>,
}

pub fn parse_passwd(text: &str) -> Vec<Account> {
    text.split('\n').filter_map(passwd_line).map(|(a, _)| a).collect()
}

fn parse_passwd_fields(text: &str) -> Vec<(String, String)> {
    text.split('\n')
        .filter_map(passwd_line)
        .filter(|(a, pw)| *pw != "x" && pw.strip_prefix("##") != Some(a.name.as_str()))
        .map(|(a, pw)| (a.name, pw.to_string()))
        .collect()
}

fn c_space(c: char) -> bool {
    c.is_ascii_whitespace() || c == '\x0b'
}

fn passwd_line(line: &str) -> Option<(Account, &str)> {
    let line = line.trim_start_matches(c_space);
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let mut f = line.splitn(7, ':');
    let name = f.next()?;

    if name.starts_with(['+', '-']) {
        return None;
    }
    let password = f.next().unwrap_or("");
    let uid = libc_id(f.next()?)?;
    let gid = libc_id(f.next()?)?;
    let _gecos = f.next();
    let home = f.next().unwrap_or("");
    let shell = f.next().unwrap_or("");
    Some((
        Account {
            name: name.to_string(),
            uid,
            gid,
            shell: shell.to_string(),
            home: home.to_string(),
        },
        password,
    ))
}

fn libc_id(field: &str) -> Option<u32> {
    let t = field.trim_start_matches(c_space);
    let (negative, digits) = match t.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let magnitude = digits.bytes().try_fold(0u64, |acc, b| {
        acc.checked_mul(10)?.checked_add(u64::from(b.wrapping_sub(b'0')))
    });
    let value = match magnitude {
        None => u64::MAX,
        Some(m) if negative => m.wrapping_neg(),
        Some(m) => m,
    };
    Some(u32::try_from(value).unwrap_or(u32::MAX))
}

fn structural(accounts: &[Account], out: &mut Vec<Finding>) {

    let mut by_uid: BTreeMap<u32, Vec<&Account>> = BTreeMap::new();
    for a in accounts {
        by_uid.entry(a.uid).or_default().push(a);
    }
    if let Some(roots) = by_uid.get(&0) {
        for a in roots.iter().filter(|a| a.name != "root") {
            out.push(Finding {
                severity: Severity::Critical,
                subject: a.name.clone(),
                what: format!("uid 0 — a second root account (shell {})", a.shell_shown()),
                why: "holds full root authority while reading as an ordinary name in logs \
                      and in `who`; nothing about this account is limited by its name"
                    .into(),
            });
        }
    }

    for (uid, group) in by_uid.iter().filter(|(u, g)| **u != 0 && g.len() > 1) {
        let names: Vec<&str> = group.iter().map(|a| a.name.as_str()).collect();
        out.push(Finding {
            severity: Severity::Warn,
            subject: names.join(", "),
            what: format!("share uid {uid}"),
            why: "two names for one identity, so per-user attribution in the evidence \
                  cannot distinguish them".into(),
        });
    }

    for a in accounts.iter().filter(|a| a.uid > 0 && a.uid < 1000 && a.can_login()) {
        out.push(Finding {
            severity: Severity::Warn,
            subject: a.name.clone(),
            what: format!(
                "system account (uid {}) has an interactive shell: {}",
                a.uid,
                a.shell_shown()
            ),
            why: "service accounts are not normally logged into; a shell here is a common \
                  way to keep access that looks like part of the system".into(),
        });
    }
}

fn include_targets(text: &str) -> Vec<(bool, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix('@').or_else(|| t.strip_prefix('#')) else {
            continue;
        };
        let (is_dir, arg) = if let Some(a) = rest.strip_prefix("includedir") {
            (true, a)
        } else if let Some(a) = rest.strip_prefix("include") {
            (false, a)
        } else {
            continue;
        };
        let arg = arg.trim();
        if !arg.is_empty() {
            out.push((is_dir, arg.to_string()));
        }
    }
    out
}

fn resolve_include(arg: &str, including: &str, host: Option<&str>) -> Option<String> {
    let mut path = String::new();
    if let Some(quoted) = arg.strip_prefix('"') {
        path.push_str(quoted.split('"').next().unwrap_or(""));
    } else {
        let mut chars = arg.chars();
        while let Some(c) = chars.next() {
            if c_space(c) {
                break;
            }
            path.push(if c == '\\' { chars.next().unwrap_or(c) } else { c });
        }
    }
    if path.contains("%h") {
        let short = host?.split('.').next().unwrap_or("").replace('/', "_");
        if short.is_empty() {
            return None;
        }
        path = path.replace("%h", &short);
    }
    if path.starts_with('/') {
        return Some(path);
    }
    let dir = std::path::Path::new(including).parent()?;
    Some(dir.join(path).to_string_lossy().into_owned())
}

fn sudoers(out: &mut Vec<Finding>, unread: &mut Vec<String>) {
    sudoers_from(&["/etc/sudoers", "/etc/sudoers.d"], out, unread);
}

const MAX_SUDOERS_FILES: usize = 256;

const MAX_BEYOND_CAP_NAMED: usize = 16;

#[derive(Default)]
struct Worklist {

    queue: std::collections::VecDeque<(String, bool)>,

    queued: std::collections::BTreeSet<(String, bool)>,

    charged: usize,

    beyond: usize,
    beyond_named: Vec<String>,
}

impl Worklist {

    fn charge(&mut self, name: &str) -> bool {
        if self.charged >= MAX_SUDOERS_FILES {
            self.beyond += 1;
            if self.beyond_named.len() < MAX_BEYOND_CAP_NAMED {
                self.beyond_named.push(name.to_string());
            }
            return false;
        }
        self.charged += 1;
        true
    }

    fn push(&mut self, path: String, listed: bool) -> bool {
        let key = (path, listed);
        if self.queued.contains(&key) {
            return true;
        }
        if !self.charge(&key.0) {
            return false;
        }
        self.queue.push_back(key.clone());
        self.queued.insert(key);
        true
    }
}

fn sudoers_from(roots: &[&str], out: &mut Vec<Finding>, unread: &mut Vec<String>) {
    use std::os::unix::fs::MetadataExt as _;

    let mut files: Vec<String> = Vec::new();
    let mut work = Worklist::default();
    for r in roots {
        work.push((*r).to_string(), false);
    }

    let mut seen: std::collections::BTreeSet<(u64, u64)> = std::collections::BTreeSet::new();

    let mut not_entered: Vec<(String, Option<(u64, u64)>)> = Vec::new();

    let mut cut: Vec<String> = Vec::new();

    let host = fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| h.trim().to_string());

    while let Some((item, listed)) = work.queue.pop_front() {
        let meta = fs::metadata(&item);
        let is_dir = meta.as_ref().is_ok_and(|m| m.is_dir());

        if is_dir && listed {
            not_entered.push((item, meta.as_ref().ok().map(|m| (m.dev(), m.ino()))));
            continue;
        }
        if let Ok(m) = &meta {
            if !seen.insert((m.dev(), m.ino())) {
                continue;
            }
        }
        if is_dir {
            match fs::read_dir(&item) {
                Ok(dir) => {
                    for e in dir.flatten() {
                        let p = e.path();
                        let Some(s) = p.to_str() else {

                            let shown = p.to_string_lossy().into_owned();
                            if !work.charge(&shown) {
                                cut.push(item.clone());
                                break;
                            }
                            unread.push(format!("{shown} (a name that is not UTF-8)"));
                            out.push(Finding {
                                severity: Severity::Warn,
                                subject: shown,
                                what: "a sudoers source whose name is not UTF-8 was not read — sudo posture unknown"
                                    .into(),
                                why: "sudo reads every file in an include directory whatever bytes its name \
                                      is, and this walk could not open this one by name. A password-free \
                                      root grant inside it would be invisible; a name like this is itself \
                                      worth explaining"
                                    .into(),
                            });
                            continue;
                        };
                        if !work.push(s.to_string(), true) {
                            cut.push(item.clone());
                            break;
                        }
                    }
                }

                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    unread.push(format!("{item} ({e})"));
                    out.push(Finding {
                        severity: Severity::Warn,
                        subject: item.clone(),
                        what: "unreadable directory — sudo posture unknown".into(),
                        why: format!(
                            "could not list this sudoers directory ({e}); every grant inside it \
                             is unexamined, including a password-free one. Re-run with privilege."
                        ),
                    });
                }
                Err(_) => {}
            }
            continue;
        }

        if let Ok(text) = crate::saferead::read_text(std::path::Path::new(&item)) {
            for (_, target) in include_targets(&text) {
                match resolve_include(&target, &item, host.as_deref()) {

                    Some(path) => {
                        work.push(path, false);
                    }
                    None => {
                        unread.push(format!("{target} (included from {item}; path not resolvable)"));
                        out.push(Finding {
                            severity: Severity::Warn,
                            subject: item.clone(),
                            what: format!("includes `{target}`, which could not be resolved — sudo posture unknown"),
                            why: "sudo substitutes the host name for `%h`, and this run could not \
                                  read one, so the file it names was not read. A password-free \
                                  grant there would be invisible"
                                .into(),
                        });
                    }
                }
            }
        }
        files.push(item);
    }
    files.sort();

    if work.beyond > 0 {
        unread.extend(
            work.beyond_named.iter().map(|p| format!("{p} (beyond the {MAX_SUDOERS_FILES}-source cap)")),
        );
        if work.beyond > work.beyond_named.len() {
            unread.push(format!(
                "{} more source(s) beyond the {MAX_SUDOERS_FILES}-source cap",
                work.beyond - work.beyond_named.len()
            ));
        }

        unread.extend(cut.iter().map(|d| format!("{d} (listed only in part: the {MAX_SUDOERS_FILES}-source cap)")));
        let rest = if cut.is_empty() {
            String::new()
        } else {
            format!(", and the listing of {} stopped there, so it holds more", cut.join(", "))
        };
        out.push(Finding {
            severity: Severity::Warn,
            subject: work.beyond_named.first().or(cut.first()).cloned().unwrap_or_default(),
            what: format!(
                "{} sudoers source(s) beyond the {MAX_SUDOERS_FILES}-source cap were not read{rest}",
                work.beyond
            ),
            why: "the walk stops at a fixed count so a hostile include chain cannot spin it, and \
                  everything past that count is unexamined — including a password-free grant. \
                  A drop-in directory this full is itself worth a look"
                .into(),
        });
    }

    not_entered.retain(|(_, key)| key.is_none_or(|k| !seen.contains(&k)));
    if !not_entered.is_empty() {
        let shown: Vec<&str> =
            not_entered.iter().take(MAX_BEYOND_CAP_NAMED).map(|(p, _)| p.as_str()).collect();
        let more = not_entered.len() - shown.len();
        out.push(Finding {
            severity: Severity::Note,
            subject: not_entered.first().map(|(p, _)| p.clone()).unwrap_or_default(),
            what: format!(
                "{} director(y/ies) inside a sudoers include directory, not entered: {}{}",
                not_entered.len(),
                shown.join(", "),
                if more > 0 { format!(" and {more} more") } else { String::new() }
            ),
            why: "sudo reads only the files directly inside an include directory, never anything \
                  below one, so nothing in these is policy unless a sudoers file includes it by \
                  name — which this sweep follows. They were not entered, so a link back up the \
                  tree cannot make the walk endless, and a grant inside one is not reported as live"
                .into(),
        });
    }

    for path in files {

        let text = match crate::saferead::read_text(std::path::Path::new(&path)) {
            Ok(t) => t,

            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                unread.push(format!("{path} ({e})"));
                out.push(Finding {
                    severity: Severity::Warn,
                    subject: path.clone(),
                    what: "unreadable — sudo posture unknown".into(),
                    why: format!(
                        "could not read this sudoers source ({e}); a password-free root \
                         grant here would be invisible. Re-run with privilege."
                    ),
                });
                continue;
            }
        };
        sudoers_findings(&text, &path, out);
    }
}

fn sudoers_findings(text: &str, path: &str, out: &mut Vec<Finding>) {
    for t in sudoers_lines(text) {
        let t = t.as_str();

        let no_password = t.contains("NOPASSWD")
            || (t.starts_with("Defaults")
                && t.split('!').skip(1).any(|r| r.trim_start().starts_with("authenticate")));
        if !no_password {
            continue;
        }
        if !t.contains("NOPASSWD") {
            out.push(Finding {
                severity: Severity::Critical,
                subject: path.to_string(),
                what: format!("disables the sudo password prompt: {t}"),
                why: "`!authenticate` is NOPASSWD written as a Default — everything it covers \
                      escalates to root with no credential. It contains none of the letters a \
                      NOPASSWD search looks for, which is what makes it worth writing that way. \
                      Confirm by hand and act only through the operator interface"
                    .into(),
            });
            continue;
        }
        out.push(Finding {
            severity: Severity::Critical,
            subject: path.to_string(),
            what: format!("grants password-free sudo: {t}"),
            why: "a compromised session for that principal escalates to root with no \
                  further credential, so a stolen shell is a stolen host. Confirm by \
                  hand — a legitimate admin account looks identical — and act on it \
                  only through the operator interface"
                .into(),
        });
    }
}

fn sudoers_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut pending = String::new();
    for line in text.lines() {
        let t = line.trim();
        if sudoers_comment(t) {
            if !pending.is_empty() {
                out.push(std::mem::take(&mut pending));
            }
            continue;
        }
        let (body, continued) = match t.strip_suffix('\\') {
            Some(b) => (b.trim_end(), true),
            None => (t, false),
        };
        if !pending.is_empty() && !body.is_empty() {
            pending.push(' ');
        }
        pending.push_str(body);
        if !continued && !pending.is_empty() {
            out.push(std::mem::take(&mut pending));
        }
    }
    if !pending.is_empty() {
        out.push(pending);
    }
    out
}

fn sudoers_comment(t: &str) -> bool {
    let Some(rest) = t.strip_prefix('#') else {
        return false;
    };
    if rest.starts_with("include") {
        return false;
    }
    let id = rest.strip_prefix('-').unwrap_or(rest);
    let after = id.trim_start_matches(|c: char| c.is_ascii_digit());
    let is_uid = after.len() < id.len() && after.starts_with([' ', '\t', ',', '\\']);
    !is_uid
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {

    pub name: String,

    pub gid: u32,

    pub has_password: bool,

    pub members: Vec<String>,

    pub admins: Vec<String>,
}

fn member_list(field: Option<&str>) -> Vec<String> {
    field
        .map(|m| {
            m.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secret {

    None_,

    Locked,

    Strong(&'static str),

    Weak(&'static str),

    Unrecognised,
}

pub fn classify_secret(field: &str) -> Secret {
    let f = field.trim();
    if f.is_empty() {
        return Secret::None_;
    }

    if f == "*" || f.starts_with('!') {
        return Secret::Locked;
    }
    if let Some(rest) = f.strip_prefix('$') {
        let id = rest.split('$').next().unwrap_or("");
        return match id {
            "y" | "gy" => Secret::Strong("yescrypt"),
            "6" => Secret::Strong("SHA-512"),
            "5" => Secret::Strong("SHA-256"),
            "2" | "2a" | "2b" | "2y" => Secret::Strong("bcrypt"),
            "1" => Secret::Weak("MD5"),
            _ => Secret::Unrecognised,
        };
    }

    if f.len() == 13 {
        return Secret::Weak("DES");
    }
    Secret::Unrecognised
}

pub fn parse_shadow(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut f = l.split(':');
            let user = f.next()?.to_string();
            let secret = f.next()?.to_string();
            (!user.is_empty()).then_some((user, secret))
        })
        .collect()
}

fn passwords(accounts: &[Account], shadow: &[(String, String)], out: &mut Vec<Finding>) {
    for (user, field) in shadow {
        let can_login = accounts
            .iter()
            .any(|a| &a.name == user && a.can_login());
        match classify_secret(field) {
            Secret::None_ => out.push(Finding {
                severity: if can_login { Severity::Critical } else { Severity::Warn },
                subject: user.clone(),
                what: "has NO password — the field in /etc/shadow is empty".into(),
                why: "an empty password field is not a locked account: anything that \
                      authenticates against it accepts an empty password. If this account has \
                      a shell, it is a way in that needs no credential at all"
                    .into(),
            }),
            Secret::Weak(alg) if can_login => out.push(Finding {
                severity: Severity::Warn,
                subject: user.clone(),
                what: format!("password is hashed with {alg}"),
                why: "MD5 and DES are brute-forceable on commodity hardware, and DES silently \
                      ignores everything past the eighth character. A hash an attacker has \
                      already read off the host is a password they will have. Re-set it so it \
                      rehashes with the system default"
                    .into(),
            }),
            Secret::Unrecognised if can_login => out.push(Finding {
                severity: Severity::Note,
                subject: user.clone(),
                what: "password field is in a form this check does not recognise".into(),
                why: "reported as unknown rather than judged in either direction — it may be a \
                      newer algorithm, or it may be a hand-edited field"
                    .into(),
            }),
            _ => {}
        }
    }
}

fn passwd_field_passwords(
    accounts: &[Account],
    fields: &[(String, String)],
    out: &mut Vec<Finding>,
) {
    for (user, field) in fields {
        let can_login = accounts.iter().any(|a| &a.name == user && a.can_login());
        let (severity, what) = match classify_secret(field) {
            Secret::Locked => continue,
            Secret::None_ => (
                if can_login { Severity::Critical } else { Severity::Warn },
                "has NO password — its password field in /etc/passwd is empty, so /etc/shadow \
                 is never consulted"
                    .to_string(),
            ),
            Secret::Strong(alg) | Secret::Weak(alg) => (
                if can_login { Severity::Warn } else { Severity::Note },
                format!("password hash ({alg}) is kept in world-readable /etc/passwd"),
            ),
            Secret::Unrecognised => (
                if can_login { Severity::Warn } else { Severity::Note },
                "password field in /etc/passwd is neither `x` nor locked".to_string(),
            ),
        };
        out.push(Finding {
            severity,
            subject: user.clone(),
            what,
            why: "pam_unix reads /etc/shadow only when this field is `x`; anything else is the \
                  password it checks, and every local account can read it. An empty one is \
                  accepted as no password at all. Put `x` back with `vipw` so the shadow row is \
                  what authenticates — then check that row too"
                .into(),
        });
    }
}

pub fn parse_group(text: &str) -> Vec<Group> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.trim_start_matches(c_space).split(':').collect();
            let pw = f.get(1).copied().unwrap_or("");
            Some(Group {
                name: (*f.first()?).to_string(),
                gid: libc_id(f.get(2)?)?,
                has_password: !matches!(pw, "" | "x" | "*" | "!"),
                members: member_list(f.get(3).copied()),
                admins: Vec::new(),
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GShadow {
    name: String,

    has_password: bool,
    admins: Vec<String>,
    members: Vec<String>,
}

fn parse_gshadow(text: &str) -> Vec<GShadow> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            let pw = f.get(1).copied().unwrap_or("");
            Some(GShadow {
                name: (*f.first()?).to_string(),

                has_password: pw != "x"
                    && !matches!(classify_secret(pw), Secret::None_ | Secret::Locked),
                admins: member_list(f.get(2).copied()),
                members: member_list(f.get(3).copied()),
            })
        })
        .collect()
}

fn apply_gshadow(groups: &mut [Group], gshadow: &[GShadow]) {
    for g in groups.iter_mut() {
        let Some(s) = gshadow.iter().find(|s| s.name == g.name) else {
            continue;
        };
        g.has_password |= s.has_password;
        for m in &s.members {
            if !g.members.contains(m) {
                g.members.push(m.clone());
            }
        }
        g.admins.clone_from(&s.admins);
    }
}

const PRIVILEGED_GROUPS: &[(&str, &str, bool)] = &[

    ("sudo", "run any command as root through sudo", false),
    ("wheel", "run any command as root through sudo", false),
    ("admin", "run any command as root through sudo", false),
    (
        "docker",
        "drive the container daemon, which will mount the host filesystem into a \
         container as root",
        true,
    ),
    (
        "lxd",
        "create a privileged container over the host filesystem",
        true,
    ),
    (
        "podman",
        "drive the container daemon, which runs the host filesystem privileged",
        true,
    ),
    (
        "shadow",
        "read /etc/shadow, and so every password hash on the host",
        true,
    ),
    (
        "disk",
        "read and write block devices directly, bypassing file permissions entirely",
        true,
    ),
];

const SUDO_BY_NAME: &[&str] = &["sudo", "wheel", "admin"];

fn group_membership(accounts: &[Account], groups: &[Group], out: &mut Vec<Finding>) {
    let uid_of: BTreeMap<&str, u32> = accounts
        .iter()
        .map(|a| (a.name.as_str(), a.uid))
        .collect();

    let privileged: Vec<(u32, &str, &str, bool)> = PRIVILEGED_GROUPS
        .iter()
        .filter_map(|(name, grants, root_equivalent)| {
            let g = groups.iter().find(|g| g.name == *name)?;
            Some((g.gid, *name, *grants, *root_equivalent))
        })
        .collect();
    let privilege_of = |gid: u32| privileged.iter().find(|p| p.0 == gid).copied();

    let name_of_gid = |gid: u32| groups.iter().find(|g| g.gid == gid).map(|g| g.name.as_str());
    let sudo_name = |name: &str| {
        PRIVILEGED_GROUPS
            .iter()
            .find(|(n, ..)| *n == name && SUDO_BY_NAME.contains(n))
            .map(|(n, grants, root_equivalent)| (*n, *grants, *root_equivalent))
    };

    for g in groups {
        if g.has_password {
            out.push(Finding {
                severity: Severity::Warn,
                subject: format!("group {}", g.name),
                what: "carries a group password".into(),
                why: "group passwords are effectively unused on modern systems; one that \
                      has been set lets anyone who knows it join the group with `newgrp`, \
                      which leaves no membership entry to find"
                    .into(),
            });
        }

        let (privilege, label) = if let Some((_, owner, grants, re)) = privilege_of(g.gid) {
            let label = if owner == g.name {
                format!("`{}` group", g.name)
            } else {
                format!("`{}` group (gid {}, the gid of `{owner}`)", g.name, g.gid)
            };
            (Some((grants, re)), label)
        } else if let Some((owner, grants, re)) = sudo_name(&g.name) {
            let label = format!(
                "`{owner}` group line with gid {} (sudo matches `%{owner}` against the names of \
                 an account's gids, so a second `{owner}` line is `{owner}` too)",
                g.gid
            );
            (Some((grants, re)), label)
        } else if let Some((owner, grants, re)) = name_of_gid(g.gid).and_then(sudo_name) {
            let label = format!(
                "`{}` group (gid {}, which getgrgid names `{owner}`, and sudo matches \
                 `%{owner}` against that name)",
                g.name, g.gid
            );
            (Some((grants, re)), label)
        } else {
            (None, format!("`{}` group", g.name))
        };

        for m in &g.members {
            let uid = uid_of.get(m.as_str()).copied();

            if g.gid == 0 && m != "root" {
                out.push(Finding {
                    severity: Severity::Warn,
                    subject: m.clone(),
                    what: format!("is a secondary member of the root group (gid 0, `{}`)", g.name),
                    why: "root-group membership grants access to every file owned by that \
                          group. Some distributions ship a daemon here legitimately, so this \
                          is a lead to confirm by provenance rather than a verdict"
                        .into(),
                });
                continue;
            }

            let Some((grants, root_equivalent)) = privilege else {
                continue;
            };

            match uid {

                None => out.push(Finding {
                    severity: Severity::Warn,
                    subject: m.clone(),
                    what: format!("is listed in the {label} but has no /etc/passwd entry"),
                    why: "a membership waiting for an account name to be recreated is a \
                          quiet way to hold privilege across a cleanup"
                        .into(),
                }),

                Some(u) if u != 0 && u < 1000 => out.push(Finding {
                    severity: Severity::Critical,
                    subject: m.clone(),
                    what: format!("is a system account (uid {u}) in the {label}, which can {grants}"),
                    why: "daemons are given the privileges they need directly; a service \
                          account holding a general path to root is a common way to keep \
                          access that looks like part of the system"
                        .into(),
                }),
                Some(_) if root_equivalent => out.push(Finding {
                    severity: Severity::Warn,
                    subject: m.clone(),
                    what: format!(
                        "is in the {label}, which can {grants} — root-equivalent, with no \
                         password prompt"
                    ),
                    why: "this is a full path to root that sudo logging and password \
                          prompts never see, and it is routinely granted without that \
                          being understood"
                        .into(),
                }),
                Some(_) => out.push(Finding {
                    severity: Severity::Note,
                    subject: m.clone(),
                    what: format!("is in the {label}, which can {grants}"),
                    why: "the ordinary administrator path. Listed so the set of accounts \
                          that can reach root is visible in one place"
                        .into(),
                }),
            }
        }

        let Some((grants, root_equivalent)) = privilege else { continue };
        for adm in &g.admins {
            let uid = uid_of.get(adm.as_str()).copied();
            if uid == Some(0) {
                continue;
            }
            out.push(Finding {
                severity: match uid {
                    Some(u) if u < 1000 => Severity::Critical,
                    None => Severity::Warn,
                    Some(_) if root_equivalent => Severity::Warn,
                    Some(_) => Severity::Note,
                },
                subject: adm.clone(),
                what: format!(
                    "administers the {label} in /etc/gshadow, so can add any account to it — \
                     itself included — and it can {grants}"
                ),
                why: "a group administrator runs `gpasswd -a` on the group with no password \
                      and no sudo, and distributions ship these lists empty. Membership is \
                      one command away and appears in no member list until it is used"
                    .into(),
            });
        }
    }

    for a in accounts {

        let (grants, root_equivalent, group) =
            if let Some((_, owner, grants, re)) = privilege_of(a.gid) {
                (grants, re, format!("`{owner}`"))
            } else if let Some((owner, grants, re)) = name_of_gid(a.gid).and_then(sudo_name) {
                let group = format!(
                    "gid {} — which getgrgid names `{owner}`, and sudo matches `%{owner}` \
                     against that name —",
                    a.gid
                );
                (grants, re, group)
            } else {
                continue;
            };

        if a.gid == 0 && a.uid == 0 {
            continue;
        }

        let severity = if a.uid != 0 && a.uid < 1000 {
            Severity::Critical
        } else if root_equivalent {
            Severity::Warn
        } else {
            Severity::Note
        };
        out.push(Finding {
            severity,
            subject: a.name.clone(),
            what: format!("has {group} as its PRIMARY group, which can {grants}"),
            why: "a primary group grants the same access as a secondary one and is listed \
                  nowhere in /etc/group, so it does not appear in the membership of that \
                  group. `id <user>` is what shows it. Granting privilege this way is \
                  quieter than adding a member line, which is the reason to look at it"
                .into(),
        });
    }
}

pub fn report() -> Report {
    let mut findings = Vec::new();

    let mut unread: Vec<String> = Vec::new();
    let mut passwd_reason: Option<String> = None;
    let (accounts, passwd_fields) = match crate::saferead::read_text(std::path::Path::new("/etc/passwd")) {
        Ok(text) => (parse_passwd(&text), parse_passwd_fields(&text)),
        Err(e) => {
            passwd_reason = Some(format!("/etc/passwd could not be read ({e})"));
            findings.push(Finding {
                severity: Severity::Warn,
                subject: "/etc/passwd".into(),
                what: "unreadable — account posture unknown".into(),
                why: format!(
                    "could not read the account list ({e}); a second uid-0, or a service \
                     account handed a login shell, would be invisible here. Re-run with \
                     privilege — and note that a read failure on a normally world-readable \
                     file can itself mean something is hooking open()/read()."
                ),
            });
            (Vec::new(), Vec::new())
        }
    };

    let mut groups = match crate::saferead::read_text(std::path::Path::new("/etc/group")) {
        Ok(text) => parse_group(&text),
        Err(e) => {
            unread.push(format!("/etc/group ({e})"));
            findings.push(Finding {
                severity: Severity::Warn,
                subject: "/etc/group".into(),
                what: "unreadable — group posture unknown".into(),
                why: format!(
                    "could not read the group file ({e}); a path to root through group \
                     membership — an out-of-place member of a privileged group — would be \
                     invisible here."
                ),
            });
            Vec::new()
        }
    };

    match crate::saferead::read_text(std::path::Path::new("/etc/gshadow")) {
        Ok(text) => apply_gshadow(&mut groups, &parse_gshadow(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            unread.push(format!("/etc/gshadow ({e})"));
            findings.push(Finding {
                severity: Severity::Warn,
                subject: "/etc/gshadow".into(),
                what: format!("could not be read ({e}) — no group password was checked"),
                why: "a group password set with `gpasswd`, or a member listed only here, lets \
                      an account `newgrp` into a privileged group, and would be invisible to \
                      this run. Re-run as root; until then group membership is partly unchecked"
                    .into(),
            });
        }
    }

    structural(&accounts, &mut findings);
    group_membership(&accounts, &groups, &mut findings);
    sudoers(&mut findings, &mut unread);

    passwd_field_passwords(&accounts, &passwd_fields, &mut findings);

    match crate::saferead::read_text(std::path::Path::new("/etc/shadow")) {
        Ok(text) => passwords(&accounts, &parse_shadow(&text), &mut findings),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            unread.push("/etc/shadow (permission denied)".into());
            findings.push(Finding {
                severity: Severity::Warn,
                subject: "/etc/shadow".into(),
                what: "unreadable — no password could be checked".into(),
                why: "an account with an empty password field, or one still hashed with MD5 \
                      or DES, would be invisible to this run. Re-run as root; until then the \
                      password surface is unchecked rather than clean"
                    .into(),
            });
        }

        Err(e) => {
            unread.push(format!("/etc/shadow ({e})"));
            findings.push(Finding {
                severity: Severity::Warn,
                subject: "/etc/shadow".into(),
                what: format!("could not be read ({e}) — no password could be checked"),
                why: "this is 'could not look', not 'nothing to find': an empty password \
                      field or a legacy hash would be invisible to this run. A single \
                      non-UTF-8 byte in the file is enough to land here, and is itself \
                      worth explaining"
                    .into(),
            });
        }
    }

    if let Ok(md) = fs::metadata("/etc/shadow") {
        use std::os::unix::fs::PermissionsExt as _;
        let full = md.permissions().mode() & 0o777;
        if full & 0o007 != 0 {
            findings.push(Finding {
                severity: Severity::Critical,
                subject: "/etc/shadow".into(),
                what: format!("world-accessible (0{full:03o})"),
                why: "password hashes any local account can read can be taken away and \
                      cracked offline, at the attacker's leisure".into(),
            });
        }
    }

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    Report {
        accounts,
        findings,
        available: passwd_reason.is_none(),
        reason: passwd_reason,
        unread,
    }
}
