use std::collections::{BTreeMap, BTreeSet};

use hs_core::severity::Severity;
use sha2::{Digest as _, Sha256};

use crate::configxml::{self, Config};
pub use crate::drift::Finding;
use crate::evidence::{Evidence, Judged, Obs};

pub const MASTER_PASSWD: &str = "/etc/master.passwd";

pub const GROUP: &str = "/etc/group";

pub const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";

pub const SUDOERS: &str = "/usr/local/etc/sudoers";

pub const DOAS_CONF: &str = "/usr/local/etc/doas.conf";

pub const DEFAULT_KEY_FILES: &[&str] = &[".ssh/authorized_keys", ".ssh/authorized_keys2"];

const HOME_DIR: &str = "home";

pub const MAX_ACCOUNTS: usize = 1024;

pub const MAX_SUDOERS_FILES: usize = 64;

pub const MAX_SMALL: u64 = 1024 * 1024;

pub const SYSTEM_ACCOUNTS: &[&str] = &[
    "root", "toor", "daemon", "operator", "bin", "tty", "kmem", "games", "news", "man", "sshd", "smmsp",
    "mailnull", "bind", "unbound", "proxy", "_pflogd", "_dhcp", "uucp", "pop", "auditdistd", "www", "ntpd",
    "_ypldap", "hast", "tests", "nobody", "cyrus", "messagebus", "openvpn", "dhcpd",
];

const NO_LOGIN: &[&str] = &["nologin", "false", "true"];

const RESTRICTED: &[&str] = &["scponly", "scponlyc", "ssh_tunnel_shell", "uucico"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passwd {

    pub name: String,

    pub uid: Option<u32>,

    pub gid: Option<u32>,

    pub password: Password,

    pub home: String,

    pub shell: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Password {

    Locked,

    Empty,

    Set,
}

impl Passwd {

    pub fn shell_name(&self) -> &str {
        if self.shell.is_empty() {
            return "sh";
        }
        self.shell.rsplit('/').next().unwrap_or("")
    }

    pub fn interactive(&self) -> bool {
        let n = self.shell_name();
        !NO_LOGIN.contains(&n) && !RESTRICTED.contains(&n)
    }
}

pub fn parse_master_passwd(text: &str) -> Vec<Passwd> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() != 10 {
                return None;
            }
            let pw = f.get(1).copied().unwrap_or_default();
            let password = if pw.is_empty() {
                Password::Empty
            } else if pw.starts_with('*') {
                Password::Locked
            } else {
                Password::Set
            };
            Some(Passwd {
                name: f.first().copied().unwrap_or_default().to_string(),
                uid: f.get(2).and_then(|u| u.parse().ok()),
                gid: f.get(3).and_then(|g| g.parse().ok()),
                password,
                home: f.get(8).copied().unwrap_or_default().to_string(),
                shell: f.get(9).copied().unwrap_or_default().to_string(),
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsGroup {

    pub name: String,

    pub gid: Option<u32>,

    pub members: Vec<String>,
}

pub fn parse_group(text: &str) -> Vec<OsGroup> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() != 4 {
                return None;
            }
            Some(OsGroup {
                name: f.first().copied().unwrap_or_default().to_string(),
                gid: f.get(2).and_then(|g| g.parse().ok()),
                members: f
                    .get(3)
                    .copied()
                    .unwrap_or_default()
                    .split(',')
                    .map(str::trim)
                    .filter(|m| !m.is_empty())
                    .map(str::to_string)
                    .collect(),
            })
        })
        .collect()
}

const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

fn is_key_type(t: &str) -> bool {
    KEY_TYPES.contains(&t) || t.ends_with("-cert-v01@openssh.com")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {

    pub options: String,

    pub kind: String,

    pub blob: String,

    pub comment: String,
}

impl Key {

    pub fn fingerprint(&self) -> Option<String> {
        let raw = configxml::base64_decode(&self.blob).ok()?;
        Some(format!("SHA256:{}", base64_nopad(&Sha256::digest(&raw))))
    }

    pub fn render(&self) -> String {
        let fp = self.fingerprint().unwrap_or_else(|| "undecodable key".into());
        let mut s = format!("{} {fp}", self.kind);
        if !self.comment.is_empty() {
            s.push_str(&format!(" ({})", self.comment));
        }
        if !self.options.is_empty() {
            s.push_str(&format!(" with options {}", self.options));
        }
        s
    }
}

pub fn base64_nopad(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in b.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, &x)| acc | (u32::from(x) << (16 - 8 * i)));
        let chars = chunk.len() + 1;
        for i in 0..chars {
            let idx = ((n >> (18 - 6 * i)) & 63) as usize;
            out.push(char::from(A.get(idx).copied().unwrap_or(b'A')));
        }
    }
    out
}

fn split_options(line: &str) -> (&str, &str) {
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => quoted = !quoted,
            ' ' | '\t' if !quoted => return (line.get(..i).unwrap_or(line), line.get(i..).unwrap_or("").trim_start()),
            _ => {}
        }
    }
    (line, "")
}

pub fn parse_authorized_keys(text: &str) -> (Vec<Key>, Vec<String>) {
    let mut keys = Vec::new();
    let mut junk = Vec::new();
    for l in text.lines() {
        let t = l.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let (first, rest) = split_options(t);
        let (options, body) = if is_key_type(first) { ("", t) } else { (first, rest) };
        let mut it = body.splitn(3, [' ', '\t']);
        let kind = it.next().unwrap_or_default();
        let blob = it.next().unwrap_or_default().trim();
        if !is_key_type(kind) || blob.is_empty() {
            junk.push(t.chars().take(120).collect());
            continue;
        }
        keys.push(Key {
            options: options.to_string(),
            kind: kind.to_string(),
            blob: blob.to_string(),
            comment: it.next().unwrap_or_default().trim().to_string(),
        });
    }
    (keys, junk)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeySources {

    pub files: Vec<String>,

    pub command: Option<String>,

    pub includes: Vec<String>,
}

pub fn key_sources(text: &str) -> KeySources {
    let mut s = KeySources::default();
    for l in text.lines() {
        let t = l.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let (k, v) = t.split_once(|c: char| c.is_whitespace() || c == '=').unwrap_or((t, ""));
        let v = v.trim_start_matches(|c: char| c.is_whitespace() || c == '=').trim();
        match k.to_ascii_lowercase().as_str() {
            "authorizedkeysfile" => {
                for p in v.split_whitespace() {
                    if p != "none" && !s.files.iter().any(|f| f == p) {
                        s.files.push(p.to_string());
                    }
                }
            }
            "authorizedkeyscommand" if !v.eq_ignore_ascii_case("none") && !v.is_empty() => {
                s.command = Some(v.to_string());
            }
            "include" => s.includes.push(v.to_string()),
            _ => {}
        }
    }
    if s.files.is_empty() {
        s.files = DEFAULT_KEY_FILES.iter().map(|f| (*f).to_string()).collect();
    }
    s
}

pub fn key_path(pattern: &str, user: &str, home: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('h') => out.push_str(home),
            Some('u') => out.push_str(user),
            Some('%') => out.push('%'),

            _ => return None,
        }
    }
    if out.starts_with('/') {
        Some(out)
    } else if home.starts_with('/') {
        Some(format!("{}/{out}", home.trim_end_matches('/')))
    } else {
        None
    }
}

pub fn key_files(accounts: &[Passwd], cfg_users: &[configxml::User], sources: &KeySources) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let homes = accounts
        .iter()
        .take(MAX_ACCOUNTS)
        .map(|a| (a.name.clone(), a.home.clone()))

        .chain(cfg_users.iter().filter(|u| !accounts.iter().any(|a| a.name == u.name)).map(|u| (u.name.clone(), format!("/{HOME_DIR}/{}", u.name))));
    for (name, home) in homes {
        for p in &sources.files {
            if let Some(f) = key_path(p, &name, &home) {
                let v = out.entry(f).or_default();
                if !v.contains(&name) {
                    v.push(name.clone());
                }
            }
        }
    }
    out
}

pub fn sudoers_lines(text: &str) -> Vec<String> {
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
    if t.is_empty() {
        return true;
    }
    let Some(rest) = t.strip_prefix('#') else { return false };
    if rest.starts_with("include") {
        return false;
    }
    let id = rest.strip_prefix('-').unwrap_or(rest);
    let after = id.trim_start_matches(|c: char| c.is_ascii_digit());
    !(after.len() < id.len() && after.starts_with([' ', '\t', ',', '\\']))
}

pub fn sudoers_includes(text: &str, from: &str) -> Vec<(bool, String)> {
    let base = from.rsplit_once('/').map_or("/usr/local/etc", |(d, _)| d);
    sudoers_lines(text)
        .iter()
        .filter_map(|l| {
            let (dir, rest) = ["#includedir", "@includedir"]
                .iter()
                .find_map(|p| l.strip_prefix(p).map(|r| (true, r)))
                .or_else(|| ["#include", "@include"].iter().find_map(|p| l.strip_prefix(p).map(|r| (false, r))))?;
            if !rest.starts_with([' ', '\t']) {
                return None;
            }
            let p = rest.trim().trim_matches('"');
            if p.is_empty() || p.contains("%h") {
                return None;
            }
            Some((dir, if p.starts_with('/') { p.to_string() } else { format!("{base}/{p}") }))
        })
        .collect()
}

pub fn sudoers_nopasswd(text: &str) -> Vec<String> {
    sudoers_lines(text)
        .into_iter()
        .filter(|t| {
            t.contains("NOPASSWD")
                || (t.starts_with("Defaults") && t.split('!').skip(1).any(|r| r.trim_start().starts_with("authenticate")))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoasRule {

    pub action: String,

    pub nopass: bool,

    pub line: String,
}

pub fn parse_doas(text: &str) -> Vec<DoasRule> {
    let mut lines = Vec::new();
    let mut pending = String::new();
    for l in text.lines() {
        let l = l.split('#').next().unwrap_or("").trim();
        let (body, more) = match l.strip_suffix('\\') {
            Some(b) => (b.trim_end(), true),
            None => (l, false),
        };
        if !pending.is_empty() && !body.is_empty() {
            pending.push(' ');
        }
        pending.push_str(body);
        if !more && !pending.is_empty() {
            lines.push(std::mem::take(&mut pending));
        }
    }
    if !pending.is_empty() {
        lines.push(pending);
    }
    lines
        .into_iter()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let action = words.next()?.to_string();
            if action != "permit" && action != "deny" {
                return None;
            }

            let mut nopass = false;
            let mut in_env = false;
            for w in words {
                if in_env {
                    in_env = !w.ends_with('}');
                    continue;
                }
                match w {
                    "nopass" => nopass = true,
                    "nolog" | "persist" | "keepenv" => {}
                    "setenv" | "setenv{" => in_env = !w.ends_with('}'),
                    "{" => {}
                    _ if w.starts_with("setenv{") => in_env = !w.ends_with('}'),
                    _ => break,
                }
            }
            Some(DoasRule { action, nopass, line })
        })
        .collect()
}

pub fn sudoers_sources(ev: &Evidence) -> (Vec<String>, Vec<String>) {
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    let mut queue = std::collections::VecDeque::from([(false, SUDOERS.to_string())]);
    let mut seen = BTreeSet::new();
    while let Some((is_dir, p)) = queue.pop_front() {
        if !seen.insert(p.clone()) || files.len() + dirs.len() >= MAX_SUDOERS_FILES {
            continue;
        }
        if is_dir {
            for e in ev.dir(&p).unwrap_or_default() {

                if !e.name.contains('.') && !e.name.ends_with('~') {
                    queue.push_back((false, crate::evidence::join(&p, &e.name)));
                }
            }
            dirs.push(p);
        } else {
            if let Some(t) = ev.text(&p) {
                queue.extend(sudoers_includes(&t, &p));
            }
            files.push(p);
        }
    }
    (files, dirs)
}

#[cfg(unix)]
pub fn gather(c: &mut crate::evidence::Collector) {
    c.file(configxml::CONFIG_PATH, configxml::MAX_BYTES);
    c.file(MASTER_PASSWD, crate::saferead::MAX_SCAN_BYTES);
    c.file(GROUP, crate::saferead::MAX_SCAN_BYTES);
    c.file(SSHD_CONFIG, MAX_SMALL);
    let accounts = c.ev.text(MASTER_PASSWD).map(|t| parse_master_passwd(&t)).unwrap_or_default();
    let users = c.ev.bytes(configxml::CONFIG_PATH).and_then(|b| configxml::parse(b).ok()).map(|c| c.users()).unwrap_or_default();
    let sources = key_sources(&c.ev.text(SSHD_CONFIG).unwrap_or_default());
    for f in key_files(&accounts, &users, &sources).keys() {
        c.file(f, MAX_SMALL);
    }

    let mut queue = std::collections::VecDeque::from([(false, SUDOERS.to_string())]);
    let mut seen = BTreeSet::new();
    while let Some((is_dir, p)) = queue.pop_front() {
        if !seen.insert(p.clone()) || seen.len() > MAX_SUDOERS_FILES {
            continue;
        }
        if is_dir {
            c.list(&p);
            let names: Vec<String> = c.ev.dir(&p).unwrap_or_default().iter().map(|e| e.name.clone()).collect();
            for n in names.into_iter().filter(|n| !n.contains('.') && !n.ends_with('~')) {
                queue.push_back((false, crate::evidence::join(&p, &n)));
            }
        } else {
            c.file(&p, MAX_SMALL);
            if let Some(t) = c.ev.text(&p) {
                queue.extend(sudoers_includes(&t, &p));
            }
        }
    }
    c.file(DOAS_CONF, MAX_SMALL);
}

fn shell_config_gives(u: &configxml::User, privs: &BTreeSet<String>) -> (&'static str, bool) {
    if u.uid == "0" {
        return ("/etc/rc.initial", true);
    }
    if u.disabled {
        return ("/sbin/nologin", false);
    }
    if privs.contains("user-shell-access") || privs.contains("page-all") {
        ("/bin/tcsh", true)
    } else if privs.contains("user-copy-files-chroot") {
        ("/usr/local/sbin/scponlyc", false)
    } else if privs.contains("user-copy-files") {
        ("/usr/local/bin/scponly", false)
    } else if privs.contains("user-ssh-tunnel") {
        ("/usr/local/sbin/ssh_tunnel_shell", false)
    } else {
        ("/sbin/nologin", false)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Opts {

    pub operator_keys: Vec<String>,
}

const CONFIRM: &str = "Confirm by hand — a legitimate admin's looks identical — and act on it only \
                       through the operator interface; nothing here changes an account";

pub fn judge(ev: &Evidence, opts: &Opts) -> Judged {
    let mut j = Judged::default();
    let mut f = |sev, subject: &str, what: String, why: &str| {
        j.findings.push(Finding { severity: sev, subject: subject.to_string(), what, why: why.to_string() });
    };
    let mut gaps = Vec::new();

    let cfg: Option<Config> = match ev.bytes(configxml::CONFIG_PATH) {
        Some(b) => match configxml::parse(b) {
            Ok(c) => Some(c),
            Err(e) => {
                gaps.push(format!("config.xml was sealed but not read ({e}): nothing could be compared with it"));
                None
            }
        },
        None => {
            gaps.push(format!("{}: {}", configxml::CONFIG_PATH, ev.unread(configxml::CONFIG_PATH).unwrap_or_else(|| "absent".into())));
            None
        }
    };
    let users = cfg.as_ref().map(Config::users).unwrap_or_default();
    let groups = cfg.as_ref().map(Config::groups).unwrap_or_default();
    let accounts = match ev.text(MASTER_PASSWD) {
        Some(t) => parse_master_passwd(&t),
        None => {
            gaps.push(format!("{MASTER_PASSWD}: {}", ev.unread(MASTER_PASSWD).unwrap_or_else(|| "absent".into())));
            Vec::new()
        }
    };
    let os_groups = match ev.text(GROUP) {
        Some(t) => parse_group(&t),
        None => {
            gaps.push(format!("{GROUP}: {}", ev.unread(GROUP).unwrap_or_else(|| "absent".into())));
            Vec::new()
        }
    };
    let cfg_root = users.iter().find(|u| u.uid == "0").map(|u| u.name.clone());
    let cfg_by_name: BTreeMap<&str, &configxml::User> = users.iter().map(|u| (u.name.as_str(), u)).collect();

    let mut privs: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut admins: BTreeSet<String> = BTreeSet::new();
    for u in &users {
        let mut p: BTreeSet<String> = u.privs.iter().cloned().collect();
        for g in groups.iter().filter(|g| g.members.contains(&u.uid)) {
            p.extend(g.privs.iter().cloned());
            if g.name == "admins" {
                admins.insert(u.name.clone());
            }
        }
        privs.insert(u.name.clone(), p);
    }

    for u in &users {
        if Some(&u.name) == cfg_root.as_ref() || u.disabled {
            continue;
        }
        let p = privs.get(&u.name).cloned().unwrap_or_default();
        let mut held: Vec<&str> = configxml::PRIVILEGED_PRIVS.iter().copied().filter(|x| p.contains(*x)).collect();
        if admins.contains(&u.name) {
            held.push("membership of admins");
        }
        if !held.is_empty() {
            f(
                Severity::Critical,
                &format!("config user {}", u.name),
                format!("config user {} (uid {}) holds {}", u.name, u.uid, held.join(", ")),
                &format!(
                    "each is the whole box: page-all includes the command prompt and the file editor, \
                     user-shell-access is a shell, admins grants page-all. A factory box gives them to \
                     the uid-0 account alone, so this one gained it. {CONFIRM}"
                ),
            );
        }
    }
    for u in users.iter().filter(|u| u.uid == "0") {
        if Some(&u.name) != cfg_root.as_ref() {
            f(
                Severity::Critical,
                &format!("config user {}", u.name),
                format!("a second config user with uid 0: {}", u.name),
                &format!("pfSense has one uid-0 account ({}); a second is a second root. {CONFIRM}", cfg_root.as_deref().unwrap_or("?")),
            );
        }
    }

    let uid0_ok = |a: &Passwd| a.name == "root" || Some(&a.name) == cfg_root.as_ref() || (a.name == "toor" && a.password == Password::Locked);
    for a in &accounts {
        let subject = format!("account {}", a.name);
        if a.uid == Some(0) && !uid0_ok(a) {
            let why = if a.name == "toor" {
                "toor is FreeBSD's spare root and ships locked; with a password it is a second way in as root"
            } else {
                "a second uid 0 is a second root, whatever it is called"
            };
            f(Severity::Critical, &subject, format!("{} has uid 0 ({})", a.name, pw_word(a.password)), &format!("{why}. {CONFIRM}"));
        }
        if a.uid.is_none() {
            f(Severity::Warn, &subject, format!("{} has a uid that is not a number", a.name), "pwd_mkdb would refuse this file; it was not written by pfSense");
        }
        let in_cfg = cfg_by_name.get(a.name.as_str());
        let is_cfg_root = Some(&a.name) == cfg_root.as_ref();
        if let Some(u) = in_cfg.filter(|_| !is_cfg_root) {
            let p = privs.get(&u.name).cloned().unwrap_or_default();
            let (want, way_in) = shell_config_gives(u, &p);
            if a.interactive() && !way_in {
                f(
                    Severity::Critical,
                    &subject,
                    format!("{} has the shell {}; its config privileges give {want}", a.name, shown_shell(a)),
                    &format!(
                        "pfSense writes the shell from the account's privileges, so a shell they do not \
                         grant was set outside the GUI — user-shell-access gained by hand. {CONFIRM}"
                    ),
                );
            }
        } else if !is_cfg_root && a.uid != Some(0) {
            let system = SYSTEM_ACCOUNTS.contains(&a.name.as_str());
            if a.interactive() && a.name != "root" {
                let why = if system {
                    "a service account ships with nologin; one with a shell is a way in that no config \
                     account accounts for"
                } else {
                    "pfSense makes every login account from config.xml, and this one is not in it: it was \
                     made by hand, outside the GUI, and it has a shell"
                };
                f(
                    Severity::Critical,
                    &subject,
                    format!("{} (uid {}) has the shell {} and is no config user", a.name, uid_word(a.uid), shown_shell(a)),
                    &format!("{why}. {CONFIRM}"),
                );
            } else if !system {
                f(
                    Severity::Note,
                    &subject,
                    format!("{} (uid {}) is neither a config user nor a stock account, and has no shell", a.name, uid_word(a.uid)),
                    "a package may have made it; it cannot log in as it stands",
                );
            }
        }

        if a.gid == Some(0) && a.name != "root" && a.name != "toor" && !is_cfg_root {
            f(
                Severity::Critical,
                &subject,
                format!("{} has wheel (gid 0) as its primary group", a.name),
                &format!("wheel is who may become root; pfSense gives it to the uid-0 account only. {CONFIRM}"),
            );
        }
    }
    for u in &users {
        if !accounts.is_empty() && !accounts.iter().any(|a| a.name == u.name) && u.uid != "0" {
            f(
                Severity::Note,
                &format!("config user {}", u.name),
                format!("config user {} is not in {MASTER_PASSWD}", u.name),
                "pfSense has not written it out (or it was removed by hand); it cannot log in as it stands",
            );
        }
    }

    let uid_of = |name: &str| accounts.iter().find(|a| a.name == name).and_then(|a| a.uid);
    for g in &os_groups {
        if g.name == "wheel" {
            for m in g.members.iter().filter(|m| m.as_str() != "root" && Some(*m) != cfg_root.as_ref()) {
                f(
                    Severity::Critical,
                    "group wheel",
                    format!("{m} is in wheel"),
                    &format!("wheel is who may `su` to root; a factory box has root alone in it. {CONFIRM}"),
                );
            }
        }
        if let Some(cg) = groups.iter().find(|c| c.name == g.name && c.privileged()) {
            let want: BTreeSet<String> = cg.members.clone().into_iter().collect();
            for m in &g.members {
                let ok = uid_of(m).is_some_and(|u| want.contains(&u.to_string()));
                if !ok {
                    f(
                        Severity::Critical,
                        &format!("group {}", g.name),
                        format!("{m} is in {} in {GROUP}, and config.xml does not put it there", g.name),
                        &format!("pfSense writes this group from config; a member it does not list was added by hand. {CONFIRM}"),
                    );
                }
            }
        }
    }

    let sources = key_sources(&ev.text(SSHD_CONFIG).unwrap_or_default());
    if ev.bytes(SSHD_CONFIG).is_none() {
        gaps.push(format!("{SSHD_CONFIG}: {}; sshd's default key files were assumed", ev.unread(SSHD_CONFIG).unwrap_or_else(|| "absent".into())));
    }
    if let Some(cmd) = &sources.command {
        f(
            Severity::Warn,
            SSHD_CONFIG,
            format!("AuthorizedKeysCommand {cmd}"),
            "sshd asks this program for keys, so who can log in is not in any file this sweep reads; \
             pfSense does not set it",
        );
    }
    for inc in &sources.includes {
        f(Severity::Warn, SSHD_CONFIG, format!("Include {inc}"), "pfSense writes no Include; what it pulls in was not read");
    }
    let enrolled: BTreeSet<&str> = opts.operator_keys.iter().map(String::as_str).collect();
    let mut seen_enrolled = BTreeSet::new();
    for (file, names) in key_files(&accounts, &users, &sources) {
        let text = match ev.obs.get(&file) {
            Some(Obs::Bytes(b)) => String::from_utf8_lossy(b).into_owned(),
            Some(Obs::Absent) => continue,
            Some(Obs::Link(t)) => {
                f(
                    Severity::Warn,
                    &file,
                    format!("a symlink to {t}, not read"),
                    "pfSense writes a plain file here; the link's target is a key file for whoever can write it",
                );
                continue;
            }
            Some(Obs::Dir(_)) => continue,
            _ => {
                gaps.push(format!("{file}: {}", ev.unread(&file).unwrap_or_default()));
                continue;
            }
        };

        let mut owners: Vec<&configxml::User> = names.iter().filter_map(|n| cfg_by_name.get(n.as_str()).copied()).collect();
        if names.iter().any(|n| accounts.iter().any(|a| &a.name == n && a.uid == Some(0))) {
            owners.extend(users.iter().filter(|u| u.uid == "0"));
        }
        let mut want: BTreeSet<(String, String)> = BTreeSet::new();
        for u in &owners {
            if let Some(Ok(t)) = &u.authorized_keys {
                want.extend(parse_authorized_keys(t).0.into_iter().map(|k| (k.kind, k.blob)));
            }
        }
        let (keys, junk) = parse_authorized_keys(&text);
        let who = names.join(", ");
        for k in keys {
            let fp = k.fingerprint();
            if fp.as_deref().is_some_and(|fp| enrolled.contains(fp)) {
                seen_enrolled.insert(fp.clone().unwrap_or_default());
                f(
                    Severity::Note,
                    &file,
                    format!("the enrolled operator key, for {who}: {}", k.render()),
                    "your own way in, named so it is not taken for anyone else's",
                );
                continue;
            }
            if want.contains(&(k.kind.clone(), k.blob.clone())) {
                continue;
            }
            f(
                Severity::Critical,
                &file,
                format!("a key for {who} that config.xml does not hold: {}", k.render()),
                &format!(
                    "pfSense writes this file from the account's config keys and nothing else, so a key \
                     only the file has was put there by hand. It logs in without a password. {CONFIRM}"
                ),
            );
        }
        for l in junk {
            f(Severity::Note, &file, format!("a line that is not a key: {l}"), "sshd ignores it; pfSense never writes one");
        }
    }
    for k in &opts.operator_keys {
        if !seen_enrolled.contains(k) {
            f(
                Severity::Note,
                "operator key",
                format!("the enrolled operator key {k} is in no key file read"),
                "check the fingerprint you enrolled; this run cannot tell your key from anyone else's",
            );
        }
    }

    if let Some(c) = &cfg {
        for r in c.sudo_rows() {
            let line = format!("{} may run {} as {}", r.username, if r.cmdlist.is_empty() { "ALL" } else { &r.cmdlist }, r.runas);
            if r.nopasswd {
                f(
                    Severity::Critical,
                    "sudo package",
                    format!("nopasswd=ON: {line}, with no password"),
                    &format!("the sudo package writes this row as a NOPASSWD: grant — root with no credential for whoever holds that account. Always Critical. {CONFIRM}"),
                );
            } else {
                f(Severity::Note, "sudo package", format!("a sudo row: {line}"), "a grant that asks for the account's password");
            }
        }
    }
    let (files, dirs) = sudoers_sources(ev);
    for p in files.iter().chain(dirs.iter()) {
        if let Some(why) = ev.unread(p) {
            gaps.push(format!("{p}: {why}; a password-free grant there would be invisible"));
        }
    }
    for p in &files {
        if let Some(t) = ev.text(p) {
            for line in sudoers_nopasswd(&t) {
                f(
                    Severity::Critical,
                    p,
                    format!("a password-free sudo grant: {line}"),
                    &format!("root with no credential for that principal. Always Critical, never allowlisted. {CONFIRM}"),
                );
            }
        }
    }
    match ev.obs.get(DOAS_CONF) {
        Some(Obs::Bytes(b)) => {
            for r in parse_doas(&String::from_utf8_lossy(b)) {
                if r.action == "permit" && r.nopass {
                    f(
                        Severity::Critical,
                        DOAS_CONF,
                        format!("a doas rule with nopass: {}", r.line),
                        &format!("doas without a password — root with no credential. Always Critical. {CONFIRM}"),
                    );
                } else if r.action == "permit" {
                    f(Severity::Note, DOAS_CONF, format!("a doas rule: {}", r.line), "a grant that asks for the account's password");
                }
            }
        }
        Some(Obs::Absent) => {}
        _ => gaps.push(format!("{DOAS_CONF}: {}", ev.unread(DOAS_CONF).unwrap_or_default())),
    }

    j.gaps = gaps;
    j.sort();
    j
}

fn pw_word(p: Password) -> &'static str {
    match p {
        Password::Locked => "locked",
        Password::Empty => "NO password",
        Password::Set => "a password set",
    }
}

fn uid_word(u: Option<u32>) -> String {
    u.map_or_else(|| "?".into(), |u| u.to_string())
}

fn shown_shell(a: &Passwd) -> String {
    if a.shell.is_empty() {
        "(empty, so /bin/sh)".into()
    } else {
        a.shell.clone()
    }
}
