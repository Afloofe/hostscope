use std::collections::{BTreeMap, BTreeSet};

use hs_core::severity::Severity;
use hs_core::snapshot::{Change, Snapshot};
use sha2::{Digest as _, Sha256};

use crate::configxml::{CertKind, Config, Element, ShellKind};

pub const SCOPE: u32 = 1;

pub const KIND: &str = "pfsense-config";

pub const PACKAGE_SHELLCMDS: &[(&str, &str, ShellKind, &str)] = &[
    ("System Patches", "systempatches.xml", ShellKind::Early, "/usr/local/bin/php-cgi -f /usr/local/bin/apply_patches.php"),
    ("pfBlockerNG", "pfblockerng.xml", ShellKind::Early, "/usr/local/pkg/pfblockerng/pfblockerng.sh aliastables"),
];

const MAX_SHOWN: usize = 256;

const MAX_TOKEN: usize = 120;

const MAX_LINES: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {

    pub severity: Severity,

    pub subject: String,

    pub what: String,

    pub why: String,
}

fn short(b: &[u8]) -> String {
    Sha256::digest(b).iter().take(8).map(|x| format!("{x:02x}")).collect()
}

fn secret(salt: &[u8; 16], v: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"hemostat/config-secret/v1");
    h.update(salt);
    h.update(v.as_bytes());
    let d: Vec<u8> = h.finalize().to_vec();
    format!("secret:{}", d.iter().take(8).map(|x| format!("{x:02x}")).collect::<String>())
}

fn is_secret(field: &str) -> bool {
    let leaf = field.rsplit(['/', '@']).next().unwrap_or(field).to_ascii_lowercase();
    ["pass", "pw", "secret", "psk", "prv", "hash", "key", "tls", "token", "community", "shared"]
        .iter()
        .any(|w| leaf.contains(w))
        && leaf != "authorizedkeys"
}

fn shown(salt: &[u8; 16], field: &str, v: &str) -> String {
    if v.is_empty() {
        return String::new();
    }

    let flag = matches!(
        v.to_ascii_lowercase().as_str(),
        "on" | "off" | "yes" | "no" | "enabled" | "disabled" | "true" | "false" | "0" | "1"
    );
    if is_secret(field) && !flag {
        return secret(salt, v);
    }

    let blob = v.len() > MAX_TOKEN && !v.contains(' ');
    if v.len() > MAX_SHOWN || v.contains('\n') || blob {
        return format!("sha256:{} ({} bytes)", short(v.as_bytes()), v.len());
    }
    v.to_string()
}

fn flat(salt: &[u8; 16], leaves: &[(String, String)]) -> String {
    leaves.iter().map(|(k, v)| format!("{k}={}", shown(salt, k, v))).collect::<Vec<_>>().join("\n")
}

fn by_content(items: &mut BTreeMap<String, String>, prefix: &str, value: String) {
    let base = format!("{prefix}/{}", short(value.as_bytes()).get(..12).unwrap_or_default());
    let mut key = base.clone();
    let mut n = 1;
    while items.contains_key(&key) {
        n += 1;
        key = format!("{base}#{n}");
    }
    items.insert(key, value);
}

fn unique(items: &mut BTreeMap<String, String>, key: String, value: String) {
    let mut k = key.clone();
    let mut n = 1;
    while items.contains_key(&k) {
        n += 1;
        k = format!("{key}#{n}");
    }
    items.insert(k, value);
}

pub fn items(c: &Config, salt: &[u8; 16]) -> BTreeMap<String, String> {
    let mut it = BTreeMap::new();
    let root = c.root();
    if let Some(v) = c.version() {
        it.insert("config/version".into(), v.to_string());
    }

    for u in c.users() {
        let v = format!(
            "uid={}; scope={}; groupname={}; priv={}; disabled={}; expires={}",
            u.uid,
            u.scope,
            u.groupname,
            u.privs.join(","),
            if u.disabled { "yes" } else { "no" },
            u.expires
        );
        unique(&mut it, format!("config/user/{}", u.name), v);
        if let Some((kind, hash)) = &u.password {
            unique(&mut it, format!("config/password/{}", u.name), format!("{kind} {}", secret(salt, hash)));
        }
        if let Some(keys) = &u.authorized_keys {
            let v = match keys {
                Ok(t) => t.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("\n"),
                Err(why) => format!("UNDECODABLE ({why})"),
            };
            unique(&mut it, format!("config/authorizedkeys/{}", u.name), v);
        }
    }
    for g in c.groups() {
        let v = format!("gid={}; scope={}; member={}; priv={}", g.gid, g.scope, g.members.join(","), g.privs.join(","));
        unique(&mut it, format!("config/group/{}", g.name), v);
    }

    let wan = c.wan_interfaces();
    let mut order = Vec::new();
    for r in c.rules() {
        let mut v = flat(salt, &r.fields);
        v.push_str(&format!("\nwan-facing-pass={}", if r.is_pass_on(&wan) { "yes" } else { "no" }));
        let id = match &r.tracker {
            Some(t) => t.clone(),
            None => format!("untracked-{}", short(v.as_bytes()).get(..12).unwrap_or_default()),
        };
        let key = format!("config/filter/rule/{id}");
        let key = if it.contains_key(&key) { format!("{key}#{}", r.index) } else { key };
        order.push(key.trim_start_matches("config/filter/rule/").to_string());
        it.insert(key, v);
    }
    if !order.is_empty() {
        it.insert("config/filter/order".into(), order.join("\n"));
    }

    if let Some(nat) = root.child("nat") {
        for r in nat.all("rule") {
            by_content(&mut it, "config/nat/rule", flat(salt, &r.leaves()));
        }
        for (list, path) in [("onetoone", "onetoone"), ("npt", "npt")] {
            for r in nat.all(path) {
                by_content(&mut it, &format!("config/nat/{list}"), flat(salt, &r.leaves()));
            }
        }
        if let Some(out) = nat.child("outbound") {
            for r in out.all("rule") {
                by_content(&mut it, "config/nat/outbound", flat(salt, &r.leaves()));
            }
            if let Some(m) = out.text_at("mode") {
                it.insert("config/nat/outbound-mode".into(), m.to_string());
            }
        }
        let rest: Vec<&Element> =
            nat.children.iter().filter(|e| !matches!(e.name.as_str(), "rule" | "onetoone" | "npt" | "outbound")).collect();
        section(&mut it, salt, "nat", &rest);
    }

    for s in c.shellcmds() {
        by_content(&mut it, &format!("config/shellcmd/{}", s.kind.element()), s.command);
    }
    for i in c.cron_items() {
        by_content(&mut it, "config/cron", i.line());
    }

    if let Some(ip) = root.child("installedpackages") {
        for p in c.packages() {
            unique(
                &mut it,
                format!("config/package/{}", p.name),
                format!("version={}; configurationfile={}", p.version, p.configurationfile),
            );
        }
        let mut rest = Vec::new();
        for e in &ip.children {
            match e.name.as_str() {
                "package" => {}
                "menu" | "service" | "tab" => rest.push(e),
                name => unique(&mut it, format!("config/pkgconf/{name}"), flat(salt, &e.leaves())),
            }
        }
        section(&mut it, salt, "installedpackages", &rest);
    }

    if let Some(sys) = root.child("system") {
        for (part, key) in [("webgui", "webgui"), ("ssh", "ssh")] {
            if let Some(e) = sys.child(part) {
                for (field, v) in e.leaves() {
                    unique(&mut it, format!("config/{key}/{field}"), shown(salt, &field, &v));
                }
            }
        }
        for a in sys.all("authserver") {
            let name = a.text_at("name").unwrap_or_default().to_string();
            unique(&mut it, format!("config/authserver/{name}"), flat(salt, &a.leaves()));
        }
        let modelled = ["user", "group", "authserver", "webgui", "ssh", "earlyshellcmd", "shellcmd", "afterbootupshellcmd"];
        let rest: Vec<&Element> = sys.children.iter().filter(|e| !modelled.contains(&e.name.as_str())).collect();
        section(&mut it, salt, "system", &rest);
    }

    for kind in [CertKind::Cert, CertKind::Ca] {
        for cert in c.certs(kind) {

            let signs = match kind {
                CertKind::Cert => String::new(),
                CertKind::Ca => {
                    let any = crate::configxml::base64_decode(&cert.crt)
                        .ok()
                        .and_then(|pem| hemostat_evcrypto::x509::certs_in(&pem).0.into_iter().find_map(|(_, c)| c.ok()))
                        .map(|c| hemostat_evcrypto::x509::signs_any(&c));
                    format!(
                        "; trust={}; signs={}",
                        if cert.trust { "enabled" } else { "off" },
                        match any {
                            Some(true) => "any",
                            Some(false) => "limited",
                            None => "unread",
                        }
                    )
                }
            };
            let v = format!(
                "descr={}; crt=sha256:{}; private key={}{signs}",
                cert.descr,
                short(cert.crt.as_bytes()),
                if cert.has_private_key { "in config" } else { "none" }
            );
            unique(&mut it, format!("config/{}/{}", kind.element(), cert.refid), v);
        }
    }

    if let Some(filter) = root.child("filter") {
        let rest: Vec<&Element> = filter.children.iter().filter(|e| e.name != "rule").collect();
        section(&mut it, salt, "filter", &rest);
    }
    let modelled =
        ["version", "revision", "system", "filter", "nat", "cron", "installedpackages", "cert", "ca"];
    let mut seen = BTreeSet::new();
    for e in &root.children {
        if modelled.contains(&e.name.as_str()) || !seen.insert(e.name.clone()) {
            continue;
        }
        let all: Vec<&Element> = root.all(&e.name).collect();
        section(&mut it, salt, &e.name, &all);
    }
    it
}

fn section(it: &mut BTreeMap<String, String>, salt: &[u8; 16], name: &str, els: &[&Element]) {
    let mut lines = Vec::new();
    for e in els {
        if e.is_leaf() {
            lines.push((e.name.clone(), e.text.clone()));
        } else {
            lines.extend(e.leaves().into_iter().map(|(k, v)| (format!("{}/{k}", e.name), v)));
        }
    }
    if !lines.is_empty() {
        it.insert(format!("config/section/{name}"), flat(salt, &lines));
    }
}

pub fn snapshot(c: &Config, salt: &[u8; 16]) -> Snapshot {
    Snapshot { items: items(c, salt), scope: SCOPE, ..Snapshot::default() }
}

pub fn diff(was: &BTreeMap<String, String>, now: &BTreeMap<String, String>) -> Vec<Change> {
    let keys: BTreeSet<&String> = was.keys().chain(now.keys()).collect();
    keys.into_iter()
        .filter(|k| was.get(*k) != now.get(*k))
        .map(|k| Change { key: k.clone(), before: was.get(k).cloned(), after: now.get(k).cloned() })
        .collect()
}

pub fn moved(before: &str, after: &str) -> Vec<String> {
    let b: Vec<&str> = before.lines().collect();
    let a: Vec<&str> = after.lines().collect();
    let pos: BTreeMap<&str, usize> = b.iter().enumerate().map(|(i, t)| (*t, i)).collect();

    let common: Vec<(&str, usize)> = a.iter().filter_map(|t| pos.get(t).map(|&p| (*t, p))).collect();

    let mut tails: Vec<usize> = Vec::new();
    let mut prev: Vec<Option<usize>> = Vec::with_capacity(common.len());
    for (i, &(_, p)) in common.iter().enumerate() {
        let at = tails.partition_point(|&j| common.get(j).is_some_and(|c| c.1 < p));
        prev.push(at.checked_sub(1).and_then(|k| tails.get(k).copied()));
        if at == tails.len() {
            tails.push(i);
        } else if let Some(slot) = tails.get_mut(at) {
            *slot = i;
        }
    }
    let mut keep = BTreeSet::new();
    let mut cur = tails.last().copied();
    while let Some(i) = cur {
        keep.insert(i);
        cur = prev.get(i).copied().flatten();
    }
    common.iter().enumerate().filter(|(i, _)| !keep.contains(i)).map(|(_, (t, _))| (*t).to_string()).collect()
}

fn only_in<'a>(a: &'a str, b: &str) -> Vec<&'a str> {
    let mut have: BTreeMap<&str, usize> = BTreeMap::new();
    for l in b.lines() {
        *have.entry(l).or_default() += 1;
    }
    a.lines()
        .filter(|l| match have.get_mut(l) {
            Some(n) if *n > 0 => {
                *n -= 1;
                false
            }
            _ => true,
        })
        .collect()
}

fn line_diff(before: &str, after: &str) -> String {
    let mut out: Vec<String> = only_in(before, after).iter().map(|l| format!("- {l}")).collect();
    out.extend(only_in(after, before).iter().map(|l| format!("+ {l}")));
    let n = out.len();
    if n > MAX_LINES {
        out.truncate(MAX_LINES);
        out.push(format!("… and {} more line(s)", n - MAX_LINES));
    }
    out.join("\n")
}

fn field<'a>(v: &'a str, name: &str) -> Option<&'a str> {
    v.split(['\n', ';']).map(str::trim).find_map(|kv| kv.strip_prefix(name).and_then(|r| r.strip_prefix('=')))
}

fn list(v: Option<&str>, name: &str) -> BTreeSet<String> {
    v.and_then(|v| field(v, name)).map(|l| l.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect()).unwrap_or_default()
}

fn package_shellcmd(hook: &str, cmd: &str, now: &BTreeMap<String, String>) -> Option<&'static str> {
    PACKAGE_SHELLCMDS
        .iter()
        .find(|(pkg, file, kind, c)| {
            kind.element() == hook
                && *c == cmd
                && now.get(&format!("config/package/{pkg}")).and_then(|v| field(v, "configurationfile")) == Some(*file)
        })
        .map(|(pkg, _, _, _)| *pkg)
}

pub fn judge(c: &Change, now: &BTreeMap<String, String>) -> Option<Finding> {
    let key = c.key.strip_prefix("config/").unwrap_or(&c.key);
    let (kind, rest) = key.split_once('/').unwrap_or((key, ""));
    let (before, after) = (c.before.as_deref(), c.after.as_deref());
    let verb = match (before, after) {
        (None, Some(_)) => "added",
        (Some(_), None) => "removed",
        _ => "changed",
    };
    let show = |v: Option<&str>| v.unwrap_or("(none)").to_string();

    let change_text = || match (before, after) {
        (None, Some(a)) => a.to_string(),
        (Some(b), None) => format!("(was {b})"),
        (Some(b), Some(a)) if b.contains('\n') || a.contains('\n') => format!("\n{}", line_diff(b, a)),
        (Some(b), Some(a)) => format!("{b} → {a}"),
        (None, None) => String::new(),
    };
    let f = |severity, what: String, why: &str| {
        Some(Finding { severity, subject: key.to_string(), what, why: why.to_string() })
    };

    match kind {
        "shellcmd" => {
            let hook = rest.split('/').next().unwrap_or(rest);
            let cmd = after.or(before).unwrap_or_default();
            if let Some(pkg) = package_shellcmd(hook, cmd, now) {
                return f(
                    Severity::Note,
                    format!("{hook} {verb}: {cmd}"),
                    &format!(
                        "the {pkg} package adds exactly this boot command when it is installed, and it \
                         is installed. The script it runs is the package's; `vendor` judges its bytes"
                    ),
                );
            }
            f(
                Severity::Critical,
                format!("{hook} {verb}: {cmd}"),
                "a boot command runs as root on every boot, before anything here can look: the way a \
                 foothold on a pfSense box outlives a reboot and a password change. If your team did not \
                 add it, remove it in the GUI (or the Shellcmd package) and find out who did — \
                 `<revision>` names the last writer",
            )
        }
        "pkgconf" if rest == "shellcmdsettings" => f(
            Severity::Critical,
            format!("the Shellcmd package's boot commands {verb}: {}", change_text()),
            "every row is a command run as root at boot. If your team did not add it, remove it",
        ),
        "pkgconf" if rest == "sudo" => {
            let grants = |v: Option<&str>| v.map_or(0, |v| v.lines().filter(|l| l.ends_with("/nopasswd=ON")).count());
            let sev = if grants(after) > grants(before) { Severity::Critical } else { Severity::Warn };
            f(
                sev,
                format!("sudo rows {verb}: {}", change_text()),
                "each row is a sudoers grant; nopasswd=ON becomes NOPASSWD:, a root shell with no \
                 password, and is Critical with no allowlist",
            )
        }
        "webgui" if rest == "noantilockout" => match after {
            Some(_) => f(
                Severity::Critical,
                "the anti-lockout rule was turned off".into(),
                "with it off, a rule on LAN can cut the GUI and SSH off from the inside, and containment \
                 preflight refuses to act without it. Turn it back on unless your team chose this",
            ),
            None => f(Severity::Note, "the anti-lockout rule was turned back on".into(), "the default"),
        },
        "filter" if rest == "order" => {
            let m = moved(before.unwrap_or_default(), after.unwrap_or_default());
            if m.is_empty() {
                return None;
            }
            f(
                Severity::Warn,
                format!("{} rule(s) moved: {}", m.len(), m.join(", ")),
                "pf takes the first matching rule, so moving one changes what passes without changing \
                 any rule. A re-order in the GUI is ordinary; check that the order is the one your team set",
            )
        }
        "filter" => {
            let wan_pass = |v: Option<&str>| v.and_then(|v| field(v, "wan-facing-pass")) == Some("yes");
            if wan_pass(after) && !wan_pass(before) {
                return f(
                    Severity::Warn,
                    format!("{} pass rule on an outward-facing interface:\n{}", if before.is_none() { "new" } else { "now a" }, show(after)),
                    "this lets traffic in from outside. Confirm your team made it and that its source \
                     and port are as narrow as they meant",
                );
            }
            f(Severity::Note, format!("rule {verb}: {}", change_text()), "rules change; the moved and outward-facing ones are graded higher")
        }
        "cert" | "ca" | "authserver" => {
            let what = match kind {
                "cert" => "certificate",
                "ca" => "certificate authority",
                _ => "authentication server",
            };

            let trusted = |v: Option<&str>| v.and_then(|v| field(v, "trust")) == Some("enabled");
            let any = after.and_then(|a| field(a, "signs")) == Some("any");
            if kind == "ca" && trusted(after) && !trusted(before) && any {
                return Some(Finding {
                    severity: Severity::Critical,
                    subject: key.to_string(),
                    what: format!(
                        "certificate authority {} since arrival, with trust ON: {}",
                        if before.is_none() { "added" } else { "put in the OS trust store" },
                        show(after)
                    ),
                    why: "trust on adds it to the operating system's store, and it can sign a certificate for \
                          any name: whoever holds its key can read the firewall's own TLS. `hemostat trust` \
                          grades it; confirm your team added it, and turn trust off or delete it in System > \
                          Cert. Manager if not"
                        .into(),
                });
            }
            let sev = if before.is_none() { Severity::Warn } else { Severity::Note };
            f(
                sev,
                format!("{what} {verb}: {}", show(after.or(before))),
                "a new CA or authentication server decides who the box trusts and who can log in; a new \
                 certificate can stand in for the GUI's. Confirm your team added it",
            )
        }
        "user" => {
            let gained = |name: &str| list(after, name).difference(&list(before, name)).cloned().collect::<Vec<_>>();
            let privs: Vec<String> =
                gained("priv").into_iter().filter(|p| crate::configxml::PRIVILEGED_PRIVS.contains(&p.as_str())).collect();
            let to_admins = after.and_then(|a| field(a, "groupname")) == Some("admins")
                && before.and_then(|b| field(b, "groupname")) != Some("admins");
            let sev = if !privs.is_empty() || to_admins { Severity::Critical } else { Severity::Warn };
            f(
                sev,
                format!("account {verb}: {}", change_text()),
                "config accounts are the GUI's and SSH's; page-all and user-shell-access are the whole \
                 box. Report only: a change to who can log in is made back by a person at the console",
            )
        }
        "group" => {
            let privileged = rest == "admins"
                || list(after, "priv").iter().any(|p| crate::configxml::PRIVILEGED_PRIVS.contains(&p.as_str()));
            let joined = !list(after, "member").difference(&list(before, "member")).collect::<Vec<_>>().is_empty();
            let new_priv = list(after, "priv")
                .difference(&list(before, "priv"))
                .any(|p| crate::configxml::PRIVILEGED_PRIVS.contains(&p.as_str()));
            let sev = if privileged && (joined || new_priv) { Severity::Critical } else { Severity::Warn };
            f(sev, format!("group {verb}: {}", change_text()), "membership of a privileged group is the box")
        }
        "password" => f(
            Severity::Warn,
            format!("password {verb}"),
            "if your team did not change it, someone who could write config.xml set one they know",
        ),
        "authorizedkeys" => f(
            if after.is_some() { Severity::Warn } else { Severity::Note },
            format!("SSH keys {verb}: {}", change_text()),
            "a key here is a login that survives a password change. Confirm each one is your team's",
        ),
        _ => f(Severity::Note, format!("{verb}: {}", change_text()), "a change to the configuration since arrival"),
    }
}

pub fn judge_all(was: &BTreeMap<String, String>, now: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut out: Vec<Finding> = diff(was, now).iter().filter_map(|c| judge(c, now)).collect();
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.subject.cmp(&b.subject)));
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judged {

    pub findings: Vec<Finding>,

    pub gaps: Vec<String>,

    pub revision: Option<crate::configxml::Revision>,
}

pub fn judge_raw(arrival: &[u8], now: &[u8], salt: &[u8; 16]) -> Judged {
    use crate::configxml::parse;
    let was = match parse(arrival) {
        Ok(c) => c,
        Err(e) => {
            return Judged {
                findings: Vec::new(),
                gaps: vec![format!("the arrival config.xml was not read, so nothing was compared: {e}")],
                revision: None,
            }
        }
    };
    let now = match parse(now) {
        Ok(c) => c,
        Err(e) => {
            return Judged {
                findings: vec![Finding {
                    severity: Severity::Critical,
                    subject: "config.xml".into(),
                    what: format!("the current config.xml was refused: {e}"),
                    why: "pfSense never writes such a file, and a config this sweep cannot read is one it \
                          cannot compare. The raw file is sealed in the drift store; read it there"
                        .into(),
                }],
                gaps: vec!["the current config.xml was refused, so no change in it was graded".into()],
                revision: None,
            }
        }
    };
    Judged { findings: judge_all(&items(&was, salt), &items(&now, salt)), gaps: Vec::new(), revision: now.revision() }
}

pub const RAW_CHUNK: usize = 3 * 1024 * 1024;

pub fn raw_records(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len() / RAW_CHUNK + 2);
    let mut head = b"R".to_vec();
    head.extend_from_slice(&Sha256::digest(bytes));
    head.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.push(head);
    out.extend(bytes.chunks(RAW_CHUNK).map(|c| [b"r".as_slice(), c].concat()));
    out
}

pub fn raw_from_records<'a>(records: impl Iterator<Item = &'a [u8]>) -> Result<Vec<u8>, String> {
    let mut head: Option<([u8; 32], u64)> = None;
    let mut body = Vec::new();
    for r in records {
        match r.split_first() {
            Some((b'R', rest)) => {
                if head.is_some() {
                    return Err("the store holds two raw config.xml headers".into());
                }
                let d: [u8; 32] = rest.get(..32).and_then(|d| d.try_into().ok()).ok_or("a short raw header")?;
                let n = rest.get(32..40).and_then(|n| n.try_into().ok()).map(u64::from_le_bytes).ok_or("a short raw header")?;
                head = Some((d, n));
            }
            Some((b'r', rest)) => {
                if head.is_none() {
                    return Err("a piece of config.xml before its header".into());
                }
                body.extend_from_slice(rest);
            }
            _ => {}
        }
    }
    let (digest, len) = head.ok_or("the store holds no raw config.xml")?;
    if body.len() as u64 != len || Sha256::digest(&body).as_slice() != digest {
        return Err(format!("the raw config.xml does not match its own header ({} of {len} bytes)", body.len()));
    }
    Ok(body)
}

pub fn raw_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
