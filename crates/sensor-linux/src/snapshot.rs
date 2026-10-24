use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::rootkit::{Finding, Severity};

pub const FILES: &[&str] = &[
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/crontab",
    "/etc/anacrontab",
    "/etc/ld.so.preload",
    "/etc/environment",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/authorized_keys2",
];

pub const DIRS: &[&str] = &[
    "/etc/sudoers.d",
    "/etc/ssh/sshd_config.d",
    "/etc/pam.d",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
    "/etc/systemd/system",
    "/etc/profile.d",
    "/etc/ld.so.conf.d",
];

pub const NESTED: &[&str] = &["/etc/systemd/system"];

pub const SCOPE: u32 = 4;

const GLIBC_SCOPE: u32 = 3;

const ANCHOR_SCOPE: u32 = 4;

const DIRS_SCOPE_1: &[&str] = &[
    "/etc/sudoers.d",
    "/etc/ssh/sshd_config.d",
    "/etc/pam.d",
    "/etc/cron.d",
    "/var/spool/cron/crontabs",
    "/etc/systemd/system",
    "/etc/profile.d",
    "/etc/ld.so.conf.d",
];

pub const PRIVILEGED_GROUPS: &[&str] =
    &["root", "sudo", "wheel", "admin", "adm", "shadow", "disk", "docker", "lxd", "systemd-journal"];

const MAX_TEXT: usize = 64 * 1024;

pub use hs_core::snapshot::{Change, Snapshot};

pub fn take(salt: &[u8; 16], services: &BTreeMap<String, String>) -> Snapshot {
    let mut s = take_in(Path::new("/"), salt, services);

    let t = crate::trust::report();
    s.items.extend(t.snapshot_items());
    s.gaps.extend(t.unread.iter().map(|u| format!("trust store: {u}")));
    let surface = crate::netpolicy::survey();
    for (proto, port, what) in surface.services {
        s.items.insert(format!("listen/{}/{port}", proto.token()), owner(&what));
    }
    s.gaps.extend(surface.unread.iter().map(|t| listener_gap(t)));

    match crate::nftables::read() {
        Ok(rs) => {
            s.items.extend(rs.rows());
            s.gaps.extend(rs.gaps);
        }
        Err(e) => s.gaps.push(format!("firewall: the nftables ruleset was not read ({e})")),
    }
    s
}

const LISTENER_GAP: &str = "listeners: socket table ";

pub fn listener_gap(table: &str) -> String {
    let proto = if table.contains("/proc/net/udp") { "UDP" } else { "TCP" };
    format!(
        "{LISTENER_GAP}{table} would not open, so the listeners in it were not recorded. \
         Drift compares no {proto} listener while either snapshot has this gap, IPv4 or IPv6, \
         since one key covers both"
    )
}

fn owner(what: &str) -> String {
    let Some(pid) = what.strip_prefix("pid ").and_then(|p| p.parse::<u32>().ok()) else {
        return what.to_string();
    };
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .map_or_else(|_| "an unreadable executable".to_string(), |p| p.display().to_string())
}

pub fn take_in(root: &Path, salt: &[u8; 16], services: &BTreeMap<String, String>) -> Snapshot {
    let at = |p: &str| root.join(p.trim_start_matches('/'));
    let mut s = Snapshot { scope: SCOPE, ..Snapshot::default() };
    let (homes, legacy_homes) = accounts(&mut s, salt, &at);
    groups(&mut s, &at);
    let mut files: Vec<PathBuf> = FILES.iter().map(PathBuf::from).collect();
    for d in DIRS {
        let v = list(&mut s, Path::new(d), &at(d));
        if NESTED.contains(d) {
            for sub in &v {
                let real = at(&sub.to_string_lossy());

                if std::fs::symlink_metadata(&real).is_ok_and(|m| m.is_dir()) {
                    files.extend(list(&mut s, sub, &real));
                }
            }
        }
        files.extend(v);
    }
    for h in &homes {
        files.push(h.join(".ssh/authorized_keys"));
        files.push(h.join(".ssh/authorized_keys2"));
    }

    files.sort();
    files.dedup();

    let keys_of = |homes: &[PathBuf]| -> BTreeSet<PathBuf> {
        homes.iter().flat_map(|h| [h.join(".ssh/authorized_keys"), h.join(".ssh/authorized_keys2")]).collect()
    };
    let (keys, legacy_keys) = (keys_of(&homes), keys_of(&legacy_homes));
    for f in &files {
        record_file(&mut s, f, &at(&f.to_string_lossy()));
        let key = format!("file/{}", f.display());
        let in_scope_2 = FILES.iter().any(|x| Path::new(x) == f) || legacy_keys.contains(f);
        if keys.contains(f) && !in_scope_2 && s.items.contains_key(&key) {
            s.legacy.insert(key, None);
        }
    }
    let mut scratch = Snapshot::default();
    for f in legacy_keys.iter().filter(|f| files.binary_search(f).is_err()) {
        record_file(&mut scratch, f, &at(&f.to_string_lossy()));
    }
    s.legacy.extend(scratch.items.into_iter().map(|(k, v)| (k, Some(v))));
    for (path, digest) in services {
        s.items.insert(format!("service/{path}"), format!("sha256:{digest}"));
    }
    s
}

fn list(s: &mut Snapshot, dir: &Path, real: &Path) -> Vec<PathBuf> {
    match std::fs::read_dir(real) {
        Ok(rd) => {
            let mut v: Vec<PathBuf> = rd.flatten().map(|e| dir.join(e.file_name())).collect();
            v.sort();
            v
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            s.gaps.push(format!("{}: not listed ({e})", dir.display()));
            Vec::new()
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn accounts(s: &mut Snapshot, salt: &[u8; 16], at: &dyn Fn(&str) -> PathBuf) -> (Vec<PathBuf>, Vec<PathBuf>) {
    use sha2::{Digest, Sha256};
    let cannot_hold_keys = |home: &str| matches!(home, "" | "/" | "/nonexistent" | "/dev/null");
    let mut homes = Vec::new();
    let mut legacy_homes = Vec::new();
    match crate::saferead::read_text(&at("/etc/passwd")) {
        Ok(text) => {
            let mut now = BTreeMap::new();
            for a in crate::accounts::parse_passwd(&text) {
                if !cannot_hold_keys(&a.home) {
                    homes.push(PathBuf::from(&a.home));
                }
                now.insert(format!("user/{}", a.name), format!("uid={} gid={} home={} shell={}", a.uid, a.gid, a.home, a.shell));
            }
            let mut was = BTreeMap::new();
            for l in text.lines() {
                let f: Vec<&str> = l.split(':').collect();
                if let [name, _, uid, gid, _, home, shell] = f.as_slice() {
                    was.insert(format!("user/{name}"), format!("uid={uid} gid={gid} home={home} shell={shell}"));
                    if !cannot_hold_keys(home) {
                        legacy_homes.push(PathBuf::from(home));
                    }
                }
            }
            s.record_with_legacy(now, was);
        }
        Err(e) => s.gaps.push(format!("/etc/passwd: not read ({e})")),
    }
    match crate::saferead::read_text(&at("/etc/shadow")) {
        Ok(text) => {
            for l in text.lines() {
                let mut f = l.split(':');
                let (Some(name), Some(field)) = (f.next(), f.next()) else { continue };
                let mut h = Sha256::new();
                h.update(salt);
                h.update(name.as_bytes());
                h.update([0]);
                h.update(field.as_bytes());
                s.items.insert(format!("password/{name}"), hex(&h.finalize()));
            }
        }
        Err(e) => s.gaps.push(format!("/etc/shadow: not read ({e}) — password changes cannot be seen")),
    }
    (homes, legacy_homes)
}

fn groups(s: &mut Snapshot, at: &dyn Fn(&str) -> PathBuf) {
    match crate::saferead::read_text(&at("/etc/group")) {
        Ok(text) => {
            let mut now = BTreeMap::new();
            for mut g in crate::accounts::parse_group(&text) {
                g.members.sort_unstable();
                now.insert(format!("group/{}", g.name), format!("gid={} members={}", g.gid, g.members.join(",")));
            }
            let mut was = BTreeMap::new();
            for l in text.lines() {
                let f: Vec<&str> = l.split(':').collect();
                if let [name, _, gid, members] = f.as_slice() {
                    let mut m: Vec<&str> = members.split(',').filter(|x| !x.is_empty()).collect();
                    m.sort_unstable();
                    was.insert(format!("group/{name}"), format!("gid={gid} members={}", m.join(",")));
                }
            }
            s.record_with_legacy(now, was);
        }
        Err(e) => s.gaps.push(format!("/etc/group: not read ({e})")),
    }
}

fn record_file(s: &mut Snapshot, path: &Path, real: &Path) {
    use std::io::ErrorKind;
    match std::fs::symlink_metadata(real) {

        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => return,
        Err(e) => {
            s.gaps.push(format!("{}: not examined ({e})", path.display()));
            return;
        }
        Ok(md) if md.is_dir() => return,
        Ok(md) if md.file_type().is_symlink() => {
            let to = std::fs::read_link(real).map_or_else(|_| "?".into(), |t| t.display().to_string());
            s.items.insert(format!("file/{}", path.display()), format!("link:{to}"));
            return;
        }
        Ok(_) => {}
    }
    let key = format!("file/{}", path.display());
    match crate::saferead::read_text(real) {
        Ok(t) if t.len() <= MAX_TEXT => {
            s.items.insert(key, format!("text:{t}"));
        }
        _ => match crate::saferead::sha256_of(real) {
            Ok(d) => {
                s.items.insert(key, format!("sha256:{}", hex(&d)));
            }

            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                let len = std::fs::metadata(real).map_or(0, |m| m.len());
                s.items.insert(key, format!("oversize:{len}"));
                s.gaps.push(format!("{}: not hashed ({e})", path.display()));
            }
            Err(_) => s.gaps.push(format!("{}: not read", path.display())),
        },
    }
}

pub fn watched_directories() -> Vec<PathBuf> {
    let mut out: BTreeSet<PathBuf> = BTreeSet::new();
    out.insert(PathBuf::from("/etc"));
    for f in FILES {
        if let Some(p) = Path::new(f).parent() {
            out.insert(p.to_path_buf());
        }
    }
    out.extend(DIRS.iter().map(PathBuf::from));
    for d in NESTED {
        if let Ok(rd) = std::fs::read_dir(d) {
            out.extend(rd.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).map(|e| e.path()));
        }
    }
    let mut scratch = Snapshot::default();
    for h in accounts(&mut scratch, &[0; 16], &|p: &str| PathBuf::from(p)).0 {
        out.insert(h.join(".ssh"));
    }
    out.into_iter().collect()
}

pub fn is_tracked(path: &Path) -> bool {
    let s = path.to_string_lossy();
    FILES.iter().any(|f| s == *f)
        || DIRS.iter().any(|d| path.parent() == Some(Path::new(d)))
        || NESTED.iter().any(|d| path.parent().and_then(Path::parent) == Some(Path::new(d)))
        || matches!(s.as_ref(), "/etc/passwd" | "/etc/shadow" | "/etc/group" | "/etc/gshadow")
        || s.ends_with("/.ssh/authorized_keys")
        || s.ends_with("/.ssh/authorized_keys2")
}

pub fn diff(was: &Snapshot, now: &Snapshot) -> Vec<Change> {
    let keys: BTreeSet<&String> = was.items.keys().chain(now.items.keys()).collect();

    let unknown: Vec<&str> = ["tcp", "udp"]
        .into_iter()
        .filter(|p| {
            was.gaps.iter().chain(&now.gaps).any(|g| {
                g.starts_with(LISTENER_GAP) && g.contains(&format!("/proc/net/{p}"))
            })
        })
        .collect();
    keys.into_iter()
        .filter(|k| !unknown.iter().any(|p| k.starts_with(&format!("listen/{p}/"))))
        .filter_map(|k| {
            let (b, a) = (was.items.get(k), now.items.get(k));
            (b != a).then(|| Change { key: k.clone(), before: b.cloned(), after: a.cloned() })
        })
        .collect()
}

pub fn compare(was: &Snapshot, now: &Snapshot) -> Result<(Vec<Change>, Vec<String>), String> {
    if was.scope > SCOPE {
        return Err(format!(
            "the arrival snapshot was taken by a newer build (scope {}) than this one (scope {SCOPE}), \
             which records less and would call the rest removed. Run drift with the build that took it",
            was.scope
        ));
    }

    let unanchored = |changes: &mut Vec<Change>, gaps: &mut Vec<String>| {
        if was.scope >= ANCHOR_SCOPE {
            return;
        }
        let before = changes.len();
        changes.retain(|c| !c.key.starts_with("anchor/"));
        if changes.len() < before || now.items.keys().any(|k| k.starts_with("anchor/")) {
            gaps.push(
                "trust anchors: not recorded by the earlier build that took the arrival snapshot, so no CA \
                 here can be called added since arrival. `snapshot --replace` records them from now on"
                    .into(),
            );
        }
    };
    if was.scope >= GLIBC_SCOPE {
        let (mut changes, mut gaps) = (diff(was, now), Vec::new());
        unanchored(&mut changes, &mut gaps);
        return Ok((changes, gaps));
    }

    let glibc = now;
    let mut as_read = now.clone();
    for (k, v) in &now.legacy {
        match v {
            Some(v) => as_read.items.insert(k.clone(), v.clone()),
            None => as_read.items.remove(k),
        };
    }
    let now = &as_read;
    let mut changes = diff(was, now);

    for c in &mut changes {
        let account = c.key.starts_with("user/") || c.key.starts_with("group/");
        if account && c.after.is_some() && matches!(glibc.legacy.get(&c.key), Some(Some(_))) {
            if let Some(v) = glibc.items.get(&c.key).filter(|v| c.before.as_ref() != Some(*v)) {
                c.after = Some(v.clone());
            }
        }
    }
    let mut gaps = Vec::new();
    if !now.legacy.is_empty() {
        let keys: Vec<&str> = now.legacy.keys().map(|k| k.strip_prefix("file/").unwrap_or(k)).collect();
        gaps.push(format!(
            "{}: the earlier build that took the arrival snapshot read /etc/passwd and /etc/group \
             more strictly than glibc does, and read these otherwise or not at all, so they are \
             compared only as that build read them. `snapshot --replace` compares them as glibc \
             reads them from now on",
            keys.join(", ")
        ));
    }
    unanchored(&mut changes, &mut gaps);
    if was.scope >= 2 {
        return Ok((changes, gaps));
    }
    let homes = scope_1_homes(was, now);
    let mut left: BTreeMap<String, usize> = BTreeMap::new();
    changes.retain(|c| {
        let Some(path) = c.key.strip_prefix("file/") else { return true };
        if recorded_in_scope_1(path, &homes) {
            return true;
        }
        *left.entry(scope_1_omission(path)).or_default() += 1;
        false
    });
    gaps.extend(left.into_iter().map(|(what, n)| {
        format!(
            "{what}: not recorded by the earlier build that took the arrival snapshot, so {n} \
             item(s) there now are not compared. `snapshot --replace` covers them from now on"
        )
    }));
    Ok((changes, gaps))
}

fn scope_1_homes(was: &Snapshot, now: &Snapshot) -> BTreeSet<String> {
    was.items
        .iter()
        .chain(now.items.iter())
        .filter(|(k, _)| k.starts_with("user/"))
        .filter(|(_, v)| field(v, "uid").and_then(|u| u.parse::<u32>().ok()).is_some_and(|u| u >= 1000))
        .filter_map(|(_, v)| field(v, "home"))
        .filter(|h| *h != "/")
        .map(str::to_string)
        .collect()
}

fn recorded_in_scope_1(path: &str, homes: &BTreeSet<String>) -> bool {
    let p = Path::new(path);
    (FILES.contains(&path) && path != "/etc/anacrontab")
        || DIRS_SCOPE_1.iter().any(|d| p.parent() == Some(Path::new(d)))
        || homes.iter().any(|h| {
            let h = Path::new(h);
            p == h.join(".ssh/authorized_keys") || p == h.join(".ssh/authorized_keys2")
        })
}

fn scope_1_omission(path: &str) -> String {
    let p = Path::new(path);
    if path.ends_with("/.ssh/authorized_keys") || path.ends_with("/.ssh/authorized_keys2") {
        return "the authorized_keys of accounts below uid 1000".into();
    }
    if NESTED.iter().any(|d| p.parent().and_then(Path::parent) == Some(Path::new(d))) {
        return "the subdirectories of /etc/systemd/system (enable links and drop-ins)".into();
    }
    match p.parent() {
        Some(d) if DIRS.iter().any(|x| Path::new(x) == d) => d.display().to_string(),
        _ => path.to_string(),
    }
}

fn line_delta(before: &str, after: &str) -> (Vec<String>, Vec<String>) {
    let content = |t: &str| -> Vec<String> {
        t.lines().filter(|l| !l.trim().is_empty()).map(str::to_string).collect()
    };
    let (b, a) = (content(before), content(after));
    let added = a.iter().filter(|l| !b.contains(l)).cloned().collect();
    let removed = b.iter().filter(|l| !a.contains(l)).cloned().collect();
    (added, removed)
}

fn field<'a>(v: &'a str, name: &str) -> Option<&'a str> {
    v.split(' ').find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
}

fn privileged_gid<'a>(now: &'a Snapshot, gid: &str) -> Option<&'a str> {
    PRIVILEGED_GROUPS
        .iter()
        .copied()
        .find(|g| now.items.get(&format!("group/{g}")).and_then(|v| field(v, "gid")) == Some(gid))
}

pub fn judge(c: &Change, now: &Snapshot) -> Finding {
    let (kind, rest) = c.key.split_once('/').unwrap_or((c.key.as_str(), ""));
    let verb = match (&c.before, &c.after) {
        (None, Some(_)) => "added",
        (Some(_), None) => "removed",
        _ => "changed",
    };
    let f = |severity, what: String, why: &str| Finding {
        severity,
        subject: rest.to_string(),
        what,
        why: why.to_string(),
    };
    match kind {
        "user" => {
            let uid0 = c.after.as_deref().and_then(|v| field(v, "uid")).and_then(|u| u.parse::<u32>().ok()) == Some(0);
            let sev = if uid0 { Severity::Critical } else { Severity::Warn };
            let what = match (&c.before, &c.after) {
                (None, Some(a)) => format!("new account since arrival: {a}"),
                (Some(b), None) => format!("account removed since arrival (was {b})"),
                (Some(b), Some(a)) => format!("account changed since arrival: {b} → {a}"),
                (None, None) => String::new(),
            };
            f(sev, what, "accounts are how access outlives the process that got it. Report only: a change to \
                           who can log in is made back by a person at the console")
        }
        "password" => f(
            if rest == "root" { Severity::Critical } else { Severity::Warn },
            format!("password {verb} since arrival"),
            "if your team did not rotate it, somebody who could write /etc/shadow did — and set a \
             password they know",
        ),
        "group" => {
            let members = |v: &Option<String>| -> BTreeSet<String> {
                v.as_deref()
                    .and_then(|v| field(v, "members"))
                    .map(|m| m.split(',').filter(|x| !x.is_empty()).map(str::to_string).collect())
                    .unwrap_or_default()
            };
            let (b, a) = (members(&c.before), members(&c.after));
            let left: Vec<String> = b.difference(&a).cloned().collect();

            let was_gid = c.before.as_deref().and_then(|v| field(v, "gid"));
            let gid = c.after.as_deref().and_then(|v| field(v, "gid")).or(was_gid);
            let alias = gid.and_then(|g| privileged_gid(now, g)).filter(|g| *g != rest);
            let privileged = PRIVILEGED_GROUPS.contains(&rest) || alias.is_some();

            let moved_in = !PRIVILEGED_GROUPS.contains(&rest)
                && alias.is_some()
                && was_gid.is_some_and(|w| Some(w) != gid && privileged_gid(now, w).is_none());
            let joined: Vec<String> =
                if moved_in { a.iter().cloned().collect() } else { a.difference(&b).cloned().collect() };
            let sev = if privileged && !joined.is_empty() {
                Severity::Critical
            } else if privileged {
                Severity::Warn
            } else {
                Severity::Note
            };
            let mut what = format!("group {verb} since arrival");
            if let (Some(owner), Some(gid)) = (alias, gid) {
                what.push_str(&format!(" (gid {gid}, the gid of `{owner}`)"));
            }
            if let (true, Some(was)) = (moved_in, was_gid) {
                what.push_str(&format!("; moved from gid {was}, so every member now holds it"));
            }
            if !joined.is_empty() {
                what.push_str(&format!("; {}: {}", if moved_in { "now privileged" } else { "joined" }, joined.join(", ")));
            }
            if !left.is_empty() {
                what.push_str(&format!("; left: {}", left.join(", ")));
            }
            f(sev, what, "membership in a privileged group is a grant of that group's power without touching \
                          sudoers")
        }
        "file" => judge_file(c, rest, verb),
        "listen" => match (&c.before, &c.after) {
            (_, None) => f(Severity::Note, format!("listener closed since arrival (was {})", c.before.as_deref().unwrap_or("?")),
                "a port that was open when the responders arrived is not now; if it was a scored service, it is down"),
            (None, Some(a)) => f(Severity::Warn, format!("new listener since arrival: {a}"),
                "a port that opened after the responders arrived was opened by something running now"),
            (Some(b), Some(a)) => f(Severity::Warn, format!("listener now served by {a} (was {b})"),
                "the same port answered by a different program is how a service gets impersonated"),
        },
        "firewall" => judge_firewall(c, rest, verb),
        "anchor" => judge_anchor(c, rest, verb),
        "service" => f(
            Severity::Critical,
            format!("a file a declared service depends on {verb} since arrival"),
            "the scored services' units, binaries and configs changing mid-engagement is either your \
             team's change or the adversary's; check which before trusting the service",
        ),
        _ => f(Severity::Warn, format!("{verb} since arrival"), "recorded on arrival and different now"),
    }
}

fn judge_anchor(c: &Change, fp: &str, verb: &str) -> Finding {
    let v = c.after.as_deref().or(c.before.as_deref()).unwrap_or_default();
    let subject = field(v, "subject").map_or_else(|| fp.to_string(), |s| s.replace('_', " "));
    let at = field(v, "at").unwrap_or("?");
    let origin = c.after.as_deref().and_then(|a| field(a, "origin")).unwrap_or("?");
    let any = c.after.as_deref().and_then(|a| field(a, "any")) == Some("yes");
    let f = |severity, what: String, why: &str| Finding { severity, subject: subject.clone(), what, why: why.to_string() };
    match (&c.before, &c.after) {
        (None, Some(_)) if origin == "vendor" => f(
            Severity::Note,
            format!("trust anchor added since arrival, shipped by a package and matching it: {at} (sha256:{fp})"),
            "a ca-certificates update adds roots like this; the package's record vouches for it",
        ),
        (None, Some(_)) => f(
            if any { Severity::Critical } else { Severity::Warn },
            format!("trust anchor ADDED since arrival ({origin}): {at} (sha256:{fp})"),
            if any {
                "a CA that can sign for any name, which no package ships, was put in the trust store after the \
                 responders arrived: whoever holds its key can read this host's HTTPS. `hemostat trust` grades it, \
                 and `remediate --anchors` offers its removal"
            } else {
                "a certificate no package ships was put in the trust store after the responders arrived"
            },
        ),
        (Some(_), None) => f(
            Severity::Note,
            format!("trust anchor {verb} since arrival: {at} (sha256:{fp})"),
            "a CA that was trusted when the responders arrived is not now; if your team did not remove it, \
             something distrusted it — which breaks what relied on it",
        ),
        _ => f(
            Severity::Note,
            format!("trust anchor now {origin} at {at} (sha256:{fp})"),
            "the same certificate, found somewhere else or by another route than on arrival",
        ),
    }
}

fn judge_firewall(c: &Change, rest: &str, verb: &str) -> Finding {
    let get = |v: &Option<String>, k: &str| v.as_deref().and_then(|v| field(v, k)).map(str::to_string);
    let (pb, pa) = (get(&c.before, "policy"), get(&c.after, "policy"));

    let dormant = |v: &Option<String>| get(v, "table").as_deref() == Some("dormant");
    let went_dormant = c.before.is_some() && !dormant(&c.before) && dormant(&c.after);
    let base_drop_gone =
        pb.as_deref() == Some("drop") && (pa.as_deref() != Some("drop") || went_dormant);
    let what = match (&c.before, &c.after) {
        (None, Some(a)) => format!("new since arrival: {a}"),
        (Some(b), None) => format!("removed since arrival (was {b})"),
        _ => {
            let mut w = String::from("changed since arrival");
            if went_dormant {
                w.push_str("; its table was switched dormant, so it filters nothing");
            } else if dormant(&c.before) && !dormant(&c.after) {
                w.push_str("; its table was switched back on");
            }
            if pb != pa {
                w.push_str(&format!(
                    "; policy {} → {}",
                    pb.as_deref().unwrap_or("none"),
                    pa.as_deref().unwrap_or("none")
                ));
            }
            for k in ["rules", "elements"] {
                let (b, a) = (get(&c.before, k), get(&c.after, k));
                if b != a {
                    w.push_str(&format!("; {k} {} → {}", b.as_deref().unwrap_or("?"), a.as_deref().unwrap_or("?")));
                } else if b.is_some() && get(&c.before, "digest") != get(&c.after, "digest") {

                    w.push_str(&format!("; {k} edited in place"));
                }
            }
            w
        }
    };
    Finding {

        severity: if base_drop_gone { Severity::Critical } else { Severity::Warn },
        subject: format!("firewall {rest}"),
        what,
        why: if base_drop_gone && went_dormant {
            "a chain that dropped by default is in a table switched dormant, so its hook is gone \
             and it drops nothing: whatever it was keeping out is let in"
        } else if base_drop_gone {
            "a chain that dropped by default no longer does: whatever it was keeping out is let in"
        } else if verb == "added" {
            "a chain or set that appeared after the responders arrived — your team's rule, or a hole"
        } else {
            "the ruleset changed after the responders arrived, read from the kernel rather than \
             from `nft`, so a replaced binary cannot hide it"
        }
        .into(),
    }
}

fn judge_file(c: &Change, path: &str, verb: &str) -> Finding {
    let critical = path.starts_with("/etc/sudoers")
        || path.starts_with("/etc/pam.d")
        || path.ends_with("authorized_keys")
        || path.ends_with("authorized_keys2")
        || path == "/etc/ld.so.preload"
        || path.starts_with("/etc/ld.so.conf.d");
    let mut what = format!("{verb} since arrival");
    let mut grew = verb == "added";
    if let (Some(b), Some(a)) = (
        c.before.as_deref().and_then(|v| v.strip_prefix("text:")),
        c.after.as_deref().and_then(|v| v.strip_prefix("text:")),
    ) {
        let (added, removed) = line_delta(b, a);
        grew = !added.is_empty();
        for l in added.iter().take(8) {
            what.push_str(&format!("\n+ {l}"));
        }
        for l in removed.iter().take(8) {
            what.push_str(&format!("\n- {l}"));
        }
    } else if let Some(a) = c.after.as_deref().and_then(|v| v.strip_prefix("text:")) {
        for l in a.lines().filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#')).take(8) {
            what.push_str(&format!("\n+ {l}"));
        }
    }

    let severity = if critical && grew {
        Severity::Critical
    } else if verb == "removed" && !critical {
        Severity::Note
    } else {
        Severity::Warn
    };
    Finding {
        severity,
        subject: path.to_string(),
        what,
        why: if critical {
            "this file decides who gets in or what runs in every process; a line added after the \
             responders arrived is access somebody gave themselves"
                .into()
        } else {
            "configuration that changed after the responders arrived — your team's edit, or not".into()
        },
    }
}
