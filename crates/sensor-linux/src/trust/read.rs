use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use hemostat_evcrypto::x509::{self, Cert};

use super::{env::Redirect, Packages, Place, Seen, BUNDLES, CAPATHS, DEBIAN_CONF, DEBIAN_LOCAL, DEBIAN_SHARE, MAX_FILES, PLACES};

const MAX_STORE_BYTES: u64 = crate::saferead::MAX_SCAN_BYTES;

const MAX_NSS_BYTES: u64 = 32 * 1024 * 1024;

const MAX_DEPTH: usize = 6;

#[derive(Debug, Default)]
pub(super) struct Found {

    pub(super) certs: BTreeMap<String, (Cert, Vec<Seen>)>,

    pub(super) unread: Vec<String>,

    pub(super) bundles: Vec<(PathBuf, usize)>,

    pub(super) cut_short: Vec<String>,

    pub(super) looked: usize,

    read: BTreeSet<String>,
}

impl Found {
    fn add(&mut self, cert: Cert, seen: Seen) {
        let e = self.certs.entry(cert.sha256_hex()).or_insert_with(|| (cert, Vec::new()));
        if !e.1.contains(&seen) {
            e.1.push(seen);
        }
    }
}

pub(super) fn at(root: &Path, host: &str) -> PathBuf {
    root.join(host.trim_start_matches('/'))
}

pub(super) fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(n) => out.push(n),
            _ => {}
        }
    }
    out
}

pub(super) fn resolve(root: &Path, host: &str) -> Option<String> {
    let mut cur = normalize(Path::new(host));
    for _ in 0..16 {
        let md = std::fs::symlink_metadata(at(root, &cur.to_string_lossy())).ok()?;
        if !md.file_type().is_symlink() {
            return Some(cur.to_string_lossy().into_owned());
        }
        let t = std::fs::read_link(at(root, &cur.to_string_lossy())).ok()?;
        cur = if t.is_absolute() { normalize(&t) } else { normalize(&cur.parent().unwrap_or(Path::new("/")).join(t)) };
    }
    None
}

fn place_of(host: &str) -> Option<Place> {
    PLACES
        .iter()
        .filter(|(d, _)| host.starts_with(&format!("{d}/")))
        .max_by_key(|(d, _)| d.len())
        .map(|(_, p)| *p)
}

fn debian_selection(root: &Path, unread: &mut Vec<String>) -> Option<BTreeSet<String>> {
    match crate::saferead::read_text(&at(root, DEBIAN_CONF)) {
        Ok(text) => Some(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('!'))
                .map(str::to_string)
                .collect(),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            unread.push(format!("{DEBIAN_CONF}: not read ({e}), so which distribution anchors are selected is not known"));
            None
        }
    }
}

fn walk(root: &Path, dir: &str, found: &mut Found) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_string(), 0usize)];
    while let Some((d, depth)) = stack.pop() {
        let rd = match std::fs::read_dir(at(root, &d)) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                found.unread.push(format!("{d}: not listed ({e})"));
                continue;
            }
        };
        let mut names: Vec<(String, bool)> = Vec::new();
        for e in rd.flatten() {
            let host = format!("{}/{}", d.trim_end_matches('/'), e.file_name().to_string_lossy());
            let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
            names.push((host, is_dir));
        }
        names.sort();
        for (host, is_dir) in names {
            if out.len() >= MAX_FILES {
                if !found.cut_short.contains(&dir.to_string()) {
                    found.cut_short.push(dir.to_string());
                }
                return out;
            }
            if is_dir {
                if depth < MAX_DEPTH {
                    stack.push((host, depth + 1));
                }
            } else {
                out.push(host);
            }
        }
    }
    out
}

struct File<'a> {

    host: &'a str,

    real: &'a str,
    place: Place,

    pkgs: Option<&'a dyn Packages>,
    selected: bool,
    via: Option<String>,
}

fn read_file(root: &Path, f: File<'_>, found: &mut Found) -> usize {
    let File { host, real, place, pkgs, selected, via } = f;
    let bytes = match crate::saferead::read_bytes(&at(root, real), MAX_STORE_BYTES) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => {
            found.unread.push(format!("{host}: not read ({e})"));
            return 0;
        }
    };
    found.read.insert(real.to_string());
    let (certs, bad) = x509::certs_in(&bytes);
    if bad > 0 {
        found.unread.push(format!("{host}: {bad} certificate block(s) in it would not decode, so they were not judged"));
    }
    let owner = pkgs.and_then(|p| p.judge(Path::new(host), &bytes));
    let n = certs.len();
    let mut ok = 0usize;
    for (i, (pem, cert)) in certs.into_iter().enumerate() {
        match cert {
            Ok(c) => {
                ok += 1;
                found.add(
                    c,
                    Seen {
                        path: PathBuf::from(host),
                        place,
                        block: i,
                        blocks: n,
                        line: pem.first_line,
                        package: owner.as_ref().map(|o| o.0.clone()),
                        matches: owner.as_ref().and_then(|o| o.1),
                        selected,
                        via: via.clone(),
                    },
                );
            }
            Err(why) => found.unread.push(format!("{host}: certificate {} of {n} could not be read ({why})", i + 1)),
        }
    }
    ok
}

pub(super) fn sources(root: &Path, pkgs: &dyn Packages, found: &mut Found) {
    let selection = debian_selection(root, &mut found.unread);

    let tops: Vec<&str> = PLACES
        .iter()
        .map(|(d, _)| *d)
        .filter(|d| !PLACES.iter().any(|(o, _)| o != d && d.starts_with(&format!("{o}/"))))
        .collect();
    for top in tops {
        if std::fs::symlink_metadata(at(root, top)).is_err() {
            continue;
        }
        found.looked += 1;
        for host in walk(root, top, found) {
            let Some(place) = place_of(&host) else { continue };
            let Some(real) = resolve(root, &host) else { continue };
            if std::fs::metadata(at(root, &real)).is_ok_and(|m| m.is_dir()) {
                continue;
            }
            let selected = if let Some(rel) = host.strip_prefix(&format!("{DEBIAN_SHARE}/")) {
                selection.as_ref().is_none_or(|s| s.contains(rel))
            } else if host.starts_with(&format!("{DEBIAN_LOCAL}/")) {
                host.ends_with(".crt")
            } else {
                true
            };
            read_file(root, File { host: &host, real: &real, place, pkgs: Some(pkgs), selected, via: None }, found);
        }
    }
}

pub(super) fn bundles(root: &Path, found: &mut Found) {
    let mut done: BTreeSet<String> = BTreeSet::new();
    for b in BUNDLES {
        let Some(real) = resolve(root, b) else { continue };
        found.looked += 1;
        if !done.insert(real.clone()) {
            continue;
        }
        let n = read_file(root, File { host: &real, real: &real, place: Place::Bundle, pkgs: None, selected: true, via: None }, found);
        found.bundles.push((PathBuf::from(&real), n));
    }
    for dir in CAPATHS {
        let Some(real_dir) = resolve(root, dir) else { continue };
        if !done.insert(format!("dir:{real_dir}")) {
            continue;
        }
        found.looked += 1;
        let rd = match std::fs::read_dir(at(root, &real_dir)) {
            Ok(rd) => rd,
            Err(e) => {
                found.unread.push(format!("{dir}: not listed ({e})"));
                continue;
            }
        };
        let mut names: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        let mut held = 0usize;
        for (i, name) in names.into_iter().enumerate() {
            if i >= MAX_FILES {
                found.cut_short.push(dir.to_string());
                break;
            }
            let link = format!("{real_dir}/{name}");
            let Some(real) = resolve(root, &link) else {

                continue;
            };
            if found.read.contains(&real) || done.contains(&real) {
                continue;
            }
            if std::fs::metadata(at(root, &real)).is_ok_and(|m| m.is_dir()) {
                continue;
            }
            let via = (real != link).then(|| format!("the link {link}"));
            held += read_file(root, File { host: &real, real: &real, place: Place::CaPath, pkgs: None, selected: true, via }, found);
        }
        found.bundles.push((PathBuf::from(&real_dir), held));
    }
}

pub(super) fn nss(root: &Path, found: &mut Found) {
    let mut dbs: Vec<String> = vec!["/etc/pki/nssdb/cert9.db".into(), "/etc/pki/nssdb/cert8.db".into()];
    for home in super::env::homes(root) {
        let h = home.trim_end_matches('/');
        dbs.push(format!("{h}/.pki/nssdb/cert9.db"));
        dbs.push(format!("{h}/.pki/nssdb/cert8.db"));
        let ff = format!("{h}/.mozilla/firefox");
        if let Ok(rd) = std::fs::read_dir(at(root, &ff)) {
            let mut profiles: Vec<String> = rd.flatten().map(|e| format!("{ff}/{}/cert9.db", e.file_name().to_string_lossy())).collect();
            profiles.sort();
            dbs.extend(profiles.into_iter().take(64));
        }
    }
    dbs.sort();
    dbs.dedup();
    for db in dbs {
        let bytes = match crate::saferead::read_bytes(&at(root, &db), MAX_NSS_BYTES) {
            Ok(b) => b,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory) => continue,
            Err(e) => {
                found.unread.push(format!("{db}: not read ({e})"));
                continue;
            }
        };
        found.looked += 1;
        let certs = x509::scan_der(&bytes);
        let n = certs.len();
        for (i, (_, c)) in certs.into_iter().enumerate() {
            found.add(
                c,
                Seen { path: PathBuf::from(&db), place: Place::Nss, block: i, blocks: n, line: 0, package: None, matches: None, selected: true, via: None },
            );
        }
    }
}

pub(super) fn redirect_target(root: &Path, rd: &Redirect, found: &mut Found) {
    let host = rd.target.to_string_lossy().into_owned();
    let Some(real) = resolve(root, &host) else { return };
    let files: Vec<String> = if std::fs::metadata(at(root, &real)).is_ok_and(|m| m.is_dir()) {
        let mut v: Vec<String> = std::fs::read_dir(at(root, &real))
            .map(|rd| rd.flatten().map(|e| format!("{}/{}", real.trim_end_matches('/'), e.file_name().to_string_lossy())).collect())
            .unwrap_or_default();
        v.sort();
        v.truncate(512);
        v
    } else {
        vec![real]
    };
    for f in files {
        let Some(r) = resolve(root, &f) else { continue };
        if std::fs::metadata(at(root, &r)).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        read_file(root, File { host: &r, real: &r, place: Place::Redirect, pkgs: None, selected: true, via: Some(rd.var.clone()) }, found);
    }
}
