use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use hemostat_evcrypto::x509::{self, Cert};

use super::{env::Redirect, Packages, Place, Seen, BUNDLES, CAPATHS, DEBIAN_CONF, DEBIAN_LOCAL, DEBIAN_SHARE, MAX_FILES, PLACES};

const MAX_STORE_BYTES: u64 = crate::saferead::MAX_SCAN_BYTES;

const MAX_NSS_BYTES: u64 = 32 * 1024 * 1024;

const MAX_DEPTH: usize = 6;

const MAX_SWEEP_BYTES: u64 = 256 * 1024 * 1024;

const MAX_SIGHTINGS: usize = 65_536;

const MAX_PROFILES: usize = 64;

const MAX_REDIRECT_FILES: usize = 512;

type Sighting = (String, PathBuf, Place, usize, usize, usize, Option<String>, Option<bool>, bool, Option<String>);

#[derive(Debug)]
pub(super) struct Found {

    pub(super) certs: BTreeMap<String, (Cert, Vec<Seen>)>,

    pub(super) unread: Vec<String>,

    pub(super) bundles: Vec<(PathBuf, usize)>,

    pub(super) cut_short: Vec<String>,

    pub(super) looked: usize,

    read: BTreeSet<String>,

    sighted: BTreeSet<Sighting>,

    inodes: BTreeMap<(u64, u64, Place), String>,

    bytes: u64,
    byte_budget: u64,

    sightings: usize,
    sighting_budget: usize,

    spent: Option<(usize, usize, String)>,
}

impl Default for Found {
    fn default() -> Self {
        Found::within(MAX_SWEEP_BYTES, MAX_SIGHTINGS)
    }
}

impl Found {

    fn within(bytes: u64, sightings: usize) -> Self {
        Found {
            certs: BTreeMap::new(),
            unread: Vec::new(),
            bundles: Vec::new(),
            cut_short: Vec::new(),
            looked: 0,
            read: BTreeSet::new(),
            sighted: BTreeSet::new(),
            inodes: BTreeMap::new(),
            bytes: 0,
            byte_budget: bytes,
            sightings: 0,
            sighting_budget: sightings,
            spent: None,
        }
    }

    fn add(&mut self, cert: Cert, seen: Seen) -> bool {
        if self.sightings >= self.sighting_budget {
            return false;
        }
        let fp = cert.sha256_hex();
        let key: Sighting = (
            fp.clone(),
            seen.path.clone(),
            seen.place,
            seen.block,
            seen.blocks,
            seen.line,
            seen.package.clone(),
            seen.matches,
            seen.selected,
            seen.via.clone(),
        );
        if self.sighted.insert(key) {
            self.sightings += 1;
            self.certs.entry(fp).or_insert_with(|| (cert, Vec::new())).1.push(seen);
        }
        true
    }

    fn admit(&mut self, host: &str, len: u64) -> bool {
        if self.bytes.saturating_add(len) <= self.byte_budget && self.sightings < self.sighting_budget {
            return true;
        }
        let line = |n: usize, first: &str| {
            format!(
                "{n} file(s) not read, the first {first}: this sweep reads at most {} bytes and records at most {} \
                 certificate sightings, and a store that size is not one a distribution makes",
                self.byte_budget, self.sighting_budget
            )
        };
        match self.spent.take() {
            Some((at, n, first)) => {
                let text = line(n + 1, &first);
                if let Some(l) = self.unread.get_mut(at) {
                    *l = text;
                }
                self.spent = Some((at, n + 1, first));
            }
            None => {
                self.unread.push(line(1, host));
                self.spent = Some((self.unread.len() - 1, 1, host.to_string()));
            }
        }
        false
    }

    fn read_at(&self, md: &std::fs::Metadata, place: Place) -> Option<&str> {
        use std::os::unix::fs::MetadataExt as _;
        self.inodes.get(&(md.dev(), md.ino(), place)).map(String::as_str)
    }

    fn mark_read(&mut self, host: &str, md: &std::fs::Metadata, place: Place) {
        use std::os::unix::fs::MetadataExt as _;
        self.inodes.entry((md.dev(), md.ino(), place)).or_insert_with(|| host.to_string());
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
    let path = at(root, real);
    let md = std::fs::metadata(&path).ok();
    if let Some(md) = &md {

        if place == Place::Redirect && found.read_at(md, place).is_some() {
            return 0;
        }

        if md.len() <= MAX_STORE_BYTES && !found.admit(host, md.len()) {
            return 0;
        }
    }
    let bytes = match crate::saferead::read_bytes(&path, MAX_STORE_BYTES) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => {
            found.unread.push(format!("{host}: not read ({e})"));
            return 0;
        }
    };
    if let Some(md) = &md {
        found.mark_read(host, md, place);
    }
    found.bytes = found.bytes.saturating_add(bytes.len() as u64);
    found.read.insert(real.to_string());
    let (certs, bad) = x509::certs_in(&bytes);
    if bad > 0 {
        found.unread.push(format!("{host}: {bad} certificate block(s) in it would not decode, so they were not judged"));
    }
    let owner = pkgs.and_then(|p| p.judge(Path::new(host), &bytes));
    let n = certs.len();
    let mut ok = 0usize;
    let mut dropped = 0usize;
    for (i, (pem, cert)) in certs.into_iter().enumerate() {
        match cert {
            Ok(c) => {
                ok += 1;
                let recorded = found.add(
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
                dropped += usize::from(!recorded);
            }
            Err(why) => found.unread.push(format!("{host}: certificate {} of {n} could not be read ({why})", i + 1)),
        }
    }
    unrecorded(found, host, dropped);
    ok
}

fn unrecorded(found: &mut Found, host: &str, dropped: usize) {
    if dropped > 0 {
        found.unread.push(format!(
            "{host}: {dropped} of its certificates were not recorded, so not judged: this sweep records at most {} \
             certificate sightings",
            found.sighting_budget
        ));
    }
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
            if profiles.len() > MAX_PROFILES {
                found.unread.push(format!("{ff}: more than {MAX_PROFILES} entries; the rest were not read"));
            }
            dbs.extend(profiles.into_iter().take(MAX_PROFILES));
        }
    }
    dbs.sort();
    dbs.dedup();
    for db in dbs {
        let path = at(root, &db);
        let md = std::fs::metadata(&path).ok();
        if let Some(md) = &md {

            if found.read_at(md, Place::Nss).is_some() {
                found.looked += 1;
                continue;
            }
            if md.len() <= MAX_NSS_BYTES && !found.admit(&db, md.len()) {
                continue;
            }
        }
        let bytes = match crate::saferead::read_bytes(&path, MAX_NSS_BYTES) {
            Ok(b) => b,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory) => continue,
            Err(e) => {
                found.unread.push(format!("{db}: not read ({e})"));
                continue;
            }
        };
        if let Some(md) = &md {
            found.mark_read(&db, md, Place::Nss);
        }
        found.bytes = found.bytes.saturating_add(bytes.len() as u64);
        found.looked += 1;
        let certs = x509::scan_der(&bytes);
        let n = certs.len();
        let mut dropped = 0usize;
        for (i, (_, c)) in certs.into_iter().enumerate() {
            let recorded = found.add(
                c,
                Seen { path: PathBuf::from(&db), place: Place::Nss, block: i, blocks: n, line: 0, package: None, matches: None, selected: true, via: None },
            );
            dropped += usize::from(!recorded);
        }
        unrecorded(found, &db, dropped);
    }
}

pub(super) fn redirect_target(root: &Path, rd: &Redirect, found: &mut Found) {
    let host = rd.target.to_string_lossy().into_owned();
    let Some(real) = resolve(root, &host) else { return };
    let files: Vec<String> = if std::fs::metadata(at(root, &real)).is_ok_and(|m| m.is_dir()) {
        let mut v: Vec<String> = match std::fs::read_dir(at(root, &real)) {
            Ok(rd) => rd.flatten().map(|e| format!("{}/{}", real.trim_end_matches('/'), e.file_name().to_string_lossy())).collect(),
            Err(e) => {
                found.unread.push(format!("{real}: not listed ({e})"));
                Vec::new()
            }
        };
        v.sort();
        if v.len() > MAX_REDIRECT_FILES {
            found.unread.push(format!("{real}: more than {MAX_REDIRECT_FILES} entries; the rest were not read"));
            v.truncate(MAX_REDIRECT_FILES);
        }
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
