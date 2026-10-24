use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use hemostat_evcrypto::x509::{self, Arrival, Cert, Grade, Level, Origin};

use crate::triage::{Finding, Severity};

pub mod env;
mod pkgs;
mod read;

pub use pkgs::{Dpkg, Packages, System};

pub const BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/tls/certs/ca-bundle.trust.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt",
    "/etc/pki/tls/cert.pem",
    "/etc/ssl/cert.pem",
    "/etc/ssl/ca-bundle.pem",
    "/var/lib/ca-certificates/ca-bundle.pem",
    "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
];

pub const CAPATHS: &[&str] =
    &["/etc/ssl/certs", "/etc/pki/tls/certs", "/var/lib/ca-certificates/openssl", "/etc/ca-certificates/extracted/cadir"];

pub const PLACES: &[(&str, Place)] = &[
    ("/usr/share/ca-certificates", Place::Source),
    ("/usr/local/share/ca-certificates", Place::Source),
    ("/etc/pki/ca-trust/source", Place::Source),
    ("/etc/pki/ca-trust/source/blacklist", Place::Distrust),
    ("/etc/pki/ca-trust/source/blocklist", Place::Distrust),
    ("/usr/share/pki/ca-trust-source", Place::Source),
    ("/usr/share/pki/ca-trust-source/blacklist", Place::Distrust),
    ("/usr/share/pki/ca-trust-source/blocklist", Place::Distrust),
    ("/etc/pki/trust", Place::Source),
    ("/etc/pki/trust/blacklist", Place::Distrust),
    ("/usr/share/pki/trust", Place::Source),
    ("/usr/share/pki/trust/blacklist", Place::Distrust),
    ("/etc/ca-certificates/trust-source", Place::Source),
    ("/etc/ca-certificates/trust-source/blocklist", Place::Distrust),
    ("/usr/share/ca-certificates/trust-source/blocklist", Place::Distrust),
];

pub const DEBIAN_CONF: &str = "/etc/ca-certificates.conf";

pub const DEBIAN_SHARE: &str = "/usr/share/ca-certificates";

pub const DEBIAN_LOCAL: &str = "/usr/local/share/ca-certificates";

pub const HOOKS: &str = "/etc/ca-certificates/update.d";

pub const MAX_FILES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Place {

    Source,

    Distrust,

    Bundle,

    CaPath,

    Nss,

    Redirect,
}

impl Place {

    pub fn label(self) -> &'static str {
        match self {
            Place::Source => "store source",
            Place::Distrust => "distrust list",
            Place::Bundle => "bundle",
            Place::CaPath => "hashed directory",
            Place::Nss => "NSS database",
            Place::Redirect => "redirect target",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {

    pub path: PathBuf,

    pub place: Place,

    pub block: usize,

    pub blocks: usize,

    pub line: usize,

    pub package: Option<String>,

    pub matches: Option<bool>,

    pub selected: bool,

    pub via: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {

    pub cert: Cert,

    pub seen: Vec<Seen>,

    pub origin: Origin,

    pub arrival: Arrival,

    pub grade: Grade,

    pub locus: PathBuf,

    pub inert: bool,
}

impl Anchor {

    pub fn package(&self) -> Option<&str> {
        self.seen.iter().find(|s| s.matches == Some(true)).and_then(|s| s.package.as_deref())
    }

    pub fn at_locus(&self) -> Option<&Seen> {
        self.seen.iter().find(|s| s.path == self.locus)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Baseline {

    None(String),

    Anchors(BTreeSet<String>),
}

impl Baseline {
    fn arrival(&self, fp: &str) -> Arrival {
        match self {
            Baseline::None(_) => Arrival::Unknown,
            Baseline::Anchors(s) if s.contains(fp) => Arrival::Present,
            Baseline::Anchors(_) => Arrival::Added,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub anchors: Vec<Anchor>,

    pub redirects: Vec<env::Redirect>,

    pub available: bool,

    pub reason: Option<String>,

    pub unread: Vec<String>,

    pub bundles: Vec<(PathBuf, usize)>,

    pub packages: Option<&'static str>,

    pub baseline: String,
}

impl Report {

    pub fn count_at_least(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity >= sev).count()
    }

    pub fn snapshot_items(&self) -> BTreeMap<String, String> {
        self.anchors
            .iter()
            .filter(|a| !a.inert && a.origin != Origin::Distrusted)
            .map(|a| {
                let origin = match a.origin {
                    Origin::Vendor => "vendor",
                    Origin::VendorModified => "vendor-modified",
                    Origin::Local => "local",
                    Origin::BundleOnly => "bundle-only",
                    Origin::Redirected => "redirected",
                    Origin::Added => "added",
                    Origin::Distrusted => "distrusted",
                };
                (
                    format!("anchor/{}", a.cert.sha256_hex()),
                    format!(
                        "origin={origin} any={} subject={} at={}",
                        if a.grade.signs_any { "yes" } else { "no" },
                        a.cert.subject.replace(' ', "_"),
                        a.locus.display()
                    ),
                )
            })
            .collect()
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

pub fn report_with(baseline: &Baseline) -> Report {
    let root = Path::new("/");
    let packages = pkgs::System::detect(root);
    let mut r = report_in(root, baseline, &packages, now());
    r.packages = packages.name();
    r
}

pub fn report() -> Report {
    report_with(&Baseline::None("no arrival snapshot was consulted".into()))
}

pub fn report_in(root: &Path, baseline: &Baseline, pkgs: &dyn Packages, now: i64) -> Report {
    let mut r = Report { available: true, ..Report::default() };
    r.baseline = match baseline {
        Baseline::None(why) => format!("not compared with an arrival snapshot: {why}"),
        Baseline::Anchors(s) => format!("compared with the arrival snapshot's {} anchor(s)", s.len()),
    };
    let mut found = read::Found::default();
    read::sources(root, pkgs, &mut found);
    read::bundles(root, &mut found);
    read::nss(root, &mut found);
    let (redirects, env_unread) = env::scan(root);
    for rd in &redirects {
        if !rd.system {
            read::redirect_target(root, rd, &mut found);
        }
    }
    r.redirects = redirects;
    r.unread.extend(found.unread.iter().cloned());
    r.unread.extend(env_unread);
    r.bundles = found.bundles.clone();
    if found.certs.is_empty() && found.looked == 0 {
        r.available = false;
        r.reason = Some("no trust store was found where any supported distribution keeps one".into());
    }

    for (fp, (cert, seen)) in &found.certs {
        let a = anchor(cert, seen, baseline.arrival(fp), now);
        r.anchors.push(a);
    }
    r.anchors.sort_by(|a, b| b.grade.level.cmp(&a.grade.level).then_with(|| a.cert.subject.cmp(&b.cert.subject)));

    findings(&mut r, &found);
    for (path, why) in hooks(root, pkgs) {
        r.findings.push(Finding::flag(
            Severity::Warn,
            "store rebuild hook",
            path,
            "runs as root every time update-ca-certificates rebuilds the trust store",
            why,
        ));
    }
    crate::triage::rank(&mut r.findings);
    r
}

fn anchor(cert: &Cert, seen: &[Seen], arrival: Arrival, now: i64) -> Anchor {
    let has = |p: Place| seen.iter().any(|s| s.place == p);
    let src: Vec<&Seen> = seen.iter().filter(|s| s.place == Place::Source).collect();
    let in_bundle = has(Place::Bundle) || has(Place::CaPath);
    let origin = if src.iter().any(|s| s.matches == Some(true)) {
        Origin::Vendor
    } else if src.iter().any(|s| s.package.is_some() && s.matches == Some(false)) {
        Origin::VendorModified
    } else if !src.is_empty() {
        Origin::Local
    } else if in_bundle {
        Origin::BundleOnly
    } else if has(Place::Redirect) {
        Origin::Redirected
    } else if has(Place::Nss) {
        Origin::Added
    } else {
        Origin::Distrusted
    };

    let inert = matches!(origin, Origin::Local | Origin::VendorModified)
        && !in_bundle
        && !has(Place::Redirect)
        && !has(Place::Nss)
        && src.iter().all(|s| !s.selected);
    let mut grade = x509::grade(cert, origin, arrival, now);
    if inert && grade.level > Level::Note {
        grade.level = Level::Note;
        grade.reasons.push(
            "the store's build leaves it out and no bundle carries it, so nothing trusts it now — \
             but one rebuild after it is selected would"
                .into(),
        );
    }
    if origin != Origin::Distrusted && has(Place::Distrust) {
        grade.reasons.push("it is also on a distrust list, which p11-kit honours over the anchor".into());
    }

    if origin == Origin::Added && !cert.self_issued && grade.level > Level::Note {
        grade.level = Level::Note;
        grade.reasons.push("it is not self-issued, so it is an intermediate a browser may have cached rather than a root".into());
    }
    let pick = |pred: &dyn Fn(&Seen) -> bool| seen.iter().find(|s| pred(s)).map(|s| s.path.clone());
    let locus = match origin {
        Origin::Vendor => pick(&|s| s.matches == Some(true)),
        Origin::VendorModified => pick(&|s| s.place == Place::Source && s.matches == Some(false)),
        Origin::Local => pick(&|s| s.place == Place::Source),
        Origin::BundleOnly => pick(&|s| s.place == Place::Bundle).or_else(|| pick(&|s| s.place == Place::CaPath)),
        Origin::Redirected => pick(&|s| s.place == Place::Redirect),
        Origin::Added => pick(&|s| s.place == Place::Nss),
        Origin::Distrusted => pick(&|s| s.place == Place::Distrust),
    }
    .or_else(|| seen.first().map(|s| s.path.clone()))
    .unwrap_or_default();
    Anchor { cert: cert.clone(), seen: seen.to_vec(), origin, arrival, grade, locus, inert }
}

fn opening(a: &Anchor) -> String {
    let what = if a.grade.signs_any { "a CA that can sign for any name" } else if a.cert.ca == Some(true) { "a CA" } else { "a certificate" };
    match a.origin {
        Origin::Vendor => format!("{what}, shipped by {}", a.package().unwrap_or("the vendor")),
        Origin::VendorModified => format!("{what}, in a file its package shipped with different bytes"),
        Origin::Local => format!("{what} no package ships, in the store's sources"),
        Origin::BundleOnly => format!("{what} in a bundle and in no source the bundle is built from"),
        Origin::Redirected => format!(
            "{what} that TLS is redirected to by {}",
            a.seen.iter().find_map(|s| s.via.clone()).unwrap_or_else(|| "a setting".into())
        ),
        Origin::Added => format!("{what} added to an NSS database"),
        Origin::Distrusted => format!("{what} on a distrust list"),
    }
}

fn findings(r: &mut Report, found: &read::Found) {
    let mut per_package: BTreeMap<String, usize> = BTreeMap::new();
    for a in &r.anchors {
        if a.origin == Origin::Vendor && a.grade.level == Level::Info {
            *per_package.entry(a.package().unwrap_or("the vendor").to_string()).or_default() += 1;
            continue;
        }
        let places: Vec<String> = a
            .seen
            .iter()
            .filter(|s| s.path != a.locus)
            .map(|s| format!("{} {}", s.place.label(), s.path.display()))
            .collect();
        let also = if places.is_empty() { String::new() } else { format!(" · also in {}", places.join(", ")) };
        let block = a
            .at_locus()
            .filter(|s| s.blocks > 1)
            .map_or_else(String::new, |s| format!(" (certificate {} of {}, line {})", s.block + 1, s.blocks, s.line));
        r.findings.push(Finding::flag(
            sev(a.grade.level),
            a.cert.subject.clone(),
            a.locus.display().to_string(),
            format!(
                "{}{block}: {} · sha256:{} · valid {}{also}",
                opening(a),
                a.cert.describe(),
                a.cert.sha256_hex(),
                a.cert.validity()
            ),
            a.grade.reasons.join("; "),
        ));
    }
    for (pkg, n) in per_package {
        r.findings.push(Finding::info(
            "trust store",
            pkg.clone(),
            format!("{n} anchor(s) shipped by {pkg}, each matching what the package installed"),
        ));
    }
    for rd in &r.redirects {
        let (sev, why) = if rd.system {
            (
                Severity::Info,
                "it points at the system store itself, which is the ordinary way to make a tool use the \
                 host's anchors"
                    .to_string(),
            )
        } else if !rd.exists {
            (
                Severity::Note,
                format!("{} does not exist, so the programs that read this setting trust nothing it adds — until it is created", rd.target.display()),
            )
        } else {
            (
                Severity::Warn,
                format!(
                    "{} trust what {} holds instead of — or as well as — the system store, and \
                     nothing in the store shows it. {}",
                    env::who(&rd.var),
                    rd.target.display(),
                    env::replaces(&rd.var)
                ),
            )
        };

        let what = rd.line.clone().unwrap_or_else(|| format!("{}={}", rd.var, rd.value));
        r.findings.push(Finding::flag(
            sev,
            format!("TLS redirected · {} → {}", rd.var, rd.target.display()),
            rd.at.clone(),
            what,
            why,
        ));
    }
    if !found.cut_short.is_empty() {
        r.findings.push(Finding::flag(
            Severity::Warn,
            "trust store",
            found.cut_short.join(", "),
            format!("more than {MAX_FILES} files; the rest were not read"),
            "a store directory this size is not one a distribution makes, and what was not read was not judged",
        ));
    }
}

fn sev(l: Level) -> Severity {
    match l {
        Level::Info => Severity::Info,
        Level::Note => Severity::Note,
        Level::Warn => Severity::Warn,
        Level::Critical => Severity::Critical,
    }
}

fn hooks(root: &Path, pkgs: &dyn Packages) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let dir = root.join(HOOKS.trim_start_matches('/'));
    let Ok(rd) = std::fs::read_dir(&dir) else { return out };
    for e in rd.flatten() {
        let host = format!("{HOOKS}/{}", e.file_name().to_string_lossy());
        let bytes = crate::saferead::read_bytes(&e.path(), crate::saferead::MAX_SCAN_BYTES).unwrap_or_default();
        match pkgs.judge(Path::new(&host), &bytes) {
            Some((_, Some(true))) => {}
            Some((p, Some(false))) => out.push((
                host,
                format!("{p} ships this hook and it no longer matches what {p} installed, so what runs as root at the next rebuild is not the package's"),
            )),
            Some((_, None)) => {}
            None => out.push((
                host,
                "no package ships it, so whoever put it here has a command that runs as root whenever \
                 the store is rebuilt — including by a responder removing a CA"
                    .into(),
            )),
        }
    }
    out.sort();
    out
}
