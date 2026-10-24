use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::rootkit::{Finding, Severity};

pub use hemostat_evcrypto::manifest::{verify_and_parse, Manifest, Refused, Verified, HEADER};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {

    Vendor,

    NotVendor,

    Absent,

    Unreadable,

    Oversize(u64),

    NotCovered,
}

pub fn judge(m: &Manifest, path: &Path) -> Verdict {
    let key = path.to_string_lossy();
    if !m.covers(&key) {
        return Verdict::NotCovered;
    }
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Verdict::Absent,
        Err(_) => return Verdict::Unreadable,
        Ok(_) => {}
    }
    match crate::saferead::sha256_of(path) {
        Ok(d) if m.is_vendor(&key, &d) == Some(true) => Verdict::Vendor,
        Ok(_) => Verdict::NotVendor,

        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            Verdict::Oversize(std::fs::metadata(path).map_or(crate::saferead::MAX_HASH_BYTES + 1, |md| md.len()))
        }
        Err(_) => Verdict::Unreadable,
    }
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub checked: usize,

    pub vendor: usize,

    pub absent: usize,

    pub unreadable: Vec<String>,

    pub uncovered: usize,

    pub judged: BTreeSet<String>,
}

impl Report {

    pub fn complete(&self) -> bool {
        self.unreadable.is_empty() && self.uncovered == 0
    }
}

pub fn sweep(m: &Manifest) -> Report {
    sweep_in(m, Path::new("/"))
}

pub fn sweep_in(m: &Manifest, root: &Path) -> Report {
    let mut r = Report::default();
    let mut mismatched: Vec<String> = Vec::new();
    for path in m.covered() {
        let path = path.as_str();
        let p = Path::new(path);
        match judge(m, p) {
            Verdict::Vendor => {
                r.checked += 1;
                r.vendor += 1;
                r.judged.insert(path.to_string());
            }
            Verdict::NotVendor => {
                r.checked += 1;
                mismatched.push(path.to_string());
            }

            Verdict::Oversize(len) => {
                r.checked += 1;
                r.judged.insert(path.to_string());
                r.findings.push(oversize_finding(m, path, len, executable(p)));
            }
            Verdict::Absent | Verdict::NotCovered => r.absent += 1,
            Verdict::Unreadable => r.unreadable.push(path.to_string()),
        }
    }
    let claims = dpkg_claims(root, &mismatched);
    for path in mismatched {
        match claims.get(&path) {
            Some((pkg, ver)) if m.covers_version(pkg, ver) == Some(false) => {
                r.uncovered += 1;
                r.findings.push(Finding {
                    severity: Severity::Warn,
                    subject: path.clone(),
                    what: format!(
                        "unverified: the host says this is {pkg} {ver}, a version the {} manifest \
                         does not cover (it covers {})",
                        m.release,
                        m.versions_of(pkg).join(", ")
                    ),
                    why: "the archive keeps a package's release and latest update, and a host \
                          installed between two updates carries a version in neither. Rebuild the \
                          manifest with an archive snapshot from when this host was installed to \
                          judge it. The version is the host's own claim, so treat this as unchecked, \
                          never as clean"
                        .into(),
                });
            }
            _ => {
                r.judged.insert(path.clone());
                r.findings.push(mismatch_finding(m, &path, executable(Path::new(&path))));
            }
        }
    }
    if !r.unreadable.is_empty() {
        r.findings.push(Finding {
            severity: Severity::Warn,
            subject: format!("{} file(s)", r.unreadable.len()),
            what: "present and could not be read in full, so not compared".into(),
            why: "a file that could not be hashed is not a file that matched; re-run as root, and \
                  treat these as unchecked"
                .into(),
        });
    }
    r.findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    r
}

fn is_config_path(path: &str) -> bool {
    path.starts_with("/etc/")
}

const RUN_DIRS: &[&str] = &[
    "/etc/init.d/",
    "/etc/cron.hourly/",
    "/etc/cron.daily/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
    "/etc/cron.yearly/",
    "/etc/update-motd.d/",
    "/etc/profile.d/",
];

const ACCESS: &[&str] = &[
    "/etc/pam.d/",
    "/etc/pam.conf",
    "/etc/sudoers",
    "/etc/sudoers.d/",
    "/etc/security/access.conf",
    "/etc/security/group.conf",
    "/etc/security/capability.conf",
    "/etc/security/pam_env.conf",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {

    Shipped,

    Code,

    Access,

    Config,
}

fn kind(path: &str, executable: bool) -> Kind {
    let listed = |set: &[&str]| set.iter().any(|e| if e.ends_with('/') { path.starts_with(e) } else { path == *e });
    if !is_config_path(path) {
        Kind::Shipped
    } else if executable || listed(RUN_DIRS) {
        Kind::Code
    } else if listed(ACCESS) {
        Kind::Access
    } else {
        Kind::Config
    }
}

fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::symlink_metadata(path).map_or(true, |md| md.permissions().mode() & 0o111 != 0)
}

fn mismatch_finding(m: &Manifest, path: &str, executable: bool) -> Finding {
    let edited = |severity, why: &str| Finding {
        severity,
        subject: path.to_string(),
        what: format!(
            "differs from every version {} shipped at this path: edited since install, or replaced",
            m.release
        ),
        why: format!(
            "{why}. Read what it says now; accounts, sshd and persistence judge the content, and \
             `drift` says whether it changed after the responders arrived"
        ),
    };
    match kind(path, executable) {
        Kind::Access => edited(
            Severity::Warn,
            "a config file is made to be edited, but this one decides who gets in or what they may \
             do, and a difference from the vendor's copy is how a PAM or sudo backdoor looks too",
        ),
        Kind::Config => edited(
            Severity::Note,
            "a config file is made to be edited, so a difference from the vendor's copy is not by \
             itself a replacement",
        ),
        Kind::Code => Finding {
            severity: Severity::Critical,
            subject: path.to_string(),
            what: format!("matches no file {} shipped at this path, and root runs it", m.release),
            why: "it is executable, or in a directory whose files root runs or sources (an init \
                  script, a cron run-parts job, a motd or login-shell fragment). Ordinary \
                  administration adds a file beside it rather than editing the vendor's, so a \
                  difference here was replaced or modified after install until someone says \
                  otherwise"
                .into(),
        },
        Kind::Shipped => Finding {
            severity: Severity::Critical,
            subject: path.to_string(),
            what: format!("matches no file {} shipped at this path", m.release),
            why: "the manifest was built off this host from the vendor's signed packages, so \
                  nothing on this host can have edited it. A file that hashes to none of the \
                  versions it lists — for a package version it does cover — was replaced or \
                  modified after install"
                .into(),
        },
    }
}

fn oversize_finding(m: &Manifest, path: &str, len: u64, executable: bool) -> Finding {
    Finding {
        what: format!(
            "{len} bytes, past the {}-byte hash cap: larger than any file {} shipped at this path",
            crate::saferead::MAX_HASH_BYTES,
            m.release
        ),
        why: "no package the manifest is built from has a file this size, so it was replaced or \
              grown after install; an executable still runs with any amount appended, and a \
              sparse tail costs no disk. It was not hashed, because the cap keeps such a file \
              from stalling the sweep, and no package version the host claims explains its size"
            .into(),
        ..mismatch_finding(m, path, executable)
    }
}

fn dpkg_claims(root: &Path, paths: &[String]) -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();
    if paths.is_empty() {
        return out;
    }
    let want: BTreeSet<&str> = paths.iter().map(String::as_str).collect();
    let info = root.join("var/lib/dpkg/info");
    let mut owner: BTreeMap<String, String> = BTreeMap::new();
    if let Ok(rd) = std::fs::read_dir(&info) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(pkg) = name.strip_suffix(".list") else { continue };
            let pkg = pkg.split(':').next().unwrap_or(pkg).to_string();
            let Some(text) = crate::saferead::read_scan_target(&e.path()) else { continue };
            for l in text.lines() {

                let norm = usr_merged(l);
                if want.contains(norm.as_str()) || want.contains(l) {
                    owner.insert(if want.contains(l) { l.to_string() } else { norm }, pkg.clone());
                }
            }
        }
    }
    let status = crate::saferead::read_scan_target(&root.join("var/lib/dpkg/status")).unwrap_or_default();
    let installed = parse_status(&status);
    for (path, pkg) in owner {
        if let Some(ver) = installed.get(&pkg) {
            out.insert(path, (pkg, ver.clone()));
        }
    }
    out
}

fn usr_merged(p: &str) -> String {
    for d in ["/bin/", "/sbin/", "/lib/", "/lib64/", "/lib32/"] {
        if let Some(rest) = p.strip_prefix(d) {
            return format!("/usr{d}{rest}");
        }
    }
    p.to_string()
}

fn parse_status(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for stanza in text.split("\n\n") {
        let mut pkg = None;
        let mut ver = None;
        let mut installed = false;
        for l in stanza.lines() {
            if let Some(v) = l.strip_prefix("Package: ") {
                pkg = Some(v.trim().to_string());
            } else if let Some(v) = l.strip_prefix("Version: ") {
                ver = Some(v.trim().to_string());
            } else if let Some(v) = l.strip_prefix("Status: ") {
                installed = v.trim().ends_with(" installed");
            }
        }
        if let (Some(p), Some(v), true) = (pkg, ver, installed) {
            out.insert(p, v);
        }
    }
    out
}
