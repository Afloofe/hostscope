use crate::triage::{Finding, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keytab {

    pub path: String,

    pub mode: u32,

    pub uid: u32,

    pub principals: Vec<String>,
}

pub const fn readable_beyond_owner(mode: u32) -> bool {
    mode & 0o044 != 0
}

pub fn judge_keytab(k: &Keytab) -> Option<Finding> {
    if readable_beyond_owner(k.mode) {
        return Some(Finding {
            severity: Severity::Critical,
            subject: "ad-keytab".into(),
            locus: k.path.clone(),
            what: format!(
                "{} is mode {:04o} — readable beyond its owner — and holds {}",
                k.path,
                k.mode & 0o7777,
                if k.principals.is_empty() {
                    "Kerberos keys".to_string()
                } else {
                    format!("keys for {}", k.principals.join(", "))
                }
            ),
            why: "a keytab is the host's long-term Kerberos key. Anyone who can read it can \
                  authenticate as this machine for as long as the key stands, and where it holds \
                  a service principal they can forge tickets other hosts will accept. Rotating \
                  the machine account is the only fix once it has been exposed"
                .into(),
        });
    }
    if k.uid != 0 {
        return Some(Finding {
            severity: Severity::Warn,
            subject: "ad-keytab".into(),
            locus: k.path.clone(),
            what: format!("{} is owned by uid {}, not root", k.path, k.uid),
            why: "a keytab owned by a non-root account can be read, replaced or removed by that \
                  account. Replacing it is how an attacker makes the host authenticate with a key \
                  they chose"
                .into(),
        });
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ccache {

    pub path: String,

    pub mode: u32,

    pub uid: u32,

    pub named_uid: Option<u32>,
}

pub fn judge_ccache(c: &Ccache) -> Option<Finding> {
    if readable_beyond_owner(c.mode) {
        return Some(Finding {
            severity: Severity::Critical,
            subject: "ad-ccache".into(),
            locus: c.path.clone(),
            what: format!(
                "{} is mode {:04o}, so a live Kerberos ticket is readable by other accounts",
                c.path,
                c.mode & 0o7777
            ),
            why: "a credential cache holds a ticket-granting ticket. Reading it is enough to \
                  impersonate its owner across the domain until the ticket expires — no password \
                  and no further access to this host required"
                .into(),
        });
    }

    if let Some(named) = c.named_uid {
        if named != c.uid {
            return Some(Finding {
                severity: Severity::Warn,
                subject: "ad-ccache".into(),
                locus: c.path.clone(),
                what: format!(
                    "{} is named for uid {named} but is owned by uid {}",
                    c.path, c.uid
                ),
                why: "the conventional name encodes the owner. A mismatch is either a stale cache \
                      from a uid change or one that was put there rather than created by a logon"
                    .into(),
            });
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Realm {

    pub default_realm: Option<String>,

    pub kdcs: Vec<String>,

    pub other_kdcs: Vec<(String, String)>,

    pub dns_lookup_kdc: bool,
}

pub fn parse_krb5_conf(text: &str) -> Realm {
    let mut r = Realm::default();
    let mut section = String::new();
    let mut current_realm: Option<String> = None;

    let mut named: Vec<(String, String)> = Vec::new();

    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").split(';').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line.trim_matches(['[', ']']).trim().to_ascii_lowercase();
            current_realm = None;
            continue;
        }

        if section == "realms" && line.ends_with('{') {
            current_realm =
                line.split('=').next().map(|s| s.trim().to_ascii_uppercase()).filter(|s| !s.is_empty());
            continue;
        }
        if line == "}" {
            current_realm = None;
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match (section.as_str(), k.as_str()) {
            ("libdefaults", "default_realm") => r.default_realm = Some(v.to_ascii_uppercase()),
            ("libdefaults", "dns_lookup_kdc") => {
                r.dns_lookup_kdc = matches!(v.to_ascii_lowercase().as_str(), "true" | "yes" | "1");
            }
            ("realms", "kdc" | "master_kdc" | "admin_server") => {
                if let Some(realm) = &current_realm {
                    named.push((realm.clone(), v.to_string()));
                }
            }
            _ => {}
        }
    }
    for (realm, kdc) in named {
        if r.default_realm.as_ref() == Some(&realm) {
            r.kdcs.push(kdc);
        } else {
            r.other_kdcs.push((realm, kdc));
        }
    }
    r
}

pub fn kdc_is_inside_realm(host: &str, realm: &str) -> bool {
    let realm = realm.to_ascii_lowercase();
    let labels: Vec<&str> = realm.split('.').filter(|l| !l.is_empty()).collect();
    if labels.is_empty() {
        return false;
    }

    for start in 0..labels.len().saturating_sub(1) {
        let suffix = labels[start..].join(".");
        if host == suffix || host.ends_with(&format!(".{suffix}")) {
            return true;
        }
    }

    labels.len() < 2
}

pub fn judge_realm(r: &Realm, expected_domain: Option<&str>) -> Vec<Finding> {
    let mut out = Vec::new();

    let Some(realm) = r.default_realm.as_deref() else {
        return out;
    };

    if let Some(dom) = expected_domain {
        let dom_up = dom.to_ascii_uppercase();
        if realm != dom_up {
            out.push(Finding {
                severity: Severity::Warn,
                subject: "ad-realm".into(),
                locus: "/etc/krb5.conf".into(),
                what: format!(
                    "the default realm is {realm} but this host is joined to {dom_up}"
                ),
                why: "authentication will be attempted against a realm the host is not a member \
                      of. That is usually a misconfiguration and is occasionally a redirection"
                    .into(),
            });
        }
    }

    let host_of = |kdc: &str| kdc.split(':').next().unwrap_or(kdc).trim().to_ascii_lowercase();

    let mut seen = std::collections::BTreeSet::new();

    for kdc in &r.kdcs {
        let host = host_of(kdc);
        if host.is_empty() || !seen.insert(host.clone()) {
            continue;
        }
        let inside = kdc_is_inside_realm(&host, realm);

        let is_ip = host.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
        if is_ip {
            out.push(Finding {
                severity: Severity::Warn,
                subject: "ad-realm".into(),
                locus: "/etc/krb5.conf".into(),
                what: format!("the KDC for {realm} is the literal address {host}"),
                why: "an address cannot be checked against the realm it claims to serve. This is \
                      a working configuration and also the shape a redirected KDC takes, so it \
                      is unverified rather than wrong"
                    .into(),
            });
            continue;
        }
        if !inside {
            out.push(Finding {
                severity: Severity::Critical,
                subject: "ad-realm".into(),
                locus: "/etc/krb5.conf".into(),
                what: format!("the KDC {host} is outside the realm {realm} it serves"),
                why: "every Kerberos authentication on this host is sent to its KDC. One outside \
                      the realm answers those requests, which means it sees the credentials and \
                      decides the outcome"
                    .into(),
            });
        }
    }

    let mut seen = std::collections::BTreeSet::new();
    for (other, kdc) in &r.other_kdcs {
        let host = host_of(kdc);
        let is_ip = host.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
        if host.is_empty() || is_ip || !seen.insert((other, host.clone())) || kdc_is_inside_realm(&host, other) {
            continue;
        }
        out.push(Finding {
            severity: Severity::Info,
            subject: "ad-realm".into(),
            locus: "/etc/krb5.conf".into(),
            what: format!("the KDC {host} listed for {other} is outside that realm"),
            why: format!(
                "a KDC for another realm is asked only about that realm's principals, or a trust \
                 to it — this host's own logons go to {realm}'s. Read it if nobody here uses {other}"
            ),
        });
    }
    out
}

#[cfg(target_os = "linux")]
pub fn sweep() -> Report {
    use std::os::unix::fs::MetadataExt as _;

    let mut r = Report::default();

    let mut candidates: Vec<String> = vec![
        "/etc/krb5.keytab".into(),
        "/etc/apache2/krb5.keytab".into(),
        "/etc/nginx/krb5.keytab".into(),
        "/etc/squid/krb5.keytab".into(),
        "/var/lib/sss/keytabs/krb5.keytab".into(),
    ];
    for dir in ["/etc/krb5.keytab.d", "/var/lib/sss/keytabs", "/etc/security/keytabs"] {
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for e in entries.flatten() {
                    if e.path().is_file() {
                        candidates.push(e.path().display().to_string());
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => r.unreadable.push(dir.to_string()),
        }
    }
    candidates.sort();
    candidates.dedup();

    for path in candidates {
        match std::fs::metadata(&path) {
            Ok(md) => {
                r.keytabs += 1;
                let k = Keytab {
                    path: path.clone(),
                    mode: md.mode(),
                    uid: md.uid(),

                    principals: Vec::new(),
                };
                if let Some(f) = judge_keytab(&k) {
                    r.findings.push(f);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => r.unreadable.push(path),
        }
    }

    match std::fs::read_dir("/tmp") {
        Ok(entries) => {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if !name.starts_with("krb5cc_") {
                    continue;
                }
                let Ok(md) = e.metadata() else {
                    r.unreadable.push(e.path().display().to_string());
                    continue;
                };
                r.ccaches += 1;
                let c = Ccache {
                    path: e.path().display().to_string(),
                    mode: md.mode(),
                    uid: md.uid(),
                    named_uid: name.trim_start_matches("krb5cc_").parse().ok(),
                };
                if let Some(f) = judge_ccache(&c) {
                    r.findings.push(f);
                }
            }
        }
        Err(_) => r.unreadable.push("/tmp".into()),
    }

    match crate::saferead::read_text(std::path::Path::new("/etc/krb5.conf")) {
        Ok(text) => {
            let realm = parse_krb5_conf(&text);
            r.domain = realm.default_realm.clone();
            let (enrolled, mut unread) = joined_domain();
            r.enrolled = enrolled;
            r.unreadable.append(&mut unread);

            if r.enrolled.is_some() || r.keytabs > 0 {
                r.findings.extend(judge_realm(&realm, r.enrolled.as_deref()));
            }
            r.realm = Some(realm);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => r.unreadable.push("/etc/krb5.conf".into()),
    }

    r
}

fn is_coverage_gap(e: &std::io::Error) -> bool {
    e.kind() != std::io::ErrorKind::NotFound
}

#[cfg(target_os = "linux")]
fn joined_domain() -> (Option<String>, Vec<String>) {
    let mut unreadable = Vec::new();
    for (path, comments) in [
        ("/etc/sssd/sssd.conf", &['#'][..]),
        ("/etc/samba/smb.conf", &['#', ';'][..]),
    ] {
        let text = match crate::saferead::read_text(std::path::Path::new(path)) {
            Ok(t) => t,
            Err(e) => {
                if is_coverage_gap(&e) {
                    unreadable.push(path.to_string());
                }
                continue;
            }
        };
        for line in text.lines() {
            let line = line.split(comments).next().unwrap_or("").trim();
            let Some((k, v)) = line.split_once('=') else { continue };
            let k = k.trim();
            let named = if path.ends_with("smb.conf") {
                k.eq_ignore_ascii_case("realm")
            } else {
                k.eq_ignore_ascii_case("ad_domain") || k.eq_ignore_ascii_case("dns_discovery_domain")
            };
            if named {
                return (Some(v.trim().to_string()), unreadable);
            }
        }
    }
    (None, unreadable)
}

#[cfg(not(target_os = "linux"))]
pub fn sweep() -> Report {
    Report::default()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {

    pub realm: Option<Realm>,

    pub domain: Option<String>,

    pub enrolled: Option<String>,

    pub keytabs: usize,

    pub ccaches: usize,

    pub unreadable: Vec<String>,

    pub findings: Vec<Finding>,
}

impl Report {

    pub fn is_joined(&self) -> bool {
        self.enrolled.is_some() || self.keytabs > 0
    }
}
