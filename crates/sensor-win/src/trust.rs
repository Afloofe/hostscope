use std::collections::BTreeSet;

use hemostat_evcrypto::x509::{self, Arrival, Cert, Level, Origin};

use crate::posture::{Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {

    Root,

    Intermediate,

    Publisher,

    NtAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {

    Machine,

    Policy,

    Enterprise,

    User,
}

#[derive(Debug, Clone, Copy)]
pub struct Store {

    pub name: &'static str,

    pub key: &'static str,

    pub purpose: Purpose,

    pub source: Source,
}

pub const MACHINE: &[Store] = &[
    Store { name: r"LocalMachine\Root", key: r"SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates", purpose: Purpose::Root, source: Source::Machine },
    Store { name: r"LocalMachine\AuthRoot", key: r"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates", purpose: Purpose::Root, source: Source::Machine },
    Store { name: r"LocalMachine\CA", key: r"SOFTWARE\Microsoft\SystemCertificates\CA\Certificates", purpose: Purpose::Intermediate, source: Source::Machine },
    Store {
        name: r"LocalMachine\TrustedPublisher",
        key: r"SOFTWARE\Microsoft\SystemCertificates\TrustedPublisher\Certificates",
        purpose: Purpose::Publisher,
        source: Source::Machine,
    },
    Store { name: r"Policy\Root", key: r"SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates", purpose: Purpose::Root, source: Source::Policy },
    Store { name: r"Policy\CA", key: r"SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates", purpose: Purpose::Intermediate, source: Source::Policy },
    Store {
        name: r"Policy\TrustedPublisher",
        key: r"SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates",
        purpose: Purpose::Publisher,
        source: Source::Policy,
    },
    Store { name: r"Enterprise\Root", key: r"SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates", purpose: Purpose::Root, source: Source::Enterprise },
    Store { name: r"Enterprise\CA", key: r"SOFTWARE\Microsoft\EnterpriseCertificates\CA\Certificates", purpose: Purpose::Intermediate, source: Source::Enterprise },
    Store { name: r"Enterprise\NTAuth", key: r"SOFTWARE\Microsoft\EnterpriseCertificates\NTAuth\Certificates", purpose: Purpose::NtAuth, source: Source::Enterprise },
    Store {
        name: r"Enterprise\TrustedPublisher",
        key: r"SOFTWARE\Microsoft\EnterpriseCertificates\TrustedPublisher\Certificates",
        purpose: Purpose::Publisher,
        source: Source::Enterprise,
    },
];

pub const USER: &[Store] = &[
    Store { name: r"User\Root", key: r"Software\Microsoft\SystemCertificates\Root\Certificates", purpose: Purpose::Root, source: Source::User },
    Store { name: r"User\Policy\Root", key: r"Software\Policies\Microsoft\SystemCertificates\Root\Certificates", purpose: Purpose::Root, source: Source::User },
];

pub const CTL_KEY: &str = r"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate";

pub const MICROSOFT: &[(&str, &str)] = &[
    ("A43489159A520F0D93D032CCAF37E7FE20A8B419", "Microsoft Root Authority"),
    ("CDD4EEAE6000AC7F40C3802C171E30148030C072", "Microsoft Root Certificate Authority"),
    ("3B1EFD3A66EA28B16697394703A72CA340A05BD5", "Microsoft Root Certificate Authority 2010"),
    ("8F43288AD272F3103B6FB1428485EA3014C0BCFE", "Microsoft Root Certificate Authority 2011"),
    ("7F88CD7223F3C813818C994614A89C99FA3B5247", "Microsoft Authenticode(tm) Root Authority"),
    ("245C97DF7514E7CF2DF8BE72AE957B9E04741E85", "Copyright (c) 1997 Microsoft Corp."),
    ("0119E81BE9A14CD8E22F40AC118C687ECBA3F4D8", "Microsoft Time Stamp Root Certificate Authority 2014"),
    ("06F1AA330B927B753A40E68CDF22E34BCBEF3352", "Microsoft ECC Product Root Certificate Authority 2018"),
    ("31F9FC8BA3805986B721EA7295C65B3A44534274", "Microsoft ECC TS Root Certificate Authority 2018"),
    ("92B46C76E13054E104F230517E6E504D43AB10B5", "Symantec Enterprise Mobile Root for Microsoft"),
    ("18F7C1FCC3090203FD5BAA2F861A754976C8DD25", "NO LIABILITY ACCEPTED, (c)97 VeriSign, Inc."),
    ("BE36A4562FB2EE05DBB3D32323ADF445084ED656", "Thawte Timestamping CA"),
    ("4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5", "VeriSign Class 3 Public Primary Certification Authority - G5"),
    ("742C3192E607E424EB4549542BE1BBC53E6174E2", "Class 3 Public Primary Certification Authority"),
    ("0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43", "DigiCert Assured ID Root CA"),
    ("A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436", "DigiCert Global Root CA"),
    ("DF3C24F9BFD666761B268073FE06D1CC8D4F82A4", "DigiCert Global Root G2"),
    ("5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25", "DigiCert High Assurance EV Root CA"),
    ("D4DE20D05E66FC53FE1A50882C78DB2852CAE474", "Baltimore CyberTrust Root"),
    ("AD7E1C28B064EF8F6003402014C3D0E3370EB58A", "Starfield Class 2 Certification Authority"),
    ("2796BAE63F1801E277261BA0D77770028F20EEE4", "Go Daddy Class 2 Certification Authority"),
    ("CABD2A79A1076A31F21D253635CB039D4329A5E8", "ISRG Root X1"),
    ("B31EB1B740E36C8402DADC37D44DF5D4674952F9", "Entrust Root Certification Authority"),
    ("B1BC968BD4F49D622AA89A81F2150152A41D829C", "GlobalSign Root CA"),
    ("D1EB23A46D17D68FD92564C2F1F1601764D8E349", "AAA Certificate Services"),
    ("2B8F1B57330DBBA2D07A6C51F70EE90DDAB9AD8E", "USERTrust RSA Certification Authority"),
    ("FEE449EE0E3965A5246F000E87FDE2A065FD89D4", "Root Agency"),
];

pub fn microsoft(thumb: &str) -> Option<&'static str> {
    MICROSOFT.iter().find(|(t, _)| t.eq_ignore_ascii_case(thumb)).map(|(_, n)| *n)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {

    pub store: &'static str,

    pub purpose: Purpose,

    pub source: Source,

    pub sid: Option<String>,

    pub key: String,

    pub der: Result<Vec<u8>, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {

    pub store: String,

    pub key: String,

    pub cert: Cert,

    pub shipped: Option<String>,

    pub level: Level,

    pub reasons: Vec<String>,

    pub signs_any: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub anchors: Vec<Anchor>,

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,

    pub unread: Vec<String>,

    pub stores: usize,

    pub users: usize,

    pub program: usize,
}

impl Report {

    pub fn complete(&self) -> bool {
        self.available && self.unread.is_empty()
    }
}

pub fn blob_der(blob: &[u8]) -> Option<Vec<u8>> {
    let mut at = 0usize;
    while let Some(head) = blob.get(at..at + 12) {
        let word = |i: usize| head.get(i..i + 4).and_then(|b| <[u8; 4]>::try_from(b).ok()).map(u32::from_le_bytes);
        let (Some(id), Some(len)) = (word(0), word(8)) else { break };
        let start = at + 12;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        let data = blob.get(start..end)?;
        if id == 32 {
            return Some(data.to_vec());
        }
        at = end;
    }
    None
}

pub fn ctl_thumbprints(der: &[u8]) -> BTreeSet<[u8; 20]> {
    fn walk(b: &[u8], depth: usize, out: &mut BTreeSet<[u8; 20]>) {
        if depth > 12 {
            return;
        }
        let mut rest = b;
        while let Some((&tag, after)) = rest.split_first() {
            let Some((&l0, after)) = after.split_first() else { return };
            let (len, after) = if l0 < 0x80 {
                (usize::from(l0), after)
            } else {
                let n = usize::from(l0 & 0x7f);
                if n == 0 || n > 4 {
                    return;
                }
                let Some((bytes, after)) = after.split_at_checked(n) else { return };
                (bytes.iter().fold(0usize, |a, x| (a << 8) | usize::from(*x)), after)
            };
            let Some((content, next)) = after.split_at_checked(len) else { return };
            match tag {
                0x04 if len == 20 => {
                    if let Ok(t) = <[u8; 20]>::try_from(content) {
                        out.insert(t);
                    }
                }

                0x04 => walk(content, depth + 1, out),
                t if t & 0x20 != 0 => walk(content, depth + 1, out),
                _ => {}
            }
            rest = next;
        }
    }
    let mut out = BTreeSet::new();
    walk(der, 0, &mut out);
    out
}

pub fn judge(entries: &[Entry], program: Option<&BTreeSet<[u8; 20]>>, now: i64) -> (Vec<Anchor>, Vec<Finding>) {
    let mut anchors = Vec::new();
    let mut findings = Vec::new();
    for e in entries {
        let where_ = match &e.sid {
            Some(sid) => format!("{} ({sid})", e.store),
            None => e.store.to_string(),
        };
        let der = match &e.der {
            Ok(d) => d,
            Err(why) => {
                findings.push(Finding {
                    severity: Severity::Warn,
                    subject: format!(r"{where_}\{}", e.key),
                    what: format!("a certificate store entry that holds no readable certificate: {why}"),
                    why: "Windows writes a certificate's properties and its encoding into each entry; one this \
                          sweep cannot read is one it cannot say anything about, and a hand-made entry looks like this"
                        .into(),
                    fix: None,
                });
                continue;
            }
        };
        let cert = match Cert::parse(der) {
            Ok(c) => c,
            Err(why) => {
                findings.push(Finding {
                    severity: Severity::Warn,
                    subject: format!(r"{where_}\{}", e.key),
                    what: format!("a certificate store entry whose certificate does not decode: {why}"),
                    why: "what the store holds could not be read, so it was not judged".into(),
                    fix: None,
                });
                continue;
            }
        };
        let thumb = cert.thumbprint();
        let ms = microsoft(&thumb);
        let in_program = program.is_some_and(|p| p.contains(&cert.sha1));
        let shipped = match (ms, in_program, e.store) {
            (Some(n), _, _) => Some(format!("Microsoft ({n})")),

            (None, true, r"LocalMachine\AuthRoot") => Some("Microsoft's root program (the host's AuthRoot list)".to_string()),
            _ => None,
        };
        let mut reasons: Vec<String> = Vec::new();
        if !thumb.eq_ignore_ascii_case(&e.key) {
            findings.push(Finding {
                severity: Severity::Warn,
                subject: format!(r"{where_}\{}", e.key),
                what: format!("filed under a thumbprint that is not its own: it is {thumb}: {}", cert.describe()),
                why: "Windows names each entry by the SHA-1 of the certificate in it, so a name that does not match \
                      was written by hand, by something hiding which certificate this is"
                    .into(),
                fix: None,
            });
        }
        if let Some(by) = &shipped {
            anchors.push(Anchor {
                store: where_,
                key: e.key.clone(),
                signs_any: x509::signs_any(&cert),
                cert,
                shipped: Some(by.clone()),
                level: Level::Info,
                reasons: vec![format!("shipped by {by}")],
            });
            continue;
        }
        let origin = match e.source {
            Source::User => Origin::Added,
            _ => Origin::Local,
        };
        let mut g = x509::grade(&cert, origin, Arrival::Unknown, now);
        match e.source {
            Source::Policy => reasons.push("Group Policy deployed it to this machine".into()),
            Source::Enterprise => reasons.push("Active Directory deployed it to this machine".into()),
            Source::User => reasons.push(
                "it is in a user's own Root store, which needs no administrator to change: every program that \
                 user runs believes it"
                    .into(),
            ),
            Source::Machine => {}
        }
        match e.purpose {
            Purpose::Root => {}
            Purpose::Intermediate => {

                if !cert.self_issued {
                    anchors.push(Anchor { store: where_, key: e.key.clone(), signs_any: g.signs_any, cert, shipped: None, level: Level::Info, reasons: vec!["an intermediate, trusted only through a root".into()] });
                    continue;
                }
                g.level = g.level.min(Level::Note);
                reasons.push("a self-issued certificate in the intermediate store, which no chain trusts as a root".into());
            }
            Purpose::Publisher => {
                g.level = g.level.max(Level::Warn);
                reasons.push(
                    "it is a trusted publisher: code it signs runs without a prompt where policy asks for one \
                     (PowerShell AllSigned, Office macros, driver and ClickOnce installs)"
                        .into(),
                );
            }
            Purpose::NtAuth => reasons.push(
                "it is in NTAuth, so a logon certificate it issues is accepted for smart-card and PKINIT logon to \
                 the domain"
                    .into(),
            ),
        }
        reasons.extend(g.reasons.iter().cloned());
        let severity = match g.level {
            Level::Info | Level::Note => Severity::Note,
            Level::Warn => Severity::Warn,
            Level::Critical => Severity::Critical,
        };
        findings.push(Finding {
            severity,
            subject: format!(r"{where_}\{thumb}"),
            what: format!(
                "{}: {} · sha256:{} · valid {}",
                if g.signs_any { "a CA that can sign for any name, not one Microsoft ships" } else { "a certificate Microsoft does not ship" },
                cert.describe(),
                cert.sha256_hex(),
                cert.validity()
            ),
            why: reasons.join("; "),
            fix: Some(
                "confirm it with whoever runs this host's PKI. Detection only: taking it out is a person's decision, \
                 in certlm.msc (machine) or certmgr.msc (user)"
                    .into(),
            ),
        });
        anchors.push(Anchor { store: where_, key: e.key.clone(), signs_any: g.signs_any, cert, shipped: None, level: g.level, reasons });
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    (anchors, findings)
}

pub fn snapshot_items(r: &Report) -> Vec<(String, String)> {
    r.anchors
        .iter()
        .map(|a| {
            (
                format!("cert/{}/{}", a.store.replace('\\', "|").replace(' ', ""), a.key.to_ascii_uppercase()),
                format!(
                    "subject={}\nshipped={}\nsigns={}\nlevel={}",
                    a.cert.subject,
                    a.shipped.as_deref().unwrap_or("no"),
                    if a.signs_any { "any" } else { "limited" },
                    a.level.tag()
                ),
            )
        })
        .collect()
}

pub fn report() -> Report {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let mut r = read::stores();
    let (anchors, findings) = judge(&r.1, r.2.as_ref(), now);
    r.0.anchors = anchors;
    r.0.findings = findings;
    r.0.program = r.2.as_ref().map_or(0, BTreeSet::len);
    r.0
}

#[cfg(target_os = "windows")]
mod read {
    use std::collections::BTreeSet;

    use super::{blob_der, ctl_thumbprints, Entry, Report, MACHINE, USER};
    use crate::reg::{self, Hive};

    const MAX_BLOB: usize = 256 * 1024;
    const MAX_CTL: usize = 4 * 1024 * 1024;

    pub(super) fn stores() -> (Report, Vec<Entry>, Option<BTreeSet<[u8; 20]>>) {
        let mut r = Report { available: true, ..Report::default() };
        let mut entries = Vec::new();
        let one = |hive: Hive, prefix: Option<&str>, s: &super::Store, sid: Option<String>, r: &mut Report, entries: &mut Vec<Entry>| {
            let key = match prefix {
                Some(p) => format!(r"{p}\{}", s.key),
                None => s.key.to_string(),
            };
            match reg::subkeys_read(hive, &key) {
                Ok(names) => {
                    r.stores += 1;
                    for n in names {
                        let der = match reg::binary(hive, &format!(r"{key}\{n}"), "Blob", MAX_BLOB) {
                            Ok(Some(b)) => blob_der(&b).ok_or_else(|| "its Blob holds no encoded certificate".to_string()),
                            Ok(None) => Err("it has no Blob value".to_string()),
                            Err(rc) => Err(format!("its Blob would not read (Win32 error {rc})")),
                        };
                        entries.push(Entry { store: s.name, purpose: s.purpose, source: s.source, sid: sid.clone(), key: n, der });
                    }
                }
                Err(rc) if rc == reg::ABSENT => {}
                Err(rc) => r.unread.push(format!("{}{}: not read (Win32 error {rc})", s.name, sid.as_deref().map_or_else(String::new, |x| format!(" ({x})")))),
            }
        };
        for s in MACHINE {
            one(Hive::Machine, None, s, None, &mut r, &mut entries);
        }
        match reg::subkeys_read(Hive::Users, "") {
            Ok(sids) => {
                for sid in sids.into_iter().filter(|x| x.starts_with("S-1-") && !x.ends_with("_Classes")) {
                    r.users += 1;
                    for s in USER {
                        one(Hive::Users, Some(&sid), s, Some(sid.clone()), &mut r, &mut entries);
                    }
                }
            }
            Err(rc) => r.unread.push(format!("the loaded user hives would not list (Win32 error {rc}), so no user's own Root store was read")),
        }
        let program = match reg::binary(Hive::Machine, super::CTL_KEY, "EncodedCtl", MAX_CTL) {
            Ok(Some(b)) => Some(ctl_thumbprints(&b)),
            Ok(None) => None,
            Err(rc) => {
                r.unread.push(format!("the root-program list ({}\\EncodedCtl) would not read (Win32 error {rc})", super::CTL_KEY));
                None
            }
        };
        (r, entries, program)
    }
}

#[cfg(not(target_os = "windows"))]
mod read {
    use std::collections::BTreeSet;

    use super::{Entry, Report};

    pub(super) fn stores() -> (Report, Vec<Entry>, Option<BTreeSet<[u8; 20]>>) {
        (
            Report { available: false, reason: Some("there is no Windows certificate store on this system".into()), ..Report::default() },
            Vec::new(),
            None,
        )
    }
}
