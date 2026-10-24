use std::collections::BTreeMap;

use hemostat_evcrypto::manifest::Manifest;
use hemostat_evcrypto::x509::{self, Arrival, Cert, Level, Origin};
use hs_core::severity::Severity;

use crate::configxml::{self, CertKind};
use crate::drift::Finding;
use crate::evidence::{join, Evidence, Judged, Obs};

pub const TRUSTED: &[&str] = &["/usr/share/certs/trusted", "/usr/local/share/certs", "/usr/local/etc/ssl/certs"];

pub const UNTRUSTED: &[&str] =
    &["/usr/share/certs/untrusted", "/usr/local/etc/ssl/untrusted", "/usr/local/etc/ssl/blacklisted", "/etc/ssl/untrusted", "/etc/ssl/blacklisted"];

pub const CAPATH: &str = "/etc/ssl/certs";

pub const BUNDLES: &[&str] = &["/etc/ssl/cert.pem", "/usr/local/etc/ssl/cert.pem", "/usr/local/openssl/cert.pem"];

pub const NSS_BUNDLE: &str = "/usr/local/share/certs/ca-root-nss.crt";

pub const MAX_FILE: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {

    Source,

    Distrust,

    CaPath,

    Bundle,
}

#[cfg(unix)]
pub fn gather(c: &mut crate::evidence::Collector) {
    c.file(configxml::CONFIG_PATH, configxml::MAX_BYTES);
    for d in TRUSTED.iter().chain(UNTRUSTED).chain([CAPATH].iter()) {
        c.dir_files(d, MAX_FILE);
    }
    for b in BUNDLES.iter().chain([NSS_BUNDLE].iter()) {
        c.file(b, MAX_FILE);
    }

    for _ in 0..4 {
        let targets: Vec<String> = c
            .ev
            .obs
            .iter()
            .filter_map(|(p, o)| match o {
                Obs::Link(t) => Some(link_target(p, t)),
                _ => None,
            })
            .filter(|t| !c.ev.obs.contains_key(t))
            .collect();
        if targets.is_empty() {
            break;
        }
        for t in targets {
            c.file(&t, MAX_FILE);
        }
    }
}

pub fn link_target(path: &str, t: &str) -> String {
    let base = if t.starts_with('/') {
        t.to_string()
    } else {
        let dir = path.rsplit_once('/').map_or("", |(d, _)| d);
        format!("{dir}/{t}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for seg in base.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    format!("/{}", parts.join("/"))
}

fn followed<'a>(ev: &'a Evidence, path: &str) -> Option<(String, &'a [u8])> {
    let mut p = path.to_string();
    for _ in 0..5 {
        match ev.obs.get(&p)? {
            Obs::Bytes(b) => return Some((p, b)),
            Obs::Link(t) => p = link_target(&p, t),
            _ => return None,
        }
    }
    None
}

#[derive(Debug, Default)]
struct Seen {
    cert: Option<Cert>,

    at: Vec<(Place, String, Option<bool>)>,

    manager: Vec<(String, String, bool)>,
}

pub fn judge(ev: &Evidence, man: Option<&Manifest>) -> Judged {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    judge_at(ev, man, now)
}

pub fn judge_at(ev: &Evidence, man: Option<&Manifest>, now: i64) -> Judged {
    let mut j = Judged::default();
    let mut certs: BTreeMap<String, Seen> = BTreeMap::new();
    let mut add = |c: Cert, place: Place, path: &str, vendor: Option<bool>| {
        let e = certs.entry(c.sha256_hex()).or_default();
        if e.cert.is_none() {
            e.cert = Some(c);
        }
        if !e.at.iter().any(|(pl, p, _)| *pl == place && p == path) {
            e.at.push((place, path.to_string(), vendor));
        }
    };
    let vendor_of = |path: &str, bytes: &[u8]| -> Option<bool> {
        use sha2::{Digest as _, Sha256};
        match man {
            Some(m) => m.is_vendor(path, &Sha256::digest(bytes).into()),

            None => (path.starts_with("/usr/share/certs/") || path == NSS_BUNDLE).then_some(true),
        }
    };
    if man.is_none() {
        j.gaps.push(
            "no signed manifest: the base system's anchors (/usr/share/certs) and ca_root_nss's bundle were \
             taken as the vendor's on where they are alone, so a CA planted among them is not seen without one"
                .into(),
        );
    }

    let mut read_certs = |path: &str, bytes: &[u8], place: Place, vendor: Option<bool>, gaps: &mut Vec<String>| {
        let (blocks, bad) = x509::certs_in(bytes);
        if bad > 0 {
            gaps.push(format!("{path}: {bad} certificate block(s) would not decode"));
        }
        for (_, c) in blocks {
            match c {
                Ok(c) => add(c, place, path, vendor),
                Err(e) => gaps.push(format!("{path}: a certificate could not be read ({e})")),
            }
        }
    };

    let dirs: Vec<(&str, Place)> = TRUSTED
        .iter()
        .map(|d| (*d, Place::Source))
        .chain(UNTRUSTED.iter().map(|d| (*d, Place::Distrust)))
        .chain([(CAPATH, Place::CaPath)])
        .collect();
    for (d, place) in dirs {
        match ev.obs.get(d) {
            Some(Obs::Dir(entries)) => {
                for e in entries {
                    let p = join(d, &e.name);
                    let Some((real, bytes)) = followed(ev, &p) else { continue };
                    let vendor = if place == Place::Source { vendor_of(&real, bytes) } else { None };
                    read_certs(&real, bytes, place, vendor, &mut j.gaps);
                }
            }
            Some(Obs::Absent) | Some(Obs::Link(_)) | None => {}
            Some(_) => j.gaps.push(format!("{d}: {}", ev.unread(d).unwrap_or_else(|| "not listed".into()))),
        }
    }
    for b in BUNDLES.iter().chain([NSS_BUNDLE].iter()) {
        let Some((real, bytes)) = followed(ev, b) else {
            if let Some(why) = ev.unread(b).filter(|_| !matches!(ev.obs.get(*b), Some(Obs::Absent) | Some(Obs::Link(_)))) {
                j.gaps.push(format!("{b}: {why}"));
            }
            continue;
        };
        let place = if real == NSS_BUNDLE { Place::Source } else { Place::Bundle };
        let vendor = if place == Place::Source { vendor_of(&real, bytes) } else { None };
        read_certs(&real, bytes, place, vendor, &mut j.gaps);
    }

    let cfg = match ev.bytes(configxml::CONFIG_PATH) {
        Some(b) => match configxml::parse(b) {
            Ok(c) => Some(c),
            Err(e) => {
                j.gaps.push(format!("config.xml was sealed but not read ({e}): the certificate manager's CAs were not judged"));
                None
            }
        },
        None => {
            j.gaps.push(format!("{}: {}", configxml::CONFIG_PATH, ev.unread(configxml::CONFIG_PATH).unwrap_or_else(|| "absent".into())));
            None
        }
    };
    let mut off_store: Vec<(String, String, Cert)> = Vec::new();
    for ca in cfg.as_ref().map(|c| c.certs(CertKind::Ca)).unwrap_or_default() {
        let pem = match configxml::base64_decode(&ca.crt) {
            Ok(p) => p,
            Err(e) => {
                j.gaps.push(format!("config.xml ca {}: its crt is not base64 ({e})", ca.refid));
                continue;
            }
        };
        let Some(c) = x509::certs_in(&pem).0.into_iter().find_map(|(_, c)| c.ok()) else {
            j.gaps.push(format!("config.xml ca {}: its crt holds no certificate this reads", ca.refid));
            continue;
        };
        if ca.trust {
            let fp = c.sha256_hex();
            certs.entry(fp.clone()).or_default().manager.push((ca.refid.clone(), ca.descr.clone(), true));
            if certs.get(&fp).is_some_and(|s| s.cert.is_none()) {
                if let Some(s) = certs.get_mut(&fp) {
                    s.cert = Some(c);
                }
            }
        } else {
            off_store.push((ca.refid, ca.descr, c));
        }
    }

    for s in certs.values() {
        let Some(c) = &s.cert else { continue };
        let has = |p: Place| s.at.iter().any(|(pl, _, _)| *pl == p);
        let src: Vec<&(Place, String, Option<bool>)> = s.at.iter().filter(|(p, _, _)| *p == Place::Source).collect();
        let origin = if src.iter().any(|(_, _, v)| *v == Some(true)) {
            Origin::Vendor
        } else if src.iter().any(|(_, _, v)| *v == Some(false)) {
            Origin::VendorModified
        } else if !src.is_empty() || !s.manager.is_empty() {
            Origin::Local
        } else if has(Place::CaPath) || has(Place::Bundle) {
            Origin::BundleOnly
        } else {
            Origin::Distrusted
        };
        let g = x509::grade(c, origin, Arrival::Unknown, now);
        let Some(severity) = (match g.level {
            Level::Info => None,
            Level::Note => Some(Severity::Note),
            Level::Warn => Some(Severity::Warn),
            Level::Critical => Some(Severity::Critical),
        }) else {
            continue;
        };
        let locus = src
            .iter()
            .find(|(_, _, v)| *v != Some(true))
            .map(|(_, p, _)| p.clone())
            .or_else(|| s.manager.first().map(|(r, _, _)| format!("config.xml ca {r}")))
            .or_else(|| s.at.first().map(|(_, p, _)| p.clone()))
            .unwrap_or_default();
        let how = match origin {
            Origin::VendorModified => "in a file the signed manifest says the vendor shipped with different bytes".to_string(),
            Origin::Local if !s.manager.is_empty() => format!(
                "in pfSense's certificate manager with trust ON, so it is in the OS trust store ({})",
                s.manager.iter().map(|(r, d, _)| format!("refid {r} `{d}`")).collect::<Vec<_>>().join(", ")
            ),
            Origin::Local => "in a trusted directory, in a file nothing vendor-shipped accounts for".into(),
            Origin::BundleOnly => "in the hashed directory or a bundle, and in no trusted directory or manager entry".into(),
            Origin::Distrusted => "on certctl's distrust list".into(),
            _ => "trusted".into(),
        };
        let places: Vec<String> = s.at.iter().map(|(_, p, _)| p.clone()).filter(|p| *p != locus).collect();
        j.findings.push(Finding {
            severity,
            subject: locus,
            what: format!(
                "{}: {how}: {} · sha256:{} · valid {}{}",
                if g.signs_any { "a CA that can sign for any name" } else { "a certificate" },
                c.describe(),
                c.sha256_hex(),
                c.validity(),
                if places.is_empty() { String::new() } else { format!(" · also at {}", places.join(", ")) }
            ),
            why: format!(
                "{}. Whether it was here on arrival is `drift`'s to say (config.xml's CAs). Detection only: \
                 removing a CA is a change to config.xml, made by a person in the GUI (System > Cert. Manager)",
                g.reasons.join("; ")
            ),
        });
    }
    for (refid, descr, c) in off_store {
        j.findings.push(Finding {
            severity: Severity::Note,
            subject: format!("config.xml ca {refid}"),
            what: format!("a CA in pfSense's certificate manager with trust off: `{descr}`: {} · sha256:{}", c.describe(), c.sha256_hex()),
            why: "trust off keeps it out of the OS store, so the box's own TLS does not believe it; what pfSense \
                  signs with it (the GUI's certificate, OpenVPN) still does. Confirm your team made it"
                .into(),
        });
    }
    j.sort();
    j
}
