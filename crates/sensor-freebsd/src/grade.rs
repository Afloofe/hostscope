use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hemostat_evcrypto::manifest::meta::{Entry as MetaEntry, Kind as MetaKind, Provenance, VerifiedMeta};
use hemostat_evcrypto::manifest::Verified;
use hs_core::severity::Severity;

use crate::patches::FilePatch;
use crate::saferead::{Throttle, MAX_HASH_BYTES};
use crate::walk::Kind;

pub const WATCHED: &[&str] = &["/usr/local/www", "/etc/inc", "/boot/kernel"];

pub const BINARY_DIRS: &[&str] = &[
    "/bin",
    "/sbin",
    "/lib",
    "/libexec",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/libexec",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/local/lib",
    "/usr/local/libexec",
];

pub const REGENERATED: &[(&str, &str)] = &[
    ("/etc/crontab", "services.inc configure_cron, from cron/item"),
    ("/etc/ssh/sshd_config", "/etc/sshd, from system/ssh"),
    ("/etc/ttys", "the console settings (system/serialspeed, disableconsolemenu)"),
    ("/etc/login.conf", "system/language"),
    ("/etc/login.conf.db", "cap_mkdb, after login.conf"),
    ("/etc/hosts", "system.inc system_hosts_generate"),
    ("/etc/inetd.conf", "the TFTP proxy and service settings"),
    ("/etc/master.passwd", "auth.inc local_sync_accounts, from system/user; the accounts sweep (S7) judges it"),
    ("/etc/passwd", "pwd_mkdb, after master.passwd (pfsense-utils.inc)"),
    ("/etc/pwd.db", "pwd_mkdb, after master.passwd (pfsense-utils.inc)"),
    ("/etc/spwd.db", "pwd_mkdb, after master.passwd (pfsense-utils.inc)"),
    ("/etc/group", "auth.inc local_sync_accounts, from system/group; the accounts sweep (S7) judges it"),
    ("/etc/pam.d/sshd", "auth.inc, from the authentication servers"),
    ("/etc/pam.d/system", "auth.inc, from the authentication servers"),
    ("/etc/nsswitch.conf", "auth.inc, from the authentication servers"),
    ("/etc/syslog.conf", "syslog.inc system_syslogd_start, from syslog"),
    ("/etc/newsyslog.conf", "syslog.inc, the log rotation settings"),
    ("/usr/local/etc/sshguard.conf", "syslog.inc, from system/sshguard_*"),
    ("/usr/local/lib/php-fpm.conf", "rc.php_ini_setup, at every boot"),
    (
        "/usr/local/share/info/dir",
        "indexinfo, which every package with info pages runs after it installs (their post-install script)",
    ),
];

pub const COPIED: &[(&str, &str, &str)] = &[
    ("/etc/ssl/openssl.cnf", "/usr/local/share/pfSense/ssl/openssl.cnf", "pfSense-rc copies it at every boot"),
    (
        "/usr/local/www/pfblockerng/www/dnsbl_active.php",
        "/usr/local/www/pfblockerng/www/dnsbl_default.php",
        "pfBlockerNG's install copies it (pfblockerng_install.inc)",
    ),
];

pub const PACKAGE_GENERATED: &[(&str, &str, &str)] = &[(
    "/usr/local/www/pfblockerng/pfblockerng_reputation.php",
    "pfBlockerNG",
    "pfb_build_reputation_tab() in pfblockerng.php writes it from the settings",
)];

pub const CSRF_SECRET: &str = "/usr/local/www/csrf/csrf-secret.php";

pub fn is_csrf_secret(b: &[u8]) -> bool {
    let Some(rest) = b.strip_prefix(b"<?php $secret = \"") else { return false };
    let Some(hex) = rest.strip_suffix(b"\";\n") else { return false };
    hex.len() == 40 && hex.iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {

    pub severity: Severity,

    pub path: String,

    pub what: String,

    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub walked: usize,

    pub hashed: usize,

    pub matched: BTreeMap<&'static str, usize>,

    pub iso_only: Vec<(String, String)>,

    pub absent: usize,

    pub unlisted: usize,

    pub metadata_differs: usize,

    pub gaps: Vec<String>,
}

impl Report {

    pub fn complete(&self) -> bool {
        self.gaps.is_empty()
    }

    pub fn count(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }
}

#[derive(Debug, Clone)]
pub struct Patched {

    pub descr: String,

    pub file: FilePatch,
}

pub const MAX_PATCHED_BYTES: u64 = 8 * 1024 * 1024;

pub const MAX_RECORD_BYTES: u64 = 32 * 1024 * 1024;

fn under(path: &str, dirs: &'static [&'static str]) -> Option<&'static str> {
    dirs.iter()
        .copied()
        .find(|d| path.len() > d.len() && path.starts_with(d) && path.as_bytes().get(d.len()) == Some(&b'/'))
}

fn is_setid(mode: u32) -> bool {
    mode & 0o6000 != 0
}

fn hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obs {

    pub entry: crate::walk::Entry,

    pub digest: Option<Result<[u8; 32], String>>,

    pub content: Option<Vec<u8>>,
}

pub const STORE_KIND: &str = "pfsense-vendor";

mod tag {
    pub(super) const KIND: u8 = b'k';
    pub(super) const MANIFEST: u8 = b'm';
    pub(super) const CONFIG: u8 = b'R';
    pub(super) const GAP: u8 = b'g';
    pub(super) const ENTRY: u8 = b'e';
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

pub fn encode(o: &Obs) -> Vec<u8> {
    let e = &o.entry;
    let mut out = Vec::with_capacity(64 + e.path.len());
    out.push(tag::ENTRY);
    let (k, size, target) = match &e.kind {
        Kind::File(n) => (0u8, *n, ""),
        Kind::Dir => (1, 0, ""),
        Kind::Link(t) => (2, 0, t.as_str()),
        Kind::Special => (3, 0, ""),
    };
    out.push(k);
    out.extend_from_slice(&e.mode.to_le_bytes());
    out.extend_from_slice(&e.uid.to_le_bytes());
    out.extend_from_slice(&e.gid.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&e.dev.to_le_bytes());
    out.extend_from_slice(&e.ino.to_le_bytes());
    out.extend_from_slice(&e.nlink.to_le_bytes());
    put_bytes(&mut out, e.path.as_bytes());
    put_bytes(&mut out, target.as_bytes());
    match &o.digest {
        None => out.push(0),
        Some(Ok(d)) => {
            out.push(1);
            out.extend_from_slice(d);
        }
        Some(Err(why)) => {
            out.push(2);
            put_bytes(&mut out, why.as_bytes());
        }
    }
    match &o.content {
        None => out.push(0),
        Some(c) => {
            out.push(1);
            put_bytes(&mut out, c);
        }
    }
    out
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("a sealed record is cut short".into());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?.first().copied().unwrap_or(0))
    }
    fn u32(&mut self) -> Result<u32, String> {
        let b: [u8; 4] = self.take(4)?.try_into().map_err(|_| "a sealed record is cut short")?;
        Ok(u32::from_le_bytes(b))
    }
    fn u64(&mut self) -> Result<u64, String> {
        let b: [u8; 8] = self.take(8)?.try_into().map_err(|_| "a sealed record is cut short")?;
        Ok(u64::from_le_bytes(b))
    }
    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn text(&mut self) -> Result<String, String> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| "a sealed path is not UTF-8".to_string())
    }
}

pub fn decode(rec: &[u8]) -> Result<Obs, String> {
    let mut r = Reader(rec);
    if r.u8()? != tag::ENTRY {
        return Err("not an entry record".into());
    }
    let k = r.u8()?;
    let mode = r.u32()?;
    let uid = r.u32()?;
    let gid = r.u32()?;
    let size = r.u64()?;
    let (dev, ino, nlink) = (r.u64()?, r.u64()?, r.u64()?);
    let path = r.text()?;
    let target = r.text()?;
    let kind = match k {
        0 => Kind::File(size),
        1 => Kind::Dir,
        2 => Kind::Link(target),
        3 => Kind::Special,
        _ => return Err("an entry of no known kind".into()),
    };
    let digest = match r.u8()? {
        0 => None,
        1 => Some(Ok(r.take(32)?.try_into().map_err(|_| "a digest is cut short")?)),
        2 => Some(Err(r.text()?)),
        _ => return Err("a digest flag of no known kind".into()),
    };
    let content = match r.u8()? {
        0 => None,
        1 => Some(r.bytes()?.to_vec()),
        _ => return Err("a content flag of no known kind".into()),
    };
    if !r.0.is_empty() {
        return Err("a sealed record has trailing bytes".into());
    }
    Ok(Obs { entry: crate::walk::Entry { path, kind, mode, uid, gid, dev, ino, nlink }, digest, content })
}

fn record(t: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + body.len());
    v.push(t);
    v.extend_from_slice(body);
    v
}

#[cfg(unix)]
pub struct Collector<'m> {
    root: PathBuf,
    walker: crate::walk::Walker,
    manifest: &'m Verified,
    meta: &'m VerifiedMeta,
    patched: std::collections::BTreeSet<String>,
    head: std::collections::VecDeque<Vec<u8>>,
    throttle: Throttle,
    bytes: u64,
    limit: u64,
    done: bool,
}

#[cfg(unix)]
impl<'m> Collector<'m> {

    pub fn new(root: &Path, manifest: &'m Verified, meta: &'m VerifiedMeta, throttle: Throttle, limit: u64) -> Self {
        let mut head = std::collections::VecDeque::new();
        head.push_back(record(tag::KIND, STORE_KIND.as_bytes()));
        head.push_back(record(tag::MANIFEST, manifest.body_sha256()));
        let mut patched = std::collections::BTreeSet::new();
        match crate::saferead::read_bytes(&crate::walk::join(root, CONFIG_XML), crate::patches::MAX_CONFIG_BYTES) {
            Ok(raw) => {
                if let Ok(recs) = crate::patches::records_from_config(&String::from_utf8_lossy(&raw)) {
                    let mut ignored = Vec::new();
                    patched.extend(index_patches(&recs, &mut ignored).into_keys());
                }
                head.push_back(record(tag::CONFIG, &raw));
            }
            Err(e) => head.push_back(record(
                tag::GAP,
                format!("{CONFIG_XML}: not read ({e}); recorded patches were not considered").as_bytes(),
            )),
        }
        Collector {
            root: root.to_path_buf(),
            walker: crate::walk::Walker::new(root, crate::walk::ROOTS),
            manifest,
            meta,
            patched,
            head,
            throttle,
            bytes: 0,
            limit,
            done: false,
        }
    }

    pub fn hashed_bytes(&self) -> u64 {
        self.throttle.bytes()
    }

    pub fn record_bytes(&self) -> u64 {
        self.bytes
    }

    fn observe(&mut self, e: crate::walk::Entry) -> Obs {
        let covered = self.manifest.covers(&e.path);
        let len = match e.kind {
            Kind::File(n) => Some(n),
            _ => None,
        };
        let shipped = !self.meta.get(&e.path).is_empty();
        let worth = covered
            || (!shipped
                && (REGENERATED.iter().any(|(p, _)| *p == e.path)
                    || under(&e.path, WATCHED).is_some()
                    || e.path.starts_with("/usr/local/etc/rc.d/")
                    || e.path.starts_with("/etc/rc.d/")
                    || under(&e.path, BINARY_DIRS).is_some()));
        let digest = match len {
            Some(n) if worth && n <= MAX_HASH_BYTES => Some(self.hash(&e.path).map_err(|err| err.to_string())),
            _ => None,
        };
        let content = match len {
            Some(n) if e.path == CSRF_SECRET && n < 128 => self.read(&e.path, 128).ok(),
            Some(n) if covered && n <= MAX_PATCHED_BYTES && self.patched.contains(&e.path) => {
                self.read(&e.path, MAX_PATCHED_BYTES).ok()
            }
            _ => None,
        };
        Obs { entry: e, digest, content }
    }

    fn hash(&mut self, path: &str) -> std::io::Result<[u8; 32]> {
        let (f, md) =
            crate::saferead::open_regular(&crate::walk::join(&self.root, path), crate::saferead::NOT_REGULAR)?;
        if md.len() > MAX_HASH_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "over the hash cap"));
        }
        crate::saferead::sha256_reader(&f, MAX_HASH_BYTES, &mut self.throttle)
    }

    fn read(&mut self, path: &str, max: u64) -> std::io::Result<Vec<u8>> {
        crate::saferead::read_bytes(&crate::walk::join(&self.root, path), max)
    }
}

#[cfg(unix)]
impl Iterator for Collector<'_> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        if let Some(r) = self.head.pop_front() {
            self.bytes += r.len() as u64;
            return Some(r);
        }
        if self.done {
            return None;
        }
        let rec = match self.walker.next()? {
            crate::walk::Step::Gap(g) => record(tag::GAP, g.as_bytes()),
            crate::walk::Step::Entry(e) => {
                let o = self.observe(e);
                encode(&o)
            }
        };
        self.bytes += rec.len() as u64;
        if self.bytes > self.limit {
            self.done = true;
            return Some(record(
                tag::GAP,
                format!("the walk stopped at {} bytes of records, the most one sweep seals", self.limit).as_bytes(),
            ));
        }
        Some(rec)
    }
}

pub fn judge_records<'a>(
    records: impl Iterator<Item = &'a [u8]>,
    manifest: &Verified,
    meta: &VerifiedMeta,
) -> Result<Report, String> {
    let mut gaps = Vec::new();
    let mut patches = BTreeMap::new();
    let mut packages = std::collections::BTreeSet::new();
    let mut kind_ok = false;
    let mut bound_ok = false;
    let mut obs = Vec::new();
    for rec in records {
        let Some((&t, body)) = rec.split_first() else { return Err("an empty sealed record".into()) };
        match t {
            tag::KIND => kind_ok = body == STORE_KIND.as_bytes(),
            tag::MANIFEST => bound_ok = body == manifest.body_sha256(),
            tag::CONFIG => {
                match crate::patches::records_from_config(&String::from_utf8_lossy(body)) {
                    Ok(recs) => patches = index_patches(&recs, &mut gaps),
                    Err(e) => gaps.push(format!("{CONFIG_XML}: recorded patches not read ({e})")),
                }
                if let Ok(cfg) = crate::configxml::parse(body) {
                    packages = cfg.packages().into_iter().map(|p| p.name).collect();
                }
            }
            tag::GAP => gaps.push(String::from_utf8_lossy(body).into_owned()),
            tag::ENTRY => obs.push(rec),
            _ => return Err(format!("a sealed record of no known kind ({t})")),
        }
    }
    if !kind_ok {
        return Err(format!("the store is not a {STORE_KIND} store"));
    }
    if !bound_ok {
        return Err("the store was collected against another manifest".into());
    }

    let mut links = std::collections::HashMap::new();
    for rec in &obs {
        let o = decode(rec)?;
        let e = &o.entry;
        if e.nlink > 1 && matches!(e.kind, Kind::File(_)) {
            if let Some(Ok(d)) = &o.digest {
                if manifest.is_vendor(&e.path, d) == Some(true) {
                    links.insert((e.dev, e.ino), e.path.clone());
                }
            }
        }
    }
    let ctx = Context { links, packages };
    let mut r = grade(obs.into_iter().map(decode), manifest, meta, &patches, &ctx)?;
    r.gaps.splice(0..0, gaps);
    Ok(r)
}

#[derive(Debug, Default)]
pub struct Context {

    pub links: std::collections::HashMap<(u64, u64), String>,

    pub packages: std::collections::BTreeSet<String>,
}

pub fn grade(
    observations: impl Iterator<Item = Result<Obs, String>>,
    manifest: &Verified,
    meta: &VerifiedMeta,
    patches: &BTreeMap<String, Vec<Patched>>,
    ctx: &Context,
) -> Result<Report, String> {
    let mut r = Report::default();
    let mut iso_by_pkg: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut seen = vec![false; manifest.paths()];
    let iso_pin = meta
        .isos
        .first()
        .map(|i| format!("{} sha256 {}", i.name, hex(&i.sha256).get(..16).unwrap_or_default()))
        .unwrap_or_else(|| "no image recorded".into());

    for o in observations {
        let o = o?;
        let e = &o.entry;
        r.walked += 1;
        let pos = manifest.position(&e.path);
        if let Some(slot) = pos.and_then(|i| seen.get_mut(i)) {
            *slot = true;
        }
        let rows = meta.get(&e.path);
        let origin = rows
            .iter()
            .map(|x| x.origin.trim_start_matches("iso:"))
            .find(|o| *o != "base" && *o != "iso")
            .or_else(|| rows.first().map(|x| x.origin))
            .unwrap_or("-")
            .to_string();
        let vendor_setid = rows.iter().any(|x| is_setid(x.mode));
        if is_setid(e.mode) && !vendor_setid {
            r.findings.push(Finding {
                severity: Severity::Critical,
                path: e.path.clone(),
                what: if rows.is_empty() {
                    "a set-id file no vendor source ships".into()
                } else {
                    "a set-id bit the vendor never set".into()
                },
                detail: format!("mode {:04o}, uid {} gid {}", e.mode, e.uid, e.gid),
            });
        }
        if pos.is_some() {
            let Kind::File(len) = &e.kind else {
                r.findings.push(Finding {
                    severity: Severity::Critical,
                    path: e.path.clone(),
                    what: format!("the vendor ships a file here; this is {}", kind_name(&e.kind)),
                    detail: format!("shipped by {origin}"),
                });
                continue;
            };
            if *len > MAX_HASH_BYTES {
                r.findings.push(Finding {
                    severity: Severity::Critical,
                    path: e.path.clone(),
                    what: "larger than any file the vendor ships".into(),
                    detail: format!("{len} bytes"),
                });
                continue;
            }
            let d = match &o.digest {
                Some(Ok(d)) => *d,
                Some(Err(err)) => {
                    r.gaps.push(format!("{}: not hashed ({err})", e.path));
                    continue;
                }
                None => {
                    r.gaps.push(format!("{}: a vendor file the sweep did not hash", e.path));
                    continue;
                }
            };
            r.hashed += 1;
            let same = |x: &MetaEntry<'_>| {
                x.kind == MetaKind::File
                    && x.mode == e.mode
                    && x.uid.is_none_or(|u| u == e.uid)
                    && x.gid.is_none_or(|g| g == e.gid)
            };
            if !rows.is_empty() && !rows.iter().any(same) {
                r.metadata_differs += 1;
            }
            match meta.provenance(manifest, &e.path, &d) {
                Some(p @ (Provenance::RepoSigned | Provenance::IsoSigned)) => {
                    *r.matched.entry(p.label()).or_insert(0) += 1;
                }
                Some(Provenance::IsoPinned) => {
                    *r.matched.entry(Provenance::IsoPinned.label()).or_insert(0) += 1;
                    iso_by_pkg.entry(origin.clone()).or_default().push(e.path.clone());
                    r.iso_only.push((origin.clone(), e.path.clone()));
                }
                None => mismatch(&mut r, &o, &d, &origin, manifest, meta, patches),
            }
            continue;
        }

        if let Some(row) = rows.first() {
            let binary = under(&e.path, BINARY_DIRS).is_some();
            match (&row.kind, &e.kind) {
                (MetaKind::Link, Kind::Link(t)) => {
                    let known = rows.iter().filter_map(|x| x.target).collect::<Vec<_>>();
                    let signed = rows.iter().any(|x| !x.origin.starts_with("iso") && x.target == Some(t.as_str()));
                    if !signed && known.contains(&t.as_str()) {

                        iso_by_pkg.entry(origin.clone()).or_default().push(e.path.clone());
                        r.iso_only.push((origin.clone(), e.path.clone()));
                    }
                    if !known.is_empty() && !known.contains(&t.as_str()) {
                        r.findings.push(Finding {
                            severity: if binary { Severity::Critical } else { Severity::Warn },
                            path: e.path.clone(),
                            what: "a vendor link that now points somewhere else".into(),
                            detail: format!("-> {t}; the vendor's points to {}", known.join(" or ")),
                        });
                    }
                }
                (MetaKind::Dir, Kind::Dir) => {}
                (MetaKind::File, _) => {

                    r.unlisted += 1;
                }
                (want, got) => r.findings.push(Finding {
                    severity: Severity::Warn,
                    path: e.path.clone(),
                    what: format!("the vendor ships a {} here; this is {}", meta_kind_name(*want), kind_name(got)),
                    detail: format!("shipped by {origin}"),
                }),
            }
            continue;
        }
        unknown(&mut r, &o, manifest, meta, ctx);
    }

    for (pkg, paths) in iso_by_pkg {
        let mut shown: Vec<&str> = paths.iter().take(3).map(String::as_str).collect();
        if paths.len() > 3 {
            shown.push("…");
        }
        let why = match pkg.as_str() {
            "iso" => "files the release image carries that no package or base.mtree lists".to_string(),
            "base" => "base-system files in the form the release image carries, which base.mtree does not record"
                .to_string(),
            _ => format!("files of {pkg} as the release image carries them; the repositories have since rebuilt it"),
        };
        r.findings.push(Finding {
            severity: Severity::Note,
            path: pkg.clone(),
            what: format!("{} {why} (match an iso-pinned digest only, not a signed one)", paths.len()),
            detail: format!("pin {iso_pin}; {}", shown.join(", ")),
        });
    }
    r.absent = seen.iter().filter(|s| !**s).count();
    r.findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.path.cmp(&b.path)));
    Ok(r)
}

fn mismatch(
    r: &mut Report,
    o: &Obs,
    d: &[u8; 32],
    origin: &str,
    manifest: &Verified,
    meta: &VerifiedMeta,
    patches: &BTreeMap<String, Vec<Patched>>,
) {
    let path = o.entry.path.as_str();
    let shown = hex(d);
    if let Some(ps) = patches.get(path).filter(|ps| !ps.is_empty()) {
        let names = ps.iter().map(|p| format!("'{}'", p.descr)).collect::<Vec<_>>().join(", ");
        match o.content.as_deref() {
            Some(content) => match undo_patches(path, content, ps, manifest, meta) {
                Some((descr, prov)) => r.findings.push(Finding {
                    severity: Severity::Note,
                    path: path.into(),
                    what: format!("the vendor's file plus exactly the recorded patch {descr}"),
                    detail: format!("sha256 {shown}; with the patch undone it is the {} digest", prov.label()),
                }),
                None => r.findings.push(Finding {
                    severity: Severity::Warn,
                    path: path.into(),
                    what: format!("named by recorded patch(es) {names}, which do not reproduce it exactly"),
                    detail: format!("sha256 {shown}; shipped by {origin}"),
                }),
            },
            None => r.gaps.push(format!("{path}: named by a recorded patch, and its bytes were not sealed")),
        }
        return;
    }
    if let Some((_, from, why)) = COPIED.iter().find(|(p, ..)| *p == path) {
        if let Some(p) = meta.provenance(manifest, from, d) {
            *r.matched.entry(p.label()).or_insert(0) += 1;
            return;
        }
        r.findings.push(Finding {
            severity: Severity::Critical,
            path: path.into(),
            what: format!("not the vendor's {from}, which {why}, nor any file the vendor shipped here"),
            detail: format!("sha256 {shown}; shipped by {origin}"),
        });
        return;
    }
    if let Some((_, why)) = REGENERATED.iter().find(|(p, _)| *p == path) {
        r.findings.push(Finding {
            severity: Severity::Note,
            path: path.into(),
            what: format!("rewritten by pfSense ({why}); what it says is not judged by this sweep"),
            detail: format!("sha256 {shown}"),
        });
        return;
    }
    r.findings.push(Finding {
        severity: Severity::Critical,
        path: path.into(),
        what: "not a file the vendor shipped here: its digest is in neither the repositories nor the release image"
            .into(),
        detail: format!("sha256 {shown}; shipped by {origin}"),
    });
}

fn undo_patches(
    path: &str,
    content: &[u8],
    ps: &[Patched],
    manifest: &Verified,
    meta: &VerifiedMeta,
) -> Option<(String, Provenance)> {
    use sha2::{Digest as _, Sha256};
    let all: Vec<&FilePatch> = ps.iter().map(|p| &p.file).collect();
    let mut tries: Vec<(String, Vec<&FilePatch>)> =
        vec![(ps.iter().map(|p| format!("'{}'", p.descr)).collect::<Vec<_>>().join(" + "), all)];
    if ps.len() > 1 {
        tries.extend(ps.iter().map(|p| (format!("'{}'", p.descr), vec![&p.file])));
    }
    for (descr, set) in tries {
        if let Some(orig) = crate::patches::reverse(content, &set) {
            let d: [u8; 32] = Sha256::digest(&orig).into();
            if let Some(p) = meta.provenance(manifest, path, &d) {
                return Some((descr, p));
            }
        }
    }
    None
}

fn unknown(r: &mut Report, o: &Obs, manifest: &Verified, meta: &VerifiedMeta, ctx: &Context) {
    let e = &o.entry;

    if e.nlink > 1 && matches!(e.kind, Kind::File(_)) {
        if ctx.links.contains_key(&(e.dev, e.ino)) {
            *r.matched.entry("hard link to a vendor file").or_insert(0) += 1;
            return;
        }
    }

    if let Some(Ok(d)) = &o.digest {
        let hexd = hex(d);
        if let Some((name, port, ver, ..)) = crate::persist::PACKAGE_RC_SCRIPTS.iter().find(|(name, port, ver, p, sha)| {
            *p == e.path
                && *sha == hexd
                && ctx.packages.contains(*name)
                && manifest.covers_version(port, ver) == Some(true)
        }) {
            r.findings.push(Finding {
                severity: Severity::Note,
                path: e.path.clone(),
                what: format!("written by {name}'s install code ({port} {ver}), byte for byte"),
                detail: format!("sha256 {hexd}"),
            });
            return;
        }
    }
    let file = matches!(e.kind, Kind::File(_));
    let evidence = match (&e.kind, &o.digest) {
        (Kind::File(_), Some(Ok(d))) => format!("sha256 {}", hex(d)),
        (Kind::File(_), Some(Err(err))) => format!("not hashed: {err}"),
        (Kind::File(n), None) => format!("{n} bytes, not hashed"),
        (k, _) => kind_name(k).to_string(),
    };
    if matches!(e.kind, Kind::Dir) {
        return;
    }
    if let Some((_, why)) = REGENERATED.iter().find(|(p, _)| *p == e.path) {
        r.findings.push(Finding {
            severity: Severity::Note,
            path: e.path.clone(),
            what: format!("written by pfSense ({why}); what it says is not judged by this sweep"),
            detail: evidence,
        });
        return;
    }
    if let (Some((_, from, why)), Some(Ok(d))) = (COPIED.iter().find(|(p, ..)| *p == e.path), &o.digest) {
        if meta.provenance(manifest, from, d).is_some() {
            *r.matched.entry("copy of a vendor file").or_insert(0) += 1;
            return;
        }
        r.findings.push(Finding {
            severity: Severity::Critical,
            path: e.path.clone(),
            what: format!("not the vendor's {from}, which {why}"),
            detail: evidence,
        });
        return;
    }
    if let Some((_, pkg, why)) = PACKAGE_GENERATED.iter().find(|(p, pkg, _)| *p == e.path && ctx.packages.contains(*pkg)) {
        r.findings.push(Finding {
            severity: Severity::Warn,
            path: e.path.clone(),
            what: format!("written by {pkg}'s own code ({why}); no digest can cover it, and what it says is not judged here"),
            detail: evidence,
        });
        return;
    }
    if e.path == CSRF_SECRET && o.content.as_deref().is_some_and(is_csrf_secret) {
        r.findings.push(Finding {
            severity: Severity::Note,
            path: e.path.clone(),
            what: "csrf-magic's secret, written at first login, in exactly the form csrf-magic writes".into(),
            detail: "a sha1 in hex and nothing else".into(),
        });
        return;
    }
    if let Some(dir) = under(&e.path, WATCHED) {
        r.findings.push(Finding {
            severity: Severity::Critical,
            path: e.path.clone(),
            what: format!("a file no vendor source ships, in {dir}, where pfSense runs or loads what it finds"),
            detail: evidence,
        });
        return;
    }
    let rc_local = e.path.starts_with("/usr/local/etc/rc.d/");
    if rc_local || e.path.starts_with("/etc/rc.d/") {
        let boot = rc_local && e.path.ends_with(".sh");
        r.findings.push(Finding {
            severity: if boot { Severity::Critical } else { Severity::Warn },
            path: e.path.clone(),
            what: if boot {
                "an rc.d script no package owns; rc.start_packages runs every *.sh here at boot".into()
            } else {
                "a file in rc.d no package owns".into()
            },
            detail: evidence,
        });
        return;
    }
    if let Some(dir) = under(&e.path, BINARY_DIRS) {
        r.findings.push(Finding {
            severity: Severity::Warn,
            path: e.path.clone(),
            what: format!("{} no vendor source ships, in {dir}", if file { "a file" } else { "an entry" }),
            detail: evidence,
        });
        return;
    }
    r.unlisted += 1;
}

fn kind_name(k: &Kind) -> &'static str {
    match k {
        Kind::File(_) => "a file",
        Kind::Dir => "a directory",
        Kind::Link(_) => "a symbolic link",
        Kind::Special => "a FIFO, socket or device",
    }
}

fn meta_kind_name(k: MetaKind) -> &'static str {
    match k {
        MetaKind::File => "file",
        MetaKind::Dir => "directory",
        MetaKind::Link => "link",
    }
}

pub fn index_patches(records: &[crate::patches::Record], gaps: &mut Vec<String>) -> BTreeMap<String, Vec<Patched>> {
    let mut out: BTreeMap<String, Vec<Patched>> = BTreeMap::new();
    for rec in records {
        if rec.patch.is_empty() {
            continue;
        }
        match crate::patches::parse_diff(&rec.patch, rec.pathstrip, &rec.basedir) {
            Ok(files) => {
                for f in files {
                    out.entry(f.path.clone()).or_default().push(Patched { descr: rec.descr.clone(), file: f });
                }
            }
            Err(e) => gaps.push(format!(
                "recorded patch '{}' could not be read ({e}); the files it names are graded without it",
                rec.descr
            )),
        }
    }
    out
}

#[cfg(unix)]
pub fn sweep_unsealed(root: &Path, manifest: &Verified, meta: &VerifiedMeta, throttle: Throttle) -> Result<Report, String> {
    let records: Vec<Vec<u8>> = Collector::new(root, manifest, meta, throttle, MAX_RECORD_BYTES).collect();
    judge_records(records.iter().map(Vec::as_slice), manifest, meta)
}

pub const CONFIG_XML: &str = "/cf/conf/config.xml";
