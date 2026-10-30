use std::fs;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use hemostat_evcrypto::x509;
use hemostat_sensor_linux::trust::{self, Packages as _};

use crate::guards::ProtectSet;
use crate::outcome::{ApplyOptions, Failure, Outcome, Plan, RefuseCause, Refusal, UndoKind, UndoRecord};
use crate::paths::path_refusal;
use crate::strip::{hex, read_for_edit, replace, sha256, snapshot, unhex32, Meta};

const MAX_BYTES: u64 = hemostat_sensor_linux::saferead::MAX_SCAN_BYTES;

const REBUILD_LIMIT: std::time::Duration = std::time::Duration::from_secs(180);

const UPDATE_CA_CERTIFICATES: &[&str] = &["/usr/sbin/update-ca-certificates", "/sbin/update-ca-certificates"];

const UPDATE_CA_TRUST: &[&str] = &["/usr/bin/update-ca-trust", "/bin/update-ca-trust", "/usr/sbin/update-ca-trust"];

const DEBIAN_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

const P11_BUNDLE: &str = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem";

const P11_SOURCES: &[&str] = &[
    "/etc/pki/ca-trust/source",
    "/usr/share/pki/ca-trust-source",
    "/etc/pki/trust/anchors",
    "/usr/share/pki/trust/anchors",
    "/etc/ca-certificates/trust-source",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRef {

    pub block: usize,

    pub cert_sha256: [u8; 32],

    pub file_sha256: [u8; 32],
}

impl AnchorRef {

    pub fn token(&self, path: &Path) -> String {
        format!("{}:{}:{}:{}", path.display(), self.block, hex(&self.cert_sha256), hex(&self.file_sha256))
    }

    pub fn parse(token: &str) -> Result<(PathBuf, AnchorRef), String> {
        let bad = || {
            format!(
                "{token:?} is not an anchor token (PATH:BLOCK:CERT-SHA256:FILE-SHA256, as \
                 `remediate --anchors` prints it)"
            )
        };
        let mut it = token.rsplitn(4, ':');
        let file = it.next().and_then(unhex32).ok_or_else(bad)?;
        let cert = it.next().and_then(unhex32).ok_or_else(bad)?;
        let block = it.next().and_then(|n| n.parse::<usize>().ok()).ok_or_else(bad)?;
        let path = it.next().filter(|p| p.starts_with('/')).ok_or_else(bad)?;
        Ok((PathBuf::from(path), AnchorRef { block, cert_sha256: cert, file_sha256: file }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Store {

    Debian,

    P11Kit,

    Bundle,
}

impl Store {

    pub fn of(path: &Path) -> Result<Store, String> {
        use std::path::Component;
        if !path.is_absolute() || !path.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_))) {
            return Err("its path is not absolute and plain".into());
        }
        let s = path.to_str().ok_or("its path is not UTF-8")?;
        let under = |d: &str| s.starts_with(&format!("{d}/"));
        if ["blacklist", "blocklist"].iter().any(|b| s.contains(&format!("/{b}/"))) {
            return Err("it is a distrust list: taking a certificate off one trusts it again".into());
        }
        if under(trust::DEBIAN_LOCAL) || under(trust::DEBIAN_SHARE) {
            return Ok(Store::Debian);
        }
        if P11_SOURCES.iter().any(|d| under(d)) {
            return Ok(Store::P11Kit);
        }
        if trust::BUNDLES.contains(&s) || trust::CAPATHS.iter().any(|d| path.parent() == Some(Path::new(d))) {
            return Ok(Store::Bundle);
        }
        Err(
            "it is not a trust store file this edits — a source under /usr/local/share/ca-certificates, \
             /usr/share/ca-certificates or a p11-kit source, a bundle applications read, or a file in a \
             hashed directory. A file elsewhere that a hashed-directory link points at is taken out of the \
             store by removing that link, by hand (this never edits a link); one a redirection points at, by \
             taking the redirection's line out (`remediate --lines`)"
                .into(),
        )
    }

    fn label(self) -> &'static str {
        match self {
            Store::Debian => "a Debian trust store source",
            Store::P11Kit => "a p11-kit trust store source",
            Store::Bundle => "a bundle applications read",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rebuild {
    tool: PathBuf,
    args: Vec<&'static str>,
    bundle: &'static str,
}

impl Rebuild {

    fn token(&self) -> &'static str {
        if self.args.is_empty() { "update-ca-certificates" } else { "update-ca-trust" }
    }

    fn command(&self) -> String {
        let mut c = self.tool.display().to_string();
        for a in &self.args {
            c.push(' ');
            c.push_str(a);
        }
        c
    }

    fn for_store(store: Store) -> Result<Option<Rebuild>, String> {
        Ok(match store {
            Store::Bundle => None,
            Store::Debian => Some(Rebuild { tool: crate::strip::vouched_tool(UPDATE_CA_CERTIFICATES)?, args: Vec::new(), bundle: DEBIAN_BUNDLE }),
            Store::P11Kit => Some(match crate::strip::vouched_tool(UPDATE_CA_TRUST) {
                Ok(t) => Rebuild { tool: t, args: vec!["extract"], bundle: P11_BUNDLE },

                Err(e) => match crate::strip::vouched_tool(UPDATE_CA_CERTIFICATES) {
                    Ok(t) => Rebuild { tool: t, args: Vec::new(), bundle: "/var/lib/ca-certificates/ca-bundle.pem" },
                    Err(_) => return Err(e),
                },
            }),
        })
    }

    fn from_token(t: &str) -> Result<Option<Rebuild>, String> {
        match t {
            "-" | "" => Ok(None),
            "update-ca-certificates" => Rebuild::for_store(Store::Debian),
            "update-ca-trust" => Rebuild::for_store(Store::P11Kit),
            other => Err(format!("the record names a rebuild this build does not know: {other:?}")),
        }
    }

    fn run(&self) -> Result<String, String> {
        let mut cmd = std::process::Command::new(&self.tool);
        cmd.args(&self.args).env_clear().env("LC_ALL", "C").env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        match hemostat_sensor_linux::sshd::output_within(&mut cmd, std::process::Stdio::null(), REBUILD_LIMIT) {
            Ok(Some(o)) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).trim().lines().last().unwrap_or("").to_string()),
            Ok(Some(o)) => Err(format!("{} exited {}: {}", self.command(), o.status, String::from_utf8_lossy(&o.stderr).trim())),
            Ok(None) => Err(format!("{} had not finished after {} seconds", self.command(), REBUILD_LIMIT.as_secs())),
            Err(e) => Err(format!("could not run {}: {e}", self.command())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {

    pub cert: x509::Cert,

    pub start: usize,

    pub end: usize,

    pub lines: (usize, usize),

    pub blocks: usize,
}

pub fn locate(bytes: &[u8], want: &AnchorRef) -> Result<Located, String> {
    if sha256(bytes) != want.file_sha256 {
        return Err(format!(
            "the file changed since the anchor was offered (it hashes to {}, the offer was made from \
             {}). Look at it again and choose from what is there now",
            hex(&sha256(bytes)),
            hex(&want.file_sha256)
        ));
    }
    let (certs, bad) = x509::certs_in(bytes);
    if bad > 0 {
        return Err(format!("{bad} certificate block(s) in the file do not decode, so what removing one leaves cannot be judged"));
    }
    let blocks = certs.len();
    let hits: Vec<usize> = certs
        .iter()
        .enumerate()
        .filter(|(_, (_, c))| c.as_ref().is_ok_and(|c| c.sha256 == want.cert_sha256))
        .map(|(i, _)| i)
        .collect();
    let i = match hits.as_slice() {
        [] => return Err("the chosen certificate is not in the file".into()),
        [one] => *one,
        many => return Err(format!("the chosen certificate is in the file {} times, and which copy is meant is not something this will guess", many.len())),
    };
    if i != want.block {
        return Err(format!(
            "the chosen certificate is number {} in the file and the offer said {}. The position is a \
             check, never the selector, and a token whose halves disagree was not made from this file",
            i + 1,
            want.block + 1
        ));
    }
    let Some((pem, Ok(cert))) = certs.into_iter().nth(i) else { return Err("the chosen certificate is not in the file".into()) };
    Ok(Located { cert, start: pem.start, end: pem.end, lines: (pem.first_line, pem.last_line), blocks })
}

pub fn without(bytes: &[u8], loc: &Located) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(bytes.get(..loc.start).unwrap_or_default());
    out.extend_from_slice(bytes.get(loc.end..).unwrap_or_default());
    out
}

pub fn rebuild_impact(anchors: &[trust::Anchor], bundle: &Path, store: Store, target: &[u8; 32]) -> Option<String> {
    use x509::Origin;
    let in_bundle = |a: &trust::Anchor| a.seen.iter().any(|s| s.path == bundle);
    let mut add: Vec<String> = Vec::new();
    let mut drop: Vec<String> = Vec::new();
    for a in anchors.iter().filter(|a| a.cert.sha256 != *target) {
        let compiled = a.seen.iter().any(|s| {
            s.place == trust::Place::Source
                && s.selected
                && match store {
                    Store::Debian => s.path.starts_with(trust::DEBIAN_SHARE) || s.path.starts_with(trust::DEBIAN_LOCAL),

                    _ => P11_SOURCES.iter().any(|d| s.path.starts_with(d)) && a.origin != Origin::Vendor,
                }
        });
        let distrusted = a.seen.iter().any(|s| s.place == trust::Place::Distrust);
        if compiled && !distrusted && !in_bundle(a) {
            add.push(format!("{} ({})", a.cert.subject, a.locus.display()));
        }
        if in_bundle(a) && a.origin == Origin::BundleOnly {
            drop.push(a.cert.subject.clone());
        }
    }
    if add.is_empty() && drop.is_empty() {
        return None;
    }
    let mut why = Vec::new();
    if !add.is_empty() {
        why.push(format!(
            "would ADD {} certificate(s) that are in the sources and not in {} yet: {} — a rebuild would \
             start trusting them",
            add.len(),
            bundle.display(),
            add.join("; ")
        ));
    }
    if !drop.is_empty() {
        why.push(format!(
            "would DROP {} certificate(s) {} holds that no source explains: {} — remove those one at a time \
             first, each from the bundle, so each is its own decision",
            drop.len(),
            bundle.display(),
            drop.join("; ")
        ));
    }
    Some(why.join(", and "))
}

pub fn unjudged(sweep: &trust::Report, bundles: &[&Path]) -> Vec<String> {

    let names = |line: &str, p: &str| line.strip_prefix(p).is_some_and(|rest| rest.starts_with('/') || rest.starts_with(':'));
    let source = |line: &str| trust::PLACES.iter().any(|(d, _)| names(line, d)) || names(line, trust::DEBIAN_CONF);
    let bundle = |line: &str| bundles.iter().any(|b| names(line, &b.to_string_lossy()));
    let mut out: Vec<String> = sweep.unread.iter().filter(|u| source(u) || bundle(u)).cloned().collect();

    for f in &sweep.findings {
        let cut = f.subject == "trust store"
            && f.severity >= hemostat_sensor_linux::triage::Severity::Warn
            && f.locus.split(", ").any(|d| source(&format!("{d}:")));
        if cut {
            out.push(format!("{}: {}", f.locus, f.what));
        }
    }
    out
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Held {

    fps: Vec<[u8; 32]>,

    undecoded: usize,
}

impl Held {

    fn of(bytes: &[u8]) -> Held {
        let (certs, bad) = x509::certs_in(bytes);
        let mut held = Held { fps: Vec::new(), undecoded: bad };
        for (_, c) in certs {
            match c {
                Ok(c) => held.fps.push(c.sha256),
                Err(_) => held.undecoded += 1,
            }
        }
        held
    }
}

fn held(path: &Path) -> Option<Held> {
    hemostat_sensor_linux::saferead::read_bytes(path, MAX_BYTES).ok().map(|b| Held::of(&b))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Rebuilt {

    AsJudged(usize),

    StillHolds,

    Otherwise(String),
}

fn rebuilt(before: Option<&Held>, after: Option<&Held>, target: &[u8; 32]) -> Rebuilt {
    let Some(after) = after else {
        return Rebuilt::Otherwise("it could not be read back, so what it holds now is not known".into());
    };
    if after.fps.contains(target) {
        return Rebuilt::StillHolds;
    }
    let Some(before) = before else {
        return Rebuilt::Otherwise("it was not read before the rebuild, so there is nothing to compare it with".into());
    };
    let mut want: Vec<[u8; 32]> = before.fps.iter().copied().filter(|d| d != target).collect();
    let mut now = after.fps.clone();
    want.sort_unstable();
    now.sort_unstable();
    let mut why: Vec<String> = Vec::new();
    if want != now {
        let gone = want.iter().filter(|d| !now.contains(d)).count();
        let new = now.iter().filter(|d| !want.contains(d)).count();
        why.push(format!("beyond this certificate it now holds {new} it did not and lacks {gone} it had"));
    }
    if after.undecoded > 0 || before.undecoded > 0 {
        why.push(format!(
            "it holds {} block(s) this cannot decode ({} before), any of which may be a certificate the rebuild \
             compiled in",
            after.undecoded, before.undecoded
        ));
    }
    if why.is_empty() {
        Rebuilt::AsJudged(now.len())
    } else {
        Rebuilt::Otherwise(why.join(", and "))
    }
}

fn refused(summary: &str, path: &Path, why: impl Into<String>) -> Outcome {
    let why = why.into();
    Outcome::Refused(Refusal {
        action: summary.to_string(),
        cause: RefuseCause::InvalidTarget(why.clone()),
        message: format!("refused to remove the anchor from {}: {why}", path.display()),
        suggested_alternative: None,
    })
}

fn failed(summary: &str, reason: impl Into<String>) -> Outcome {
    Outcome::Failed(Failure { action: summary.to_string(), reason: reason.into() })
}

pub(crate) fn plan(path: &Path, want: &AnchorRef, summary: String) -> Plan {
    let store = Store::of(path).map_or("a file this does not edit", Store::label);
    Plan {
        summary,
        detail: format!(
            "Snapshot {} ({store}) into the vault, then take out certificate {} — matched by its SHA-256 \
             {} and checked against the file's digest when it was offered — and, for a store source, \
             rebuild the store with the distribution's own tool.",
            path.display(),
            want.block + 1,
            hex(&want.cert_sha256)
        ),
        undo: "Put the vault copy back — only while the file is exactly as the removal left it — and \
               rebuild again if the removal did."
            .into(),
        reversible: true,
        prefer_instead: None,
    }
}

fn digest_of(path: &Path) -> Option<[u8; 32]> {
    hemostat_sensor_linux::saferead::read_bytes(path, MAX_BYTES).ok().map(|b| sha256(&b))
}

fn fingerprints(path: &Path) -> Vec<[u8; 32]> {
    let b = hemostat_sensor_linux::saferead::read_bytes(path, MAX_BYTES).unwrap_or_default();
    x509::certs_in(&b).0.into_iter().filter_map(|(_, c)| c.ok()).map(|c| c.sha256).collect()
}

pub(crate) fn apply(summary: String, path: &Path, want: &AnchorRef, opts: &ApplyOptions, protect: &ProtectSet) -> Outcome {
    if let Some(reason) = protect.path_reason(path) {
        return Outcome::Refused(Refusal {
            action: summary,
            message: format!("refused to edit {}: {}", path.display(), reason.describe()),
            cause: RefuseCause::Protected(reason),
            suggested_alternative: None,
        });
    }
    if let Some(reason) = path_refusal(path) {
        return refused(&summary, path, reason);
    }
    let store = match Store::of(path) {
        Ok(s) => s,
        Err(why) => return refused(&summary, path, why),
    };
    let r = match read_for_edit(path) {
        Ok(r) => r,
        Err(why) => return refused(&summary, path, why),
    };
    let loc = match locate(&r.bytes, want) {
        Ok(l) => l,
        Err(why) => return refused(&summary, path, why),
    };
    let pkgs = trust::System::detect(Path::new("/"));
    if let Some((pkg, Some(true))) = pkgs.judge(path, &r.bytes) {
        return refused(
            &summary,
            path,
            format!(
                "{pkg} ships this file and it still matches what {pkg} installed. A distribution anchor is \
                 deselected (dpkg-reconfigure ca-certificates, or a `!` line in /etc/ca-certificates.conf) \
                 or its package removed, not deleted from under the package"
            ),
        );
    }
    let whole = loc.blocks == 1;
    if !whole && path.extension().is_some_and(|e| e == "p11-kit") {
        return refused(
            &summary,
            path,
            "it is a p11-kit file with several objects, and each certificate in one carries attributes \
             around it that taking out the PEM block alone would leave behind. Use `trust anchor --remove` \
             for one object, or remove the whole file",
        );
    }
    if whole && store == Store::Bundle && trust::BUNDLES.contains(&path.to_string_lossy().as_ref()) {
        return refused(&summary, path, "it is the only certificate in a main bundle, and removing it would leave that bundle empty");
    }
    let rebuild = match Rebuild::for_store(store) {
        Ok(r) => r,
        Err(why) => return refused(&summary, path, format!("the store cannot be rebuilt by a tool this trusts, so the source is not removed: {why}")),
    };
    let sweep = trust::report();
    if let Some(rb) = &rebuild {
        if !sweep.available {
            return refused(
                &summary,
                path,
                format!(
                    "the sweep of the store did not run ({}), so what the rebuild would change cannot be judged",
                    sweep.reason.as_deref().unwrap_or("no reason given")
                ),
            );
        }

        let real = fs::canonicalize(rb.bundle).ok();
        let bundles: Vec<&Path> = std::iter::once(Path::new(rb.bundle)).chain(real.as_deref()).collect();
        let unseen = unjudged(&sweep, &bundles);
        if !unseen.is_empty() {
            return refused(
                &summary,
                path,
                format!(
                    "the sweep could not read all of what the rebuild compiles from and rewrites, so what it would \
                     add or drop cannot be judged, and a certificate this cannot read is one the rebuild compiles in \
                     all the same: {}. Deal with those first (`hemostat trust` lists them as NOT READ)",
                    unseen.join("; ")
                ),
            );
        }
        if let Some(why) = rebuild_impact(&sweep.anchors, Path::new(rb.bundle), store, &want.cert_sha256) {
            return refused(&summary, path, format!("the rebuild {why}"));
        }
        let hooks: Vec<&str> = sweep.findings.iter().filter(|f| f.subject == "store rebuild hook").map(|f| f.locus.as_str()).collect();
        if !hooks.is_empty() {
            return refused(
                &summary,
                path,
                format!(
                    "the rebuild would run {} as root, and no package vouches for {}. Read and deal with \
                     the hook first",
                    hooks.join(", "),
                    if hooks.len() == 1 { "it" } else { "them" }
                ),
            );
        }
    }
    let meta = Meta { mode: r.md.mode(), uid: r.md.uid(), gid: r.md.gid() };
    let after = without(&r.bytes, &loc);
    let what = if whole {
        format!("move {} (it holds only this certificate) into the vault", path.display())
    } else {
        format!("take lines {}–{} (certificate {} of {}) out of {}", loc.lines.0, loc.lines.1, want.block + 1, loc.blocks, path.display())
    };
    let bundle_before = rebuild.as_ref().and_then(|rb| digest_of(Path::new(rb.bundle)));

    let held_before = match &rebuild {
        Some(rb) => match held(Path::new(rb.bundle)) {
            Some(h) => Some(h),
            None => {
                return refused(
                    &summary,
                    path,
                    format!("{} cannot be read now, so what the rebuild does to it could not be checked", rb.bundle),
                )
            }
        },
        None => None,
    };

    if !opts.armed {
        let mut detail = format!(
            "Remove {} ({}, sha256 {}, valid {}) from {}: snapshot the file into the vault, then {what}.",
            loc.cert.subject,
            loc.cert.describe(),
            loc.cert.sha256_hex(),
            loc.cert.validity(),
            store.label()
        );
        match &rebuild {
            Some(rb) => detail.push_str(&format!(
                " Then rebuild the store with `{}`, which rewrites {} (and the hashed links); that is a \
                 configuration change and part of this action. The rebuilt bundle must be the bundle as it \
                 is now without this certificate, block for block, and the sweep — which read every source \
                 and the bundle whole — says it will be: no other source is waiting to be compiled in and \
                 the bundle holds nothing a rebuild would drop.",
                rb.command(),
                rb.bundle
            )),
            None => detail.push_str(
                " Nothing is rebuilt: no source holds this certificate, so the bundle's own copy is the one to \
                 take out, and a rebuild would also drop anything else no source explains.",
            ),
        }
        return Outcome::Planned(Plan {
            summary,
            detail,
            undo: format!(
                "hemostat undo <journal>: the vault copy goes back while {} is exactly as this left it{}",
                path.display(),
                if rebuild.is_some() { ", and the store is rebuilt again" } else { "" }
            ),
            reversible: true,
            prefer_instead: None,
        });
    }

    let vault = match snapshot(path, &r.bytes, &opts.vault_dir) {
        Ok(v) => v,
        Err(why) => return failed(&summary, why),
    };
    let changed = if whole { unlink_pinned(&r, &want.file_sha256) } else { replace(&r, &after, meta, None, &want.file_sha256) };
    if let Err(why) = changed {
        let _ = fs::remove_file(&vault);
        return failed(&summary, format!("{why}; {} is unchanged", path.display()));
    }
    let after_digest = if whole { None } else { Some(sha256(&after)) };
    let mut note = String::new();
    if let Some(rb) = &rebuild {
        match rb.run() {
            Ok(said) => {

                note = match rebuilt(held_before.as_ref(), held(Path::new(rb.bundle)).as_ref(), &want.cert_sha256) {
                    Rebuilt::AsJudged(n) => format!(
                        " `{}` rebuilt {} ({n} certificates; {said}): the bundle before, less this one and nothing else.",
                        rb.command(),
                        rb.bundle
                    ),
                    Rebuilt::StillHolds => format!(
                        " WARNING: {} ran and {} STILL holds the certificate — something else puts it there; \
                         the source is in the vault and the bundle needs a look by hand",
                        rb.command(),
                        rb.bundle
                    ),
                    Rebuilt::Otherwise(why) => format!(
                        " WARNING: `{}` rebuilt {}, and {why}. Read `hemostat trust` before trusting the store",
                        rb.command(),
                        rb.bundle
                    ),
                };
            }
            Err(e) => {

                let back = put_back(path, &r.bytes, meta, after_digest.as_ref());
                let again = back.as_ref().ok().map(|()| rb.run());
                return failed(
                    &summary,
                    match (back, again) {
                        (Ok(()), Some(Ok(_))) => format!("the rebuild failed ({e}), so the file was put back and the store rebuilt as it was"),
                        (Ok(()), _) => format!("the rebuild failed ({e}); the file was put back, and the store could not be rebuilt again — run {} by hand", rb.command()),
                        (Err(b), _) => format!("the rebuild failed ({e}) and putting the file back FAILED ({b}). Restore it by hand NOW from {}, then run {}", vault.display(), rb.command()),
                    },
                );
            }
        }
    }
    Outcome::Applied(UndoRecord {
        did: format!("removed {} (sha256 {}) from {}: {what}.{note}", loc.cert.subject, loc.cert.sha256_hex(), path.display()),
        undo: UndoKind::RestoreAnchor {
            vault,
            original: path.to_path_buf(),
            cert_sha256: hex(&want.cert_sha256),
            before: hex(&want.file_sha256),
            after: after_digest.map_or_else(|| "absent".to_string(), |d| hex(&d)),
            mode: meta.mode & 0o7777,
            uid: meta.uid,
            gid: meta.gid,
            rebuild: rebuild.as_ref().map_or_else(|| "-".to_string(), |r| r.token().to_string()),
            bundle_before: bundle_before.map_or_else(|| "-".to_string(), |d| hex(&d)),
        },
        reversible: true,
    })
}

fn unlink_pinned(r: &crate::strip::Read, expect: &[u8; 32]) -> Result<(), String> {
    let now = r.pinned.stat().map_err(|e| format!("the original vanished: {e}"))?;
    if now.st_ino != r.md.ino() || now.st_dev != r.md.dev() {
        return Err("the name now points at a different file than the one read".into());
    }
    let mut again = Vec::new();
    crate::strip::reopen(&r.file)?.take(MAX_BYTES + 1).read_to_end(&mut again).map_err(|e| e.to_string())?;
    if sha256(&again) != *expect {
        return Err("the file was changed while the removal was being prepared".into());
    }

    if unsafe { libc::unlinkat(r.pinned.dir_fd(), r.pinned.name().as_ptr(), 0) } != 0 {
        return Err(format!("unlink failed: {}", std::io::Error::last_os_error()));
    }
    sync_dir(r.pinned.dir_fd());
    Ok(())
}

fn sync_dir(dir: std::os::fd::RawFd) {
    use std::os::fd::FromRawFd as _;

    let dfd = unsafe { libc::openat(dir, c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if dfd >= 0 {

        let d = unsafe { fs::File::from_raw_fd(dfd) };
        let _ = d.sync_all();
    }
}

fn create(path: &Path, bytes: &[u8], meta: Meta) -> Result<(), String> {
    use std::ffi::CString;
    use std::io::Write as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::fs::PermissionsExt as _;
    let pinned = crate::paths::pin_parent(path)?;
    let dir = pinned.dir_fd();
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let tmp = CString::new(format!(".hemostat-anchor.{}.{nonce}", std::process::id())).map_err(|_| "a NUL in the temporary name".to_string())?;

    let fd = unsafe { libc::openat(dir, tmp.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600 as libc::c_uint) };
    if fd < 0 {
        return Err(format!("could not create the restored file: {}", std::io::Error::last_os_error()));
    }

    let mut out = unsafe { fs::File::from_raw_fd(fd) };
    let unlink_tmp = || {

        unsafe { libc::unlinkat(dir, tmp.as_ptr(), 0) };
    };
    let result = (|| -> Result<(), String> {
        out.write_all(bytes).map_err(|e| format!("writing the restored file: {e}"))?;

        if unsafe { libc::fchown(out.as_raw_fd(), meta.uid, meta.gid) } != 0 {
            return Err(format!("could not give it owner {}:{}: {}", meta.uid, meta.gid, std::io::Error::last_os_error()));
        }
        out.set_permissions(fs::Permissions::from_mode(meta.mode & 0o7777)).map_err(|e| format!("could not give it mode {:o}: {e}", meta.mode & 0o7777))?;
        out.sync_all().map_err(|e| format!("syncing the restored file: {e}"))?;

        if unsafe { libc::linkat(dir, tmp.as_ptr(), dir, pinned.name().as_ptr(), 0) } != 0 {
            return Err(format!("could not put it at its name: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    })();
    unlink_tmp();
    result?;
    sync_dir(dir);
    Ok(())
}

fn put_back(path: &Path, bytes: &[u8], meta: Meta, after: Option<&[u8; 32]>) -> Result<(), String> {
    match after {
        None => {
            if fs::symlink_metadata(path).is_ok() {
                return Err(format!("{} exists again, and is not overwritten", path.display()));
            }
            create(path, bytes, meta)
        }
        Some(a) => {
            let now = read_for_edit(path)?;
            if sha256(&now.bytes) != *a {
                return Err(format!("{} has changed since the removal", path.display()));
            }
            replace(&now, bytes, meta, None, a)
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Recorded<'a> {
    pub(crate) vault: &'a Path,
    pub(crate) original: &'a Path,
    pub(crate) cert_sha256: &'a str,
    pub(crate) before: &'a str,
    pub(crate) after: &'a str,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) rebuild: &'a str,
    pub(crate) bundle_before: &'a str,
}

pub(crate) fn undo(rec: Recorded<'_>, opts: &ApplyOptions) -> Outcome {
    let path = rec.original;
    let summary = format!("restore the anchor at {} from the vault", path.display());
    let deny = |why: String| {
        Outcome::Refused(Refusal {
            action: summary.clone(),
            cause: RefuseCause::InvalidTarget(why.clone()),
            message: format!("refused to restore {}: {why}", path.display()),
            suggested_alternative: None,
        })
    };
    if let Some(reason) = path_refusal(path) {
        return deny(reason);
    }
    if let Err(why) = Store::of(path) {
        return deny(format!("this record was not written by the anchor removal: {why}"));
    }
    let (Some(before), Some(cert)) = (unhex32(rec.before), unhex32(rec.cert_sha256)) else {
        return deny("the record's digests are not digests".into());
    };
    let after = match rec.after {
        "absent" => None,
        a => match unhex32(a) {
            Some(d) => Some(d),
            None => return deny("the record's digests are not digests".into()),
        },
    };
    let snap = match hemostat_sensor_linux::saferead::read_bytes(rec.vault, MAX_BYTES) {
        Ok(b) => b,
        Err(e) => return deny(format!("the vault copy {} is unreadable: {e}", rec.vault.display())),
    };
    if sha256(&snap) != before {
        return deny(format!("the vault copy {} is not what was snapshotted", rec.vault.display()));
    }
    if !x509::certs_in(&snap).0.iter().any(|(_, c)| c.as_ref().is_ok_and(|c| c.sha256 == cert)) {
        return deny("the vault copy does not hold the certificate the record names".into());
    }
    match after {
        None => {
            if fs::symlink_metadata(path).is_ok() {
                return deny(format!(
                    "something is at {} again, so putting the vault copy there would replace it. Nothing was \
                     written; the vault copy is {}",
                    path.display(),
                    rec.vault.display()
                ));
            }
        }
        Some(a) => match read_for_edit(path) {
            Ok(now) if sha256(&now.bytes) == a => {}
            Ok(now) => {
                return deny(format!(
                    "it has changed since the removal, so putting the vault copy back would also undo that \
                     change. Nothing was written. What the restore would do to it now (- removed, + added):\n{}\n\
                     The vault copy is {}; merge by hand",
                    crate::strip::line_diff(&now.bytes, &snap),
                    rec.vault.display()
                ))
            }
            Err(why) => return deny(why),
        },
    }
    let rebuild = match Rebuild::from_token(rec.rebuild) {
        Ok(r) => r,
        Err(why) => return deny(format!("the store cannot be rebuilt by a tool this trusts: {why}")),
    };
    if !opts.armed {
        return Outcome::Planned(Plan {
            summary,
            detail: format!(
                "Put {} back from the vault{}.",
                path.display(),
                rebuild.as_ref().map_or_else(String::new, |r| format!(", then rebuild the store with `{}`", r.command()))
            ),
            undo: "Remove it again.".into(),
            reversible: true,
            prefer_instead: None,
        });
    }
    let meta = Meta { mode: rec.mode, uid: rec.uid, gid: rec.gid };
    if let Err(why) = put_back(path, &snap, meta, after.as_ref()) {
        return Outcome::Failed(Failure { action: summary, reason: format!("{why}; nothing was restored") });
    }
    let mut note = String::new();
    if let Some(rb) = &rebuild {
        match rb.run() {
            Ok(_) => {
                let back = fingerprints(Path::new(rb.bundle)).contains(&cert);
                let exact = unhex32(rec.bundle_before).zip(digest_of(Path::new(rb.bundle))).map(|(b, n)| b == n);
                note = match (back, exact) {
                    (true, Some(true)) => format!(" `{}` rebuilt {}, and it is byte for byte what it was before the removal.", rb.command(), rb.bundle),
                    (true, _) => format!(
                        " `{}` rebuilt {}; the certificate is back in it, and the bundle is not byte for byte what it \
                         was before the removal — something else in the store changed since",
                        rb.command(),
                        rb.bundle
                    ),
                    (false, _) => format!(" WARNING: `{}` ran and the certificate is NOT back in {}", rb.command(), rb.bundle),
                };
            }
            Err(e) => note = format!(" WARNING: the file is back and the rebuild failed ({e}); run it by hand"),
        }
    }
    Outcome::Applied(UndoRecord {
        did: format!("restored {} from the vault (sha256 {}).{note}", path.display(), rec.cert_sha256),
        undo: UndoKind::Irreversible {
            note: format!("the anchor is back; remove it again if that was wrong (the vault copy is {})", rec.vault.display()),
        },
        reversible: false,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {

    pub path: PathBuf,

    pub anchor: AnchorRef,

    pub subject: String,

    pub store: Store,

    pub blocks: usize,
}

impl Offer {

    pub fn token(&self) -> String {
        self.anchor.token(&self.path)
    }
}

pub fn offer_for_anchor(a: &trust::Anchor) -> Result<Offer, String> {
    let seen = a
        .at_locus()
        .ok_or_else(|| format!("the sweep did not read this certificate at {}", a.locus.display()))?;
    offer_for(&a.locus, &a.cert.sha256, seen.block, &a.cert.subject)
}

pub fn offer_for(path: &Path, fp: &[u8; 32], block: usize, subject: &str) -> Result<Offer, String> {
    let store = Store::of(path)?;
    let r = read_for_edit(path)?;
    let (at, blocks) = choose(&r.bytes, fp, block, subject).map_err(|why| format!("{}: {why}", path.display()))?;
    Ok(Offer {
        path: path.to_path_buf(),
        anchor: AnchorRef { block: at, cert_sha256: *fp, file_sha256: sha256(&r.bytes) },
        subject: subject.to_string(),
        store,
        blocks,
    })
}

pub fn choose(bytes: &[u8], fp: &[u8; 32], block: usize, subject: &str) -> Result<(usize, usize), String> {
    let (certs, _) = x509::certs_in(bytes);
    let blocks = certs.len();
    let hits: Vec<(usize, String)> = certs
        .into_iter()
        .enumerate()
        .filter_map(|(i, (_, c))| c.ok().filter(|c| c.sha256 == *fp).map(|c| (i, c.subject)))
        .collect();
    let [(at, found)] = hits.as_slice() else {
        return Err(format!("the certificate is in the file {} times", hits.len()));
    };
    if found != subject {
        return Err(format!(
            "the certificate with that fingerprint is {found:?}, and the finding is about {subject:?}: the \
             fingerprint does not belong to the finding's certificate"
        ));
    }
    if *at != block {
        return Err(format!(
            "the certificate is number {} in the file and the sweep read it as number {}: the file is not \
             the one the finding was made from. Run the sweep again",
            at + 1,
            block + 1
        ));
    }
    Ok((*at, blocks))
}
