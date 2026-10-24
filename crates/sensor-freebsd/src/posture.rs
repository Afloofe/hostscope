pub mod parse;

use std::collections::{BTreeMap, BTreeSet};

use hemostat_evcrypto::manifest::Manifest;
use hs_core::severity::Severity;

use crate::store::{covering, parse_mount_p, Mount};
use crate::tools::{Invocation, Runner, Tool};
use parse::{ProcBasic, ProcBinary, Socket, TextVnode};

pub const SCOPE: &str = "posture/2";

pub const SCOPE_V1: &str = "posture/1";

pub const KERNEL_DIR: &str = "/boot/kernel";

pub const PIDFILE_DIRS: [&str; 2] = ["/var/run", "/var/dhcpd/var/run"];

pub const MAX_PIDFILES: usize = 512;
const MAX_PIDFILE_BYTES: u64 = 64;

pub const EXEC_DIRS: [&str; 8] =
    ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec", "/usr/local/bin", "/usr/local/sbin", "/usr/local/libexec"];

fn namesakes(comm: &str) -> Vec<String> {
    if comm.is_empty() || comm.contains('/') || comm == "." || comm == ".." {
        return Vec::new();
    }
    EXEC_DIRS.iter().map(|d| format!("{d}/{comm}")).collect()
}

pub const MAX_IMAGES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {

    Binaries,

    Processes,

    Text,

    Sockets,

    Klds,

    Mounts,
}

impl Source {

    pub const ALL: [Source; 6] =
        [Source::Binaries, Source::Processes, Source::Text, Source::Sockets, Source::Klds, Source::Mounts];

    pub fn invocation(self) -> Invocation {
        match self {
            Source::Binaries => Invocation::new(Tool::Procstat, &["--libxo", "json", "-ab"]),
            Source::Processes => Invocation::new(Tool::Procstat, &["--libxo", "json", "-a"]),
            Source::Text => Invocation::new(Tool::Fstat, &[]),
            Source::Sockets => Invocation::new(Tool::Sockstat, &["-46lc"]),
            Source::Klds => Invocation::new(Tool::Kldstat, &["-v"]),
            Source::Mounts => Invocation::new(Tool::Mount, &["-p"]),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Source::Binaries => "procstat -ab",
            Source::Processes => "procstat -a",
            Source::Text => "fstat",
            Source::Sockets => "sockstat -46lc",
            Source::Klds => "kldstat -v",
            Source::Mounts => "mount -p",
        }
    }

    fn from_label(s: &str) -> Option<Source> {
        Source::ALL.into_iter().find(|x| x.label() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {

    pub source: Source,

    pub tool_sha256: Option<[u8; 32]>,

    pub outcome: Result<(Option<i32>, Vec<u8>), String>,
}

impl Run {

    fn stdout(&self) -> Option<&[u8]> {
        match &self.outcome {
            Ok((Some(0), out)) => Some(out),
            _ => None,
        }
    }

    fn failure(&self) -> Option<String> {
        match &self.outcome {
            Ok((Some(0), _)) => None,
            Ok((Some(c), _)) => Some(format!("{} exited {c}", self.source.label())),
            Ok((None, _)) => Some(format!("{} was ended by a signal", self.source.label())),
            Err(e) => Some(format!("{}: {e}", self.source.label())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImageKind {

    Process,

    Kld,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measured {

    pub ino: u64,

    pub size: u64,

    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {

    pub kind: ImageKind,

    pub path: String,

    pub measured: Result<Measured, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pidfile {

    pub path: String,

    pub content: Result<Vec<u8>, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Raw {

    pub agent_pid: u32,

    pub runs: Vec<Run>,

    pub images: Vec<Image>,

    pub pidfiles: Vec<Pidfile>,

    pub gaps: Vec<String>,

    pub integrity: Option<crate::evidence::Evidence>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn field(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let i = b.iter().position(|x| *x == 0)?;
    Some((b.get(..i)?, b.get(i + 1..)?))
}

fn text(b: &[u8]) -> Result<String, String> {
    String::from_utf8(b.to_vec()).map_err(|_| "a record field is not UTF-8".to_string())
}

impl Raw {

    pub fn records(&self) -> Vec<Vec<u8>> {
        let scope = if self.integrity.is_some() { SCOPE } else { SCOPE_V1 };
        let mut out = vec![[b"V".as_slice(), scope.as_bytes()].concat()];
        out.push(format!("A{}", self.agent_pid).into_bytes());
        for r in &self.runs {
            let mut rec = format!("R{}\0{}\0", r.source.label(), r.tool_sha256.map(|d| hex(&d)).unwrap_or_default())
                .into_bytes();
            match &r.outcome {
                Ok((status, stdout)) => {
                    rec.extend_from_slice(status.map(|s| s.to_string()).unwrap_or_else(|| "signal".into()).as_bytes());
                    rec.extend_from_slice(b"\0o");
                    rec.extend_from_slice(stdout);
                }
                Err(e) => {
                    rec.extend_from_slice(b"-\0e");
                    rec.extend_from_slice(e.as_bytes());
                }
            }
            out.push(rec);
        }
        for i in &self.images {
            let kind = match i.kind {
                ImageKind::Process => "p",
                ImageKind::Kld => "k",
            };
            let tail = match &i.measured {
                Ok(m) => format!("o{}\0{}\0{}", m.ino, m.size, hex(&m.sha256)),
                Err(e) => format!("e{e}"),
            };
            out.push(format!("I{kind}{}\0{tail}", i.path).into_bytes());
        }
        for p in &self.pidfiles {
            let mut rec = format!("F{}\0", p.path).into_bytes();
            match &p.content {
                Ok(b) => {
                    rec.push(b'o');
                    rec.extend_from_slice(b);
                }
                Err(e) => {
                    rec.push(b'e');
                    rec.extend_from_slice(e.as_bytes());
                }
            }
            out.push(rec);
        }
        for g in &self.gaps {
            out.push(format!("G{g}").into_bytes());
        }
        if let Some(ev) = &self.integrity {
            out.extend(ev.records().into_iter().map(|r| [b"X".as_slice(), &r].concat()));
        }
        out
    }

    pub fn from_records<'a>(records: impl IntoIterator<Item = &'a [u8]>) -> Result<Raw, String> {
        let mut raw = Raw::default();
        let mut scope = None;
        let mut agent = None;
        let mut integrity: Vec<&[u8]> = Vec::new();
        for rec in records {
            let Some((&kind, body)) = rec.split_first() else {
                return Err("an empty record".into());
            };
            let bad = |what: &str| format!("a malformed {what} record");
            match kind {
                b'V' => scope = Some(text(body)?),
                b'A' => agent = Some(text(body)?.parse::<u32>().map_err(|_| bad("agent"))?),
                b'R' => {
                    let (label, rest) = field(body).ok_or_else(|| bad("run"))?;
                    let (digest, rest) = field(rest).ok_or_else(|| bad("run"))?;
                    let (status, rest) = field(rest).ok_or_else(|| bad("run"))?;
                    let label = text(label)?;
                    let source = Source::from_label(&label).ok_or_else(|| format!("a run of {label:?}, which posture does not make"))?;
                    let digest = text(digest)?;
                    let tool_sha256 = if digest.is_empty() { None } else { Some(unhex32(&digest).ok_or_else(|| bad("run"))?) };
                    let outcome = match rest.split_first() {
                        Some((b'o', out)) => {
                            let status = match text(status)?.as_str() {
                                "signal" => None,
                                s => Some(s.parse::<i32>().map_err(|_| bad("run"))?),
                            };
                            Ok((status, out.to_vec()))
                        }
                        Some((b'e', why)) => Err(text(why)?),
                        _ => return Err(bad("run")),
                    };
                    raw.runs.push(Run { source, tool_sha256, outcome });
                }
                b'I' => {
                    let (&k, body) = body.split_first().ok_or_else(|| bad("image"))?;
                    let kind = match k {
                        b'p' => ImageKind::Process,
                        b'k' => ImageKind::Kld,
                        _ => return Err(bad("image")),
                    };
                    let (path, rest) = field(body).ok_or_else(|| bad("image"))?;
                    let measured = match rest.split_first() {
                        Some((b'o', m)) => {
                            let m = text(m)?;
                            let mut it = m.split('\0');
                            let ino = it.next().and_then(|s| s.parse().ok()).ok_or_else(|| bad("image"))?;
                            let size = it.next().and_then(|s| s.parse().ok()).ok_or_else(|| bad("image"))?;
                            let sha256 = it.next().and_then(unhex32).ok_or_else(|| bad("image"))?;
                            Ok(Measured { ino, size, sha256 })
                        }
                        Some((b'e', why)) => Err(text(why)?),
                        _ => return Err(bad("image")),
                    };
                    raw.images.push(Image { kind, path: text(path)?, measured });
                }
                b'F' => {
                    let (path, rest) = field(body).ok_or_else(|| bad("pidfile"))?;
                    let content = match rest.split_first() {
                        Some((b'o', b)) => Ok(b.to_vec()),
                        Some((b'e', why)) => Err(text(why)?),
                        _ => return Err(bad("pidfile")),
                    };
                    raw.pidfiles.push(Pidfile { path: text(path)?, content });
                }
                b'G' => raw.gaps.push(text(body)?),
                b'X' => integrity.push(body),
                _ => return Err("a record of a kind this build does not know".into()),
            }
        }
        match scope.as_deref() {
            Some(SCOPE) => {
                if integrity.is_empty() {
                    return Err(format!("a {SCOPE} store with no integrity records"));
                }
                raw.integrity = Some(crate::evidence::Evidence::from_records(integrity)?);
            }
            Some(SCOPE_V1) if integrity.is_empty() => {}
            Some(SCOPE_V1) => return Err(format!("a {SCOPE_V1} store with integrity records in it")),
            Some(other) => return Err(format!("the store records {other:?}, not {SCOPE:?} or {SCOPE_V1:?}")),
            None => return Err("the store carries no scope record".into()),
        }
        raw.agent_pid = agent.ok_or("the store does not say which pid was the agent")?;
        Ok(raw)
    }

    fn run(&self, s: Source) -> Option<&Run> {
        self.runs.iter().find(|r| r.source == s)
    }

    fn text_of(&self, s: Source) -> Result<String, String> {
        let r = self.run(s).ok_or_else(|| format!("{} was not run", s.label()))?;
        match r.stdout() {
            Some(out) => Ok(String::from_utf8_lossy(out).into_owned()),
            None => Err(r.failure().unwrap_or_default()),
        }
    }
}

#[cfg(unix)]
pub fn collect(runner: &mut dyn Runner, root: &std::path::Path, throttle: &mut crate::saferead::Throttle, agent_pid: u32) -> Raw {
    let mut raw = Raw { agent_pid, ..Raw::default() };
    for s in Source::ALL {
        let inv = s.invocation();
        let outcome = runner.run(&inv).map(|o| (o.status, o.stdout)).map_err(|e| e.to_string());
        raw.runs.push(Run { source: s, tool_sha256: runner.tool_sha256(inv.tool()), outcome });
    }

    let mut paths: BTreeSet<(ImageKind, String)> = BTreeSet::new();
    if let Ok(t) = raw.text_of(Source::Binaries) {
        if let Ok(b) = parse::binaries(&t) {

            let text = raw.text_of(Source::Text).map(|t| parse::fstat_text(&t).0).unwrap_or_default();
            let basics = raw.text_of(Source::Processes).and_then(|t| parse::basics(&t)).unwrap_or_default();
            for p in b.iter().filter(|p| p.pid != agent_pid) {
                match &p.path {
                    Some(path) => {
                        paths.insert((ImageKind::Process, path.clone()));
                    }
                    None if p.nameless || text.contains_key(&p.pid) => {
                        let comm = basics.get(&p.pid).map_or(p.command.as_str(), |b| b.command.as_str());
                        for q in namesakes(comm) {
                            if std::fs::symlink_metadata(crate::tools::verify::at(root, &q)).is_ok_and(|m| m.is_file()) {
                                paths.insert((ImageKind::Process, q));
                            }
                        }
                    }
                    None => {}
                }
            }
        }
    }
    if let Ok(t) = raw.text_of(Source::Klds) {
        if let Ok((k, _)) = parse::kldstat(&t) {
            paths.extend(k.into_iter().filter_map(|k| k.path).map(|p| (ImageKind::Kld, p)));
        }
    }
    if paths.len() > MAX_IMAGES {
        raw.gaps.push(format!("{} image paths, over the {MAX_IMAGES} hashed in one sweep; the rest are not judged", paths.len()));
    }
    for (kind, path) in paths.into_iter().take(MAX_IMAGES) {
        let measured = measure(root, &path, throttle);
        raw.images.push(Image { kind, path, measured });
    }

    let (pidfiles, gaps) = read_pidfiles(root);
    raw.pidfiles = pidfiles;
    raw.gaps.extend(gaps);
    raw
}

#[cfg(unix)]
fn measure(root: &std::path::Path, path: &str, throttle: &mut crate::saferead::Throttle) -> Result<Measured, String> {
    use std::os::unix::fs::MetadataExt as _;
    if !path.starts_with('/') {
        return Err("not an absolute path".into());
    }
    let full = crate::tools::verify::at(root, path);
    let (f, md) = crate::saferead::open_regular(&full, crate::saferead::NOT_REGULAR).map_err(|e| e.to_string())?;
    if md.len() > crate::saferead::MAX_HASH_BYTES {
        return Err(format!("{} bytes, over the hash cap", md.len()));
    }
    let sha256 = crate::saferead::sha256_reader(&f, crate::saferead::MAX_HASH_BYTES, throttle).map_err(|e| e.to_string())?;
    Ok(Measured { ino: md.ino(), size: md.size(), sha256 })
}

#[cfg(unix)]
fn read_pidfiles(root: &std::path::Path) -> (Vec<Pidfile>, Vec<String>) {
    let mut found: Vec<String> = Vec::new();
    let mut gaps = Vec::new();
    let list = |dir: &str| -> std::io::Result<Vec<(String, bool)>> {
        let mut v = Vec::new();
        for e in std::fs::read_dir(crate::tools::verify::at(root, dir))? {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            v.push((format!("{}/{name}", dir.trim_end_matches('/')), is_dir));
        }
        v.sort();
        Ok(v)
    };
    for (i, dir) in PIDFILE_DIRS.iter().enumerate() {
        match list(dir) {
            Ok(entries) => {
                for (p, is_dir) in entries {
                    if is_dir && i == 0 {
                        if let Ok(sub) = list(&p) {
                            found.extend(sub.into_iter().filter(|(q, d)| !d && q.ends_with(".pid")).map(|(q, _)| q));
                        }
                    } else if !is_dir && p.ends_with(".pid") {
                        found.push(p);
                    }
                }
            }

            Err(e) if i > 0 && e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => gaps.push(format!("{dir} could not be listed ({e}), so no listener there can be tied to a service")),
        }
    }
    if found.len() > MAX_PIDFILES {
        gaps.push(format!("{} pidfiles, over the {MAX_PIDFILES} read; the rest name no service", found.len()));
    }
    let files = found
        .into_iter()
        .take(MAX_PIDFILES)
        .map(|path| {
            let full = crate::tools::verify::at(root, &path);
            let content = match crate::saferead::open_regular(&full, crate::saferead::NOT_REGULAR) {
                Ok((f, _)) => {
                    use std::io::Read as _;
                    let mut b = Vec::new();
                    (&f).take(MAX_PIDFILE_BYTES).read_to_end(&mut b).map(|_| b).map_err(|e| e.to_string())
                }
                Err(e) => Err(e.to_string()),
            };
            Pidfile { path, content }
        })
        .collect();
    (files, gaps)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Subject {

    Process,

    Kld,

    Listener,

    ProcView,

    SockView,

    KldLoad,

    LoaderEnv,

    Kernel,
}

impl Subject {

    pub fn label(self) -> &'static str {
        match self {
            Subject::Process => "process",
            Subject::Kld => "kld",
            Subject::Listener => "listener",
            Subject::ProcView => "proc-view",
            Subject::SockView => "sock-view",
            Subject::KldLoad => "kld-load",
            Subject::LoaderEnv => "ld-env",
            Subject::Kernel => "kernel",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {

    pub severity: Severity,

    pub subject: Subject,

    pub what: String,

    pub why: String,

    pub pids: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owned {

    pub pid: u32,

    pub command: String,

    pub pidfile: String,

    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub gaps: Vec<String>,

    pub processes: usize,

    pub kernel_processes: usize,

    pub vendor_images: usize,

    pub images: usize,

    pub listeners: usize,

    pub owned: Vec<Owned>,

    pub klds: usize,

    pub agent: Option<(u32, Option<String>)>,

    pub tools: Vec<(Source, Option<[u8; 32]>)>,

    pub views: Vec<String>,

    pub integrity_tools: Vec<(String, String)>,
}

impl Report {

    pub fn complete(&self) -> bool {
        self.gaps.is_empty()
    }

    pub fn count(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Bytes {
    Vendor,
    Not(String),
}

fn judge_bytes(m: &Manifest, img: Option<&Image>, path: &str) -> (Bytes, Option<Measured>) {
    let Some(img) = img else {
        return (Bytes::Not(format!("{path} was not hashed")), None);
    };
    match &img.measured {
        Err(e) => (Bytes::Not(format!("{path} could not be hashed ({e}), so the running image cannot be shown to be the vendor's")), None),
        Ok(ms) => match m.is_vendor(path, &ms.sha256) {
            None => (Bytes::Not(format!("{path} is not in the vendor manifest")), Some(*ms)),
            Some(false) => (
                Bytes::Not(format!("{path} hashes to {}, which the vendor never shipped there", hex(ms.sha256.get(..8).unwrap_or_default()))),
                Some(*ms),
            ),
            Some(true) => (Bytes::Vendor, Some(*ms)),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Running {

    Confirmed,

    Elsewhere(String),

    Unconfirmed,
}

fn running(tv: Option<&TextVnode>, ms: Option<&Measured>, path: &str, mounts: Option<&[Mount]>) -> Running {
    let (Some(tv), Some(ms)) = (tv, ms) else { return Running::Unconfirmed };
    let mount = mounts.and_then(|m| covering(m, path)).map(|m| m.mountpoint.as_str());
    let mut why = Vec::new();
    if tv.inum != ms.ino {
        why.push(format!("it runs inode {} and the path is inode {}", tv.inum, ms.ino));
    }
    if tv.size != ms.size {
        why.push(format!("it runs {} bytes and the path holds {}", tv.size, ms.size));
    }
    if let Some(mp) = mount {
        if mp != tv.mount {
            why.push(format!("it runs from the filesystem at {} and the path is on {mp}", tv.mount));
        }
    }
    if why.is_empty() {
        Running::Confirmed
    } else {
        Running::Elsewhere(why.join("; "))
    }
}

type Grouped = BTreeMap<(Severity, String, String), (BTreeSet<String>, Vec<u32>)>;

#[derive(Debug, Clone)]
struct Standing {
    vendor_running: bool,
    image: Option<(String, Option<u64>)>,
}

pub fn judge(raw: &Raw, m: &Manifest) -> Report {
    let mut rep = Report {
        gaps: raw.gaps.clone(),
        tools: raw.runs.iter().map(|r| (r.source, r.tool_sha256)).collect(),
        ..Report::default()
    };
    for s in Source::ALL {
        if raw.run(s).is_none() {
            rep.gaps.push(format!("{} was not run", s.label()));
        }
    }

    let mounts = match raw.text_of(Source::Mounts).and_then(|t| parse_mount_p(&t)) {
        Ok(m) => Some(m),
        Err(e) => {
            rep.gaps.push(format!("{e}: a running image is compared with its path by inode and size only"));
            None
        }
    };
    let text = match raw.text_of(Source::Text) {
        Ok(t) => {
            let (rows, unread) = parse::fstat_text(&t);
            if unread > 0 {
                rep.gaps.push(format!("fstat: {unread} text row(s) not understood"));
            }
            Some(rows)
        }
        Err(e) => {
            rep.gaps.push(format!("{e}: no running image could be tied to the file at its path"));
            None
        }
    };
    let basics: BTreeMap<u32, ProcBasic> = match raw.text_of(Source::Processes).and_then(|t| parse::basics(&t)) {
        Ok(b) => b,
        Err(e) => {
            rep.gaps.push(format!("{e}: no worker can be tied to its service's parent"));
            BTreeMap::new()
        }
    };
    let images: BTreeMap<(ImageKind, &str), &Image> = raw.images.iter().map(|i| ((i.kind, i.path.as_str()), i)).collect();

    let mut standing: BTreeMap<u32, Standing> = BTreeMap::new();
    let mut grouped: Grouped = BTreeMap::new();
    let mut judged_images: BTreeMap<String, bool> = BTreeMap::new();
    match raw.text_of(Source::Binaries).and_then(|t| parse::binaries(&t)) {
        Err(e) => rep.gaps.push(format!("{e}: no process was judged")),
        Ok(procs) => {
            for mut p in procs {
                if p.pid == raw.agent_pid {
                    rep.agent = Some((p.pid, p.path.clone()));
                    continue;
                }

                if p.command.is_empty() {
                    if let Some(b) = basics.get(&p.pid) {
                        p.command.clone_from(&b.command);
                    }
                }
                let tv = text.as_ref().and_then(|t| t.get(&p.pid));
                judge_process(&p, tv, text.is_some(), m, &images, mounts.as_deref(), &mut rep, &mut standing, &mut grouped, &mut judged_images);
            }
        }
    }
    for ((severity, what, why), (commands, pids)) in grouped {
        let names: Vec<String> = commands.into_iter().collect();
        rep.findings.push(Finding {
            severity,
            subject: Subject::Process,
            what: if what.is_empty() { names.join(", ") } else { what },
            why,
            pids,
        });
    }
    rep.images = judged_images.len();
    rep.vendor_images = judged_images.values().filter(|v| **v).count();

    let mut standings: Vec<crate::integrity::KldStanding> = Vec::new();
    let mut kld_finding: BTreeMap<u32, usize> = BTreeMap::new();
    let kld_text = raw.text_of(Source::Klds).ok();
    match raw.text_of(Source::Klds).and_then(|t| parse::kldstat(&t)) {
        Err(e) => rep.gaps.push(format!("{e}: no kernel file was judged")),
        Ok((klds, unread)) => {
            if unread > 0 {
                rep.gaps.push(format!("kldstat: {unread} file row(s) not understood"));
            }
            for k in klds {
                rep.klds += 1;
                let Some(path) = k.path.as_deref() else {
                    standings.push(crate::integrity::KldStanding { id: k.id, name: k.name.clone(), path: None, vendor: false });
                    kld_finding.insert(k.id, rep.findings.len());
                    rep.findings.push(Finding {
                        severity: Severity::Critical,
                        subject: Subject::Kld,
                        what: k.name.clone(),
                        why: "loaded with no path recorded, so where it came from cannot be judged".into(),
                        pids: Vec::new(),
                    });
                    continue;
                };
                let mut why = Vec::new();
                let parent = path.rsplit_once('/').map_or("", |(d, _)| d);
                if parent != KERNEL_DIR {
                    why.push(format!("loaded from {path}, outside {KERNEL_DIR}"));
                }
                if let (Bytes::Not(w), _) = judge_bytes(m, images.get(&(ImageKind::Kld, path)).copied(), path) {
                    why.push(w);
                }
                standings.push(crate::integrity::KldStanding {
                    id: k.id,
                    name: k.name.clone(),
                    path: Some(path.to_string()),
                    vendor: why.is_empty(),
                });
                if !why.is_empty() {
                    kld_finding.insert(k.id, rep.findings.len());
                    rep.findings.push(Finding {
                        severity: Severity::Critical,
                        subject: Subject::Kld,
                        what: format!("{} (id {})", k.name, k.id),
                        why: why.join("; "),
                        pids: Vec::new(),
                    });
                }
            }
        }
    }

    let service: BTreeMap<u32, &str> = raw
        .pidfiles
        .iter()
        .filter_map(|f| Some((parse::pidfile(f.content.as_ref().ok()?)?, f.path.as_str())))
        .collect();
    match raw.text_of(Source::Sockets).and_then(|t| parse::sockstat(&t)) {
        Err(e) => rep.gaps.push(format!("{e}: no listener was judged")),
        Ok((sockets, unread)) => {
            if unread > 0 {
                rep.gaps.push(format!("sockstat: {unread} line(s) not understood"));
            }
            judge_listeners(&sockets, raw.agent_pid, &standing, &basics, &service, &mut rep);
        }
    }

    match &raw.integrity {
        None => rep.views.push(format!(
            "integrity cross-views: not in this store ({SCOPE_V1}, written by an agent from before them); nothing was compared"
        )),
        Some(ev) => {
            let klds = kld_text.as_deref().filter(|_| !standings.is_empty()).map(|t| (standings.as_slice(), t));
            let (j, ctx) = crate::integrity::judge(ev, raw.agent_pid, m, klds);
            for (id, c) in ctx {
                if let Some(f) = kld_finding.get(&id).and_then(|i| rep.findings.get_mut(*i)) {
                    f.why = format!("{}; {c}", f.why);
                }
            }
            rep.findings.extend(j.findings);
            rep.views.extend(j.views);
            rep.gaps.extend(j.gaps);
            rep.integrity_tools = crate::integrity::tool_digests(ev);
        }
    }

    rep.findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.subject.cmp(&b.subject)).then(a.what.cmp(&b.what)));
    rep
}

#[allow(clippy::too_many_arguments)]
fn judge_process(
    p: &ProcBinary,
    tv: Option<&TextVnode>,
    have_text: bool,
    m: &Manifest,
    images: &BTreeMap<(ImageKind, &str), &Image>,
    mounts: Option<&[Mount]>,
    rep: &mut Report,
    standing: &mut BTreeMap<u32, Standing>,
    grouped: &mut Grouped,
    judged: &mut BTreeMap<String, bool>,
) {
    let mut flag = |sev: Severity, what: String, why: String| {
        let e = grouped.entry((sev, what, why)).or_default();
        e.0.insert(p.command.clone());
        e.1.push(p.pid);
    };
    let Some(path) = p.path.as_deref() else {
        if !p.nameless && tv.is_none() {
            if have_text {

                rep.kernel_processes += 1;
            } else {
                rep.processes += 1;
                standing.insert(p.pid, Standing { vendor_running: false, image: None });
                flag(
                    Severity::Warn,
                    String::new(),
                    "has no image path, and with no fstat it cannot be told from a kernel process".into(),
                );
            }
            return;
        }

        rep.processes += 1;
        standing.insert(p.pid, Standing { vendor_running: false, image: None });
        let inode = tv.map(|t| format!(" (inode {})", t.inum)).unwrap_or_default();
        let namesake = namesakes(&p.command)
            .into_iter()
            .find(|q| judge_bytes(m, images.get(&(ImageKind::Process, q.as_str())).copied(), q).0 == Bytes::Vendor);
        match namesake {
            Some(q) => flag(
                Severity::Warn,
                q.clone(),
                format!(
                    "running an image that no longer has a name{inode}: its binary was replaced or deleted \
                     after it started, and {q} now holds the vendor's file of that name. A package upgrade \
                     without a restart looks like this; restart the service and sweep again. The running \
                     bytes cannot be hashed"
                ),
            ),
            None => flag(
                Severity::Critical,
                String::new(),
                format!(
                    "running an image that no longer has a name{inode}, and no vendor file named {:?} is in \
                     the system directories: its binary was deleted after it started, so the running bytes \
                     cannot be hashed",
                    p.command
                ),
            ),
        }
        return;
    };
    rep.processes += 1;
    let (bytes, ms) = judge_bytes(m, images.get(&(ImageKind::Process, path)).copied(), path);
    let run = running(tv, ms.as_ref(), path, mounts);

    let vendor_running = bytes == Bytes::Vendor && run == Running::Confirmed;
    let image = Some((path.to_string(), tv.map(|t| t.inum)));
    standing.insert(p.pid, Standing { vendor_running, image });
    match (&bytes, &run) {
        (Bytes::Not(why), _) => {
            judged.insert(path.to_string(), false);
            flag(Severity::Critical, path.to_string(), why.clone());
        }
        (Bytes::Vendor, Running::Elsewhere(how)) => {

            flag(
                Severity::Warn,
                path.to_string(),
                format!(
                    "the file now at the path is the vendor's, but the process is not running it ({how}): \
                     its binary was replaced after it started, and the running bytes cannot be hashed. A \
                     package upgrade without a restart looks the same; restart the service and sweep again"
                ),
            );
        }
        (Bytes::Vendor, Running::Confirmed) => {
            judged.entry(path.to_string()).or_insert(true);
        }

        (Bytes::Vendor, Running::Unconfirmed) => {
            judged.entry(path.to_string()).or_insert(true);
        }
    }
}

fn judge_listeners(
    sockets: &[Socket],
    agent_pid: u32,
    standing: &BTreeMap<u32, Standing>,
    basics: &BTreeMap<u32, ProcBasic>,
    service: &BTreeMap<u32, &str>,
    rep: &mut Report,
) {
    let mut by_owner: BTreeMap<Option<u32>, (String, Vec<String>)> = BTreeMap::new();
    for s in sockets.iter().filter(|s| s.is_listener()) {
        rep.listeners += 1;
        let e = by_owner.entry(s.pid).or_insert_with(|| (s.command.clone(), Vec::new()));
        e.1.push(format!("{} {}", s.proto, s.local));
    }
    for (pid, (command, addresses)) in by_owner {
        let Some(pid) = pid else {
            rep.findings.push(Finding {
                severity: Severity::Warn,
                subject: Subject::Listener,
                what: addresses.join(", "),
                why: "listening with no owning process sockstat can name, so no pfSense service owns it".into(),
                pids: Vec::new(),
            });
            continue;
        };
        if pid == agent_pid {
            continue;
        }
        let st = standing.get(&pid);
        let why = match st {
            None => Some("its process was not in the process list, so its image was never judged".to_string()),
            Some(s) if !s.vendor_running => Some("its process is not running a confirmed vendor image".to_string()),
            Some(_) => match owner(pid, standing, basics, service) {
                Some(pf) => {
                    rep.owned.push(Owned { pid, command: command.clone(), pidfile: pf.to_string(), addresses: addresses.clone() });
                    None
                }
                None => Some(
                    "its image is vendor, but no pidfile names it or a parent running the same image, so it is \
                     not one of pfSense's services"
                        .to_string(),
                ),
            },
        };
        if let Some(why) = why {
            rep.findings.push(Finding {
                severity: Severity::Warn,
                subject: Subject::Listener,
                what: format!("{command} on {}", addresses.join(", ")),
                why,
                pids: vec![pid],
            });
        }
    }
}

fn owner<'a>(pid: u32, standing: &BTreeMap<u32, Standing>, basics: &BTreeMap<u32, ProcBasic>, service: &BTreeMap<u32, &'a str>) -> Option<&'a str> {
    let image = standing.get(&pid)?.image.clone()?;
    let mut cur = pid;
    for _ in 0..16 {
        if let Some(pf) = service.get(&cur) {
            return Some(pf);
        }
        let parent = basics.get(&cur)?.ppid;
        if parent == 0 || parent == cur {
            return None;
        }
        let ps = standing.get(&parent)?;
        if !ps.vendor_running || ps.image.as_ref() != Some(&image) {
            return None;
        }
        cur = parent;
    }
    None
}
