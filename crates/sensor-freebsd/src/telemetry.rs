pub mod arp;
pub mod filterlog;
pub mod leases;
pub mod ring;
pub mod states;
pub mod tail;
pub mod timeouts;

use std::collections::BTreeMap;
use std::net::IpAddr;

use hemostat_evcrypto::manifest::Manifest;
use sha2::{Digest as _, Sha256};

use crate::tools::{Invocation, Runner, Tool};

pub const SCOPE: &str = "telemetry/1";

pub const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;

pub const LOGGERS: [&str; 2] = ["/usr/local/sbin/filterlog", "/usr/sbin/syslogd"];

pub const LEASE_FILES: [(&str, leases::Server); 4] = [
    ("/var/dhcpd/var/db/dhcpd.leases", leases::Server::Isc),
    ("/var/dhcpd/var/db/dhcpd6.leases", leases::Server::Isc),
    ("/var/lib/kea/dhcp4.leases", leases::Server::Kea),
    ("/var/lib/kea/dhcp6.leases", leases::Server::Kea),
];

pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

const CHUNK: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {

    Sockets,

    States,

    Timeouts,

    Rules,

    Arp,

    Ndp,

    Physmem,
}

impl Source {

    pub const ALL: [Source; 7] =
        [Source::Sockets, Source::States, Source::Timeouts, Source::Rules, Source::Arp, Source::Ndp, Source::Physmem];

    pub fn invocation(self) -> Invocation {
        match self {
            Source::Sockets => Invocation::new(Tool::Sockstat, &["-46"]),
            Source::States => Invocation::new(Tool::Pfctl, &["-ss", "-vv"]),
            Source::Timeouts => Invocation::new(Tool::Pfctl, &["-st"]),
            Source::Rules => Invocation::new(Tool::Pfctl, &["-sr", "-vv"]),
            Source::Arp => Invocation::new(Tool::Arp, &["--libxo", "json", "-an"]),
            Source::Ndp => Invocation::new(Tool::Ndp, &["--libxo", "json", "-an"]),
            Source::Physmem => Invocation::new(Tool::Sysctl, &["-n", "hw.physmem"]),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Source::Sockets => "sockstat -46",
            Source::States => "pfctl -ss -vv",
            Source::Timeouts => "pfctl -st",
            Source::Rules => "pfctl -sr -vv",
            Source::Arp => "arp -an",
            Source::Ndp => "ndp -an",
            Source::Physmem => "sysctl hw.physmem",
        }
    }

    pub fn reports(self) -> bool {
        !matches!(self, Source::Physmem)
    }

    pub fn required(self) -> bool {
        !matches!(self, Source::Sockets | Source::Timeouts)
    }

    fn from_label(s: &str) -> Option<Source> {
        Source::ALL.into_iter().find(|x| x.label() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {

    pub source: Source,

    pub tool_sha256: Option<[u8; 32]>,

    pub unverified: bool,

    pub outcome: Result<(Option<i32>, Vec<u8>), String>,
}

impl Run {
    fn stdout(&self) -> Result<&[u8], String> {
        match &self.outcome {
            Ok((Some(0), out)) => Ok(out),
            Ok((Some(c), _)) => Err(format!("{} exited {c}", self.source.label())),
            Ok((None, _)) => Err(format!("{} was ended by a signal", self.source.label())),
            Err(e) => Err(format!("{}: {e}", self.source.label())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {

    pub file: tail::LogFile,

    pub from: u64,

    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRead {

    pub path: String,

    pub content: Result<Option<Vec<u8>>, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {

    pub path: String,

    pub sha256: Result<[u8; 32], String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Raw {

    pub now: u64,

    pub cursor: Result<Option<tail::Cursor>, String>,

    pub files: Vec<tail::LogFile>,

    pub segments: Vec<Segment>,

    pub runs: Vec<Run>,

    pub reads: Vec<FileRead>,

    pub images: Vec<Image>,

    pub gaps: Vec<String>,

    pub timings: Vec<(Source, u64, u64)>,
}

impl Default for Raw {
    fn default() -> Raw {
        Raw {
            now: 0,
            cursor: Ok(None),
            files: Vec::new(),
            segments: Vec::new(),
            runs: Vec::new(),
            reads: Vec::new(),
            images: Vec::new(),
            gaps: Vec::new(),
            timings: Vec::new(),
        }
    }
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

fn text(b: &[u8]) -> Result<String, String> {
    String::from_utf8(b.to_vec()).map_err(|_| "a record field is not UTF-8".to_string())
}

fn blob(out: &mut Vec<Vec<u8>>, mut head: Vec<u8>, data: &[u8], chunk: u8) {
    head.extend_from_slice(format!("\0{}\0{}", data.len(), hex(&Sha256::digest(data))).as_bytes());
    out.push(head);
    out.extend(data.chunks(CHUNK).map(|c| [&[chunk][..], c].concat()));
}

fn fields(body: &[u8], n: usize) -> Option<Vec<&[u8]>> {
    let v: Vec<&[u8]> = body.splitn(n, |b| *b == 0).collect();
    (v.len() == n).then_some(v)
}

impl Raw {

    pub fn records(&self) -> Vec<Vec<u8>> {
        let mut out = vec![[b"V".as_slice(), SCOPE.as_bytes()].concat(), format!("N{}", self.now).into_bytes()];
        out.push(match &self.cursor {
            Ok(Some(c)) => format!("Co{}", c.encode()).into_bytes(),
            Ok(None) => b"Cn".to_vec(),
            Err(e) => format!("Ce{e}").into_bytes(),
        });
        for f in &self.files {
            out.push(Self::file_record(b'L', f));
        }
        for s in &self.segments {
            let mut head = Self::file_record(b'S', &s.file);
            head.extend_from_slice(format!("\0{}", s.from).as_bytes());
            blob(&mut out, head, &s.bytes, b's');
        }
        for r in &self.runs {
            let head = format!(
                "R{}\0{}\0{}",
                r.source.label(),
                r.tool_sha256.map(|d| hex(&d)).unwrap_or_default(),
                u8::from(r.unverified)
            );
            match &r.outcome {
                Ok((status, stdout)) => {
                    let st = status.map_or("signal".to_string(), |s| s.to_string());
                    blob(&mut out, format!("{head}\0o{st}").into_bytes(), stdout, b'r');
                }
                Err(e) => out.push(format!("{head}\0e{e}\0\0").into_bytes()),
            }
        }
        for f in &self.reads {
            match &f.content {
                Ok(Some(b)) => blob(&mut out, format!("F{}\0o", f.path).into_bytes(), b, b'f'),
                Ok(None) => out.push(format!("F{}\0a\0\0", f.path).into_bytes()),
                Err(e) => out.push(format!("F{}\0e{e}\0\0", f.path).into_bytes()),
            }
        }
        for i in &self.images {
            out.push(match &i.sha256 {
                Ok(d) => format!("I{}\0o{}", i.path, hex(d)).into_bytes(),
                Err(e) => format!("I{}\0e{e}", i.path).into_bytes(),
            });
        }
        out.extend(self.gaps.iter().map(|g| format!("G{g}").into_bytes()));
        out.extend(self.timings.iter().map(|(s, a, b)| format!("W{}\0{a}\0{b}", s.label()).into_bytes()));
        out
    }

    fn file_record(kind: u8, f: &tail::LogFile) -> Vec<u8> {
        let rot = f.rotation.map_or("-".to_string(), |r| r.to_string());
        let mut v = vec![kind];
        v.extend_from_slice(format!("{}\0{}\0{}\0{}\0{}\0{}", f.path, f.dev, f.ino, f.size, rot, u8::from(f.compressed)).as_bytes());
        v
    }

    fn parse_file(f: &[&[u8]]) -> Result<tail::LogFile, String> {
        let bad = || "a malformed log-file record".to_string();
        let get = |i: usize| f.get(i).ok_or_else(bad).and_then(|b| text(b));
        let num = |i: usize| get(i).and_then(|s| s.parse::<u64>().map_err(|_| bad()));
        let rotation = match get(4)?.as_str() {
            "-" => None,
            r => Some(r.parse::<u32>().map_err(|_| bad())?),
        };
        Ok(tail::LogFile { path: get(0)?, dev: num(1)?, ino: num(2)?, size: num(3)?, rotation, compressed: get(5)? == "1" })
    }

    pub fn from_records<'a>(records: impl IntoIterator<Item = &'a [u8]>) -> Result<Raw, String> {
        enum Open {
            Seg(tail::LogFile, u64),
            Run(Source, Option<[u8; 32]>, bool, Option<i32>),
            File(String),
        }
        struct Pending {
            what: Open,
            want: usize,
            sha: [u8; 32],
            tag: u8,
            data: Vec<u8>,
        }
        fn close(raw: &mut Raw, p: Pending) -> Result<(), String> {
            if p.data.len() != p.want || <[u8; 32]>::from(Sha256::digest(&p.data)) != p.sha {
                return Err("a sealed blob does not match its own length and digest".into());
            }
            match p.what {
                Open::Seg(file, from) => raw.segments.push(Segment { file, from, bytes: p.data }),
                Open::Run(source, tool_sha256, unverified, status) => {
                    raw.runs.push(Run { source, tool_sha256, unverified, outcome: Ok((status, p.data)) })
                }
                Open::File(path) => raw.reads.push(FileRead { path, content: Ok(Some(p.data)) }),
            }
            Ok(())
        }
        let mut raw = Raw::default();
        let mut scope = None;
        let mut now = None;
        let mut cursor = None;
        let mut pending: Option<Pending> = None;
        let bad = |what: &str| format!("a malformed {what} record");
        let blob_tail = |len: &[u8], sha: &[u8]| -> Result<(usize, [u8; 32]), String> {
            let want = text(len)?.parse::<usize>().map_err(|_| bad("blob"))?;
            let sha = unhex32(&text(sha)?).ok_or_else(|| bad("blob"))?;
            Ok((want, sha))
        };
        for rec in records {
            let Some((&kind, body)) = rec.split_first() else { return Err("an empty record".into()) };
            if let Some(p) = pending.as_mut() {
                if kind == p.tag && p.data.len() < p.want {
                    p.data.extend_from_slice(body);
                    if p.data.len() > p.want {
                        return Err("a sealed blob runs past its own length".into());
                    }
                    continue;
                }
            }
            if let Some(p) = pending.take() {
                close(&mut raw, p)?;
            }
            match kind {
                b'V' => scope = Some(text(body)?),
                b'N' => now = Some(text(body)?.parse::<u64>().map_err(|_| bad("time"))?),
                b'C' => {
                    cursor = Some(match body.split_first() {
                        Some((b'o', c)) => Ok(Some(tail::Cursor::decode(&text(c)?).ok_or_else(|| bad("cursor"))?)),
                        Some((b'n', _)) => Ok(None),
                        Some((b'e', e)) => Err(text(e)?),
                        _ => return Err(bad("cursor")),
                    })
                }
                b'L' => raw.files.push(Self::parse_file(&fields(body, 6).ok_or_else(|| bad("log-file"))?)?),
                b'S' => {
                    let f = fields(body, 9).ok_or_else(|| bad("segment"))?;
                    let file = Self::parse_file(&f)?;
                    let from = f.get(6).map(|b| text(b)).transpose()?.and_then(|s| s.parse().ok()).ok_or_else(|| bad("segment"))?;
                    let (want, sha) = blob_tail(f.get(7).copied().unwrap_or_default(), f.get(8).copied().unwrap_or_default())?;
                    pending = Some(Pending { what: Open::Seg(file, from), want, sha, tag: b's', data: Vec::new() });
                }
                b'R' => {
                    let f = fields(body, 6).ok_or_else(|| bad("run"))?;
                    let get = |i: usize| f.get(i).copied().unwrap_or_default();
                    let label = text(get(0))?;
                    let source = Source::from_label(&label).ok_or_else(|| format!("a run of {label:?}, which telemetry does not make"))?;
                    let digest = text(get(1))?;
                    let tool_sha256 = if digest.is_empty() { None } else { Some(unhex32(&digest).ok_or_else(|| bad("run"))?) };
                    let unverified = get(2) == b"1";
                    match get(3).split_first() {
                        Some((b'o', st)) => {
                            let status = match text(st)?.as_str() {
                                "signal" => None,
                                s => Some(s.parse::<i32>().map_err(|_| bad("run"))?),
                            };
                            let (want, sha) = blob_tail(get(4), get(5))?;
                            pending = Some(Pending { what: Open::Run(source, tool_sha256, unverified, status), want, sha, tag: b'r', data: Vec::new() });
                        }
                        Some((b'e', e)) => raw.runs.push(Run { source, tool_sha256, unverified, outcome: Err(text(e)?) }),
                        _ => return Err(bad("run")),
                    }
                }
                b'F' => {
                    let f = fields(body, 4).ok_or_else(|| bad("file"))?;
                    let get = |i: usize| f.get(i).copied().unwrap_or_default();
                    let path = text(get(0))?;
                    match get(1).split_first() {
                        Some((b'o', _)) => {
                            let (want, sha) = blob_tail(get(2), get(3))?;
                            pending = Some(Pending { what: Open::File(path), want, sha, tag: b'f', data: Vec::new() });
                        }
                        Some((b'a', _)) => raw.reads.push(FileRead { path, content: Ok(None) }),
                        Some((b'e', e)) => raw.reads.push(FileRead { path, content: Err(text(e)?) }),
                        _ => return Err(bad("file")),
                    }
                }
                b'I' => {
                    let f = fields(body, 2).ok_or_else(|| bad("image"))?;
                    let path = text(f.first().copied().unwrap_or_default())?;
                    let sha256 = match f.get(1).and_then(|b| b.split_first()) {
                        Some((b'o', d)) => Ok(unhex32(&text(d)?).ok_or_else(|| bad("image"))?),
                        Some((b'e', e)) => Err(text(e)?),
                        _ => return Err(bad("image")),
                    };
                    raw.images.push(Image { path, sha256 });
                }
                b'G' => raw.gaps.push(text(body)?),
                b'W' => {
                    let f = fields(body, 3).ok_or_else(|| bad("timing"))?;
                    let get = |i: usize| f.get(i).map(|b| text(b)).transpose().ok().flatten().unwrap_or_default();
                    let source = Source::from_label(&get(0)).ok_or_else(|| bad("timing"))?;
                    let a = get(1).parse::<u64>().map_err(|_| bad("timing"))?;
                    let b = get(2).parse::<u64>().map_err(|_| bad("timing"))?;
                    raw.timings.push((source, a, b));
                }
                _ => return Err("a record of a kind this build does not know".into()),
            }
        }
        if let Some(p) = pending.take() {
            close(&mut raw, p)?;
        }
        match scope.as_deref() {
            Some(SCOPE) => {}
            Some(other) => return Err(format!("the store records {other:?}, not {SCOPE:?}")),
            None => return Err("the store carries no scope record".into()),
        }
        raw.now = now.ok_or("the store does not say when it was collected")?;
        raw.cursor = cursor.ok_or("the store does not say whether there was a cursor")?;
        Ok(raw)
    }

    pub fn next_cursor(&self) -> Option<tail::Cursor> {
        let s = self.segments.iter().rev().find(|s| s.file.rotation.is_none())?;
        Some(tail::Cursor::after(&s.file, s.from.saturating_add(s.bytes.len() as u64), &s.bytes, self.now))
    }

    fn run(&self, s: Source) -> Result<&[u8], String> {
        self.runs.iter().find(|r| r.source == s).ok_or_else(|| format!("{} was not run", s.label()))?.stdout()
    }
}

#[cfg(unix)]
pub fn collect(
    runner: &mut dyn Runner,
    root: &std::path::Path,
    throttle: &mut crate::saferead::Throttle,
    cursor: Result<Option<String>, String>,
    now: u64,
) -> Raw {
    let mut raw = Raw { now, ..Raw::default() };
    raw.cursor = match cursor {
        Ok(Some(t)) => tail::Cursor::decode(&t).map(Some).ok_or_else(|| "the cursor file is not one this agent writes".to_string()),
        Ok(None) => Ok(None),
        Err(e) => Err(e),
    };

    read_log(root, &mut raw);
    let t0 = std::time::Instant::now();
    let ms = |t: std::time::Instant| u64::try_from(t.duration_since(t0).as_millis()).unwrap_or(u64::MAX);
    for s in Source::ALL {
        let inv = s.invocation();
        let started = ms(std::time::Instant::now());
        let res = runner.run(&inv);
        raw.timings.push((s, started, ms(std::time::Instant::now())));
        let unverified = res.as_ref().err().is_some_and(crate::tools::RunError::is_unverified);
        let outcome = res.map(|o| (o.status, o.stdout)).map_err(|e| e.to_string());
        raw.runs.push(Run { source: s, tool_sha256: runner.tool_sha256(inv.tool()), unverified, outcome });
    }
    let mut paths: Vec<&str> = vec![crate::configxml::CONFIG_PATH];
    paths.extend(LEASE_FILES.iter().map(|(p, _)| *p));
    for path in paths {
        let full = crate::tools::verify::at(root, path);
        let content = match crate::saferead::read_bytes(&full, MAX_FILE_BYTES) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        };
        raw.reads.push(FileRead { path: path.to_string(), content });
    }
    for path in LOGGERS {
        let full = crate::tools::verify::at(root, path);
        let sha256 = crate::saferead::open_regular(&full, crate::saferead::NOT_REGULAR)
            .and_then(|(f, _)| crate::saferead::sha256_reader(&f, crate::saferead::MAX_HASH_BYTES, throttle))
            .map_err(|e| e.to_string());
        raw.images.push(Image { path: path.to_string(), sha256 });
    }
    raw
}

#[cfg(unix)]
fn read_log(root: &std::path::Path, raw: &mut Raw) {
    use std::io::{Read as _, Seek as _, SeekFrom};
    use std::os::unix::fs::MetadataExt as _;

    let dir = crate::tools::verify::at(root, "/var/log");
    let mut names: Vec<String> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| tail::classify(n).is_some()).collect(),
        Err(e) => {
            raw.gaps.push(format!("/var/log could not be listed ({e}); filter.log was not read"));
            return;
        }
    };
    names.sort();
    if names.len() > tail::MAX_ROTATIONS {
        raw.gaps.push(format!("{} filter.log rotations, over the {} listed", names.len(), tail::MAX_ROTATIONS));
        names.truncate(tail::MAX_ROTATIONS);
    }

    let mut opened = Vec::new();
    for n in names {
        let Some((rotation, compressed)) = tail::classify(&n) else { continue };
        let path = format!("/var/log/{n}");
        match crate::saferead::open_regular(&crate::tools::verify::at(root, &path), crate::saferead::NOT_REGULAR) {
            Ok((f, md)) => {
                let lf = tail::LogFile { path, dev: md.dev(), ino: md.ino(), size: md.size(), rotation, compressed };
                raw.files.push(lf.clone());
                opened.push((lf, f));
            }
            Err(e) => raw.gaps.push(format!("{path} could not be opened ({e}); its lines were not read")),
        }
    }
    if !raw.files.iter().any(|f| f.rotation.is_none()) {
        raw.gaps.push(format!("{} is not there; only rotations were read", tail::LIVE));
    }
    let listing: Vec<tail::LogFile> = opened.iter().map(|(l, _)| l.clone()).collect();
    let mut segs: Vec<Segment> = Vec::new();
    for (i, from, to) in tail::plan(&listing, MAX_LOG_BYTES) {
        let Some((lf, f)) = opened.get_mut(i) else { continue };
        let mut buf = Vec::new();
        let r = f.seek(SeekFrom::Start(from)).and_then(|_| f.take(to - from).read_to_end(&mut buf));
        match r {
            Ok(_) => segs.push(Segment { file: lf.clone(), from, bytes: buf }),
            Err(e) => raw.gaps.push(format!("{} could not be read ({e})", lf.path)),
        }
    }

    let live_ino = raw.files.iter().find(|f| f.rotation.is_none()).map(|f| (f.dev, f.ino));
    if let Ok((mut f, md)) = crate::saferead::open_regular(&crate::tools::verify::at(root, tail::LIVE), crate::saferead::NOT_REGULAR) {
        if live_ino.is_some_and(|li| li != (md.dev(), md.ino())) {
            let lf = tail::LogFile { path: tail::LIVE.into(), dev: md.dev(), ino: md.ino(), size: md.size(), rotation: None, compressed: false };
            let mut buf = Vec::new();
            if (&mut f).take(MAX_LOG_BYTES).read_to_end(&mut buf).is_ok() {

                for s in segs.iter_mut().filter(|s| Some((s.file.dev, s.file.ino)) == live_ino) {
                    s.file.rotation = Some(0);
                }
                for f in raw.files.iter_mut().filter(|f| Some((f.dev, f.ino)) == live_ino) {
                    f.rotation = Some(0);
                }
                raw.files.push(lf.clone());
                segs.insert(0, Segment { file: lf, from: 0, bytes: buf });
            }
        }
    }

    segs.reverse();
    raw.segments = segs;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleName {

    pub tracker: String,

    pub action: String,

    pub logs: bool,

    pub descr: String,

    pub nr: Option<u32>,

    pub from_config: bool,
}

pub fn same_tracker(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let num = |s: &str| (!s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())).then(|| s.trim_start_matches('0').to_string());
    matches!((num(a), num(b)), (Some(x), Some(y)) if x == y)
}

#[derive(Debug, Clone)]
pub struct Evidence {

    pub now: u64,

    pub ring: ring::Ring,

    pub lines: usize,

    pub rejects: BTreeMap<filterlog::Reject, usize>,

    pub states: Option<Vec<states::State>>,

    pub rules: BTreeMap<u32, states::PfRule>,

    pub names: Vec<RuleName>,

    pub neighbours: Vec<arp::Neighbour>,

    pub leases: Vec<leases::Lease>,

    pub wan: Vec<String>,

    pub ifnames: BTreeMap<String, String>,

    pub own: Vec<IpAddr>,

    pub continuity: tail::Continuity,

    pub cursor: Option<tail::Cursor>,

    pub unread_history: Vec<(String, u64)>,

    pub suspect: Vec<String>,

    pub gaps: Vec<String>,

    pub tools: Vec<(Source, Option<[u8; 32]>)>,

    pub physmem: Option<u64>,

    pub sockets: Result<Vec<crate::posture::parse::Socket>, String>,

    pub timeouts: Result<timeouts::Timeouts, String>,

    pub sockets_lag_ms: Option<u64>,
}

impl Evidence {

    pub fn rule(&self, tracker: &str) -> Option<&RuleName> {
        self.names.iter().find(|n| same_tracker(&n.tracker, tracker))
    }

    pub fn is_wan(&self, dev: &str) -> bool {
        self.wan.iter().any(|w| w == dev)
    }

    pub fn silent_passes(&self) -> Vec<&states::PfRule> {
        self.rules.values().filter(|r| r.action == "pass" && !r.logs).collect()
    }
}

pub fn judge(raw: &Raw, m: &Manifest) -> Evidence {
    let mut gaps = raw.gaps.clone();
    let mut suspect = Vec::new();

    let mut tools = Vec::new();
    for r in &raw.runs {
        tools.push((r.source, r.tool_sha256));
        if r.unverified && r.source.reports() {
            suspect.push(format!("{} failed verification, so what it reports cannot be shown to be the box's", r.source.label()));
        }
    }
    for i in &raw.images {
        match &i.sha256 {
            Ok(d) => match m.is_vendor(&i.path, d) {
                Some(true) => {}
                Some(false) => suspect.push(format!("{} is not the vendor's binary, and it writes filter.log", i.path)),
                None => suspect.push(format!("{} is not in the vendor manifest, and it writes filter.log", i.path)),
            },
            Err(e) => suspect.push(format!("{} could not be hashed ({e}), and it writes filter.log", i.path)),
        }
    }

    let cursor = match &raw.cursor {
        Ok(c) => *c,
        Err(e) => {
            gaps.push(format!("the last sweep's cursor could not be read ({e}); continuity is not judged"));
            None
        }
    };
    let spans: Vec<tail::Span<'_>> = raw.segments.iter().map(|s| tail::Span { file: &s.file, from: s.from, bytes: &s.bytes }).collect();
    let continuity = tail::continuity(cursor.as_ref(), &spans);
    if continuity.tampered() {
        suspect.push(continuity.describe(cursor.as_ref()));
    }
    let physmem = raw.run(Source::Physmem).ok().and_then(|b| std::str::from_utf8(b).ok()).and_then(|s| s.trim().parse::<u64>().ok());
    let mut ring = ring::Ring::new(ring::capacity(physmem));
    let mut rejects: BTreeMap<filterlog::Reject, usize> = BTreeMap::new();
    let mut lines = 0;

    let cursor_seg = cursor.and_then(|c| raw.segments.iter().position(|s| s.file.dev == c.dev && s.file.ino == c.ino));
    for (si, s) in raw.segments.iter().enumerate() {

        let mut off = s.from;
        let mut body: &[u8] = &s.bytes;

        if s.from > 0 {
            let cut = body.iter().position(|b| *b == b'\n').map_or(body.len(), |i| i + 1);
            off = off.saturating_add(cut as u64);
            body = body.get(cut..).unwrap_or_default();
        }
        for l in body.split_inclusive(|b| *b == b'\n') {
            let start = off;
            off = off.saturating_add(l.len() as u64);
            if l.iter().all(|b| *b == b'\n') {
                continue;
            }
            lines += 1;
            let new = match (cursor_seg, cursor) {
                (Some(cs), Some(c)) => si > cs || (si == cs && start >= c.offset),
                _ => true,
            };
            match filterlog::parse_line(l) {
                Ok(line) => ring.push(line, new),
                Err(r) => *rejects.entry(r).or_default() += 1,
            }
        }
    }
    let unread_history: Vec<(String, u64)> = raw.files.iter().filter(|f| f.compressed).map(|f| (f.path.clone(), f.size)).collect();

    let states = match raw.run(Source::States) {
        Ok(b) => {
            let t = states::parse(&String::from_utf8_lossy(b));
            if t.unread > 0 {
                gaps.push(format!("{} state(s) printed in a shape this build does not read", t.unread));
            }
            if t.truncated {
                gaps.push(format!("more than {} states; the rest were not read", states::MAX_STATES));
            }
            Some(t.states)
        }
        Err(e) => {
            gaps.push(format!("the state table was not read ({e}): no flow can be shown to have left by its state"));
            None
        }
    };
    let sockets = raw.run(Source::Sockets).and_then(|b| {
        let (s, unread) = crate::posture::parse::sockstat(&String::from_utf8_lossy(b))?;
        if unread > 0 {
            return Err(format!("sockstat -46: {unread} line(s) not understood"));
        }
        Ok(s)
    });
    let timeouts = raw.run(Source::Timeouts).and_then(|b| timeouts::parse(&String::from_utf8_lossy(b)));
    let when = |s: Source| raw.timings.iter().find(|t| t.0 == s).copied();

    for (src, res) in [(Source::Sockets, sockets.as_ref().err()), (Source::Timeouts, timeouts.as_ref().err())] {
        if let (Some(e), true) = (res, raw.runs.iter().any(|r| r.source == src)) {
            gaps.push(format!("{} was not read ({e}): the firewall's own states are not matched to its sockets", src.label()));
        }
    }
    let sockets_lag_ms = match (when(Source::Sockets), when(Source::States)) {
        (Some((_, a, _)), Some((_, _, b))) if b >= a => Some(b - a),
        _ => None,
    };
    let rules: BTreeMap<u32, states::PfRule> = match raw.run(Source::Rules) {
        Ok(b) => states::parse_rules(&String::from_utf8_lossy(b)).into_iter().map(|r| (r.nr, r)).collect(),
        Err(e) => {
            gaps.push(format!("the loaded rules were not read ({e}): a rule is named by its config entry or not at all"));
            BTreeMap::new()
        }
    };

    let mut neighbours = Vec::new();
    for (s, f) in [(Source::Arp, arp::parse_arp as fn(&str) -> Result<arp::Table, String>), (Source::Ndp, arp::parse_ndp)] {
        match raw.run(s).and_then(|b| f(&String::from_utf8_lossy(b))) {
            Ok(t) => neighbours.extend(t.entries),
            Err(e) => gaps.push(format!("{} was not read: {e}", s.label())),
        }
    }
    let mut all_leases = Vec::new();
    for (path, server) in LEASE_FILES {
        match raw.reads.iter().find(|r| r.path == path).map(|r| &r.content) {
            Some(Ok(Some(b))) => {
                let t = String::from_utf8_lossy(b);
                let l = match server {
                    leases::Server::Isc => leases::parse_isc(&t),
                    leases::Server::Kea => leases::parse_kea(&t),
                };
                if l.unread > 0 {
                    gaps.push(format!("{path}: {} entr(ies) not read", l.unread));
                }
                all_leases.extend(l.leases);
            }
            Some(Ok(None)) => {}
            Some(Err(e)) => gaps.push(format!("{path} could not be read ({e})")),
            None => gaps.push(format!("{path} was not looked at")),
        }
    }

    let mut wan = Vec::new();
    let mut ifnames = BTreeMap::new();
    let mut own = Vec::new();
    let mut names: Vec<RuleName> = Vec::new();
    match raw.reads.iter().find(|r| r.path == crate::configxml::CONFIG_PATH).map(|r| &r.content) {
        Some(Ok(Some(b))) => match crate::configxml::parse(b) {
            Ok(c) => {
                let outward = c.wan_interfaces();
                if let Some(ifs) = c.root().child("interfaces") {
                    for i in &ifs.children {
                        let Some(dev) = i.text_at("if").filter(|d| !d.is_empty()) else { continue };
                        ifnames.insert(dev.to_string(), i.name.clone());
                        if outward.contains(&i.name) {
                            wan.push(dev.to_string());
                        }
                        for k in ["ipaddr", "ipaddrv6"] {
                            if let Some(a) = i.text_at(k).and_then(|a| a.parse::<IpAddr>().ok()) {
                                own.push(a);
                            }
                        }
                    }
                }
                for r in c.rules() {
                    let Some(t) = r.tracker.clone() else { continue };
                    let nr = rules.values().find(|p| p.tracker.as_deref().is_some_and(|pt| same_tracker(pt, &t))).map(|p| p.nr);
                    let logs = match nr.and_then(|n| rules.get(&n)) {
                        Some(p) => p.logs,
                        None => r.fields.iter().any(|(k, _)| k == "log"),
                    };
                    names.push(RuleName { tracker: t, action: r.kind.clone(), logs, descr: r.descr.clone(), nr, from_config: true });
                }
            }
            Err(e) => gaps.push(format!("config.xml was sealed but not read ({e}); no interface is known to face outward")),
        },
        Some(Ok(None)) => gaps.push("config.xml is not there; no interface is known to face outward".into()),
        Some(Err(e)) => gaps.push(format!("config.xml could not be read ({e}); no interface is known to face outward")),
        None => gaps.push("config.xml was not looked at".into()),
    }

    for p in rules.values() {
        let Some(t) = &p.tracker else { continue };
        if !names.iter().any(|n| same_tracker(&n.tracker, t)) {
            names.push(RuleName { tracker: t.clone(), action: p.action.clone(), logs: p.logs, descr: p.label.clone().unwrap_or_default(), nr: Some(p.nr), from_config: false });
        }
    }

    Evidence {
        now: raw.now,
        ring,
        lines,
        rejects,
        states,
        rules,
        names,
        neighbours,
        leases: all_leases,
        wan,
        ifnames,
        own,
        continuity,
        cursor,
        unread_history,
        suspect,
        gaps,
        tools,
        physmem,
        sockets,
        timeouts,
        sockets_lag_ms,
    }
}
