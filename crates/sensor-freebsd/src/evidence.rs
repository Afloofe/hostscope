use std::collections::BTreeMap;
#[cfg(unix)]
use std::path::{Path, PathBuf};

use crate::tools::Invocation;
#[cfg(unix)]
use crate::tools::Runner;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Obs {

    Bytes(Vec<u8>),

    Digest {

        sha256: [u8; 32],

        len: u64,
    },

    Dir(Vec<Entry>),

    Link(String),

    Absent,

    Refused(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {

    File,

    Dir,

    Link,

    Other,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Kind::File => b'f',
            Kind::Dir => b'd',
            Kind::Link => b'l',
            Kind::Other => b'o',
        }
    }

    fn from_byte(b: u8) -> Option<Kind> {
        Some(match b {
            b'f' => Kind::File,
            b'd' => Kind::Dir,
            b'l' => Kind::Link,
            b'o' => Kind::Other,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {

    pub name: String,

    pub kind: Kind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolObs {

    Ran {

        status: Option<i32>,

        stdout: Vec<u8>,
    },

    Failed(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evidence {

    pub kind: String,

    pub obs: BTreeMap<String, Obs>,

    pub tools: BTreeMap<String, ToolObs>,
}

pub fn tool_key(inv: &Invocation) -> String {
    let mut k = inv.tool().name().to_string();
    for a in inv.args() {
        k.push(' ');
        k.push_str(a);
    }
    k
}

impl Evidence {

    pub fn new(kind: &str) -> Evidence {
        Evidence { kind: kind.to_string(), ..Evidence::default() }
    }

    pub fn bytes(&self, path: &str) -> Option<&[u8]> {
        match self.obs.get(path) {
            Some(Obs::Bytes(b)) => Some(b),
            _ => None,
        }
    }

    pub fn text(&self, path: &str) -> Option<String> {
        self.bytes(path).map(|b| String::from_utf8_lossy(b).into_owned())
    }

    pub fn dir(&self, path: &str) -> Option<&[Entry]> {
        match self.obs.get(path) {
            Some(Obs::Dir(d)) => Some(d),
            _ => None,
        }
    }

    pub fn sha256(&self, path: &str) -> Option<[u8; 32]> {
        use sha2::{Digest as _, Sha256};
        match self.obs.get(path) {
            Some(Obs::Bytes(b)) => Some(Sha256::digest(b).into()),
            Some(Obs::Digest { sha256, .. }) => Some(*sha256),
            _ => None,
        }
    }

    pub fn unread(&self, path: &str) -> Option<String> {
        match self.obs.get(path) {
            Some(Obs::Refused(why)) => Some(why.clone()),
            Some(Obs::Digest { len, .. }) => Some(format!("{len} bytes, too large to read; only its digest was kept")),
            None => Some("never looked at".into()),
            _ => None,
        }
    }

    pub fn records(&self) -> Vec<Vec<u8>> {
        let mut out = vec![[b"k".as_slice(), self.kind.as_bytes()].concat()];
        for (path, o) in &self.obs {
            let (tag, payload): (u8, Vec<u8>) = match o {
                Obs::Bytes(b) => (b'B', b.clone()),
                Obs::Digest { sha256, len } => (b'D', [sha256.as_slice(), &len.to_be_bytes()].concat()),
                Obs::Dir(es) => {
                    let mut p = Vec::new();
                    for (i, e) in es.iter().enumerate() {
                        if i > 0 {
                            p.push(0);
                        }
                        p.push(e.kind.byte());
                        p.extend_from_slice(e.name.as_bytes());
                    }
                    (b'L', p)
                }
                Obs::Link(t) => (b'S', t.as_bytes().to_vec()),
                Obs::Absent => (b'A', Vec::new()),
                Obs::Refused(why) => (b'X', why.as_bytes().to_vec()),
            };
            out.push([&[b'o', tag], path.as_bytes(), b"\0", &payload].concat());
        }
        for (key, t) in &self.tools {
            let payload = match t {
                ToolObs::Ran { status, stdout } => {
                    let s = status.map_or_else(|| "-".to_string(), |c| c.to_string());
                    [b"R".as_slice(), s.as_bytes(), b"\0", stdout].concat()
                }
                ToolObs::Failed(why) => [b"F".as_slice(), why.as_bytes()].concat(),
            };
            out.push([b"t".as_slice(), key.as_bytes(), b"\0", &payload].concat());
        }
        out
    }

    pub fn from_records<'a>(recs: impl IntoIterator<Item = &'a [u8]>) -> Result<Evidence, String> {
        let mut ev = Evidence::default();
        let mut kind = None;
        let text = |b: &[u8]| String::from_utf8(b.to_vec()).map_err(|_| "a record key is not UTF-8".to_string());
        for r in recs {
            match r.split_first() {
                Some((b'k', rest)) => kind = Some(text(rest)?),
                Some((b'o', rest)) => {
                    let (&tag, rest) = rest.split_first().ok_or("an empty observation record")?;
                    let nul = rest.iter().position(|&b| b == 0).ok_or("an observation record with no path")?;
                    let (path, payload) = (text(rest.get(..nul).unwrap_or_default())?, rest.get(nul + 1..).unwrap_or_default());
                    let o = match tag {
                        b'B' => Obs::Bytes(payload.to_vec()),
                        b'D' => {
                            let sha: [u8; 32] = payload.get(..32).and_then(|s| s.try_into().ok()).ok_or("a short digest record")?;
                            let len: [u8; 8] = payload.get(32..40).and_then(|s| s.try_into().ok()).ok_or("a short digest record")?;
                            if payload.len() != 40 {
                                return Err("a digest record of the wrong length".into());
                            }
                            Obs::Digest { sha256: sha, len: u64::from_be_bytes(len) }
                        }
                        b'L' => {
                            let mut es = Vec::new();
                            if !payload.is_empty() {
                                for e in payload.split(|&b| b == 0) {
                                    let (&k, name) = e.split_first().ok_or("an empty directory entry")?;
                                    let kind = Kind::from_byte(k).ok_or("a directory entry of no known kind")?;
                                    es.push(Entry { name: String::from_utf8_lossy(name).into_owned(), kind });
                                }
                            }
                            Obs::Dir(es)
                        }
                        b'S' => Obs::Link(String::from_utf8_lossy(payload).into_owned()),
                        b'A' => Obs::Absent,
                        b'X' => Obs::Refused(String::from_utf8_lossy(payload).into_owned()),
                        _ => return Err("an observation of a kind this build does not know".into()),
                    };
                    ev.obs.insert(path, o);
                }
                Some((b't', rest)) => {
                    let nul = rest.iter().position(|&b| b == 0).ok_or("a tool record with no key")?;
                    let (key, payload) = (text(rest.get(..nul).unwrap_or_default())?, rest.get(nul + 1..).unwrap_or_default());
                    let t = match payload.split_first() {
                        Some((b'R', rest)) => {
                            let nul = rest.iter().position(|&b| b == 0).ok_or("a tool record with no status")?;
                            let s = std::str::from_utf8(rest.get(..nul).unwrap_or_default()).map_err(|_| "a bad status")?;
                            let status = if s == "-" { None } else { Some(s.parse::<i32>().map_err(|_| "a bad status")?) };
                            ToolObs::Ran { status, stdout: rest.get(nul + 1..).unwrap_or_default().to_vec() }
                        }
                        Some((b'F', why)) => ToolObs::Failed(String::from_utf8_lossy(why).into_owned()),
                        _ => return Err("a tool record of a kind this build does not know".into()),
                    };
                    ev.tools.insert(key, t);
                }
                _ => return Err("a record of a kind this build does not know".into()),
            }
        }
        ev.kind = kind.ok_or("the store has no kind record")?;
        Ok(ev)
    }

    pub fn size(&self) -> usize {
        self.records().iter().map(Vec::len).sum()
    }

    pub fn shed_to(&mut self, room: u64) -> u64 {
        let mut size = u64::try_from(self.size()).unwrap_or(u64::MAX);
        if size <= room {
            return size;
        }
        let mut kept: Vec<(bool, usize, String)> = self
            .obs
            .iter()
            .filter_map(|(p, o)| match o {
                Obs::Bytes(b) => Some((p.as_str() != crate::configxml::CONFIG_PATH, b.len(), p.clone())),
                _ => None,
            })
            .collect();

        kept.sort_unstable();
        while size > room {
            let Some((_, len, path)) = kept.pop() else { break };
            let why = format!(
                "{len} bytes, read and not kept: the evidence store had no room for it beside the rest of this \
                 sweep, short of the part kept for containment evidence"
            );

            let Some(freed) = len.checked_sub(why.len()).filter(|f| *f > 0) else { continue };
            size = size.saturating_sub(u64::try_from(freed).unwrap_or(u64::MAX));
            self.obs.insert(path, Obs::Refused(why));
        }
        size
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Judged {

    pub findings: Vec<crate::drift::Finding>,

    pub gaps: Vec<String>,
}

impl Judged {

    pub fn sort(&mut self) {
        self.findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.subject.cmp(&b.subject)).then_with(|| a.what.cmp(&b.what)));
        self.findings.dedup();
        self.gaps.sort();
        self.gaps.dedup();
    }

    pub fn count(&self, sev: hs_core::severity::Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }
}

pub const MAX_ENTRIES: usize = 4096;

pub const MAX_KEPT_BYTES: u64 = 64 * 1024 * 1024;

pub const ROOM_SLACK: u64 = 1024 * 1024;

#[cfg(unix)]
#[derive(Debug)]
pub struct Collector {
    root: PathBuf,

    pub ev: Evidence,
    throttle: crate::saferead::Throttle,

    kept: u64,
    budget: u64,

    room_cut: bool,
}

#[cfg(unix)]
impl Collector {

    pub fn new(kind: &str, root: &Path) -> Collector {
        Collector {
            root: root.to_path_buf(),
            ev: Evidence::new(kind),
            throttle: crate::saferead::Throttle::new(crate::saferead::HASH_BYTES_PER_SEC),
            kept: 0,
            budget: MAX_KEPT_BYTES,
            room_cut: false,
        }
    }

    pub fn keep_within(&mut self, room: u64) {
        let held = u64::try_from(self.ev.size()).unwrap_or(u64::MAX);
        let cap = self.kept.saturating_add(room.saturating_sub(held).saturating_sub(ROOM_SLACK));
        if cap < self.budget {
            self.budget = cap;
            self.room_cut = true;
        }
    }

    fn over_budget(&self, len: u64) -> String {
        if self.room_cut {
            format!(
                "{len} bytes, not read: this sweep had already kept {} bytes of files, and the evidence store had \
                 room for {} of them short of the part kept for containment evidence",
                self.kept, self.budget
            )
        } else {
            format!("{len} bytes, not read: this sweep had already kept {} bytes of files, and keeps at most {}", self.kept, self.budget)
        }
    }

    pub fn unthrottled(kind: &str, root: &Path) -> Collector {
        Collector { throttle: crate::saferead::Throttle::unlimited(), ..Collector::new(kind, root) }
    }

    fn at(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }

    fn have(&self, path: &str) -> bool {
        self.ev.obs.contains_key(path)
    }

    fn stat(&mut self, path: &str) -> Option<Kind> {
        let p = self.at(path);
        match std::fs::symlink_metadata(&p) {
            Ok(md) if md.file_type().is_symlink() => {
                let t = std::fs::read_link(&p).map(|t| t.to_string_lossy().into_owned()).unwrap_or_default();
                self.ev.obs.insert(path.to_string(), Obs::Link(t));
                None
            }
            Ok(md) if md.is_file() => Some(Kind::File),
            Ok(md) if md.is_dir() => Some(Kind::Dir),
            Ok(_) => {
                self.ev.obs.insert(path.to_string(), Obs::Refused(crate::saferead::NOT_REGULAR.into()));
                None
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.ev.obs.insert(path.to_string(), Obs::Absent);
                None
            }
            Err(e) => {
                self.ev.obs.insert(path.to_string(), Obs::Refused(e.to_string()));
                None
            }
        }
    }

    pub fn file(&mut self, path: &str, max: u64) {
        if self.have(path) {
            return;
        }
        match self.stat(path) {
            Some(Kind::File) => {}
            Some(Kind::Dir) => return self.list(path),
            _ => return,
        }
        let p = self.at(path);
        let left = self.budget.saturating_sub(self.kept);
        let o = match crate::saferead::open_regular(&p, crate::saferead::NOT_REGULAR) {
            Ok((_, md)) if md.len() > max => return self.hash(path),

            Ok((_, md)) if md.len() > left => Obs::Refused(self.over_budget(md.len())),
            Ok((f, md)) => match crate::saferead::read_open(&f, &md, max.min(left)) {
                Ok(b) => {
                    self.kept = self.kept.saturating_add(b.len() as u64);
                    Obs::Bytes(b)
                }

                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => return self.hash(path),
                Err(e) => Obs::Refused(e.to_string()),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Obs::Absent,
            Err(e) => Obs::Refused(e.to_string()),
        };
        self.ev.obs.insert(path.to_string(), o);
    }

    pub fn hash(&mut self, path: &str) {
        if matches!(self.ev.obs.get(path), Some(Obs::Digest { .. } | Obs::Bytes(_))) {
            return;
        }
        self.ev.obs.remove(path);
        match self.stat(path) {
            Some(Kind::File) => {}
            Some(Kind::Dir) => {
                self.ev.obs.insert(path.to_string(), Obs::Refused("a directory where a file was expected".into()));
                return;
            }
            _ => return,
        }
        let p = self.at(path);
        let o = match crate::saferead::open_regular(&p, crate::saferead::NOT_REGULAR) {
            Ok((f, md)) if md.len() <= crate::saferead::MAX_HASH_BYTES => {
                match crate::saferead::sha256_reader(&f, crate::saferead::MAX_HASH_BYTES, &mut self.throttle) {
                    Ok(d) => Obs::Digest { sha256: d, len: md.len() },
                    Err(e) => Obs::Refused(e.to_string()),
                }
            }
            Ok((_, md)) => Obs::Refused(format!("{} bytes, over the hash cap", md.len())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Obs::Absent,
            Err(e) => Obs::Refused(e.to_string()),
        };
        self.ev.obs.insert(path.to_string(), o);
    }

    pub fn list(&mut self, path: &str) {
        if matches!(self.ev.obs.get(path), Some(Obs::Dir(_))) {
            return;
        }
        self.ev.obs.remove(path);
        match self.stat(path) {
            Some(Kind::Dir) => {}
            Some(Kind::File) => {
                self.ev.obs.insert(path.to_string(), Obs::Refused("a file where a directory was expected".into()));
                return;
            }
            _ => return,
        }
        let rd = match std::fs::read_dir(self.at(path)) {
            Ok(rd) => rd,
            Err(e) => {
                self.ev.obs.insert(path.to_string(), Obs::Refused(e.to_string()));
                return;
            }
        };
        let mut es = Vec::new();
        for e in rd {
            let e = match e {
                Ok(e) => e,
                Err(err) => {
                    self.ev.obs.insert(path.to_string(), Obs::Refused(format!("listing stopped: {err}")));
                    return;
                }
            };
            if es.len() >= MAX_ENTRIES {
                self.ev.obs.insert(path.to_string(), Obs::Refused(format!("more than {MAX_ENTRIES} entries")));
                return;
            }
            let kind = match e.file_type() {
                Ok(t) if t.is_symlink() => Kind::Link,
                Ok(t) if t.is_file() => Kind::File,
                Ok(t) if t.is_dir() => Kind::Dir,
                _ => Kind::Other,
            };
            es.push(Entry { name: e.file_name().to_string_lossy().into_owned(), kind });
        }
        es.sort();
        self.ev.obs.insert(path.to_string(), Obs::Dir(es));
    }

    pub fn dir_files(&mut self, dir: &str, max: u64) {
        self.list(dir);
        let names: Vec<(String, Kind)> =
            self.ev.dir(dir).unwrap_or_default().iter().map(|e| (e.name.clone(), e.kind)).collect();
        for (name, kind) in names {
            let p = join(dir, &name);
            match kind {
                Kind::File => self.file(&p, max),
                Kind::Link | Kind::Other => {
                    self.stat(&p);
                }
                Kind::Dir => {}
            }
        }
    }

    pub fn tool(&mut self, runner: &mut dyn Runner, inv: &Invocation) {
        let key = tool_key(inv);
        let t = match runner.run(inv) {
            Ok(o) => ToolObs::Ran { status: o.status, stdout: o.stdout },
            Err(e) => ToolObs::Failed(e.to_string()),
        };
        self.ev.tools.insert(key, t);
    }
}

pub fn join(dir: &str, name: &str) -> String {
    format!("{}/{name}", dir.trim_end_matches('/'))
}
