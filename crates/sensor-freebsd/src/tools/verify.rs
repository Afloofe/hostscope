use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use hemostat_evcrypto::manifest::meta::{Kind, VerifiedMeta};
use hemostat_evcrypto::manifest::Verified;

use super::elf::{dyn_info, DynInfo};
use super::loader;
use super::{PhpExt, Tool};
use crate::saferead::Throttle;

pub const MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unverified {

    NoManifest,

    NotCovered(String),

    NotVendor {

        path: String,

        digest: [u8; 32],
    },

    Unreadable {

        path: String,

        why: String,
    },

    NotCanonical {

        path: String,

        resolves: String,
    },

    BadElf {

        path: String,

        why: String,
    },

    Interp {

        path: String,

        interp: String,
    },

    SearchDir {

        path: String,

        dir: String,
    },

    Unresolved {

        lib: String,

        by: String,
    },

    LibMap {

        path: String,

        why: String,
    },

    Hints(String),

    Changed(String),

    TooDeep(String),
}

impl core::fmt::Display for Unverified {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Unverified::NoManifest => f.write_str("no signed manifest is loaded, so nothing it runs can be checked"),
            Unverified::NotCovered(p) => write!(f, "{p} is not in the manifest"),
            Unverified::NotVendor { path, digest } => {
                write!(f, "{path} hashes to {}, which the vendor never shipped there", hex(digest))
            }
            Unverified::Unreadable { path, why } => write!(f, "{path} could not be read: {why}"),
            Unverified::NotCanonical { path, resolves } => {
                write!(f, "{path} resolves to {resolves}: a symlink is on the path")
            }
            Unverified::BadElf { path, why } => write!(f, "{path} is not a readable ELF object: {why}"),
            Unverified::Interp { path, interp } => {
                write!(f, "{path} names {interp} as its interpreter, not {}", loader::INTERP)
            }
            Unverified::SearchDir { path, dir } => write!(f, "{path} searches {dir:?}, which is not followed"),
            Unverified::Unresolved { lib, by } => write!(
                f,
                "{lib} (needed by {by}) is not in the verified search path; the loader would \
                 look for it through ld-elf.so.hints"
            ),
            Unverified::LibMap { path, why } => write!(f, "{path}: {why}"),
            Unverified::Hints(why) => write!(f, "{}: {why}", loader::HINTS),
            Unverified::Changed(p) => write!(f, "{p} changed between verification and the spawn"),
            Unverified::TooDeep(p) => write!(f, "{p}: more links or library levels than are followed"),
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    dev: u64,
    ino: u64,
    ctime: i64,
    ctime_nsec: i64,
    size: u64,
    mode: u32,
}

#[cfg(unix)]
impl Stamp {
    fn of(md: &std::fs::Metadata) -> Stamp {
        use std::os::unix::fs::MetadataExt as _;
        Stamp {
            dev: md.dev(),
            ino: md.ino(),
            ctime: md.ctime(),
            ctime_nsec: md.ctime_nsec(),
            size: md.size(),
            mode: md.mode(),
        }
    }
}

#[cfg(unix)]
fn lstamp(path: &Path) -> Result<Option<Stamp>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(md) => Ok(Some(Stamp::of(&md))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {

    Tool,

    Interp,

    Library,

    Link,

    Extension,

    LibMap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {

    pub path: String,

    pub role: Role,

    pub digest: [u8; 32],
    stamp: Stamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {

    pub tool: Tool,

    pub exts: Vec<PhpExt>,

    pub objects: Vec<Object>,

    guards: Vec<Guard>,

    pub setid: bool,

    pub is_static: bool,
}

impl Verification {

    #[cfg(test)]
    pub(crate) fn for_test(tool: Tool) -> Verification {
        Verification { tool, exts: Vec::new(), objects: Vec::new(), guards: Vec::new(), setid: false, is_static: true }
    }

    pub fn env(&self) -> Vec<(&'static str, String)> {
        vec![
            ("LC_ALL", "C".to_string()),
            ("LD_LIBRARY_PATH", self.tool.library_path().join(":")),
            ("LD_LIBMAP_DISABLE", "1".to_string()),

            ("PATH", "/var/empty".to_string()),
        ]
    }

    pub fn libraries(&self) -> impl Iterator<Item = &Object> {
        self.objects.iter().filter(|o| o.role == Role::Library)
    }

    pub fn digest(&self) -> Option<[u8; 32]> {
        self.objects.first().map(|o| o.digest)
    }

    #[cfg(unix)]
    pub fn recheck(&self, root: &Path) -> Result<(), Unverified> {
        for o in &self.objects {
            if lstamp(&at(root, &o.path)).ok().flatten() != Some(o.stamp) {
                return Err(Unverified::Changed(o.path.clone()));
            }
        }
        for g in &self.guards {
            let full = at(root, &g.path);
            if lstamp(&full).ok() != Some(g.stamp) || (g.stamp.is_some() && g.listing.is_some() && libmap_listing(&full).ok() != g.listing) {
                return Err(Unverified::Changed(g.path.clone()));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Guard {
    path: String,
    stamp: Option<Stamp>,
    listing: Option<Vec<String>>,
}

#[cfg(unix)]
fn libmap_listing(dir: &Path) -> std::io::Result<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| loader::libmap_dir_reads(n))
        .collect();
    names.sort();
    Ok(names)
}

pub(crate) fn at(root: &Path, abs: &str) -> PathBuf {
    root.join(abs.trim_start_matches('/'))
}

#[derive(Debug)]
pub struct Verifier<'m> {
    manifest: Option<&'m Verified>,
    meta: Option<&'m VerifiedMeta>,
    root: PathBuf,
    throttle: Throttle,
}

impl<'m> Verifier<'m> {

    pub fn new(manifest: Option<&'m Verified>) -> Verifier<'m> {
        Verifier::with_root(manifest, PathBuf::from("/"), Throttle::new(crate::saferead::HASH_BYTES_PER_SEC))
    }

    pub fn with_root(manifest: Option<&'m Verified>, root: PathBuf, throttle: Throttle) -> Verifier<'m> {
        Verifier { manifest, meta: None, root, throttle }
    }

    pub fn with_meta(mut self, meta: Option<&'m VerifiedMeta>) -> Verifier<'m> {
        self.meta = meta;
        self
    }

    fn sidecar_link(&self, path: &str) -> Option<Result<String, ()>> {
        let rows = self.meta?.get(path);
        if rows.is_empty() {
            return None;
        }
        let mut target: Option<&str> = None;
        for r in rows {
            match (r.kind, r.target) {
                (Kind::Link, Some(t)) if target.is_none_or(|x| x == t) => target = Some(t),
                _ => return Some(Err(())),
            }
        }
        target.map(|t| Ok(t.to_string()))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn hashed(&self) -> u64 {
        self.throttle.bytes()
    }

    #[cfg(unix)]
    pub fn verify(&mut self, tool: Tool, exts: &[PhpExt]) -> Result<Verification, Unverified> {
        let manifest = self.manifest.ok_or(Unverified::NoManifest)?;
        let mut v = Verification {
            tool,
            exts: exts.to_vec(),
            objects: Vec::new(),
            guards: Vec::new(),
            setid: false,
            is_static: false,
        };

        self.canonical(tool.path(), false)?;
        let (main_obj, main_bytes) = self.object(manifest, tool.path(), Role::Tool)?;
        v.setid = main_obj.stamp.mode & 0o6000 != 0;
        v.objects.push(main_obj);
        let main = dyn_info(&main_bytes).map_err(|why| Unverified::BadElf { path: tool.path().into(), why })?;
        drop(main_bytes);

        self.libmap(manifest, &mut v)?;

        if main.is_static() {
            v.is_static = true;
            if !exts.is_empty() {
                return Err(Unverified::BadElf {
                    path: tool.path().into(),
                    why: "static, so it cannot load extensions".into(),
                });
            }
            return Ok(v);
        }
        match main.interp.as_deref() {
            Some(loader::INTERP) => {}
            Some(other) => return Err(Unverified::Interp { path: tool.path().into(), interp: other.into() }),
            None => {
                return Err(Unverified::BadElf {
                    path: tool.path().into(),
                    why: "dynamic but names no interpreter".into(),
                })
            }
        }
        self.canonical(loader::INTERP, false)?;
        let (interp, _) = self.object(manifest, loader::INTERP, Role::Interp)?;
        v.objects.push(interp);

        let hints = if v.setid { Some(self.hints(&mut v)?) } else { None };

        let mut queue: VecDeque<(String, DynInfo, usize)> = VecDeque::from([(tool.path().to_string(), main.clone(), 0)]);
        for e in exts {
            let path = e.path();
            self.canonical(&path, false)?;
            let (obj, bytes) = self.object(manifest, &path, Role::Extension)?;
            v.objects.push(obj);
            let info = dyn_info(&bytes).map_err(|why| Unverified::BadElf { path: path.clone(), why })?;
            queue.push_back((path, info, 1));
        }
        let mut seen: Vec<String> = Vec::new();
        while let Some((by, info, depth)) = queue.pop_front() {
            if depth > MAX_DEPTH {
                return Err(Unverified::TooDeep(by));
            }
            for dir in info.rpath.iter().chain(&info.runpath) {
                if !loader::followable_dir(dir) {
                    return Err(Unverified::SearchDir { path: by.clone(), dir: dir.clone() });
                }
            }
            let dirs = loader::search_order(
                &info.rpath,
                &info.runpath,
                &main.rpath,
                &main.runpath,
                by == tool.path(),
                tool.library_path(),
                hints.as_deref(),
            );
            for lib in &info.needed {
                let found = self.find(lib, &by, &dirs)?;
                if seen.contains(&found) {
                    continue;
                }
                seen.push(found.clone());
                let (path, bytes) = self.library(manifest, &found, &mut v)?;
                let sub = dyn_info(&bytes).map_err(|why| Unverified::BadElf { path: path.clone(), why })?;
                queue.push_back((path, sub, depth + 1));
            }
        }
        Ok(v)
    }

    #[cfg(unix)]
    fn canonical(&self, path: &str, last_may_link: bool) -> Result<(), Unverified> {
        let full = at(&self.root, path);
        let (check, expect) = if last_may_link {
            let parent = full.parent().map(Path::to_path_buf).unwrap_or_else(|| self.root.clone());
            (parent.clone(), parent)
        } else {
            (full.clone(), full)
        };
        let root = std::fs::canonicalize(&self.root).unwrap_or_else(|_| self.root.clone());
        let rel = expect.strip_prefix(&self.root).unwrap_or(&expect);
        let want = root.join(rel);
        match std::fs::canonicalize(&check) {
            Ok(got) if got == want => Ok(()),
            Ok(got) => Err(Unverified::NotCanonical {
                path: path.into(),
                resolves: got.strip_prefix(&root).map(|p| format!("/{}", p.display())).unwrap_or_else(|_| got.display().to_string()),
            }),
            Err(e) => Err(Unverified::Unreadable { path: path.into(), why: e.to_string() }),
        }
    }

    #[cfg(unix)]
    fn object(&mut self, m: &Verified, path: &str, role: Role) -> Result<(Object, Vec<u8>), Unverified> {
        let full = at(&self.root, path);
        let unreadable = |why: String| Unverified::Unreadable { path: path.into(), why };
        let (f, md) = crate::saferead::open_regular(&full, crate::saferead::NOT_REGULAR)
            .map_err(|e| unreadable(e.to_string()))?;
        let stamp = Stamp::of(&md);
        let bytes = crate::saferead::read_open(&f, &md, MAX_OBJECT_BYTES).map_err(|e| unreadable(e.to_string()))?;
        let digest = crate::saferead::sha256_bytes(&bytes, &mut self.throttle);

        if lstamp(&full).ok().flatten() != Some(stamp) {
            return Err(Unverified::Changed(path.into()));
        }
        match m.is_vendor(path, &digest) {
            None => return Err(Unverified::NotCovered(path.into())),
            Some(false) => return Err(Unverified::NotVendor { path: path.into(), digest }),
            Some(true) => {}
        }
        Ok((Object { path: path.into(), role, digest, stamp }, bytes))
    }

    #[cfg(unix)]
    fn find(&self, lib: &str, by: &str, dirs: &[String]) -> Result<String, Unverified> {
        if lib.contains('/') {

            return if lib.starts_with('/') {
                Ok(lib.to_string())
            } else {
                Err(Unverified::Unresolved { lib: lib.into(), by: by.into() })
            };
        }
        for d in dirs {
            if !loader::followable_dir(d) {
                return Err(Unverified::SearchDir { path: by.into(), dir: d.clone() });
            }
            let candidate = format!("{}/{lib}", d.trim_end_matches('/'));
            if std::fs::metadata(at(&self.root, &candidate)).is_ok() {
                return Ok(candidate);
            }
        }
        Err(Unverified::Unresolved { lib: lib.into(), by: by.into() })
    }

    #[cfg(unix)]
    fn library(&mut self, m: &Verified, path: &str, v: &mut Verification) -> Result<(String, Vec<u8>), Unverified> {
        let mut cur = path.to_string();
        for _ in 0..8 {
            self.canonical(&cur, true)?;
            let full = at(&self.root, &cur);
            let md = std::fs::symlink_metadata(&full)
                .map_err(|e| Unverified::Unreadable { path: cur.clone(), why: e.to_string() })?;
            if !md.file_type().is_symlink() {
                let (o, bytes) = self.object(m, &cur, Role::Library)?;
                v.objects.push(o);
                return Ok((cur, bytes));
            }
            let target = std::fs::read_link(&full)
                .map_err(|e| Unverified::Unreadable { path: cur.clone(), why: e.to_string() })?;
            let text = target.to_string_lossy().into_owned();
            let mut t = Throttle::unlimited();
            let digest = crate::saferead::sha256_bytes(text.trim_start_matches('/').as_bytes(), &mut t);
            match m.is_vendor(&cur, &digest) {
                Some(true) => {}
                Some(false) => return Err(Unverified::NotVendor { path: cur, digest }),
                None => match self.sidecar_link(&cur) {

                    Some(Ok(t)) if t == text => {}
                    Some(Ok(_)) => return Err(Unverified::NotVendor { path: cur, digest }),
                    Some(Err(())) | None => return Err(Unverified::NotCovered(cur)),
                },
            }
            v.objects.push(Object { path: cur.clone(), role: Role::Link, digest, stamp: Stamp::of(&md) });
            cur = if text.starts_with('/') {
                text
            } else {
                let dir = cur.rsplit_once('/').map_or("", |(d, _)| d);
                format!("{dir}/{text}")
            };
            if !loader::followable_dir(&cur) {
                return Err(Unverified::SearchDir { path: path.into(), dir: cur });
            }
        }
        Err(Unverified::TooDeep(path.into()))
    }

    #[cfg(unix)]
    fn libmap(&mut self, m: &Verified, v: &mut Verification) -> Result<(), Unverified> {
        let mut files = VecDeque::from([loader::LIBMAP_CONF.to_string()]);
        let mut read: Vec<String> = Vec::new();
        while let Some(path) = files.pop_front() {
            if read.contains(&path) {
                continue;
            }
            if read.len() >= 64 {
                return Err(Unverified::TooDeep(path));
            }
            read.push(path.clone());
            let refuse = |why: String| Unverified::LibMap { path: path.clone(), why };
            let full = at(&self.root, &path);
            let present = lstamp(&full).map_err(&refuse)?;
            if present.is_none() {
                v.guards.push(Guard { path: path.clone(), stamp: None, listing: None });
                continue;
            }
            let (o, bytes) = match self.object(m, &path, Role::LibMap) {
                Ok(x) => x,
                Err(Unverified::NotCovered(_)) => return Err(refuse("present, and not a file the vendor ships".into())),
                Err(Unverified::NotVendor { .. }) => return Err(refuse("present, and not as the vendor shipped it".into())),
                Err(e) => return Err(refuse(e.to_string())),
            };
            v.objects.push(o);
            let parsed = loader::parse_libmap(&String::from_utf8_lossy(&bytes));
            if let Some(line) = parsed.mappings.first() {
                return Err(refuse(format!(
                    "line {line} maps a library; mappings are refused, not followed"
                )));
            }
            files.extend(parsed.include);
            for dir in parsed.include_dir {
                let full = at(&self.root, &dir);
                let stamp = lstamp(&full).map_err(|why| Unverified::LibMap { path: dir.clone(), why })?;
                if stamp.is_none() {
                    v.guards.push(Guard { path: dir.clone(), stamp, listing: None });
                    continue;
                }
                let names = libmap_listing(&full).map_err(|e| Unverified::LibMap { path: dir.clone(), why: e.to_string() })?;
                v.guards.push(Guard { path: dir.clone(), stamp, listing: Some(names.clone()) });
                files.extend(names.into_iter().map(|n| format!("{}/{n}", dir.trim_end_matches('/'))));
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn hints(&self, v: &mut Verification) -> Result<Vec<String>, Unverified> {
        let full = at(&self.root, loader::HINTS);
        let stamp = lstamp(&full).map_err(Unverified::Hints)?;
        v.guards.push(Guard { path: loader::HINTS.into(), stamp, listing: None });
        if stamp.is_none() {
            return Ok(Vec::new());
        }
        let bytes = crate::saferead::read_bytes(&full, 1024 * 1024).map_err(|e| Unverified::Hints(e.to_string()))?;
        let dirs = loader::parse_hints(&bytes).map_err(Unverified::Hints)?;
        if let Some(bad) = dirs.iter().find(|d| !loader::followable_dir(d)) {
            return Err(Unverified::Hints(format!("lists {bad:?}, which is not followed")));
        }
        Ok(dirs)
    }
}
