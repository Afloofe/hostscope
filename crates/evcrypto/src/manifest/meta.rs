use std::collections::BTreeMap;

use super::index::{self, Paths};
use super::{parse_hex32, sign_with, verify_with, ManifestKey, Verified};

pub const META_HEADER: &str = "# hemostat mtree meta v2";

pub const META_CONTEXT: &[u8] = b"hemostat/vendor-manifest-meta/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {

    File,

    Dir,

    Link,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Provenance {

    RepoSigned,

    IsoSigned,

    IsoPinned,
}

impl Provenance {

    pub fn label(self) -> &'static str {
        match self {
            Provenance::RepoSigned => "repo-signed",
            Provenance::IsoSigned => "iso-signed",
            Provenance::IsoPinned => "iso-pinned",
        }
    }

    fn parse(s: &str) -> Option<Provenance> {
        match s {
            "repo-signed" => Some(Provenance::RepoSigned),
            "iso-signed" => Some(Provenance::IsoSigned),
            "iso-pinned" => Some(Provenance::IsoPinned),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsoPin {

    pub name: String,

    pub sha256: [u8; 32],

    pub how: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<'a> {

    pub kind: Kind,

    pub mode: u32,

    pub uid: Option<u32>,

    pub gid: Option<u32>,

    pub flags: Option<&'a str>,

    pub origin: &'a str,

    pub target: Option<&'a str>,
}

const NONE: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row {
    kind: Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    flags: u32,
    origin: u32,
    target: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {

    pub release: String,

    pub manifest: [u8; 32],

    pub source: Option<String>,

    pub isos: Vec<IsoPin>,

    pub default: Option<Provenance>,
    paths: Paths,

    row_first: Vec<u32>,
    rows: Vec<Row>,

    names: Vec<String>,

    targets: Vec<String>,

    provenance: Vec<(Box<str>, [u8; 32], Provenance)>,
}

struct RawRow<'a> {
    path: &'a str,
    kind: Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    flags: Option<&'a str>,
    origin: &'a str,
    target: Option<&'a str>,
}

impl Meta {

    pub fn parse<'t>(text: &'t str) -> Result<Meta, String> {
        let mut lines = text.lines();
        if lines.next() != Some(META_HEADER) {
            return Err("not a hemostat mtree meta sidecar (bad first line)".into());
        }
        let mut release = None;
        let mut manifest = None;
        let mut source = None;
        let mut default = None;
        let mut isos = Vec::new();
        let mut raw = Rows::default();
        let mut prov: Vec<(&'t str, [u8; 32], Provenance)> = Vec::new();
        for (n, line) in lines.enumerate() {
            let at = n + 2;
            if line.is_empty() {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            let once = |slot: &mut Option<String>, what: &str| -> Result<(), String> {
                if f.len() != 2 || slot.is_some() {
                    return Err(format!("line {at}: expected one {what}<TAB>value line"));
                }
                *slot = f.get(1).map(|s| (*s).to_string());
                Ok(())
            };
            match f.first().copied() {
                Some("release") => once(&mut release, "release")?,
                Some("source") => once(&mut source, "source")?,
                Some("manifest") => {
                    if manifest.is_some() {
                        return Err(format!("line {at}: a second manifest line"));
                    }
                    let mut hex = None;
                    once(&mut hex, "manifest")?;
                    manifest = Some(
                        hex.as_deref()
                            .and_then(parse_hex32)
                            .ok_or_else(|| format!("line {at}: the manifest digest is not a sha256"))?,
                    );
                }
                Some("default") => {
                    let mut d = None;
                    if default.is_some() {
                        return Err(format!("line {at}: a second default line"));
                    }
                    once(&mut d, "default")?;
                    default = Some(
                        d.as_deref().and_then(Provenance::parse).ok_or_else(|| format!("line {at}: provenance"))?,
                    );
                }
                Some("iso") => {
                    let (Some(name), Some(hex), Some(how), 4) = (f.get(1), f.get(2), f.get(3), f.len()) else {
                        return Err(format!("line {at}: expected iso<TAB>name<TAB>sha256<TAB>how"));
                    };
                    let sha256 = parse_hex32(hex).ok_or_else(|| format!("line {at}: the image digest is not a sha256"))?;
                    if name.is_empty() || how.is_empty() {
                        return Err(format!("line {at}: an iso line names no image or no pin"));
                    }
                    isos.push(IsoPin { name: (*name).to_string(), sha256, how: (*how).to_string() });
                }
                Some("digest") => {
                    let (Some(path), Some(hex), Some(p), 4) = (f.get(1), f.get(2), f.get(3), f.len()) else {
                        return Err(format!("line {at}: expected digest<TAB>path<TAB>sha256<TAB>provenance"));
                    };
                    if !path.starts_with('/') {
                        return Err(format!("line {at}: `{path}` is not an absolute path"));
                    }
                    let d = parse_hex32(hex).ok_or_else(|| format!("line {at}: not a sha256"))?;
                    let p = Provenance::parse(p).ok_or_else(|| format!("line {at}: provenance `{p}`"))?;
                    prov.push((path, d, p));
                }
                Some(k @ ("file" | "dir" | "link")) => {
                    raw.push(parse_entry(k, &f).map_err(|e| format!("line {at}: {e}"))?);
                }
                _ => return Err(format!("line {at}: not a sidecar line")),
            }
        }
        let release = release.ok_or("no release line")?;
        let manifest = manifest.ok_or("no manifest line: the sidecar is bound to no manifest")?;
        if raw.is_empty() {
            return Err("the sidecar lists no paths".into());
        }
        let iso_digests = prov.iter().any(|(_, _, p)| *p != Provenance::RepoSigned)
            || default.is_some_and(|d| d != Provenance::RepoSigned);
        if iso_digests && isos.is_empty() {
            return Err("digests come from a release image, and no iso line says which or how it was pinned".into());
        }

        let built = raw.finish()?;
        prov.sort_unstable_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(&b.1)));
        if let Some(w) = prov.windows(2).find(|w| matches!(w, [a, b] if a.0 == b.0 && a.1 == b.1)) {
            let p = w.first().map(|r| r.0).unwrap_or_default();
            return Err(format!("{p} has that digest's provenance twice"));
        }
        let paths = built.paths;
        let provenance: Vec<(Box<str>, [u8; 32], Provenance)> =
            prov.iter().map(|(p, d, v)| (Box::<str>::from(*p), *d, *v)).collect();
        let (row_first, rows, names, targets) = (built.row_first, built.rows, built.names, built.targets);
        Ok(Meta {
            release,
            manifest,
            source,
            isos,
            default,
            paths,
            row_first,
            rows,
            names,
            targets,
            provenance,
        })
    }

    pub fn paths(&self) -> usize {
        self.paths.len()
    }

    pub fn rows(&self) -> usize {
        self.rows.len()
    }

    fn entry(&self, r: &Row) -> Entry<'_> {
        let name = |i: u32| self.names.get(i as usize).map(String::as_str);
        Entry {
            kind: r.kind,
            mode: u32::from(r.mode),
            uid: (r.uid != NONE).then_some(r.uid),
            gid: (r.gid != NONE).then_some(r.gid),
            flags: if r.flags == NONE { None } else { name(r.flags) },
            origin: name(r.origin).unwrap_or_default(),
            target: if r.target == NONE { None } else { self.targets.get(r.target as usize).map(String::as_str) },
        }
    }

    fn rows_at(&self, i: usize) -> &[Row] {
        let (a, b) = (self.row_first.get(i).copied().unwrap_or(0), self.row_first.get(i + 1).copied().unwrap_or(0));
        self.rows.get(a as usize..b as usize).unwrap_or_default()
    }

    pub fn get(&self, path: &str) -> Vec<Entry<'_>> {
        self.paths.find(path).map(|i| self.rows_at(i).iter().map(|r| self.entry(r)).collect()).unwrap_or_default()
    }

    pub fn iter(&self) -> impl Iterator<Item = (String, Vec<Entry<'_>>)> + '_ {
        self.paths.iter().enumerate().map(move |(i, p)| (p, self.rows_at(i).iter().map(|r| self.entry(r)).collect()))
    }

    pub fn listed(&self, path: &str, digest: &[u8; 32]) -> Option<Provenance> {
        self.provenance
            .binary_search_by(|(p, d, _)| (**p).cmp(path).then_with(|| d.cmp(digest)))
            .ok()
            .and_then(|k| self.provenance.get(k))
            .map(|(_, _, v)| *v)
    }

    pub fn listed_counts(&self) -> BTreeMap<Provenance, usize> {
        let mut c = BTreeMap::new();
        for (_, _, p) in &self.provenance {
            *c.entry(*p).or_insert(0) += 1;
        }
        c
    }

    fn listed_rows(&self) -> impl Iterator<Item = (&str, &[u8; 32])> {
        self.provenance.iter().map(|(p, d, _)| (&**p, d))
    }
}

#[derive(Default)]
struct Rows<'t> {
    paths: Vec<&'t str>,
    row_first: Vec<u32>,
    rows: Vec<Row>,
    interned: BTreeMap<&'t str, u32>,
    names: Vec<String>,
    targets: Vec<String>,

    name_refs: Vec<&'t str>,
    target_refs: Vec<&'t str>,
    unsorted: Option<Vec<RawRow<'t>>>,
    error: Option<String>,
}

struct Built {
    paths: Paths,
    row_first: Vec<u32>,
    rows: Vec<Row>,
    names: Vec<String>,
    targets: Vec<String>,
}

impl<'t> Rows<'t> {
    fn intern(&mut self, s: &'t str) -> u32 {
        if let Some(&i) = self.interned.get(s) {
            return i;
        }
        let i = self.names.len() as u32;
        self.names.push(s.to_string());
        self.name_refs.push(s);
        self.interned.insert(s, i);
        i
    }

    fn push(&mut self, r: RawRow<'t>) {
        if let Some(v) = &mut self.unsorted {
            v.push(r);
            return;
        }
        let last = self.paths.last().copied();
        match last {
            Some(p) if p > r.path => {

                let mut v = Vec::new();
                for (i, p) in self.paths.iter().enumerate() {
                    let a = self.row_first.get(i).copied().unwrap_or(0) as usize;
                    let b = self.row_first.get(i + 1).copied().map_or(self.rows.len(), |x| x as usize);
                    for row in self.rows.get(a..b).unwrap_or_default() {
                        v.push(self.unrow(p, row));
                    }
                }
                v.push(r);
                self.unsorted = Some(v);
                return;
            }
            Some(p) if p == r.path => {
                let a = self.row_first.last().copied().unwrap_or(0) as usize;
                let origin = self.interned.get(r.origin).copied();
                if self.rows.get(a..).unwrap_or_default().iter().any(|x| Some(x.origin) == origin) {
                    self.error.get_or_insert_with(|| format!("{} is listed twice for {}", r.path, r.origin));
                }
            }
            _ => {
                self.row_first.push(self.rows.len() as u32);
                self.paths.push(r.path);
            }
        }
        let flags = match r.flags {
            Some(f) => self.intern(f),
            None => NONE,
        };
        let origin = self.intern(r.origin);
        let target = match r.target {
            Some(t) => {
                self.targets.push(t.to_string());
                self.target_refs.push(t);
                (self.targets.len() - 1) as u32
            }
            None => NONE,
        };
        self.rows.push(Row { kind: r.kind, mode: r.mode, uid: r.uid, gid: r.gid, flags, origin, target });
    }

    fn unrow(&self, path: &'t str, row: &Row) -> RawRow<'t> {
        let name = |i: u32| self.name_refs.get(i as usize).copied();
        RawRow {
            path,
            kind: row.kind,
            mode: row.mode,
            uid: row.uid,
            gid: row.gid,
            flags: if row.flags == NONE { None } else { name(row.flags) },
            origin: name(row.origin).unwrap_or_default(),
            target: if row.target == NONE { None } else { self.target_refs.get(row.target as usize).copied() },
        }
    }

    fn is_empty(&self) -> bool {
        self.rows.is_empty() && self.unsorted.as_ref().is_none_or(Vec::is_empty)
    }

    fn finish(mut self) -> Result<Built, String> {
        if let Some(mut v) = self.unsorted.take() {
            v.sort_by(|a, b| a.path.cmp(b.path));
            let mut fresh = Rows::default();
            for r in v {
                fresh.push(r);
            }
            if let Some(e) = fresh.error.take() {
                return Err(e);
            }
            return fresh.finish();
        }
        if let Some(e) = self.error.take() {
            return Err(e);
        }
        self.row_first.push(self.rows.len() as u32);
        let paths = Paths::from_sorted(self.paths.iter().copied())?;
        Ok(Built { paths, row_first: self.row_first, rows: self.rows, names: self.names, targets: self.targets })
    }
}

fn parse_entry<'a>(kind: &str, f: &[&'a str]) -> Result<RawRow<'a>, String> {
    let kind = match kind {
        "file" => Kind::File,
        "dir" => Kind::Dir,
        _ => Kind::Link,
    };
    let want = if kind == Kind::Link { 8 } else { 7 };
    if f.len() != want {
        return Err(format!("expected {want} tab-separated fields, found {}", f.len()));
    }
    let field = |i: usize| f.get(i).copied().unwrap_or_default();
    let path = field(1);
    if !path.starts_with('/') {
        return Err(format!("`{path}` is not an absolute path"));
    }
    let mode = field(2);
    if mode.len() != 4 || !mode.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Err(format!("mode `{mode}` is not four octal digits"));
    }
    let mode = u16::from_str_radix(mode, 8).map_err(|_| format!("mode `{mode}`"))?;
    let num = |s: &str, what: &str| -> Result<u32, String> {
        if s == "-" {
            return Ok(NONE);
        }
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("{what} `{s}` is not a number"));
        }
        match s.parse::<u32>() {
            Ok(n) if n != NONE => Ok(n),
            _ => Err(format!("{what} `{s}` is out of range")),
        }
    };
    let uid = num(field(3), "uid")?;
    let gid = num(field(4), "gid")?;
    let flags = match field(5) {
        "-" => None,
        s if !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b == b',') => Some(s),
        s => return Err(format!("flags `{s}`")),
    };
    let origin = field(6);
    if origin.is_empty() || origin.contains(' ') {
        return Err(format!("origin `{origin}`"));
    }
    let target = match (kind, field(7)) {
        (Kind::Link, "-") => None,
        (Kind::Link, "") => return Err("a link with an empty target".into()),
        (Kind::Link, t) => Some(t),
        _ => None,
    };
    Ok(RawRow { path, kind, mode, uid, gid, flags, origin, target })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaRefused {

    Signature,

    NotUtf8,

    Malformed(String),

    Unbound(String),

    Read(String),
}

impl core::fmt::Display for MetaRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MetaRefused::Signature => f.write_str("not signed by the pinned manifest key as a sidecar"),
            MetaRefused::NotUtf8 => f.write_str("not UTF-8"),
            MetaRefused::Malformed(why) | MetaRefused::Unbound(why) | MetaRefused::Read(why) => f.write_str(why),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMeta {
    meta: Meta,
    counts: BTreeMap<Provenance, usize>,
}

impl VerifiedMeta {

    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    pub fn provenance(&self, manifest: &Verified, path: &str, digest: &[u8; 32]) -> Option<Provenance> {
        if manifest.is_vendor(path, digest) != Some(true) {
            return None;
        }
        self.meta.listed(path, digest).or(self.meta.default)
    }

    pub fn provenance_counts(&self) -> &BTreeMap<Provenance, usize> {
        &self.counts
    }
}

impl core::ops::Deref for VerifiedMeta {
    type Target = Meta;

    fn deref(&self) -> &Meta {
        &self.meta
    }
}

impl ManifestKey {

    pub fn sign_meta(&self, payload: &[u8]) -> Vec<u8> {
        sign_with(self, payload, META_CONTEXT)
    }
}

pub fn verify(public: &[u8; 32], payload: &[u8], cose: &[u8]) -> bool {
    verify_with(public, payload, cose, META_CONTEXT)
}

fn finish(meta: Meta, manifest: &Verified) -> Result<VerifiedMeta, MetaRefused> {
    bound(&meta, &manifest.release, manifest.body_sha256()).map_err(MetaRefused::Unbound)?;
    let counts = covers_exactly(&meta, manifest).map_err(MetaRefused::Unbound)?;
    Ok(VerifiedMeta { meta, counts })
}

pub fn verify_and_parse(
    public: &[u8; 32],
    body: &[u8],
    cose: &[u8],
    manifest: &Verified,
) -> Result<VerifiedMeta, MetaRefused> {
    if !verify(public, body, cose) {
        return Err(MetaRefused::Signature);
    }
    let text = core::str::from_utf8(body).map_err(|_| MetaRefused::NotUtf8)?;
    finish(Meta::parse(text).map_err(MetaRefused::Malformed)?, manifest)
}

pub fn read_and_parse(
    public: &[u8; 32],
    cose: &[u8],
    manifest: &Verified,
    len: u64,
    fill: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>,
) -> Result<VerifiedMeta, MetaRefused> {
    let signed = index::read_signed(public, cose, META_CONTEXT, len, fill).map_err(|e| match e {
        index::SignedRead::Read(why) => MetaRefused::Read(why),
        index::SignedRead::Signature => MetaRefused::Signature,
    })?;
    let text = core::str::from_utf8(signed.payload()).map_err(|_| MetaRefused::NotUtf8)?;
    let meta = Meta::parse(text).map_err(MetaRefused::Malformed)?;
    drop(signed);
    finish(meta, manifest)
}

pub fn covers_exactly(meta: &Meta, manifest: &super::Manifest) -> Result<BTreeMap<Provenance, usize>, String> {
    for (path, d) in meta.listed_rows() {
        if manifest.is_vendor(path, d) != Some(true) {
            return Err(format!("the sidecar gives provenance for a digest of {path} the manifest does not hold"));
        }
    }
    let mut counts = meta.listed_counts();
    let listed: usize = counts.values().sum();
    let held = manifest.digest_count();
    match meta.default {
        Some(d) => *counts.entry(d).or_insert(0) += held.saturating_sub(listed),
        None if listed != held => {
            return Err(format!("the sidecar gives provenance for {listed} digests, and the manifest holds {held}"));
        }
        None => {}
    }
    Ok(counts)
}

pub fn bound(meta: &Meta, release: &str, manifest_sha256: &[u8; 32]) -> Result<(), String> {
    if meta.release != release {
        return Err(format!("the sidecar is for {}, the manifest for {release}", meta.release));
    }
    if &meta.manifest != manifest_sha256 {
        return Err("the sidecar was built beside a different manifest (its manifest digest differs)".into());
    }
    Ok(())
}
