use std::collections::{BTreeMap, BTreeSet};

mod index;
pub mod meta;

pub use index::{read_signed, Signed, SignedRead};

use coset::iana;
use coset::{CborSerializable as _, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

pub const MANIFEST_CONTEXT: &[u8] = b"hemostat/vendor-manifest/v1";

pub struct ManifestKey {
    signing: SigningKey,
}

impl ManifestKey {

    pub fn from_seed(seed: [u8; 32]) -> Self {
        ManifestKey { signing: SigningKey::from_bytes(&seed) }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign(&self, payload: &[u8]) -> Vec<u8> {
        sign_with(self, payload, MANIFEST_CONTEXT)
    }
}

fn sign_with(key: &ManifestKey, payload: &[u8], context: &[u8]) -> Vec<u8> {
    let protected = HeaderBuilder::new().algorithm(iana::Algorithm::EdDSA).build();
    CoseSign1Builder::new()
        .protected(protected)
        .create_detached_signature(payload, context, |tbs| key.signing.sign(tbs).to_vec())
        .build()
        .to_vec()
        .unwrap_or_default()
}

pub fn verify(public: &[u8; 32], payload: &[u8], cose: &[u8]) -> bool {
    verify_with(public, payload, cose, MANIFEST_CONTEXT)
}

pub(crate) fn verify_with(public: &[u8; 32], payload: &[u8], cose: &[u8], context: &[u8]) -> bool {
    index::verify_bytes(public, payload, cose, context)
}

pub const HEADER: &str = "# hemostat vendor manifest v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {

    pub release: String,

    pub source: Option<String>,

    paths: index::Paths,

    first: Vec<u32>,

    digests: Vec<[u8; 32]>,
    versions: BTreeMap<String, BTreeSet<String>>,
}

impl Manifest {

    pub fn parse(text: &str) -> Result<Manifest, String> {
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err("not a hemostat vendor manifest (bad first line)".into());
        }
        let mut release = None;
        let mut source = None;

        let mut pairs: Pairs<'_> = Pairs::default();
        let mut versions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (n, line) in lines.enumerate() {
            let at = n + 2;
            if line.is_empty() {
                continue;
            }
            let Some((a, b)) = line.split_once('\t') else {
                return Err(format!("line {at}: no tab"));
            };
            match a {
                "release" => release = Some(b.to_string()),
                "source" => source = Some(b.to_string()),
                "version" => {
                    let (Some((pkg, ver)), false) = (b.split_once('\t'), b.matches('\t').count() > 1) else {
                        return Err(format!("line {at}: expected version<TAB>package<TAB>version"));
                    };
                    versions.entry(pkg.to_string()).or_default().insert(ver.to_string());
                }
                hex => {
                    let digest = parse_hex32(hex).ok_or_else(|| format!("line {at}: not a sha256"))?;
                    if !b.starts_with('/') || b.contains('\t') {
                        return Err(format!("line {at}: `{b}` is not an absolute path"));
                    }
                    pairs.push(b, digest);
                }
            }
        }
        let release = release.ok_or("no release line")?;
        if pairs.is_empty() {
            return Err("the manifest lists no files".into());
        }
        let (paths, first, digests) = index_sorted(&mut pairs)?;
        Ok(Manifest { release, source, paths, first, digests, versions })
    }

    fn group(&self, i: usize) -> &[[u8; 32]] {
        let (a, b) = (self.first.get(i).copied().unwrap_or(0), self.first.get(i + 1).copied().unwrap_or(0));
        self.digests.get(a as usize..b as usize).unwrap_or_default()
    }

    pub fn paths(&self) -> usize {
        self.paths.len()
    }

    pub fn digest_count(&self) -> usize {
        self.digests.len()
    }

    pub fn covered(&self) -> impl Iterator<Item = String> + '_ {
        self.paths.iter()
    }

    pub fn digests(&self) -> impl Iterator<Item = (String, &[u8; 32])> + '_ {
        self.paths
            .iter()
            .enumerate()
            .flat_map(move |(i, p)| self.group(i).iter().map(move |d| (p.clone(), d)))
    }

    pub fn digests_of(&self, path: &str) -> impl Iterator<Item = &[u8; 32]> {
        self.paths.find(path).map(|i| self.group(i)).unwrap_or_default().iter()
    }

    pub fn position(&self, path: &str) -> Option<usize> {
        self.paths.find(path)
    }

    pub fn covers(&self, path: &str) -> bool {
        self.paths.find(path).is_some()
    }

    pub fn covers_version(&self, package: &str, version: &str) -> Option<bool> {
        self.versions.get(package).map(|v| v.contains(version))
    }

    pub fn versions_of(&self, package: &str) -> Vec<&str> {
        self.versions.get(package).map(|v| v.iter().map(String::as_str).collect()).unwrap_or_default()
    }

    pub fn is_vendor(&self, path: &str, digest: &[u8; 32]) -> Option<bool> {
        self.paths.find(path).map(|i| self.group(i).binary_search(digest).is_ok())
    }
}

#[derive(Default)]
struct Pairs<'a> {
    arena: Vec<&'a str>,
    first: Vec<u32>,
    digests: Vec<[u8; 32]>,
    unsorted: Option<Vec<(&'a str, [u8; 32])>>,
}

impl<'a> Pairs<'a> {
    fn push(&mut self, path: &'a str, d: [u8; 32]) {
        if let Some(v) = &mut self.unsorted {
            v.push((path, d));
            return;
        }
        let last = self.arena.last().copied();
        let in_order = match last {
            None => true,
            Some(p) if p < path => true,
            Some(p) if p == path => self.digests.last().is_some_and(|x| *x < d),
            Some(_) => false,
        };
        if in_order {
            if last != Some(path) {
                self.first.push(self.digests.len() as u32);
                self.arena.push(path);
            }
            self.digests.push(d);
            return;
        }

        let mut v: Vec<(&'a str, [u8; 32])> = Vec::with_capacity(self.digests.len() + 1);
        for (i, p) in self.arena.iter().enumerate() {
            let a = self.first.get(i).copied().unwrap_or(0) as usize;
            let b = self.first.get(i + 1).copied().map_or(self.digests.len(), |x| x as usize);
            v.extend(self.digests.get(a..b).unwrap_or_default().iter().map(|d| (*p, *d)));
        }
        v.push((path, d));
        self.arena = Vec::new();
        self.first = Vec::new();
        self.digests = Vec::new();
        self.unsorted = Some(v);
    }

    fn is_empty(&self) -> bool {
        self.digests.is_empty() && self.unsorted.as_ref().is_none_or(Vec::is_empty)
    }
}

fn index_sorted(pairs: &mut Pairs<'_>) -> Result<(index::Paths, Vec<u32>, Vec<[u8; 32]>), String> {
    if let Some(mut v) = pairs.unsorted.take() {
        v.sort_unstable();
        v.dedup();
        for (p, d) in v {
            pairs.push(p, d);
        }
    }
    let paths = index::Paths::from_sorted(pairs.arena.iter().copied())?;
    let mut first = std::mem::take(&mut pairs.first);
    let digests = std::mem::take(&mut pairs.digests);
    first.push(u32::try_from(digests.len()).map_err(|_| "over 4 billion digests")?);
    first.shrink_to_fit();
    Ok((paths, first, digests))
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    manifest: Manifest,
    sha256: [u8; 32],
}

impl Verified {

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn body_sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

impl core::ops::Deref for Verified {
    type Target = Manifest;

    fn deref(&self) -> &Manifest {
        &self.manifest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {

    Signature,

    NotUtf8,

    Malformed(String),
}

impl core::fmt::Display for Refused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Refused::Signature => f.write_str("not signed by the pinned manifest key"),
            Refused::NotUtf8 => f.write_str("not UTF-8"),
            Refused::Malformed(why) => f.write_str(why),
        }
    }
}

pub fn verify_and_parse(public: &[u8; 32], body: &[u8], cose: &[u8]) -> Result<Verified, Refused> {
    if !verify(public, body, cose) {
        return Err(Refused::Signature);
    }
    let text = core::str::from_utf8(body).map_err(|_| Refused::NotUtf8)?;
    let sha256 = Sha256::digest(body).into();
    Manifest::parse(text).map(|manifest| Verified { manifest, sha256 }).map_err(Refused::Malformed)
}

#[derive(Debug)]
pub enum ReadRefused {

    Read(String),

    Refused(Refused),
}

pub fn read_and_parse(
    public: &[u8; 32],
    cose: &[u8],
    len: u64,
    fill: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>,
) -> Result<Verified, ReadRefused> {
    let signed = read_signed(public, cose, MANIFEST_CONTEXT, len, fill).map_err(|e| match e {
        SignedRead::Read(why) => ReadRefused::Read(why),
        SignedRead::Signature => ReadRefused::Refused(Refused::Signature),
    })?;
    let body = signed.payload();
    let text = core::str::from_utf8(body).map_err(|_| ReadRefused::Refused(Refused::NotUtf8))?;
    let sha256 = Sha256::digest(body).into();
    Manifest::parse(text)
        .map(|manifest| Verified { manifest, sha256 })
        .map_err(|e| ReadRefused::Refused(Refused::Malformed(e)))
}
