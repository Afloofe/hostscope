use std::fmt;
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::disk::{create_dir_private, read_regular, stream_dir_name, sync_dir, write_file_synced};
use crate::segment::StreamId;
use crate::store::StoreHeader;
use crate::STORE_HEADER_FILE;

pub const PARCEL_MAGIC: [u8; 4] = *b"HPCL";

pub const PARCEL_VERSION: u16 = 1;

pub const PARCEL_EXT: &str = "hpcl";

pub const MAX_PARCEL_BYTES: u64 = 256 * 1024 * 1024;

pub const MAX_PARCEL_FILES: u32 = 65_536;

const PREFIX_LEN: usize = 20;

const TRAILER_LEN: usize = 32;

const STREAMS: [StreamId; 4] = [StreamId::Custody, StreamId::Evidence, StreamId::Journal, StreamId::Telemetry];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParcelFile {

    pub path: String,

    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parcel {

    pub files: Vec<ParcelFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParcelError {

    Truncated {

        what: &'static str,
    },

    BadPrefix {

        what: String,
    },

    TooLarge {

        what: String,
    },

    BadPath {

        path: String,
    },

    NotCanonical {

        what: String,
    },

    DigestMismatch {

        what: String,
    },

    TrailingBytes {

        count: usize,
    },
}

impl fmt::Display for ParcelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParcelError::Truncated { what } => {
                write!(f, "parcel truncated while reading {what} (a cut tail, or a copy that did not finish)")
            }
            ParcelError::BadPrefix { what } => write!(f, "not a parcel this version reads: {what}"),
            ParcelError::TooLarge { what } => write!(f, "parcel over its bound: {what}"),
            ParcelError::BadPath { path } => write!(
                f,
                "parcel lists a file named {path}, which is not a store header or a segment of one of \
                 the four streams; nothing was unpacked"
            ),
            ParcelError::NotCanonical { what } => write!(f, "parcel is not in its one encoding: {what}"),
            ParcelError::DigestMismatch { what } => {
                write!(f, "parcel digest mismatch: {what} (damaged in transit, or altered after packing)")
            }
            ParcelError::TrailingBytes { count } => {
                write!(f, "{count} byte(s) after the parcel's trailing digest, covered by nothing")
            }
        }
    }
}

impl std::error::Error for ParcelError {}

pub fn valid_path(path: &str) -> bool {
    if path == STORE_HEADER_FILE {
        return true;
    }
    let Some((dir, name)) = path.split_once('/') else { return false };
    if !STREAMS.iter().any(|s| stream_dir_name(*s) == dir) {
        return false;
    }
    let Some(digits) = name.strip_prefix("seg-").and_then(|n| n.strip_suffix(".hcs")) else {
        return false;
    };
    digits.len() == 10 && digits.bytes().all(|b| b.is_ascii_digit())
}

fn shown(raw: &[u8]) -> String {
    let mut s = String::from("\"");
    for &b in raw.iter().take(200) {
        if (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\' {
            s.push(char::from(b));
        } else {
            s.push_str(&format!("\\x{b:02x}"));
        }
    }
    if raw.len() > 200 {
        s.push_str("...");
    }
    s.push('"');
    s
}

impl Parcel {

    pub fn pack_dir(dir: impl AsRef<Path>) -> std::io::Result<(Parcel, Vec<String>)> {
        let dir = dir.as_ref();
        let mut files = vec![ParcelFile { path: STORE_HEADER_FILE.to_string(), bytes: read_regular(&dir.join(STORE_HEADER_FILE))? }];
        let mut skipped = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_stream = STREAMS.iter().any(|s| stream_dir_name(*s) == name);
            if name == STORE_HEADER_FILE || is_stream {
                continue;
            }
            skipped.push(name);
        }
        for stream in STREAMS {
            let sname = stream_dir_name(stream);
            let sdir = dir.join(sname);
            match fs::symlink_metadata(&sdir) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
                Ok(m) if !m.is_dir() => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("{} is not a directory; refusing to pack it", sdir.display()),
                    ))
                }
                Ok(_) => {}
            }
            for entry in fs::read_dir(&sdir)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let path = format!("{sname}/{name}");
                if valid_path(&path) {
                    files.push(ParcelFile { bytes: read_regular(&entry.path())?, path });
                } else {
                    skipped.push(path);
                }
            }
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        skipped.sort();
        let parcel = Parcel { files };
        let total = parcel.encoded_len();
        if total > MAX_PARCEL_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("the store packs to {total} bytes, over the {MAX_PARCEL_BYTES}-byte parcel bound"),
            ));
        }
        Ok((parcel, skipped))
    }

    pub fn store_header(&self) -> Option<StoreHeader> {
        let f = self.files.iter().find(|f| f.path == STORE_HEADER_FILE)?;
        StoreHeader::decode(&f.bytes).ok().map(|(h, _)| h)
    }

    pub fn body_len(&self) -> u64 {
        self.files.iter().map(|f| f.bytes.len() as u64).sum()
    }

    fn encoded_len(&self) -> u64 {
        let index: u64 = self.files.iter().map(|f| 2 + f.path.len() as u64 + 8 + 32).sum();
        PREFIX_LEN as u64 + index + self.body_len() + TRAILER_LEN as u64
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(usize::try_from(self.encoded_len()).unwrap_or(0));
        out.extend_from_slice(&PARCEL_MAGIC);
        out.extend_from_slice(&PARCEL_VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(self.files.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.body_len().to_le_bytes());
        for f in &self.files {
            out.extend_from_slice(&(f.path.len() as u16).to_le_bytes());
            out.extend_from_slice(f.path.as_bytes());
            out.extend_from_slice(&(f.bytes.len() as u64).to_le_bytes());
            out.extend_from_slice(&Sha256::digest(&f.bytes));
        }
        for f in &self.files {
            out.extend_from_slice(&f.bytes);
        }
        let digest = Sha256::digest(&out);
        out.extend_from_slice(&digest);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Parcel, ParcelError> {
        if b.len() as u64 > MAX_PARCEL_BYTES {
            return Err(ParcelError::TooLarge { what: format!("{} bytes, over {MAX_PARCEL_BYTES}", b.len()) });
        }
        let mut r = Reader { b, off: 0 };
        let magic: [u8; 4] = r.array("magic")?;
        if magic != PARCEL_MAGIC {
            return Err(ParcelError::BadPrefix { what: format!("magic is {}, not \"HPCL\"", shown(&magic)) });
        }
        let version = u16::from_le_bytes(r.array("version")?);
        if version != PARCEL_VERSION {
            return Err(ParcelError::BadPrefix { what: format!("version {version}; this reads {PARCEL_VERSION}") });
        }
        let flags = u16::from_le_bytes(r.array("flags")?);
        if flags != 0 {
            return Err(ParcelError::BadPrefix { what: format!("flags {flags:#06x}; none are defined") });
        }
        let count = u32::from_le_bytes(r.array("file count")?);
        if count > MAX_PARCEL_FILES {
            return Err(ParcelError::TooLarge { what: format!("{count} files, over {MAX_PARCEL_FILES}") });
        }
        let body_len = u64::from_le_bytes(r.array("body length")?);

        let mut index: Vec<(String, u64, [u8; 32])> = Vec::with_capacity(count.min(1024) as usize);
        let mut sum: u64 = 0;
        for _ in 0..count {
            let plen = u16::from_le_bytes(r.array("index path length")?) as usize;
            let raw = r.take(plen, "index path")?;
            let path = match std::str::from_utf8(raw) {
                Ok(p) if valid_path(p) => p.to_string(),
                _ => return Err(ParcelError::BadPath { path: shown(raw) }),
            };
            let size = u64::from_le_bytes(r.array("index file size")?);
            let digest: [u8; 32] = r.array("index file digest")?;
            if let Some((prev, _, _)) = index.last() {
                if path.as_str() <= prev.as_str() {
                    return Err(ParcelError::NotCanonical {
                        what: format!("{} listed after {} (names must be strictly ascending)", shown(path.as_bytes()), shown(prev.as_bytes())),
                    });
                }
            }
            sum = sum
                .checked_add(size)
                .filter(|s| *s <= MAX_PARCEL_BYTES)
                .ok_or_else(|| ParcelError::TooLarge { what: "the index's file sizes add up past the bound".to_string() })?;
            index.push((path, size, digest));
        }
        if sum != body_len {
            return Err(ParcelError::DigestMismatch {
                what: format!("the index's file sizes add up to {sum}, and the prefix says {body_len}"),
            });
        }
        if !index.iter().any(|(p, _, _)| p == STORE_HEADER_FILE) {
            return Err(ParcelError::BadPath { path: "(no store.hdr: a parcel carries one store, header first)".to_string() });
        }

        let mut files = Vec::with_capacity(index.len());
        for (path, size, digest) in index {
            let size = usize::try_from(size).map_err(|_| ParcelError::TooLarge { what: "a file size".to_string() })?;
            let bytes = r.take(size, "file bytes")?;
            if Sha256::digest(bytes).as_slice() != digest {
                return Err(ParcelError::DigestMismatch { what: format!("{path}: its bytes do not hash to the index's digest") });
            }
            files.push(ParcelFile { path, bytes: bytes.to_vec() });
        }
        let covered = r.off;
        let trailer: [u8; 32] = r.array("trailing digest")?;
        let whole = b.get(..covered).ok_or(ParcelError::Truncated { what: "trailing digest" })?;
        if Sha256::digest(whole).as_slice() != trailer {
            return Err(ParcelError::DigestMismatch { what: "the trailing digest does not cover the bytes before it".to_string() });
        }
        if r.off != b.len() {
            return Err(ParcelError::TrailingBytes { count: b.len() - r.off });
        }
        Ok(Parcel { files })
    }

    pub fn unpack_into(&self, dir: impl AsRef<Path>) -> std::io::Result<()> {
        let dir = dir.as_ref();
        if fs::symlink_metadata(dir).is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already exists; a parcel unpacks only into a new directory", dir.display()),
            ));
        }
        create_dir_private(dir)?;
        for f in &self.files {
            if !valid_path(&f.path) {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("refusing to write {}", shown(f.path.as_bytes()))));
            }
            let target = dir.join(&f.path);
            if let Some(parent) = target.parent() {
                if parent != dir && fs::symlink_metadata(parent).is_err() {
                    create_dir_private(parent)?;
                }
            }
            write_file_synced(&target, &f.bytes)?;
            if let Some(parent) = target.parent() {
                sync_dir(parent);
            }
        }
        sync_dir(dir);
        Ok(())
    }
}

struct Reader<'a> {
    b: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], ParcelError> {
        let end = self.off.checked_add(n).ok_or(ParcelError::Truncated { what })?;
        let s = self.b.get(self.off..end).ok_or(ParcelError::Truncated { what })?;
        self.off = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], ParcelError> {
        let s = self.take(N, what)?;
        <[u8; N]>::try_from(s).map_err(|_| ParcelError::Truncated { what })
    }
}
