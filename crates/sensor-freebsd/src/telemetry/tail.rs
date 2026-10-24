use sha2::{Digest as _, Sha256};

pub const LIVE: &str = "/var/log/filter.log";

pub const MAX_ROTATIONS: usize = 64;

pub const TAIL_BYTES: u64 = 256;

pub const COMPRESSED: [&str; 4] = [".bz2", ".gz", ".xz", ".zst"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFile {

    pub path: String,

    pub dev: u64,

    pub ino: u64,

    pub size: u64,

    pub rotation: Option<u32>,

    pub compressed: bool,
}

pub fn classify(name: &str) -> Option<(Option<u32>, bool)> {
    let rest = match name.strip_prefix("filter.log") {
        Some("") => return Some((None, false)),
        Some(r) => r.strip_prefix('.')?,
        None => return None,
    };
    let (num, compressed) = match COMPRESSED.iter().find_map(|s| rest.strip_suffix(s)) {
        Some(n) => (n, true),
        None => (rest, false),
    };
    if num.is_empty() || num.len() > 3 || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((Some(num.parse().ok()?), compressed))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {

    pub dev: u64,

    pub ino: u64,

    pub offset: u64,

    pub tail_len: u64,

    pub tail: [u8; 32],

    pub at: u64,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Cursor {

    pub fn after(file: &LogFile, offset: u64, bytes: &[u8], at: u64) -> Cursor {
        let n = (bytes.len() as u64).min(TAIL_BYTES).min(offset);
        let start = bytes.len().saturating_sub(n as usize);
        let tail: [u8; 32] = Sha256::digest(bytes.get(start..).unwrap_or_default()).into();
        Cursor { dev: file.dev, ino: file.ino, offset, tail_len: n, tail, at }
    }

    pub fn encode(&self) -> String {
        format!("filterlog-cursor/1 {} {} {} {} {} {}\n", self.dev, self.ino, self.offset, self.tail_len, hex(&self.tail), self.at)
    }

    pub fn decode(text: &str) -> Option<Cursor> {
        let mut it = text.trim_end_matches('\n').split(' ');
        if it.next()? != "filterlog-cursor/1" {
            return None;
        }
        let dev = it.next()?.parse().ok()?;
        let ino = it.next()?.parse().ok()?;
        let offset = it.next()?.parse().ok()?;
        let tail_len: u64 = it.next()?.parse().ok()?;
        let t = it.next()?;
        let at = it.next()?.parse().ok()?;
        if it.next().is_some() || t.len() != 64 || tail_len > TAIL_BYTES || tail_len > offset {
            return None;
        }
        let mut tail = [0u8; 32];
        for (i, o) in tail.iter_mut().enumerate() {
            *o = u8::from_str_radix(t.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some(Cursor { dev, ino, offset, tail_len, tail, at })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Continuity {

    First,

    Continues {

        path: String,

        new_bytes: u64,

        checked: bool,
    },

    Rotated,

    Truncated {

        path: String,

        was: u64,

        now: u64,
    },

    Rewritten {

        path: String,
    },
}

impl Continuity {

    pub fn tampered(&self) -> bool {
        matches!(self, Continuity::Truncated { .. } | Continuity::Rewritten { .. })
    }

    pub fn describe(&self, cursor: Option<&Cursor>) -> String {
        let since = cursor.map_or(String::new(), |c| format!(" (last sweep at {} s)", c.at));
        match self {
            Continuity::First => "first sweep: no earlier cursor to continue from".into(),
            Continuity::Continues { path, new_bytes, checked: true } => {
                format!("continues from the last sweep{since}: {new_bytes} bytes new in {path}, earlier bytes unchanged")
            }
            Continuity::Continues { path, new_bytes, checked: false } => format!(
                "continues from the last sweep{since}: {new_bytes} bytes new in {path}; the bytes before the old \
                 offset were outside this read and not compared"
            ),
            Continuity::Rotated => format!(
                "rotated since the last sweep{since}: the lines after where it stopped are in a compressed rotation \
                 this agent does not read"
            ),
            Continuity::Truncated { path, was, now } => format!(
                "{path} is {now} bytes, shorter than the {was} the last sweep{since} read: the log was cut in place, \
                 which rotation never does"
            ),
            Continuity::Rewritten { path } => format!(
                "{path} no longer holds the bytes the last sweep{since} read before its offset: the log was rewritten \
                 in place, which rotation never does"
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span<'a> {

    pub file: &'a LogFile,

    pub from: u64,

    pub bytes: &'a [u8],
}

pub fn continuity(cursor: Option<&Cursor>, spans: &[Span<'_>]) -> Continuity {
    let Some(c) = cursor else { return Continuity::First };
    let Some(s) = spans.iter().find(|s| s.file.dev == c.dev && s.file.ino == c.ino) else {
        return Continuity::Rotated;
    };
    let end = s.from + s.bytes.len() as u64;
    if end < c.offset {
        return Continuity::Truncated { path: s.file.path.clone(), was: c.offset, now: end };
    }
    let tail_from = c.offset.saturating_sub(c.tail_len);
    if tail_from < s.from {
        return Continuity::Continues { path: s.file.path.clone(), new_bytes: end - c.offset, checked: false };
    }
    let a = (tail_from - s.from) as usize;
    let b = (c.offset - s.from) as usize;
    let seen: [u8; 32] = Sha256::digest(s.bytes.get(a..b).unwrap_or_default()).into();
    if seen != c.tail {
        return Continuity::Rewritten { path: s.file.path.clone() };
    }
    Continuity::Continues { path: s.file.path.clone(), new_bytes: end - c.offset, checked: true }
}

pub fn plan(files: &[LogFile], budget: u64) -> Vec<(usize, u64, u64)> {
    let mut order: Vec<usize> = (0..files.len()).filter(|i| files.get(*i).is_some_and(|f| !f.compressed)).collect();
    order.sort_by_key(|i| files.get(*i).map(|f| f.rotation.map_or(0, |r| u64::from(r) + 1)).unwrap_or(u64::MAX));
    let mut left = budget;
    let mut out = Vec::new();
    for i in order {
        let Some(f) = files.get(i) else { continue };
        if left == 0 {
            break;
        }
        let take = f.size.min(left);
        out.push((i, f.size - take, f.size));
        left -= take;
    }
    out
}
