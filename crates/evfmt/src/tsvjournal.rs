use std::path::{Path, PathBuf};

pub fn unique_path(dir: &Path, stem: &str) -> Option<PathBuf> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    unique_path_at(dir, stem, stamp)
}

fn unique_path_at(dir: &Path, stem: &str, stamp: u64) -> Option<PathBuf> {

    let free = |p: &Path| std::fs::symlink_metadata(p).is_err();
    let first = dir.join(format!("{stem}-{stamp}.tsv"));
    if free(&first) {
        return Some(first);
    }

    (1..1000).map(|n| dir.join(format!("{stem}-{stamp}-{n}.tsv"))).find(|p| free(p))
}

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out
}

pub fn unesc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('\\') => out.push('\\'),
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => {}
        }
    }
    out
}

pub const PAIR_SEP: char = '\x1f';

pub fn encode_pairs(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(&PAIR_SEP.to_string())
}

pub fn decode_pairs(s: &str) -> Vec<(String, String)> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(PAIR_SEP)
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub fn records<'a>(
    text: &'a str,
    header: &str,
    what: &str,
) -> Result<impl Iterator<Item = (usize, &'a str)>, String> {
    let mut lines = text.lines();
    match lines.next() {
        Some(h) if h.trim() == header => {}
        Some(other) => return Err(format!("not {what} (first line: {other:?})")),
        None => return Err("empty file".to_string()),
    }
    Ok(lines
        .enumerate()

        .map(|(i, line)| (i + 2, line))
        .filter(|(_, line)| !(line.trim().is_empty() || line.starts_with('#'))))
}

pub struct Appender {
    dir: PathBuf,
    stem: &'static str,
    header: &'static str,

    path: PathBuf,

    named: bool,
    file: Option<std::fs::File>,
}

impl Appender {

    pub fn new(dir: &Path, stem: &'static str, header: &'static str) -> Self {
        let (path, named) = match unique_path(dir, stem) {
            Some(p) => (p, true),
            None => (dir.join(format!("{stem}.tsv")), false),
        };
        Appender { dir: dir.to_path_buf(), stem, header, path, named, file: None }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn started(&self) -> bool {
        self.file.is_some()
    }

    pub fn append(&mut self, line: &str) -> std::io::Result<()> {
        use std::io::Write as _;
        if self.file.is_none() {
            std::fs::create_dir_all(&self.dir)?;
            let mut f = self.create()?;
            writeln!(f, "{}", self.header)?;
            self.file = Some(f);
        }
        let Some(f) = self.file.as_mut() else {
            return Err(std::io::Error::other("journal file vanished"));
        };
        f.write_all(line.as_bytes())?;
        f.flush()?;
        f.sync_data()
    }

    fn create(&mut self) -> std::io::Result<std::fs::File> {
        if !self.named {
            self.path = unique_path(&self.dir, self.stem).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::AlreadyExists, "no free journal name")
            })?;
            self.named = true;
        }
        let mut taken = None;
        for _ in 0..16 {
            match crate::disk::create_new_file(&self.path) {
                Ok(f) => return Ok(f),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    taken = Some(e);
                    match unique_path(&self.dir, self.stem) {
                        Some(next) => self.path = next,
                        None => break,
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Err(taken.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AlreadyExists, "no free journal name")
        }))
    }
}
