use std::path::{Path, PathBuf};

pub fn unique_path(dir: &Path, stem: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let first = dir.join(format!("{stem}-{stamp}.tsv"));
    if !first.exists() {
        return first;
    }

    for n in 1..1000 {
        let p = dir.join(format!("{stem}-{stamp}-{n}.tsv"));
        if !p.exists() {
            return p;
        }
    }
    dir.join(format!("{stem}-{stamp}-full.tsv"))
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
    path: PathBuf,
    header: &'static str,
    file: Option<std::fs::File>,
}

impl Appender {

    pub fn new(path: PathBuf, header: &'static str) -> Self {
        Appender { path, header, file: None }
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
            if let Some(parent) = self.path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
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
}
