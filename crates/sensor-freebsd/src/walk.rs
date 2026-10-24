use std::path::{Path, PathBuf};

pub const ROOTS: &[&str] = &[
    "/bin",
    "/sbin",
    "/lib",
    "/libexec",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/libexec",
    "/boot/kernel",
    "/etc",
    "/usr/local",
];

pub const MAX_DEPTH: usize = 32;

pub const MAX_ENTRIES: usize = 400_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {

    File(u64),

    Dir,

    Link(String),

    Special,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {

    pub path: String,

    pub kind: Kind,

    pub mode: u32,

    pub uid: u32,

    pub gid: u32,

    pub dev: u64,

    pub ino: u64,

    pub nlink: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Walk {

    pub entries: Vec<Entry>,

    pub gaps: Vec<String>,
}

impl Walk {

    pub fn complete(&self) -> bool {
        self.gaps.is_empty()
    }
}

#[cfg(unix)]
pub fn walk(root: &Path) -> Walk {
    walk_roots(root, ROOTS)
}

#[cfg(unix)]
pub fn walk_roots(root: &Path, roots: &[&str]) -> Walk {
    let mut w = Walk::default();
    for step in Walker::new(root, roots) {
        match step {
            Step::Entry(e) => w.entries.push(e),
            Step::Gap(g) => w.gaps.push(g),
        }
    }
    w
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {

    Entry(Entry),

    Gap(String),
}

#[cfg(unix)]
#[derive(Debug)]
pub struct Walker {
    root: PathBuf,
    roots: Vec<String>,

    stack: Vec<(PathBuf, String, usize, u64)>,

    names: Vec<std::ffi::OsString>,
    dir: Option<(PathBuf, String, usize, u64)>,
    queued: std::collections::VecDeque<Step>,
    seen: usize,
    stopped: bool,
}

#[cfg(unix)]
impl Walker {

    pub fn new(root: &Path, roots: &[&str]) -> Walker {
        Walker {
            root: root.to_path_buf(),
            roots: roots.iter().rev().map(|r| (*r).to_string()).collect(),
            stack: Vec::new(),
            names: Vec::new(),
            dir: None,
            queued: std::collections::VecDeque::new(),
            seen: 0,
            stopped: false,
        }
    }

    pub fn seen(&self) -> usize {
        self.seen
    }

    fn entry(&mut self, path: String, on_disk: &Path, md: &std::fs::Metadata) {
        let mut w = Walk::default();
        push(&mut w, path, on_disk, md);
        self.queued.extend(w.gaps.into_iter().map(Step::Gap));
        self.queued.extend(w.entries.into_iter().map(Step::Entry));
    }

    fn advance(&mut self) {
        use std::os::unix::fs::MetadataExt as _;
        loop {
            if !self.queued.is_empty() || self.stopped {
                return;
            }
            if let Some((dir, shown, depth, dev)) = self.dir.clone() {
                let Some(name) = self.names.pop() else {
                    self.dir = None;
                    continue;
                };
                if self.seen >= MAX_ENTRIES {
                    self.queued.push_back(Step::Gap(format!(
                        "stopped at {MAX_ENTRIES} entries; the rest of {shown} was not walked"
                    )));
                    self.stopped = true;
                    return;
                }
                let Some(n) = name.to_str() else {
                    self.queued.push_back(Step::Gap(format!("{shown}: an entry whose name is not UTF-8 was not judged")));
                    continue;
                };
                let p = dir.join(n);
                let shown_p = format!("{shown}/{n}");
                let md = match std::fs::symlink_metadata(&p) {
                    Ok(m) => m,
                    Err(e) => {
                        self.queued.push_back(Step::Gap(format!("{shown_p}: not read ({e})")));
                        continue;
                    }
                };
                self.entry(shown_p.clone(), &p, &md);
                if md.file_type().is_dir() {
                    if md.dev() != dev {
                        self.queued
                            .push_back(Step::Gap(format!("{shown_p}: another filesystem is mounted here, and was not walked")));
                    } else if depth + 1 >= MAX_DEPTH {
                        self.queued.push_back(Step::Gap(format!("{shown_p}: deeper than {MAX_DEPTH} levels, not walked")));
                    } else {
                        self.stack.push((p, shown_p, depth + 1, dev));
                    }
                }
                continue;
            }
            if let Some((dir, shown, depth, dev)) = self.stack.pop() {
                match std::fs::read_dir(&dir) {
                    Ok(rd) => {
                        let mut names: Vec<_> = rd.filter_map(|e| e.ok().map(|e| e.file_name())).collect();

                        names.sort_by(|a, b| b.cmp(a));
                        self.names = names;
                        self.dir = Some((dir, shown, depth, dev));
                    }
                    Err(e) => self.queued.push_back(Step::Gap(format!("{shown}: not listed ({e})"))),
                }
                continue;
            }
            let Some(r) = self.roots.pop() else { return };
            let top = join(&self.root, &r);
            match std::fs::symlink_metadata(&top) {
                Ok(md) if md.file_type().is_dir() => self.stack.push((top, r, 0, md.dev())),

                Ok(md) => self.entry(r, &top, &md),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => self.queued.push_back(Step::Gap(format!("{r}: not read ({e})"))),
            }
        }
    }
}

#[cfg(unix)]
impl Iterator for Walker {
    type Item = Step;

    fn next(&mut self) -> Option<Step> {
        self.advance();
        let s = self.queued.pop_front();
        if matches!(s, Some(Step::Entry(_))) {
            self.seen += 1;
        }
        s
    }
}

#[cfg(unix)]
fn push(w: &mut Walk, path: String, on_disk: &Path, md: &std::fs::Metadata) {
    use std::os::unix::fs::MetadataExt as _;
    let ft = md.file_type();
    let kind = if ft.is_file() {
        Kind::File(md.len())
    } else if ft.is_dir() {
        Kind::Dir
    } else if ft.is_symlink() {
        match std::fs::read_link(on_disk) {
            Ok(t) => Kind::Link(t.to_string_lossy().into_owned()),
            Err(e) => {
                w.gaps.push(format!("{path}: a link whose target could not be read ({e})"));
                Kind::Link(String::new())
            }
        }
    } else {
        Kind::Special
    };
    w.entries.push(Entry {
        path,
        kind,
        mode: md.mode() & 0o7777,
        uid: md.uid(),
        gid: md.gid(),
        dev: md.dev(),
        ino: md.ino(),
        nlink: md.nlink(),
    });
}

pub fn join(root: &Path, path: &str) -> PathBuf {
    root.join(path.trim_start_matches('/'))
}
