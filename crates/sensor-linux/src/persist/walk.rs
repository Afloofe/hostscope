use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

pub(super) fn boot_time() -> Option<u64> {
    let stat = fs::read_to_string("/proc/stat").ok()?;
    stat.lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse().ok())
}

pub(super) fn mtime(path: &Path) -> Option<u64> {
    fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

pub(super) fn home_dirs() -> Vec<(String, PathBuf)> {
    home_dirs_with_gap().0
}

pub(super) fn home_dirs_with_gap() -> (Vec<(String, PathBuf)>, Option<String>) {
    home_dirs_from(Path::new("/etc/passwd"))
}

pub(super) fn home_dirs_from(passwd: &Path) -> (Vec<(String, PathBuf)>, Option<String>) {
    let (text, gap) = match crate::saferead::read_scan_target_bounded(passwd) {
        None => return (Vec::new(), Some("/etc/passwd could not be read, so no home directory was listed".into())),
        Some((t, true)) => (t, Some("/etc/passwd was read only in part, so later homes were not listed".into())),
        Some((t, false)) => (t, None),
    };
    (parse_home_dirs(&text), gap)
}

fn parse_home_dirs(text: &str) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut f = line.split(':');
        let (Some(user), Some(_pw), Some(_uid), Some(_gid), Some(_gecos), Some(home)) =
            (f.next(), f.next(), f.next(), f.next(), f.next(), f.next())
        else {
            continue;
        };
        if home.is_empty() || home == "/" || home == "/nonexistent" || home == "/dev/null" {
            continue;
        }
        out.push((user.to_string(), PathBuf::from(home)));
    }

    out.sort();
    out.dedup_by(|a, b| a.1 == b.1);
    out
}

pub(super) fn presence(p: &Path) -> Presence {
    match fs::symlink_metadata(p) {
        Ok(_) => Presence::Present,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Presence::Absent,
        Err(_) => Presence::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Presence {

    Present,

    Absent,

    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DeadLink {

    Masked,

    Dangling(PathBuf),
}

pub(super) fn dead_link(p: &Path) -> Option<DeadLink> {
    let target = fs::read_link(p).ok()?;
    if target == Path::new("/dev/null") {
        return Some(DeadLink::Masked);
    }
    match fs::metadata(p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Some(DeadLink::Dangling(target)),
        _ => None,
    }
}

pub(super) fn files_in(dir: &Path) -> Result<Vec<PathBuf>, ()> {
    let entries = fs::read_dir(dir).map_err(|_| ())?;
    let mut out = Vec::new();
    for e in entries.flatten() {
        let p = e.path();

        let Ok(md) = fs::symlink_metadata(&p) else { continue };
        if md.is_file() || md.file_type().is_symlink() {
            out.push(p);
        }
    }
    out.sort();
    Ok(out)
}

pub(super) fn files_in_all(dirs: &[&str]) -> Walked {
    let mut w = Walked::default();
    let mut read: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for d in dirs {
        let dir = Path::new(d);
        match presence(dir) {
            Presence::Absent => continue,
            Presence::Unknown => {
                w.any_existed = true;
                w.refused.push((*d).to_string());
                continue;
            }
            Presence::Present => {}
        }
        w.any_existed = true;
        if let Ok(real) = dir.canonicalize() {
            if !read.insert(real) {
                continue;
            }
        }
        match files_in(dir) {
            Ok(files) => {
                w.any_read = true;
                w.files.extend(files);
            }
            Err(()) => w.refused.push((*d).to_string()),
        }
    }
    w
}

pub(super) fn distinct_files(paths: &[&str]) -> Vec<PathBuf> {
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    paths
        .iter()
        .map(PathBuf::from)
        .filter(|p| {
            let key = match p.canonicalize() {
                Ok(real) if real.is_file() => real,
                _ => p.clone(),
            };
            seen.insert(key)
        })
        .collect()
}

pub(super) fn is_supervisor_runtime(p: &Path) -> bool {
    matches!(
        p.file_name().and_then(|n| n.to_str()),

        Some("supervise" | "event")
    )
}

#[derive(Debug, Default)]
pub(super) struct Walked {

    pub(super) files: Vec<PathBuf>,

    pub(super) refused: Vec<String>,

    pub(super) any_existed: bool,

    pub(super) any_read: bool,
}

pub(super) fn per_user_files(rels: &[&str], homes: &[(String, PathBuf)]) -> Walked {
    let mut w = Walked::default();
    for (_user, home) in homes {
        for rel in rels {
            let p = home.join(rel);
            match presence(&p) {
                Presence::Absent => continue,

                Presence::Unknown => {
                    w.any_existed = true;
                    w.refused.push(p.display().to_string());
                    continue;
                }
                Presence::Present => {}
            }
            w.any_existed = true;
            if p.is_dir() {
                match files_in(&p) {
                    Ok(files) => {
                        w.any_read = true;
                        w.files.extend(files);
                    }
                    Err(()) => w.refused.push(p.display().to_string()),
                }
            } else {
                w.files.push(p);
            }
        }
    }
    w
}

pub(super) fn tree_under_all(dirs: &[&str], budget: &mut usize) -> Walked {
    let mut w = Walked::default();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for d in dirs {
        let dir = Path::new(d);
        match presence(dir) {
            Presence::Absent => continue,
            Presence::Unknown => {
                w.any_existed = true;
                w.refused.push((*d).to_string());
                continue;
            }
            Presence::Present => {}
        }
        w.any_existed = true;
        let found = tree_under(dir, budget, &mut seen);
        if !found.read_something {

            w.refused.push((*d).to_string());
            continue;
        }
        w.any_read = true;
        w.files.extend(found.files);

        for u in found.unreadable {
            w.refused.push(u.display().to_string());
        }
        if let Some(why) = found.stopped {
            w.refused.push(format!("{d}: {why}"));
        }
    }
    w
}

#[derive(Debug, Default)]
pub(super) struct Subtree {

    pub(super) files: Vec<PathBuf>,

    pub(super) unreadable: Vec<PathBuf>,

    pub(super) stopped: Option<String>,

    pub(super) read_something: bool,
}

pub(super) fn tree_under(
    dir: &Path,
    budget: &mut usize,
    seen: &mut std::collections::HashSet<PathBuf>,
) -> Subtree {
    const MAX_DEPTH: usize = 6;
    let mut found = Subtree::default();
    let mut stack = vec![(dir.to_path_buf(), 0usize)];
    while let Some((d, depth)) = stack.pop() {

        if depth > MAX_DEPTH {
            found.stopped.get_or_insert_with(|| {
                format!("the walk stopped at {MAX_DEPTH} directories deep")
            });
            continue;
        }
        if *budget == 0 {
            found
                .stopped
                .get_or_insert_with(|| "the sweep's file budget ran out".to_string());
            continue;
        }
        match fs::read_dir(&d) {
            Err(_) => found.unreadable.push(d.clone()),
            Ok(entries) => {
                found.read_something = true;
                for e in entries.flatten() {
                    if *budget == 0 {
                        found
                            .stopped
                            .get_or_insert_with(|| "the sweep's file budget ran out".to_string());
                        break;
                    }
                    let p = e.path();

                    let dangling = fs::symlink_metadata(&p)
                        .is_ok_and(|m| m.file_type().is_symlink())
                        && fs::metadata(&p).is_err();
                    if p.is_dir() {
                        if is_supervisor_runtime(&p) {
                            continue;
                        }
                        stack.push((p, depth + 1));
                    } else if p.is_file() || dangling {

                        let key = p.canonicalize().unwrap_or_else(|_| p.clone());
                        if !seen.insert(key) {
                            continue;
                        }
                        *budget -= 1;
                        found.files.push(p);
                    }
                }
            }
        }
    }
    found.files.sort();
    found
}

pub(super) use crate::saferead::read_scan_target_bounded;
