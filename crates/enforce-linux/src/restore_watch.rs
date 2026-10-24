use std::fs;
use std::path::{Path, PathBuf};

const TMPFILES_DIRS: &[&str] = &["/etc/tmpfiles.d", "/run/tmpfiles.d", "/usr/lib/tmpfiles.d"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restorer {

    pub rule_file: PathBuf,

    pub target: PathBuf,

    pub line: String,
}

pub fn line_restores(line: &str, target: &Path) -> bool {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return false;
    }
    let mut f = t.split_whitespace();
    let Some(kind) = f.next().and_then(|k| k.chars().next()) else { return false };
    if !matches!(kind, 'C' | 'L' | 'f' | 'F' | 'w') {
        return false;
    }
    let Some(path) = f.next() else { return false };
    if Path::new(path) == target {
        return true;
    }

    matches!(kind, 'C' | 'L') && f.nth(4).is_some_and(|arg| Path::new(arg) == target)
}

pub fn restorers_for(removed: &[PathBuf]) -> Vec<Restorer> {
    let mut out = Vec::new();
    if removed.is_empty() {
        return out;
    }
    for dir in TMPFILES_DIRS {
        let Ok(entries) = fs::read_dir(dir) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            if !p.is_file() {
                continue;
            }
            let Some(text) = hemostat_sensor_linux::saferead::read_scan_target(&p) else { continue };
            for line in text.lines() {
                for target in removed {
                    if line_restores(line, target) {
                        out.push(Restorer {
                            rule_file: p.clone(),
                            target: target.clone(),
                            line: line.trim().to_string(),
                        });
                    }
                }
            }
        }
    }
    out
}
