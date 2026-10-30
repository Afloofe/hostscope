use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {

    Dpkg,

    Rpm,

    Pacman,
}

impl Kind {

    pub fn name(self) -> &'static str {
        match self {
            Kind::Dpkg => "dpkg",
            Kind::Rpm => "rpm",
            Kind::Pacman => "pacman",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Manager {

    pub kind: Kind,

    pub tool: PathBuf,
}

fn resolve(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

pub fn manager() -> Option<Manager> {
    if let Some(tool) = resolve(&["/usr/bin/dpkg", "/bin/dpkg"]) {
        return Some(Manager { kind: Kind::Dpkg, tool });
    }
    if let Some(tool) = resolve(&["/usr/bin/rpm", "/bin/rpm"]) {
        return Some(Manager { kind: Kind::Rpm, tool });
    }
    if let Some(tool) = resolve(&["/usr/bin/pacman", "/bin/pacman"]) {
        return Some(Manager { kind: Kind::Pacman, tool });
    }
    None
}

fn capture(tool: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new(tool).args(args).env_clear().env("LC_ALL", "C").output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn parse_dpkg_owner(out: &str) -> Option<String> {
    for line in out.lines() {
        if line.starts_with("diversion ") {
            continue;
        }
        let Some((pkgs, _)) = line.split_once(": /") else { continue };
        let pkg = pkgs.split(',').next()?.trim();
        if !pkg.is_empty() && !pkg.contains(' ') && !pkg.contains('/') {
            return Some(pkg.to_string());
        }
    }
    None
}

pub fn parse_pacman_owner(out: &str) -> Option<String> {
    let pkg = out.split(" is owned by ").nth(1)?.split_whitespace().next()?;
    (!pkg.is_empty()).then(|| pkg.to_string())
}

pub fn parse_dpkg_version(out: &str) -> Option<String> {
    out.lines()
        .find_map(|l| l.strip_prefix("Version:"))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

impl Manager {

    pub fn owner(&self, path: &Path) -> Option<String> {
        if let Some(pkg) = self.owner_exact(path) {
            return Some(pkg);
        }
        let real = path.canonicalize().ok()?;
        (real != path).then(|| self.owner_exact(&real)).flatten()
    }

    fn owner_exact(&self, path: &Path) -> Option<String> {
        let p = path.to_str()?;
        match self.kind {
            Kind::Dpkg => parse_dpkg_owner(&capture(&self.tool, &["-S", p])?),
            Kind::Rpm => {
                let out = capture(&self.tool, &["-qf", "--queryformat", "%{NAME}", p])?;
                let pkg = out.trim();
                (!pkg.is_empty() && !pkg.contains(' ') && !pkg.contains("not owned"))
                    .then(|| pkg.to_string())
            }
            Kind::Pacman => parse_pacman_owner(&capture(&self.tool, &["-Qo", p])?),
        }
    }

    pub fn owns(&self, path: &Path) -> bool {
        self.owner(path).is_some()
    }

    pub fn drift(&self, package: &str) -> Vec<Drift> {
        match self.kind {
            Kind::Dpkg => capture(&self.tool, &["-V", package])
                .map(|v| v.lines().filter_map(parse_verify_line).collect())
                .unwrap_or_default(),
            Kind::Rpm => capture(&self.tool, &["-V", package])
                .map(|v| v.lines().filter_map(parse_verify_line).collect())
                .unwrap_or_default(),
            Kind::Pacman => capture(&self.tool, &["-Qkk", package])
                .map(|v| v.lines().filter_map(parse_pacman_drift).collect())
                .unwrap_or_default(),
        }
    }

    pub fn installed_version(&self, package: &str) -> Option<String> {
        match self.kind {
            Kind::Dpkg => parse_dpkg_version(&capture(&self.tool, &["-s", package])?),
            Kind::Rpm => {
                let out = capture(&self.tool, &["-q", "--qf", "%{VERSION}-%{RELEASE}", package])?;
                let v = out.trim();
                (!v.is_empty() && !v.contains(' ') && !v.contains("not installed")).then(|| v.to_string())
            }
            Kind::Pacman => {
                capture(&self.tool, &["-Q", package])?.split_whitespace().nth(1).map(str::to_string)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drift {

    pub path: PathBuf,

    pub is_config: bool,
}

pub fn parse_verify_line(line: &str) -> Option<Drift> {
    let t = line.trim();
    if t.is_empty() {
        return None;
    }
    let mut f = t.split_whitespace();
    let flags = f.next()?;

    if flags.len() < 3 || flags.contains('/') || !flags.contains('5') {
        return None;
    }
    let next = f.next()?;
    let (is_config, path) = if next == "c" || next == "d" {
        (next == "c", f.next()?)
    } else {
        (false, next)
    };
    path.starts_with('/').then(|| Drift { path: PathBuf::from(path), is_config })
}

pub fn parse_pacman_drift(line: &str) -> Option<Drift> {
    if !line.contains("mismatch") || line.contains("Modification time") {
        return None;
    }
    let path = line.split(": ").nth(1)?.split_whitespace().next()?;
    path.starts_with('/')
        .then(|| Drift { path: PathBuf::from(path), is_config: path.starts_with("/etc/") })
}
