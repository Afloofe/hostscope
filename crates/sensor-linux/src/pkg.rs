use std::path::{Path, PathBuf};
use std::process::Command;
use std::collections::BTreeMap;
use std::time::Duration;

pub const QUERY_LIMIT: Duration = Duration::from_secs(15);

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

const VOUCH_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);

static VOUCH_HUNG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn capture_within(tool: &Path, args: &[&str]) -> Option<(Option<i32>, String)> {
    capture_bounded(tool, args, VOUCH_LIMIT, &VOUCH_HUNG)
}

fn capture_bounded(
    tool: &Path,
    args: &[&str],
    limit: std::time::Duration,
    hung: &std::sync::atomic::AtomicBool,
) -> Option<(Option<i32>, String)> {
    use std::sync::atomic::Ordering;
    if hung.load(Ordering::Relaxed) {
        return None;
    }
    let mut cmd = Command::new(tool);
    cmd.args(args).env_clear().env("LC_ALL", "C");
    match crate::sshd::output_within(&mut cmd, std::process::Stdio::null(), limit) {
        Ok(Some(out)) => Some((out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned())),
        Ok(None) => {
            hung.store(true, Ordering::Relaxed);
            None
        }
        Err(_) => None,
    }
}

fn capture_text_within(tool: &Path, args: &[&str]) -> Option<String> {
    capture_within(tool, args).map(|(_, out)| out)
}

fn run_bounded(tool: &Path, args: &[&str]) -> Option<std::process::Output> {
    let mut cmd = Command::new(tool);
    cmd.args(args).env_clear().env("LC_ALL", "C");
    let out = crate::sshd::output_within(&mut cmd, std::process::Stdio::null(), QUERY_LIMIT).ok()??;
    out.status.code().is_some().then_some(out)
}

fn plain_package_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "+.:_~@-".contains(c))
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
        self.owner_by(path, capture)
    }

    fn owner_by(&self, path: &Path, run: fn(&Path, &[&str]) -> Option<String>) -> Option<String> {
        if let Some(pkg) = self.owner_exact(path, run) {
            return Some(pkg);
        }
        let real = path.canonicalize().ok()?;
        (real != path).then(|| self.owner_exact(&real, run)).flatten()
    }

    fn owner_exact(&self, path: &Path, run: fn(&Path, &[&str]) -> Option<String>) -> Option<String> {
        let p = path.to_str()?;
        self.parse_owner(&run(&self.tool, &self.owner_query(p))?)
    }

    fn owner_query<'a>(&self, p: &'a str) -> Vec<&'a str> {
        match self.kind {
            Kind::Dpkg => vec!["-S", p],
            Kind::Rpm => vec!["-qf", "--queryformat", "%{NAME}", p],
            Kind::Pacman => vec!["-Qo", p],
        }
    }

    fn parse_owner(&self, out: &str) -> Option<String> {
        match self.kind {
            Kind::Dpkg => parse_dpkg_owner(out),
            Kind::Rpm => {
                let pkg = out.trim();
                (!pkg.is_empty() && !pkg.contains(' ') && !pkg.contains("not owned"))
                    .then(|| pkg.to_string())
            }
            Kind::Pacman => parse_pacman_owner(out),
        }
    }

    pub fn owner_bounded(&self, path: &Path) -> Option<Option<String>> {
        if let Some(pkg) = self.owner_exact_bounded(path)? {
            return Some(Some(pkg));
        }
        match path.canonicalize() {
            Ok(real) if real != path => self.owner_exact_bounded(&real),
            _ => Some(None),
        }
    }

    fn owner_exact_bounded(&self, path: &Path) -> Option<Option<String>> {
        let Some(p) = path.to_str() else { return Some(None) };
        let out = run_bounded(&self.tool, &self.owner_query(p))?;
        Some(self.parse_owner(&String::from_utf8_lossy(&out.stdout)))
    }

    pub fn verify(&self, package: &str) -> Option<Vec<PathBuf>> {
        let args: [&str; 2] = match self.kind {
            Kind::Dpkg | Kind::Rpm => ["-V", package],
            Kind::Pacman => ["-Qkk", package],
        };
        let (code, out) = capture_within(&self.tool, &args)?;
        verify_answer(self.kind, code, &out)
    }

    pub fn vouches(&self, path: &Path, verified: &mut BTreeMap<String, Option<Vec<PathBuf>>>) -> Option<String> {
        let pkg = self.owner_by(path, capture_text_within)?;
        let drifted = verified.entry(pkg.clone()).or_insert_with(|| self.verify(&pkg)).as_ref()?;
        let real = path.canonicalize().ok();
        let changed = drifted.iter().any(|d| {
            d == path || real.as_deref() == Some(d.as_path()) || (real.is_some() && d.canonicalize().ok() == real)
        });
        (!changed).then_some(pkg)
    }

    pub fn verification(&self, package: &str) -> Option<Verification> {
        if !plain_package_name(package) {
            return None;
        }
        let args = match self.kind {
            Kind::Dpkg => vec!["-V", package],
            Kind::Rpm => vec!["-V", "--nodeps", "--noscripts", package],
            Kind::Pacman => vec!["-Qkk", package],
        };
        let out = run_bounded(&self.tool, &args)?;
        Some(Verification {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
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

fn verify_answer(kind: Kind, code: Option<i32>, stdout: &str) -> Option<Vec<PathBuf>> {
    let code = code?;
    if (code != 0 && stdout.trim().is_empty())
        || stdout.contains("is not installed")
        || stdout.contains("was not found")
    {
        return None;
    }
    let parse: fn(&str) -> Option<Drift> = match kind {
        Kind::Pacman => parse_pacman_drift,
        Kind::Dpkg | Kind::Rpm => parse_verify_line,
    };
    Some(stdout.lines().filter_map(parse).map(|d| d.path).collect())
}

#[derive(Debug, Clone)]
pub struct Verification {

    ok: bool,

    stdout: String,

    stderr: String,
}

impl Verification {

    pub fn clears(&self, path: &Path) -> bool {
        let real = path.canonicalize().ok();
        clears(path, real.as_deref(), self, &|p: &Path| p.canonicalize().ok())
    }
}

fn is_file_line(line: &str) -> bool {
    let Some(mask) = line.split_whitespace().next() else { return false };
    let masked = mask == "missing"
        || ((8..=9).contains(&mask.len()) && mask.chars().all(|c| "SM5DLUGTPV.?".contains(c)));
    masked && line.contains(" /")
}

fn clears(path: &Path, real: Option<&Path>, run: &Verification, resolve: &dyn Fn(&Path) -> Option<PathBuf>) -> bool {
    if !run.stderr.trim().is_empty() {
        return false;
    }
    let spellings: Vec<&str> = [Some(path), real].into_iter().flatten().filter_map(Path::to_str).collect();
    let names_it = |line: &str| {
        spellings.iter().any(|s| line.contains(s))
            || match (line.find('/'), real) {
                (Some(at), Some(r)) => line
                    .get(at..)
                    .map(str::trim_end)
                    .and_then(|p| resolve(Path::new(p)))
                    .is_some_and(|q| q == r),
                _ => false,
            }
    };
    let lines: Vec<&str> = run.stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.iter().any(|l| names_it(l)) {
        return false;
    }
    run.ok || (!lines.is_empty() && lines.iter().all(|l| is_file_line(l)))
}

#[derive(Debug, Default)]
pub struct Vouching {

    manager: Option<Option<Manager>>,

    asked: usize,

    stopped: bool,
}

impl Vouching {

    pub const MAX_FILES: usize = 32;

    pub fn vouches_for(&mut self, path: &Path) -> Option<String> {
        if self.stopped || self.asked >= Self::MAX_FILES {
            return None;
        }
        self.asked += 1;
        let pm = self.manager.get_or_insert_with(manager).as_ref()?;
        let Some(owner) = pm.owner_bounded(path) else {
            self.stopped = true;
            return None;
        };
        let pkg = owner?;
        let Some(run) = pm.verification(&pkg) else {
            self.stopped = true;
            return None;
        };
        run.clears(path).then_some(pkg)
    }
}
