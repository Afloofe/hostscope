#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

pub const RULES_DIR: &str = "/etc/hemostat/yara";

pub const MAX_FILE: u64 = 64 * 1024 * 1024;

pub const SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(unix)]
fn open_target(p: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)
}

#[cfg(not(unix))]
fn open_target(p: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(p)
}

fn open_refusal(e: &std::io::Error) -> String {
    #[cfg(unix)]
    if e.raw_os_error() == Some(libc::ELOOP) {
        return "a symlink, which is never followed".to_string();
    }
    e.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {

    pub rule: String,

    pub path: PathBuf,

    pub note: String,

    pub own_image: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {

    pub hits: Vec<Hit>,

    pub scanned: usize,

    pub skipped: Vec<(PathBuf, String)>,

    pub rules: usize,

    pub unavailable: Option<String>,
}

pub const BUILTIN: &str = include_str!("builtin.yar");

fn count_rules(src: &str) -> usize {
    src.lines().filter(|l| declares_rule(l)).count()
}

fn declares_rule(line: &str) -> bool {
    let mut rest = line.trim_start();

    for _ in 0..2 {
        for m in ["private", "global"] {
            if let Some(tail) = rest.strip_prefix(m) {
                if tail.starts_with(char::is_whitespace) {
                    rest = tail.trim_start();
                }
            }
        }
    }
    rest.strip_prefix("rule").is_some_and(|t| t.starts_with(char::is_whitespace))
}

fn compile(dir: Option<&Path>) -> Result<(yara_x::Rules, usize, Vec<String>), String> {
    let mut compiler = yara_x::Compiler::new();
    let mut problems = Vec::new();
    let mut rule_count = 0usize;

    compiler.enable_includes(false);

    compiler.new_namespace("hemostat_builtin");
    compiler.add_source(BUILTIN).map_err(|e| format!("the built-in rules do not compile: {e}"))?;
    rule_count += count_rules(BUILTIN);

    if let Some(dir) = dir {
        compiler.new_namespace("feed");
        let mut files = Vec::new();
        collect_rules(dir, &mut files, &mut problems)?;
        files.sort();
        for f in files {
            match read_rule_file(&f) {
                Ok(text) => match compiler.add_source(text.as_str()) {
                    Ok(_) => rule_count += count_rules(&text),
                    Err(e) => problems.push(format!("{}: {e}", f.display())),
                },
                Err(e) => problems.push(format!("{}: {e}", f.display())),
            }
        }
    }
    Ok((compiler.build(), rule_count, problems))
}

fn read_rule_file(p: &Path) -> Result<String, String> {
    let f = open_target(p).map_err(|e| open_refusal(&e))?;
    let md = f.metadata().map_err(|e| e.to_string())?;
    if !md.is_file() {
        return Err("not a regular file — its rules were not loaded".to_string());
    }
    if md.len() > MAX_FILE {
        return Err(format!("{} bytes, over the {MAX_FILE} cap — its rules were not loaded", md.len()));
    }
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(&f, MAX_FILE), &mut body)
        .map_err(|e| e.to_string())?;
    String::from_utf8(body).map_err(|e| e.to_string())
}

fn collect_rules(
    dir: &Path,
    out: &mut Vec<PathBuf>,
    problems: &mut Vec<String>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                problems.push(format!("{}: could not read an entry: {e}", dir.display()));
                continue;
            }
        };
        let path = entry.path();

        match entry.file_type() {
            Ok(t) if t.is_dir() => collect_rules(&path, out, problems)?,
            Ok(t) if t.is_file() => {
                if path
                    .extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| x == "yar" || x == "yara")
                {
                    out.push(path);
                }
            }

            Ok(t) if t.is_symlink() => problems.push(format!(
                "{}: a symlink, not followed — its rules were not loaded",
                path.display()
            )),
            Ok(_) => problems.push(format!(
                "{}: not a regular file or directory — skipped",
                path.display()
            )),
            Err(e) => problems.push(format!("{}: {e}", path.display())),
        }
    }
    Ok(())
}

fn meta_text(v: &yara_x::MetaValue<'_>) -> String {
    match v {
        yara_x::MetaValue::String(s) => (*s).to_string(),
        yara_x::MetaValue::Bytes(b) => String::from_utf8_lossy(b.as_ref()).into_owned(),
        yara_x::MetaValue::Integer(i) => i.to_string(),
        yara_x::MetaValue::Float(f) => f.to_string(),
        yara_x::MetaValue::Bool(b) => b.to_string(),
    }
}

#[cfg(target_os = "linux")]
fn own_image() -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata("/proc/self/exe").ok().map(|m| (m.dev(), m.ino()))
}

#[cfg(not(target_os = "linux"))]
fn own_image() -> Option<(u64, u64)> {
    None
}

#[cfg(unix)]
fn identity(md: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    Some((md.dev(), md.ino()))
}

#[cfg(not(unix))]
fn identity(_md: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

fn scan(rules: &yara_x::Rules, paths: &[PathBuf], own: Option<(u64, u64)>, out: &mut Outcome) {
    let mut scanner = yara_x::Scanner::new(rules);

    scanner.set_timeout(SCAN_TIMEOUT);
    for p in paths {

        let f = match open_target(p) {
            Ok(f) => f,
            Err(e) => {
                out.skipped.push((p.clone(), open_refusal(&e)));
                continue;
            }
        };
        let md = match f.metadata() {
            Ok(m) => m,
            Err(e) => {
                out.skipped.push((p.clone(), e.to_string()));
                continue;
            }
        };
        if !md.is_file() {
            let kind = if md.is_dir() { "a directory" } else { "not a regular file" };
            out.skipped.push((p.clone(), kind.to_string()));
            continue;
        }
        if md.len() > MAX_FILE {
            out.skipped.push((p.clone(), format!("{} bytes, over the {MAX_FILE} cap", md.len())));
            continue;
        }
        let mut body = Vec::new();
        let mut capped = std::io::Read::take(&f, MAX_FILE);
        if let Err(e) = std::io::Read::read_to_end(&mut capped, &mut body) {
            out.skipped.push((p.clone(), e.to_string()));
            continue;
        }

        let own_image = own.is_some() && identity(&md) == own;
        match scanner.scan(&body) {
            Ok(results) => {
                out.scanned += 1;
                for m in results.matching_rules() {
                    out.hits.push(Hit {
                        rule: m.identifier().to_string(),
                        path: p.clone(),
                        note: m
                            .metadata()
                            .into_iter()
                            .find(|(k, _)| *k == "description")
                            .map(|(_, v)| meta_text(&v))
                            .unwrap_or_default(),
                        own_image,
                    });
                }
            }
            Err(e) => out.skipped.push((p.clone(), e.to_string())),
        }
    }
}

pub fn scan_files(paths: &[PathBuf], dir: Option<&Path>) -> Outcome {
    scan_files_as(paths, dir, own_image())
}

fn scan_files_as(paths: &[PathBuf], dir: Option<&Path>, own: Option<(u64, u64)>) -> Outcome {
    let mut out = Outcome::default();
    match compile(dir) {
        Ok((rules, rule_count, problems)) => {
            out.rules = rule_count;
            for p in problems {
                out.skipped.push((PathBuf::from("<rules>"), p));
            }
            scan(&rules, paths, own, &mut out);
        }
        Err(e) => out.unavailable = Some(e),
    }
    out
}

pub fn rules_dir(override_: Option<&str>) -> Option<PathBuf> {
    let p = PathBuf::from(override_.unwrap_or(RULES_DIR));
    p.is_dir().then_some(p)
}
