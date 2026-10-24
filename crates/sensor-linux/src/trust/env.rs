use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::read::{at, resolve};
use super::{BUNDLES, CAPATHS};

pub const VARS: &[&str] = &[
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
    "GIT_SSL_CAPATH",
    "PIP_CERT",
    "AWS_CA_BUNDLE",
    "HTTPLIB2_CA_CERTS",
    "WEBSOCKET_CLIENT_CA_BUNDLE",
    "NIX_SSL_CERT_FILE",
    "CARGO_HTTP_CAINFO",
    "DENO_CERT",
];

const ENV_FILES: &[&str] = &[
    "/etc/environment",
    "/etc/security/pam_env.conf",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "/etc/zshenv",
    "/etc/zsh/zshenv",
    "/etc/zsh/zprofile",
    "/etc/csh.cshrc",
    "/etc/csh.login",
    "/etc/systemd/system.conf",
    "/etc/systemd/user.conf",
];

const ENV_DIRS: &[&str] =
    &["/etc/profile.d", "/etc/environment.d", "/etc/systemd/system.conf.d", "/etc/systemd/user.conf.d"];

const UNIT_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/etc/systemd/user",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

const TOOL_FILES: &[&str] = &["/etc/gitconfig", "/etc/pip.conf", "/etc/xdg/pip/pip.conf", "/etc/npmrc", "/etc/wgetrc", "/etc/apt/apt.conf"];

const TOOL_DIRS: &[&str] = &["/etc/apt/apt.conf.d"];

const HOME_FILES: &[&str] = &[
    ".bashrc",
    ".profile",
    ".bash_profile",
    ".bash_login",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".pam_environment",
    ".gitconfig",
    ".config/git/config",
    ".config/pip/pip.conf",
    ".pip/pip.conf",
    ".npmrc",
    ".curlrc",
    ".wgetrc",
];

const HOME_DIRS: &[&str] = &[".config/environment.d"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {

    pub var: String,

    pub value: String,

    pub target: PathBuf,

    pub at: String,

    pub line: Option<String>,

    pub system: bool,

    pub exists: bool,
}

pub fn who(var: &str) -> &'static str {
    match var {
        "SSL_CERT_FILE" | "SSL_CERT_DIR" => "OpenSSL, and every program linked against it that does not set its own trust (Python's ssl, curl, Ruby, PHP),",
        "REQUESTS_CA_BUNDLE" => "Python programs that use requests",
        "CURL_CA_BUNDLE" => "curl and Python's requests",
        "NODE_EXTRA_CA_CERTS" => "Node.js programs",
        "GIT_SSL_CAINFO" | "GIT_SSL_CAPATH" | "git sslCAInfo" | "git sslCAPath" => "git",
        "PIP_CERT" | "pip cert" => "pip, which installs code,",
        "AWS_CA_BUNDLE" => "the AWS CLI and SDKs",
        "apt CaInfo" | "apt CaPath" => "apt, which installs packages as root,",
        "npm cafile" => "npm, which installs code,",
        "curl cacert" | "curl capath" => "curl run by that account",
        "wget ca_certificate" | "wget ca_directory" => "wget",
        _ => "the programs that read it",
    }
}

pub fn replaces(var: &str) -> &'static str {
    match var {
        "NODE_EXTRA_CA_CERTS" => "It adds to Node's built-in roots rather than replacing them, which is the property an interception CA wants: nothing that worked stops working.",
        _ => "It replaces the system store for them, so a file holding the system's roots and one more passes every look at the store.",
    }
}

pub fn homes(root: &Path) -> Vec<String> {
    let mut out = vec!["/root".to_string()];
    if let Ok(text) = crate::saferead::read_text(&at(root, "/etc/passwd")) {
        for a in crate::accounts::parse_passwd(&text) {
            if !matches!(a.home.as_str(), "" | "/" | "/nonexistent" | "/dev/null") && a.home.starts_with('/') {
                out.push(a.home);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

pub fn quote(line: &str) -> String {
    let t = line.trim();
    if t.chars().count() > 160 {
        format!("{}…", t.chars().take(160).collect::<String>())
    } else {
        t.to_string()
    }
}

fn value_at(s: &str) -> String {
    let s = s.trim_start();
    if let Some(rest) = s.strip_prefix('"') {
        return rest.split('"').next().unwrap_or("").to_string();
    }
    if let Some(rest) = s.strip_prefix('\'') {
        return rest.split('\'').next().unwrap_or("").to_string();
    }
    s.split(|c: char| c.is_whitespace() || c == ';' || c == '"' || c == '\'').next().unwrap_or("").to_string()
}

pub fn env_settings(line: &str) -> Vec<(String, String)> {
    let t = line.trim_start();
    if t.starts_with('#') || t.starts_with(';') {
        return Vec::new();
    }
    let mut out = Vec::new();
    for var in VARS {
        let mut from = 0usize;
        while let Some(off) = t.get(from..).and_then(|s| s.find(var)) {
            let i = from + off;
            from = i + var.len();
            let before = t.get(..i).and_then(|b| b.chars().last());
            if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            let after = t.get(i + var.len()..).unwrap_or("");
            let value = if let Some(v) = after.strip_prefix('=') {
                value_at(v)
            } else if let Some(v) = after.trim_start().strip_prefix("DEFAULT=").or_else(|| after.trim_start().strip_prefix("OVERRIDE=")) {
                value_at(v)
            } else if t.get(..i).is_some_and(|b| b.trim_end().ends_with("setenv")) && after.starts_with(char::is_whitespace) {
                value_at(after)
            } else {
                continue;
            };
            let value = value.trim_end_matches(['"', '\'']).to_string();
            if !value.is_empty() {
                out.push(((*var).to_string(), value));
            }
        }
    }
    out
}

pub fn tool_settings(kind: Tool, line: &str) -> Vec<(String, String)> {
    let t = line.trim();
    if t.starts_with('#') || t.starts_with(';') || t.starts_with("//") {
        return Vec::new();
    }
    let low = t.to_ascii_lowercase();
    let keyed = |keys: &[(&str, &str)]| -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (key, label) in keys {
            let Some(rest) = low.strip_prefix(key) else { continue };
            let rest_orig = t.get(key.len()..).unwrap_or("");
            let r = rest.trim_start();
            if let Some(v) = r.strip_prefix('=') {
                let skip = rest_orig.len() - v.len();
                let v = value_at(rest_orig.get(skip..).unwrap_or(""));
                if !v.is_empty() {
                    out.push(((*label).to_string(), v));
                }
            } else if kind == Tool::Curl && rest.starts_with(char::is_whitespace) {
                let v = value_at(rest_orig);
                if !v.is_empty() {
                    out.push(((*label).to_string(), v));
                }
            }
        }
        out
    };
    match kind {
        Tool::Git => keyed(&[("sslcainfo", "git sslCAInfo"), ("sslcapath", "git sslCAPath")]),
        Tool::Pip => keyed(&[("cert", "pip cert")]),
        Tool::Npm => keyed(&[("cafile", "npm cafile")]),
        Tool::Wget => keyed(&[("ca_certificate", "wget ca_certificate"), ("ca_directory", "wget ca_directory")]),
        Tool::Curl => {
            let l = low.trim_start_matches('-');
            let offset = low.len() - l.len();
            let orig = t.get(offset..).unwrap_or("");
            let mut out = Vec::new();
            for (key, label) in [("cacert", "curl cacert"), ("capath", "curl capath")] {
                if let Some(rest) = l.strip_prefix(key) {
                    let ro = orig.get(key.len()..).unwrap_or("");
                    let r = rest.trim_start();
                    let v = if r.starts_with('=') || r.starts_with(':') {
                        value_at(ro.trim_start().get(1..).unwrap_or(""))
                    } else if rest.starts_with(char::is_whitespace) {
                        value_at(ro)
                    } else {
                        continue;
                    };
                    if !v.is_empty() {
                        out.push((label.to_string(), v));
                    }
                }
            }
            out
        }
        Tool::Apt => {
            let mut out = Vec::new();
            for (key, label) in [("cainfo", "apt CaInfo"), ("capath", "apt CaPath")] {
                if let Some(i) = low.find(key) {
                    let rest = t.get(i + key.len()..).unwrap_or("");
                    let v = value_at(rest.trim_start());
                    if !v.is_empty() {
                        out.push((label.to_string(), v));
                    }
                }
            }
            out
        }
        Tool::None => Vec::new(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {

    Git,

    Pip,

    Npm,

    Curl,

    Wget,

    Apt,

    None,
}

pub fn tool_of(path: &str) -> Tool {
    let name = Path::new(path).file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name == "gitconfig" || name == ".gitconfig" || path.ends_with("/git/config") {
        Tool::Git
    } else if name == "pip.conf" {
        Tool::Pip
    } else if name == "npmrc" || name == ".npmrc" {
        Tool::Npm
    } else if name == ".curlrc" {
        Tool::Curl
    } else if name == "wgetrc" || name == ".wgetrc" {
        Tool::Wget
    } else if path.starts_with("/etc/apt/") {
        Tool::Apt
    } else {
        Tool::None
    }
}

fn target_of(value: &str, home: Option<&str>) -> PathBuf {
    let h = home.unwrap_or("/root");
    let v = if let Some(rest) = value.strip_prefix("~/") {
        format!("{h}/{rest}")
    } else if let Some(rest) = value.strip_prefix("$HOME/").or_else(|| value.strip_prefix("${HOME}/")) {
        format!("{h}/{rest}")
    } else {
        value.to_string()
    };
    PathBuf::from(v)
}

fn is_system(root: &Path, target: &Path) -> bool {
    let Some(t) = resolve(root, &target.to_string_lossy()) else { return false };
    BUNDLES.iter().chain(CAPATHS).any(|b| resolve(root, b).is_some_and(|r| r == t))
}

pub fn scan(root: &Path) -> (Vec<Redirect>, Vec<String>) {
    let mut out: Vec<Redirect> = Vec::new();
    let mut unread: Vec<String> = Vec::new();
    let mut files: Vec<(String, Option<String>)> = Vec::new();
    files.extend(ENV_FILES.iter().chain(TOOL_FILES).map(|f| ((*f).to_string(), None)));
    for d in ENV_DIRS.iter().chain(TOOL_DIRS) {
        files.extend(list(root, d, &mut unread).into_iter().map(|f| (f, None)));
    }

    let mut unit_dirs: Vec<String> = Vec::new();
    for d in UNIT_DIRS {
        if let Some(real) = resolve(root, d) {
            if !unit_dirs.contains(&real) {
                unit_dirs.push(real);
            }
        }
    }
    for d in &unit_dirs {
        for f in list(root, d, &mut unread) {
            if f.ends_with(".d") {
                files.extend(list(root, &f, &mut unread).into_iter().map(|g| (g, None)));
            } else {
                files.push((f, None));
            }
        }
    }
    for h in homes(root) {
        files.extend(HOME_FILES.iter().map(|f| (format!("{}/{f}", h.trim_end_matches('/')), Some(h.clone()))));
        for d in HOME_DIRS {
            let dir = format!("{}/{d}", h.trim_end_matches('/'));
            files.extend(list(root, &dir, &mut unread).into_iter().map(|f| (f, Some(h.clone()))));
        }
    }
    files.sort();
    files.dedup();

    let mut env_files: Vec<String> = Vec::new();
    for (f, home) in &files {
        let text = match crate::saferead::read_text(&at(root, f)) {
            Ok(t) => t,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory) => continue,

            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => continue,
            Err(e) => {
                unread.push(format!("{f}: not read ({e})"));
                continue;
            }
        };
        let tool = tool_of(f);
        for line in text.lines() {
            if let Some(ef) = line.trim().strip_prefix("EnvironmentFile=") {
                let ef = ef.trim().trim_start_matches('-').to_string();
                if ef.starts_with('/') {
                    env_files.push(ef);
                }
            }
            let mut found = env_settings(line);
            found.extend(tool_settings(tool, line));
            for (var, value) in found {
                out.push(redirect(root, var, value, f, Some(quote(line)), home.as_deref()));
            }
        }
    }
    env_files.sort();
    env_files.dedup();
    for f in env_files {
        if let Ok(text) = crate::saferead::read_text(&at(root, &f)) {
            for line in text.lines() {
                for (var, value) in env_settings(line) {
                    out.push(redirect(root, var, value, &f, Some(quote(line)), None));
                }
            }
        }
    }
    let (procs, refused) = processes(root);
    out.extend(procs);
    if refused > 0 {
        unread.push(format!(
            "the environments of {refused} process(es) could not be read, so a setting in force only in a running \
             process would not be seen there; re-run as root"
        ));
    }
    out.dedup();
    (out, unread)
}

fn list(root: &Path, dir: &str, unread: &mut Vec<String>) -> Vec<String> {
    match std::fs::read_dir(at(root, dir)) {
        Ok(rd) => {
            let mut v: Vec<String> =
                rd.flatten().map(|e| format!("{}/{}", dir.trim_end_matches('/'), e.file_name().to_string_lossy())).collect();
            v.sort();
            v.truncate(super::MAX_FILES);
            v
        }
        Err(e) if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory) => Vec::new(),
        Err(e) => {
            unread.push(format!("{dir}: not listed ({e})"));
            Vec::new()
        }
    }
}

fn redirect(root: &Path, var: String, value: String, at_: &str, line: Option<String>, home: Option<&str>) -> Redirect {
    let target = target_of(&value, home);
    let exists = target.is_absolute() && resolve(root, &target.to_string_lossy()).is_some();
    let system = exists && is_system(root, &target);
    Redirect { var, value, target, at: at_.to_string(), line, system, exists }
}

fn processes(root: &Path) -> (Vec<Redirect>, usize) {
    let mut seen: BTreeMap<(String, String), (u32, String, usize)> = BTreeMap::new();
    let mut refused = 0usize;
    let Ok(rd) = std::fs::read_dir(at(root, "/proc")) else { return (Vec::new(), 0) };
    let mut pids: Vec<u32> = rd.flatten().filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok())).collect();
    pids.sort_unstable();
    for pid in pids {
        let env_path = at(root, &format!("/proc/{pid}/environ"));
        let bytes = match crate::saferead::read_proc(&env_path, crate::saferead::MAX_PROC_BYTES) {
            Ok((b, _)) => b,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                refused += 1;
                continue;
            }
            Err(_) => continue,
        };
        let mut comm: Option<String> = None;
        for kv in bytes.split(|b| *b == 0) {
            let kv = String::from_utf8_lossy(kv);
            let Some((k, v)) = kv.split_once('=') else { continue };
            if !VARS.contains(&k) || v.is_empty() {
                continue;
            }
            let c = comm
                .get_or_insert_with(|| {
                    crate::saferead::read_proc(&at(root, &format!("/proc/{pid}/comm")), 256)
                        .map(|(b, _)| String::from_utf8_lossy(&b).trim().to_string())
                        .unwrap_or_default()
                })
                .clone();
            seen.entry((k.to_string(), v.to_string())).and_modify(|e| e.2 += 1).or_insert((pid, c, 1));
        }
    }
    let out = seen
        .into_iter()
        .map(|((var, value), (pid, comm, n))| {
            let at_ = if n > 1 { format!("pid {pid} ({comm}) and {} other process(es)", n - 1) } else { format!("pid {pid} ({comm})") };
            redirect(root, var, value, &at_, None, None)
        })
        .collect();
    (out, refused)
}
