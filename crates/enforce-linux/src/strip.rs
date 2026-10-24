use std::ffi::{CStr, CString};
use std::fs;
use std::io::{Read as _, Seek as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::guards::ProtectSet;
use crate::outcome::{
    ApplyOptions, Failure, Outcome, Plan, RefuseCause, Refusal, UndoKind, UndoRecord,
};
use crate::paths::{ensure_vault, path_refusal, pin_parent, vault_dest, Pinned};

const MAX_BYTES: u64 = hemostat_sensor_linux::saferead::MAX_SCAN_BYTES;

const CHECK_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);

const VISUDO: &[&str] = &["/usr/sbin/visudo", "/sbin/visudo", "/usr/bin/visudo"];

const SSHD: &[&str] = &["/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"];

const SSH_CA_FILES: &[&str] =
    &["/etc/ssh/trusted_user_ca_keys", "/etc/ssh/ca.pub", "/etc/ssh/authorized_principals"];

const NEVER: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/fstab",
    "/etc/crypttab",
];

const LOGIN_PROFILES: &[&str] = &["/etc/profile", "/etc/bash.bashrc", "/etc/bashrc"];

const ADMIN_GROUPS: &[&str] = &["sudo", "wheel", "admin"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineRef {

    pub line_no: usize,

    pub line_sha256: [u8; 32],

    pub file_sha256: [u8; 32],
}

impl LineRef {

    pub fn token(&self, path: &Path) -> String {
        format!(
            "{}:{}:{}:{}",
            path.display(),
            self.line_no,
            hex(&self.line_sha256),
            hex(&self.file_sha256)
        )
    }

    pub fn parse(token: &str) -> Result<(PathBuf, LineRef), String> {
        let bad = || {
            format!(
                "{token:?} is not a line token (PATH:LINE:LINE-SHA256:FILE-SHA256, as \
                 `remediate --lines PATH` prints it)"
            )
        };
        let mut it = token.rsplitn(4, ':');
        let file = it.next().and_then(unhex32).ok_or_else(bad)?;
        let line = it.next().and_then(unhex32).ok_or_else(bad)?;
        let line_no = it.next().and_then(|n| n.parse::<usize>().ok()).filter(|n| *n > 0).ok_or_else(bad)?;
        let path = it.next().filter(|p| p.starts_with('/')).ok_or_else(bad)?;
        Ok((PathBuf::from(path), LineRef { line_no, line_sha256: line, file_sha256: file }))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StripAuthority {

    pub auth: bool,

    pub operator_keys: Vec<String>,

    pub session_key_unknown: bool,

    pub last_admin_key: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {

    Shared,

    Sudoers {

        main: bool,
    },

    AuthorizedKeys,

    SshCa,

    Pam,

    Sshd {

        main: bool,
    },
}

impl FileKind {

    pub fn of(path: &Path) -> Option<FileKind> {
        if !path.is_absolute()
            || !path.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        {
            return None;
        }
        let s = path.to_str()?;
        let parent = path.parent()?;
        let name = path.file_name()?.to_str()?;
        if s == "/etc/sudoers" {
            return Some(FileKind::Sudoers { main: true });
        }
        if parent == Path::new("/etc/sudoers.d") {
            return Some(FileKind::Sudoers { main: false });
        }
        if parent == Path::new("/etc/pam.d") {
            return Some(FileKind::Pam);
        }
        if s == "/etc/ssh/sshd_config" {
            return Some(FileKind::Sshd { main: true });
        }
        if parent == Path::new("/etc/ssh/sshd_config.d") {
            return Some(FileKind::Sshd { main: false });
        }
        if SSH_CA_FILES.contains(&s) {
            return Some(FileKind::SshCa);
        }
        if matches!(name, "authorized_keys" | "authorized_keys2")
            && parent.file_name().is_some_and(|n| n == ".ssh")
        {
            return Some(FileKind::AuthorizedKeys);
        }

        if s.starts_with("/etc/ssh/")
            || s.starts_with("/etc/sudoers")
            || s.starts_with("/etc/pam.d/")
            || s.starts_with("/etc/hemostat/")
            || NEVER.contains(&s)
        {
            return None;
        }
        ["/etc/", "/var/spool/cron/", "/var/spool/incron/", "/root/", "/home/"]
            .iter()
            .any(|p| s.starts_with(p))
            .then_some(FileKind::Shared)
    }

    pub fn is_auth(self) -> bool {
        !matches!(self, FileKind::Shared)
    }

    pub fn label(self) -> &'static str {
        match self {
            FileKind::Shared => "a shared configuration file",
            FileKind::Sudoers { main: true } => "the sudoers policy",
            FileKind::Sudoers { main: false } => "a sudoers drop-in",
            FileKind::AuthorizedKeys => "an authorized_keys file",
            FileKind::SshCa => "an SSH certificate-authority list",
            FileKind::Pam => "a PAM stack",
            FileKind::Sshd { main: true } => "the sshd configuration",
            FileKind::Sshd { main: false } => "an sshd drop-in",
        }
    }
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

fn spans(bytes: &[u8]) -> Vec<(usize, usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'\n' {
            out.push((start, i, i + 1));
            start = i + 1;
        }
    }
    if start < bytes.len() {
        out.push((start, bytes.len(), bytes.len()));
    }
    out
}

fn content(bytes: &[u8], span: (usize, usize, usize)) -> &[u8] {
    bytes.get(span.0..span.1).unwrap_or_default()
}

fn continues(line: &[u8]) -> bool {
    line.iter().rev().find(|b| !b.is_ascii_whitespace()) == Some(&b'\\')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {

    pub line_no: usize,

    pub start: usize,

    pub end: usize,

    pub text: String,
}

pub fn locate(bytes: &[u8], want: &LineRef) -> Result<Located, String> {
    if sha256(bytes) != want.file_sha256 {
        return Err(format!(
            "the file changed since the line was offered (it hashes to {}, the offer was made \
             from {}). Look at it again and choose the line from what is there now",
            hex(&sha256(bytes)),
            hex(&want.file_sha256)
        ));
    }
    let sp = spans(bytes);
    let hits: Vec<usize> = sp
        .iter()
        .enumerate()
        .filter(|(_, s)| sha256(content(bytes, **s)) == want.line_sha256)
        .map(|(i, _)| i)
        .collect();
    let i = match hits.as_slice() {
        [] => return Err("the chosen line is not in the file".into()),
        [one] => *one,
        many => {
            return Err(format!(
                "the chosen line occurs {} times (lines {}), so which one is meant is not \
                 something this will guess. Edit the file by hand",
                many.len(),
                many.iter().map(|i| (i + 1).to_string()).collect::<Vec<_>>().join(", ")
            ))
        }
    };
    if i + 1 != want.line_no {
        return Err(format!(
            "the chosen line is line {} of the file, and the offer said line {}. The position is \
             a check, never the selector, and a token whose two halves disagree was not made \
             from this file",
            i + 1,
            want.line_no
        ));
    }
    let Some(&span) = sp.get(i) else { return Err("the chosen line is not in the file".into()) };
    let line = content(bytes, span);
    if line.iter().all(u8::is_ascii_whitespace) {
        return Err("the chosen line is blank".into());
    }
    let prev_continues = i.checked_sub(1).and_then(|p| sp.get(p)).is_some_and(|s| continues(content(bytes, *s)));
    if continues(line) || prev_continues {
        return Err(
            "the chosen line is part of a line continued with `\\`, so removing it alone changes \
             what the lines around it mean. Edit the file by hand"
                .into(),
        );
    }
    Ok(Located {
        line_no: i + 1,
        start: span.0,
        end: span.2,
        text: String::from_utf8_lossy(line).into_owned(),
    })
}

pub fn without(bytes: &[u8], loc: &Located) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(bytes.get(..loc.start).unwrap_or_default());
    out.extend_from_slice(bytes.get(loc.end..).unwrap_or_default());
    out
}

fn has_directives(bytes: &[u8]) -> bool {
    String::from_utf8_lossy(bytes).lines().map(str::trim).any(|l| {
        !l.is_empty() && (!l.starts_with('#') || l.starts_with("#include"))
    })
}

fn needs_content(path: &Path, kind: FileKind) -> bool {
    match kind {
        FileKind::Sudoers { main } | FileKind::Sshd { main } => main,
        FileKind::Pam => true,
        FileKind::Shared => path.to_str().is_some_and(|s| LOGIN_PROFILES.contains(&s)),
        FileKind::AuthorizedKeys | FileKind::SshCa => false,
    }
}

pub fn pam_auth_lines(bytes: &[u8]) -> usize {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| {
            let mut t = l.split_whitespace();
            match t.next() {
                Some("@include") => t.next().is_some_and(|s| s.contains("auth")),
                Some(ty) => ty.trim_start_matches('-').eq_ignore_ascii_case("auth"),
                None => false,
            }
        })
        .count()
}

pub fn result_refusal(path: &Path, kind: FileKind, before: &[u8], after: &[u8]) -> Option<String> {
    if needs_content(path, kind) && !has_directives(after) {
        return Some(format!(
            "removing it leaves {} with nothing in it, and {} with nothing in it is a lockout or a \
             host that stops behaving, not a cleaned file",
            path.display(),
            kind.label()
        ));
    }
    if kind == FileKind::Pam && pam_auth_lines(before) > 0 && pam_auth_lines(after) == 0 {
        return Some(
            "it is the last `auth` line in this PAM stack. A stack with no auth line fails every \
             authentication through it — sshd, sudo, login — which locks out the responder as \
             surely as the attacker. Replace the module by hand instead"
                .into(),
        );
    }
    None
}

const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

fn is_key_type(t: &str) -> bool {
    KEY_TYPES.contains(&t) || t.ends_with("-cert-v01@openssh.com")
}

fn split_options(line: &str) -> (&str, &str) {
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => quoted = !quoted,
            ' ' | '\t' if !quoted => return (line.get(..i).unwrap_or(""), line.get(i..).unwrap_or("").trim_start()),
            _ => {}
        }
    }
    (line, "")
}

pub fn key_of(line: &str) -> Option<(String, String, String)> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let mut rest = t;
    for _ in 0..3 {
        let mut it = rest.split_whitespace();
        let first = it.next()?;
        if is_key_type(first) {
            let blob = it.next()?.to_string();
            let comment = it.collect::<Vec<_>>().join(" ");
            return Some((first.to_string(), blob, comment));
        }
        rest = if first.starts_with('@') {
            rest.get(first.len()..)?.trim_start()
        } else {
            split_options(rest).1
        };
        if rest.is_empty() {
            return None;
        }
    }
    None
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn b64_nopad(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in b.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, &x)| acc | (u32::from(x) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            let idx = ((n >> (18 - 6 * i)) & 63) as usize;
            out.push(char::from(A.get(idx).copied().unwrap_or(b'A')));
        }
    }
    out
}

pub fn fingerprint(blob: &str) -> Option<String> {
    let raw = b64_decode(blob)?;
    Some(format!("SHA256:{}", b64_nopad(&sha256(&raw))))
}

fn key_count(bytes: &[u8]) -> usize {
    String::from_utf8_lossy(bytes).lines().filter(|l| key_of(l).is_some()).count()
}

pub fn parse_operator_keys(flags: &[String], env: Option<&str>) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = flags.to_vec();
    if out.is_empty() {
        out.extend(env.unwrap_or_default().split([',', ' ']).filter(|s| !s.is_empty()).map(str::to_string));
    }
    for k in &out {
        let b = k.strip_prefix("SHA256:").unwrap_or("");
        if b.len() != 43 || !b.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/') {
            return Err(format!(
                "{k:?} is not an OpenSSH SHA256 fingerprint; `ssh-keygen -lf KEY.pub` prints the one to name"
            ));
        }
    }
    Ok(out)
}

pub fn session_key_fingerprints() -> Vec<String> {
    let Ok(p) = std::env::var("SSH_USER_AUTH") else { return Vec::new() };
    let Ok(text) = hemostat_sensor_linux::saferead::read_text(Path::new(&p)) else { return Vec::new() };
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("publickey "))
        .filter_map(|k| key_of(k).and_then(|(_, blob, _)| fingerprint(&blob)))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {

    pub name: String,

    pub uid: u32,

    pub gid: u32,

    pub home: PathBuf,
}

pub fn parse_passwd(text: &str) -> Vec<Account> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            Some(Account {
                name: (*f.first()?).to_string(),
                uid: f.get(2)?.parse().ok()?,
                gid: f.get(3)?.parse().ok()?,
                home: PathBuf::from(f.get(5)?),
            })
        })
        .collect()
}

pub fn admins(accounts: &[Account], group_text: &str) -> Vec<String> {
    let mut out: Vec<String> = accounts.iter().filter(|a| a.uid == 0).map(|a| a.name.clone()).collect();
    for l in group_text.lines() {
        let f: Vec<&str> = l.split(':').collect();
        let (Some(name), Some(gid)) = (f.first(), f.get(2).and_then(|g| g.parse::<u32>().ok())) else { continue };
        if !ADMIN_GROUPS.contains(name) {
            continue;
        }
        let members = f.get(3).copied().unwrap_or("").split(',').map(str::trim).filter(|m| !m.is_empty());
        out.extend(members.map(str::to_string));
        out.extend(accounts.iter().filter(|a| a.gid == gid).map(|a| a.name.clone()));
    }
    out.sort();
    out.dedup();
    out
}

pub fn owner_of<'a>(path: &Path, accounts: &'a [Account]) -> Option<&'a Account> {
    let ssh = path.parent()?;
    let home = ssh.parent()?;
    accounts.iter().find(|a| a.home == home)
}

#[allow(clippy::too_many_arguments)]
pub fn key_refusal(
    fp: Option<&str>,
    authority: &StripAuthority,
    owner_is_operator: bool,
    in_ssh: bool,
    owner_is_admin: bool,
    keys_left_here: usize,
    other_admin_keys: usize,
) -> Option<String> {
    if let Some(fp) = fp {
        if authority.operator_keys.iter().any(|k| k == fp) {
            return Some(format!(
                "{fp} is the operator's own key — the one this session authenticated with, or one \
                 the operator enrolled as theirs. Removing it is how a responder cuts themselves \
                 off the host, and there is no flag for it"
            ));
        }
    }
    if owner_is_operator && in_ssh && authority.operator_keys.is_empty() && !authority.session_key_unknown {
        return Some(
            "this is the authorized_keys of the account you are logged in as, and this run cannot \
             tell which key your SSH session used: sshd does not record it in the session, and \
             sudo resets the environment that would (`$SSH_USER_AUTH`, with ExposeAuthInfo). \
             Name your key with --operator-key SHA256:… (`ssh-keygen -lf KEY.pub`), or pass \
             --session-key-unknown to say you have checked this is not it"
                .into(),
        );
    }
    if owner_is_admin && keys_left_here == 0 && other_admin_keys == 0 && !authority.last_admin_key {
        return Some(
            "it is the last key of the only administrator with any, so after it no administrator \
             can log in with a key. If that is what you mean — a password or the console is \
             your way back — pass --last-admin-key"
                .into(),
        );
    }
    None
}

fn in_ssh_session() -> bool {
    if std::env::var("SSH_CONNECTION").is_ok_and(|v| !v.trim().is_empty()) {
        return true;
    }
    crate::guards::session_chain(std::process::id()).into_iter().any(|pid| {
        hemostat_sensor_linux::saferead::read_scan_target(Path::new(&format!("/proc/{pid}/comm")))
            .is_some_and(|c| c.trim().starts_with("sshd"))
    })
}

fn other_admin_keys(exclude_owner: &str, accounts: &[Account], admin_names: &[String]) -> usize {
    accounts
        .iter()
        .filter(|a| a.name != exclude_owner && admin_names.contains(&a.name))
        .flat_map(|a| ["authorized_keys", "authorized_keys2"].map(|n| a.home.join(".ssh").join(n)))
        .filter_map(|p| hemostat_sensor_linux::saferead::read_bytes(&p, MAX_BYTES).ok())
        .map(|b| key_count(&b))
        .sum()
}

fn host_key_refusal(path: &Path, line: &str, after: &[u8], authority: &StripAuthority) -> Option<String> {
    let fp = key_of(line).and_then(|(_, blob, _)| fingerprint(&blob));
    let accounts = hemostat_sensor_linux::saferead::read_text(Path::new("/etc/passwd"))
        .map(|t| parse_passwd(&t))
        .unwrap_or_default();
    let groups = hemostat_sensor_linux::saferead::read_text(Path::new("/etc/group")).unwrap_or_default();
    let admin_names = admins(&accounts, &groups);
    let owner = owner_of(path, &accounts);
    let operator = crate::account::operator_uids();
    let owner_is_operator = owner.is_none_or(|a| operator.contains(&a.uid));
    let owner_is_admin = owner.is_some_and(|a| admin_names.contains(&a.name));
    let others = owner.map_or(0, |a| other_admin_keys(&a.name, &accounts, &admin_names));

    let left = if fp.is_some() { key_count(after) } else { usize::MAX };
    key_refusal(fp.as_deref(), authority, owner_is_operator, in_ssh_session(), owner_is_admin, left, others)
}

pub(crate) fn vouched_tool(candidates: &[&str]) -> Result<PathBuf, String> {
    let path = candidates
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .ok_or_else(|| format!("none of {} exists", candidates.join(", ")))?;
    let f = crate::paths::open_unredirected(&path)
        .map_err(|e| format!("{} could not be opened without being redirected: {e}", path.display()))?;
    let md = f.metadata().map_err(|e| format!("{}: {e}", path.display()))?;
    if !md.is_file() || md.uid() != 0 || md.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is not a root-owned file only root can write (uid {}, mode {:o})",
            path.display(),
            md.uid(),
            md.mode() & 0o7777
        ));
    }
    let pm = hemostat_sensor_linux::pkg::manager().ok_or_else(|| {
        format!("no package manager here to vouch for {}, so its answer is not trusted", path.display())
    })?;
    let pkg = pm
        .owner(&path)
        .ok_or_else(|| format!("no package owns {}, so it is not the distribution's", path.display()))?;
    let real = path.canonicalize().ok();
    if pm.drift(&pkg).iter().any(|d| d.path == path || real.as_deref() == Some(d.path.as_path())) {
        return Err(format!(
            "{} no longer matches what {pkg} shipped, so its verdict on a privilege file is not \
             one to act on",
            path.display()
        ));
    }
    Ok(path)
}

pub(crate) fn reopen(f: &fs::File) -> Result<fs::File, String> {
    fs::File::open(format!("/proc/self/fd/{}", f.as_raw_fd())).map_err(|e| format!("could not reopen the candidate: {e}"))
}

fn visudo_check(bin: &Path, candidate: Option<fs::File>) -> Result<(), String> {
    let mut cmd = std::process::Command::new(bin);
    cmd.env_clear().env("LC_ALL", "C").arg("-c");
    let stdin = match candidate {
        Some(f) => {
            cmd.args(["-f", "/proc/self/fd/0"]);
            std::process::Stdio::from(f)
        }
        None => std::process::Stdio::null(),
    };
    match hemostat_sensor_linux::sshd::output_within(&mut cmd, stdin, CHECK_LIMIT) {
        Ok(Some(o)) if o.status.success() => Ok(()),
        Ok(Some(o)) => {
            let mut why = String::from_utf8_lossy(&o.stderr).trim().to_string();
            if why.is_empty() {
                why = String::from_utf8_lossy(&o.stdout).trim().to_string();
            }
            Err(if why.is_empty() { format!("visudo -c exited {}", o.status) } else { why })
        }
        Ok(None) => Err(format!("visudo -c had not answered after {} seconds", CHECK_LIMIT.as_secs())),
        Err(e) => Err(format!("could not run {}: {e}", bin.display())),
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Validator {
    Visudo(PathBuf),
    Sshd(PathBuf),
}

impl Validator {
    fn for_kind(kind: FileKind) -> Result<Option<Validator>, String> {
        Ok(match kind {
            FileKind::Sudoers { .. } => Some(Validator::Visudo(vouched_tool(VISUDO)?)),
            FileKind::Sshd { .. } => Some(Validator::Sshd(vouched_tool(SSHD)?)),
            _ => None,
        })
    }

    fn name(&self) -> &'static str {
        match self {
            Validator::Visudo(_) => "visudo -c -f",
            Validator::Sshd(_) => "sshd -t -f",
        }
    }

    fn check(&self, candidate: &fs::File) -> Result<(), String> {
        let f = reopen(candidate)?;
        match self {
            Validator::Visudo(b) => visudo_check(b, Some(f)),
            Validator::Sshd(b) => hemostat_sensor_linux::sshd::check_config(b, f),
        }
    }

    fn check_live(&self) -> Result<(), String> {
        match self {
            Validator::Visudo(b) => visudo_check(b, None),
            Validator::Sshd(b) => {
                let main = fs::File::open("/etc/ssh/sshd_config").map_err(|e| format!("/etc/ssh/sshd_config: {e}"))?;
                hemostat_sensor_linux::sshd::check_config(b, main)
            }
        }
    }
}

fn memfd_with(bytes: &[u8], mode: u32) -> Result<fs::File, String> {

    let fd = unsafe { libc::memfd_create(c"hemostat-strip".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(format!("memfd_create: {}", std::io::Error::last_os_error()));
    }

    let mut f = unsafe { fs::File::from_raw_fd(fd) };
    f.write_all(bytes).map_err(|e| format!("writing the candidate: {e}"))?;
    use std::os::unix::fs::PermissionsExt as _;
    f.set_permissions(fs::Permissions::from_mode(mode & 0o7777)).map_err(|e| format!("candidate mode: {e}"))?;
    f.rewind().map_err(|e| e.to_string())?;
    Ok(f)
}

pub(crate) struct Read {
    pub(crate) pinned: Pinned,
    pub(crate) file: fs::File,
    pub(crate) md: fs::Metadata,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) fn read_for_edit(path: &Path) -> Result<Read, String> {
    let pinned = pin_parent(path)?;
    let mut file = pinned.open(libc::O_RDONLY | libc::O_NONBLOCK, 0).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            "it is a symlink, which is refused outright rather than followed".to_string()
        } else {
            e.to_string()
        }
    })?;
    let md = file.metadata().map_err(|e| e.to_string())?;
    if !md.is_file() {
        return Err("it is not a regular file".into());
    }
    if md.nlink() != 1 {
        return Err(format!(
            "it has {} hard links. The same bytes are reachable by another name, so a rewrite \
             here leaves the other name holding the line, and a rewrite of the other name is \
             what this would be made to do by whoever made the link",
            md.nlink()
        ));
    }
    if md.len() > MAX_BYTES {
        return Err(format!("it is {} bytes, past the {MAX_BYTES}-byte cap the sweep reads", md.len()));
    }
    let mut bytes = Vec::new();
    (&mut file).take(MAX_BYTES + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("it grew past the read cap while being read".into());
    }
    Ok(Read { pinned, file, md, bytes })
}

fn copy_xattrs(from: &fs::File, to: &fs::File) -> Result<(), String> {
    fn names(fd: libc::c_int) -> Result<Vec<CString>, String> {

        let n = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            return if e.raw_os_error() == Some(libc::ENOTSUP) { Ok(Vec::new()) } else { Err(e.to_string()) };
        }
        let mut buf = vec![0u8; usize::try_from(n).unwrap_or(0)];

        let n = unsafe { libc::flistxattr(fd, buf.as_mut_ptr().cast(), buf.len()) };
        let n = usize::try_from(n).map_err(|_| std::io::Error::last_os_error().to_string())?;
        buf.truncate(n);
        Ok(buf.split(|b| *b == 0).filter(|s| !s.is_empty()).filter_map(|s| CString::new(s).ok()).collect())
    }
    fn value(fd: libc::c_int, name: &CStr) -> Result<Vec<u8>, String> {

        let n = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
        let n = usize::try_from(n).map_err(|_| std::io::Error::last_os_error().to_string())?;
        let mut buf = vec![0u8; n];

        let n = unsafe { libc::fgetxattr(fd, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        let n = usize::try_from(n).map_err(|_| std::io::Error::last_os_error().to_string())?;
        buf.truncate(n);
        Ok(buf)
    }
    let src = names(from.as_raw_fd())?;
    for name in &src {
        let v = value(from.as_raw_fd(), name).map_err(|e| format!("reading {}: {e}", name.to_string_lossy()))?;

        let rc = unsafe { libc::fsetxattr(to.as_raw_fd(), name.as_ptr(), v.as_ptr().cast(), v.len(), 0) };
        if rc != 0 {
            return Err(format!(
                "could not carry the extended attribute {} across: {}",
                name.to_string_lossy(),
                std::io::Error::last_os_error()
            ));
        }
    }
    for extra in names(to.as_raw_fd())?.iter().filter(|n| !src.contains(n)) {

        let rc = unsafe { libc::fremovexattr(to.as_raw_fd(), extra.as_ptr()) };
        if rc != 0 {
            return Err(format!(
                "the new file carries {} and the original does not, and it could not be removed: {}",
                extra.to_string_lossy(),
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Meta {
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

pub(crate) fn replace(
    r: &Read,
    content: &[u8],
    meta: Meta,
    validator: Option<&Validator>,
    expect_sha: &[u8; 32],
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = r.pinned.dir_fd();
    let base: String = r.pinned.name().to_string_lossy().chars().take(100).collect();
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());

    let tmp = CString::new(format!(".{base}.hemostat-strip.{}.{nonce}", std::process::id()))
        .map_err(|_| "the temporary name has a NUL in it".to_string())?;

    let fd = unsafe {
        libc::openat(
            dir,
            tmp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(format!("could not create the replacement: {}", std::io::Error::last_os_error()));
    }

    let mut out = unsafe { fs::File::from_raw_fd(fd) };
    let unlink = || {

        unsafe { libc::unlinkat(dir, tmp.as_ptr(), 0) };
    };
    let result = (|| -> Result<(), String> {
        out.write_all(content).map_err(|e| format!("writing the replacement: {e}"))?;

        if unsafe { libc::fchown(out.as_raw_fd(), meta.uid, meta.gid) } != 0 {
            return Err(format!(
                "could not give the replacement owner {}:{}: {}",
                meta.uid,
                meta.gid,
                std::io::Error::last_os_error()
            ));
        }

        out.set_permissions(fs::Permissions::from_mode(meta.mode & 0o7777))
            .map_err(|e| format!("could not give the replacement mode {:o}: {e}", meta.mode & 0o7777))?;
        copy_xattrs(&r.file, &out)?;
        out.sync_all().map_err(|e| format!("syncing the replacement: {e}"))?;
        if let Some(v) = validator {
            v.check(&out).map_err(|e| format!("{} rejected the result, so nothing was changed: {e}", v.name()))?;
        }

        let now = r.pinned.stat().map_err(|e| format!("the original vanished: {e}"))?;
        if now.st_ino != r.md.ino() || now.st_dev != r.md.dev() {
            return Err("the name now points at a different file than the one read".into());
        }
        let mut again = Vec::new();
        reopen(&r.file)?.take(MAX_BYTES + 1).read_to_end(&mut again).map_err(|e| e.to_string())?;
        if sha256(&again) != *expect_sha {
            return Err("the file was changed while the edit was being prepared".into());
        }

        if unsafe { libc::renameat(dir, tmp.as_ptr(), dir, r.pinned.name().as_ptr()) } != 0 {
            return Err(format!("rename failed: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    })();
    if result.is_err() {
        unlink();
        return result;
    }

    let dfd = unsafe { libc::openat(dir, c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if dfd >= 0 {

        let d = unsafe { fs::File::from_raw_fd(dfd) };
        let _ = d.sync_all();
    }
    Ok(())
}

pub(crate) fn snapshot(path: &Path, bytes: &[u8], vault_dir: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    ensure_vault(vault_dir)?;
    let dest = vault_dest(vault_dir, path);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&dest)
        .map_err(|e| format!("could not snapshot into the vault: {e}"))?;
    f.write_all(bytes).and_then(|()| f.sync_all()).map_err(|e| format!("could not snapshot into the vault: {e}"))?;
    if let Ok(d) = fs::File::open(vault_dir) {
        let _ = d.sync_all();
    }
    Ok(dest)
}

pub fn line_diff(from: &[u8], to: &[u8]) -> String {
    let a: Vec<&str> = std::str::from_utf8(from).map(|s| s.lines().collect()).unwrap_or_default();
    let b: Vec<&str> = std::str::from_utf8(to).map(|s| s.lines().collect()).unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    if a.len().saturating_mul(b.len()) > 4_000_000 {
        out.extend(a.iter().filter(|l| !b.contains(l)).map(|l| format!("- {l}")));
        out.extend(b.iter().filter(|l| !a.contains(l)).map(|l| format!("+ {l}")));
    } else {

        let (n, m) = (a.len(), b.len());
        let mut t = vec![0u32; (n + 1) * (m + 1)];
        let at = |i: usize, j: usize| i * (m + 1) + j;
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                let v = if a.get(i) == b.get(j) {
                    t.get(at(i + 1, j + 1)).copied().unwrap_or(0) + 1
                } else {
                    t.get(at(i + 1, j)).copied().unwrap_or(0).max(t.get(at(i, j + 1)).copied().unwrap_or(0))
                };
                if let Some(c) = t.get_mut(at(i, j)) {
                    *c = v;
                }
            }
        }
        let (mut i, mut j) = (0usize, 0usize);
        while i < n || j < m {
            let down = t.get(at(i + 1, j)).copied().unwrap_or(0);
            let right = t.get(at(i, j + 1)).copied().unwrap_or(0);
            if i < n && j < m && a.get(i) == b.get(j) {
                i += 1;
                j += 1;
            } else if j < m && (i >= n || right >= down) {
                out.push(format!("+ {}", b.get(j).copied().unwrap_or("")));
                j += 1;
            } else {
                out.push(format!("- {}", a.get(i).copied().unwrap_or("")));
                i += 1;
            }
        }
    }
    if out.len() > 200 {
        let more = out.len() - 200;
        out.truncate(200);
        out.push(format!("… and {more} more line(s)"));
    }
    if out.is_empty() {
        "(no line differs; the bytes do — line endings or a final newline)".into()
    } else {
        out.join("\n")
    }
}

fn refused(summary: &str, path: &Path, why: impl Into<String>) -> Outcome {
    let why = why.into();
    Outcome::Refused(Refusal {
        action: summary.to_string(),
        cause: RefuseCause::InvalidTarget(why.clone()),
        message: format!("refused to strip a line from {}: {why}", path.display()),
        suggested_alternative: None,
    })
}

fn failed(summary: &str, reason: impl Into<String>) -> Outcome {
    Outcome::Failed(Failure { action: summary.to_string(), reason: reason.into() })
}

pub(crate) fn plan(path: &Path, want: &LineRef, summary: String) -> Plan {
    let kind = FileKind::of(path);
    let check = match kind {
        Some(FileKind::Sudoers { .. }) => " The result must pass `visudo -c` before it replaces the file, and the whole policy is checked again after; a policy that parsed before and not after is put back at once.",
        Some(FileKind::Sshd { .. }) => " The result must pass `sshd -t` before it replaces the file, and the whole configuration is checked again after. sshd is NOT reloaded: the running daemon keeps its configuration until you reload it.",
        Some(FileKind::Pam) => " A PAM stack that authenticated must still have an `auth` line.",
        Some(FileKind::AuthorizedKeys) => " The operator's own key and the last key of the only administrator are refused.",
        _ => "",
    };
    Plan {
        summary,
        detail: format!(
            "Snapshot {} ({}) into the vault, then rewrite it without line {} — matched by its \
             SHA-256 and checked against the file's digest when it was offered, never by position \
             alone — through a new file in the same directory with the same owner, mode and \
             extended attributes, synced and renamed into place.{check}",
            path.display(),
            kind.map_or("a file this does not edit", FileKind::label),
            want.line_no
        ),
        undo: "Put the vault copy back — only while the file is exactly as the strip left it; \
               anything else is refused with a diff. A login or privilege file needs `hemostat \
               undo <journal> --auth`."
            .into(),
        reversible: true,
        prefer_instead: None,
    }
}

pub(crate) fn apply(
    summary: String,
    path: &Path,
    want: &LineRef,
    authority: &StripAuthority,
    opts: &ApplyOptions,
    protect: &ProtectSet,
) -> Outcome {
    if let Some(reason) = protect.path_reason(path) {
        return Outcome::Refused(Refusal {
            action: summary,
            message: format!("refused to edit {}: {}", path.display(), reason.describe()),
            cause: RefuseCause::Protected(reason),
            suggested_alternative: None,
        });
    }
    if let Some(reason) = path_refusal(path) {
        return refused(&summary, path, reason);
    }
    let Some(kind) = FileKind::of(path) else {
        return refused(
            &summary,
            path,
            "it is not a file this edits a line of — a crontab, a profile, rc.local or a conffile \
             under /etc, a user's dotfile, or (with --auth) sudoers, PAM, sshd and authorized_keys. \
             The account databases, the mount tables, host keys and anything under /usr are not",
        );
    };
    if kind.is_auth() && !authority.auth {
        return refused(
            &summary,
            path,
            format!(
                "it is {}, a login or privilege file. A slip here locks out the responder as easily \
                 as the attacker, so it needs its own flag: pass --auth once you have read the line",
                kind.label()
            ),
        );
    }
    let r = match read_for_edit(path) {
        Ok(r) => r,
        Err(why) => return refused(&summary, path, why),
    };
    let loc = match locate(&r.bytes, want) {
        Ok(l) => l,
        Err(why) => return refused(&summary, path, why),
    };
    let after = without(&r.bytes, &loc);
    if let Some(why) = result_refusal(path, kind, &r.bytes, &after) {
        return refused(&summary, path, why);
    }
    if kind == FileKind::AuthorizedKeys {
        if let Some(why) = host_key_refusal(path, &loc.text, &after, authority) {
            return refused(&summary, path, why);
        }
    }
    if kind == FileKind::SshCa {
        if let Some(fp) = key_of(&loc.text).and_then(|(_, b, _)| fingerprint(&b)) {
            if authority.operator_keys.contains(&fp) {
                return refused(&summary, path, format!("{fp} is a key the operator named as theirs"));
            }
        }
    }
    let validator = match Validator::for_kind(kind) {
        Ok(v) => v,
        Err(why) => {
            return refused(&summary, path, format!("the result cannot be validated, so it is not written: {why}"))
        }
    };
    let meta = Meta { mode: r.md.mode(), uid: r.md.uid(), gid: r.md.gid() };

    if let Some(v) = &validator {
        if let Err(e) = memfd_with(&after, meta.mode).and_then(|f| v.check(&f)) {
            return refused(&summary, path, format!("{} rejects the result: {e}", v.name()));
        }
    }
    if !opts.armed {
        let mut p = plan(path, want, summary.clone());
        if let Some(v) = &validator {
            p.detail.push_str(&format!(" `{}` accepts the result.", v.name()));
        }
        p.detail.push_str(&format!(" The line: `{}`", loc.text));
        return Outcome::Planned(p);
    }

    let live_ok_before = validator.as_ref().map(|v| v.check_live().is_ok());
    let vault = match snapshot(path, &r.bytes, &opts.vault_dir) {
        Ok(v) => v,
        Err(why) => return failed(&summary, why),
    };
    if let Err(why) = replace(&r, &after, meta, validator.as_ref(), &want.file_sha256) {
        let _ = fs::remove_file(&vault);
        return failed(&summary, format!("{why}; {} is unchanged", path.display()));
    }

    if let (Some(v), Some(true)) = (&validator, live_ok_before) {
        if let Err(e) = v.check_live() {
            let put_back = read_for_edit(path)
                .and_then(|now| replace(&now, &r.bytes, meta, None, &sha256(&after)));
            return failed(
                &summary,
                match put_back {
                    Ok(()) => format!(
                        "the whole configuration stopped parsing after the change ({e}), so the \
                         original was put back. {} is as it was",
                        path.display()
                    ),
                    Err(why) => format!(
                        "the whole configuration stopped parsing after the change ({e}) and putting \
                         the original back FAILED ({why}). Restore it by hand NOW from {}",
                        vault.display()
                    ),
                },
            );
        }
    }
    let after_sha = sha256(&after);
    let tail = if matches!(kind, FileKind::Sshd { .. }) {
        " The RUNNING sshd is unchanged; reload it yourself when ready (`systemctl reload ssh` or \
         `sshd`), from a second session you keep open until the first new login works."
    } else {
        ""
    };
    Outcome::Applied(UndoRecord {
        did: format!("removed line {} of {}: `{}`.{tail}", loc.line_no, path.display(), loc.text),
        undo: UndoKind::RestoreStripped {
            vault,
            original: path.to_path_buf(),
            line_no: loc.line_no,
            line_sha256: hex(&want.line_sha256),
            before: hex(&want.file_sha256),
            after: hex(&after_sha),
            mode: meta.mode & 0o7777,
            uid: meta.uid,
            gid: meta.gid,
        },
        reversible: true,
    })
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Recorded<'a> {
    pub(crate) vault: &'a Path,
    pub(crate) original: &'a Path,
    pub(crate) line_no: usize,
    pub(crate) line_sha256: &'a str,
    pub(crate) before: &'a str,
    pub(crate) after: &'a str,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

pub(crate) fn undo(rec: Recorded<'_>, opts: &ApplyOptions, allow_auth: bool) -> Outcome {
    let path = rec.original;
    let summary = format!("restore {} from the vault", path.display());
    let deny = |why: String| {
        Outcome::Refused(Refusal {
            action: summary.clone(),
            cause: RefuseCause::InvalidTarget(why.clone()),
            message: format!("refused to restore {}: {why}", path.display()),
            suggested_alternative: None,
        })
    };
    if let Some(reason) = path_refusal(path) {
        return deny(reason);
    }
    let Some(kind) = FileKind::of(path) else {
        return deny("it is not a file the strip edits, so this record was not written by it".into());
    };
    let (Some(before), Some(after), Some(line_sha)) = (unhex32(rec.before), unhex32(rec.after), unhex32(rec.line_sha256)) else {
        return deny("the record's digests are not digests".into());
    };
    let snap = match hemostat_sensor_linux::saferead::read_bytes(rec.vault, MAX_BYTES) {
        Ok(b) => b,
        Err(e) => return deny(format!("the vault copy {} is unreadable: {e}", rec.vault.display())),
    };
    if sha256(&snap) != before {
        return deny(format!(
            "the vault copy {} is not what was snapshotted — it hashes to {}, the record says {}",
            rec.vault.display(),
            hex(&sha256(&snap)),
            rec.before
        ));
    }

    let want = LineRef { line_no: rec.line_no, line_sha256: line_sha, file_sha256: before };
    let loc = match locate(&snap, &want) {
        Ok(l) if sha256(&without(&snap, &l)) == after => l,
        _ => return deny("the record does not describe one line removed from the vault copy".into()),
    };
    let r = match read_for_edit(path) {
        Ok(r) => r,
        Err(why) => return deny(why),
    };
    if sha256(&r.bytes) != after {
        return deny(format!(
            "it has changed since the strip, so putting the vault copy back would also undo that \
             change. Nothing was written. What the restore would do to it now (- removed, + \
             added):\n{}\nThe vault copy is {}; merge by hand",
            line_diff(&r.bytes, &snap),
            rec.vault.display()
        ));
    }
    if kind.is_auth() && !allow_auth {
        return deny(format!(
            "it is {}, and putting `{}` back into it is granting it again. That is never done from \
             the journal alone — re-run `hemostat undo <journal> --auth` once you have read the line",
            kind.label(),
            loc.text
        ));
    }
    let validator = match Validator::for_kind(kind) {
        Ok(v) => v,
        Err(why) => return deny(format!("the restored file cannot be validated, so it is not written: {why}")),
    };
    let meta = Meta { mode: rec.mode, uid: rec.uid, gid: rec.gid };
    if let Some(v) = &validator {
        if let Err(e) = memfd_with(&snap, meta.mode).and_then(|f| v.check(&f)) {
            return deny(format!("{} rejects the vault copy: {e}", v.name()));
        }
    }
    if !opts.armed {
        return Outcome::Planned(Plan {
            summary,
            detail: format!("Put line {} `{}` back into {}.", loc.line_no, loc.text, path.display()),
            undo: "Strip it again.".into(),
            reversible: true,
            prefer_instead: None,
        });
    }
    if let Err(why) = replace(&r, &snap, meta, validator.as_ref(), &after) {
        return Outcome::Failed(Failure { action: summary, reason: format!("{why}; {} is unchanged", path.display()) });
    }
    Outcome::Applied(UndoRecord {
        did: format!(
            "restored {} from the vault: line {} `{}` is back{}",
            path.display(),
            loc.line_no,
            loc.text,
            if matches!(kind, FileKind::Sshd { .. }) { " (sshd not reloaded)" } else { "" }
        ),
        undo: UndoKind::Irreversible {
            note: format!("the line is back; strip it again if that was wrong (the vault copy is {})", rec.vault.display()),
        },
        reversible: false,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {

    pub path: PathBuf,

    pub kind: FileKind,

    pub line: LineRef,

    pub text: String,

    pub key: Option<String>,
}

impl Offer {

    pub fn token(&self) -> String {
        self.line.token(&self.path)
    }
}

pub fn offers_in(path: &Path, kind: FileKind, bytes: &[u8]) -> Vec<Offer> {
    let file = sha256(bytes);
    spans(bytes)
        .into_iter()
        .enumerate()
        .filter_map(|(i, s)| {
            let line = content(bytes, s);
            let text = String::from_utf8_lossy(line).into_owned();
            let t = text.trim();
            if t.is_empty() || (t.starts_with('#') && !t.starts_with("#include")) {
                return None;
            }
            let key = key_of(&text).map(|(ty, blob, c)| {
                let fp = fingerprint(&blob).unwrap_or_else(|| "undecodable".into());
                if c.is_empty() { format!("{ty} {fp}") } else { format!("{ty} {fp} {c}") }
            });
            Some(Offer {
                path: path.to_path_buf(),
                kind,
                line: LineRef { line_no: i + 1, line_sha256: sha256(line), file_sha256: file },
                text,
                key,
            })
        })
        .collect()
}

pub fn offers(path: &Path) -> Result<Vec<Offer>, String> {
    let kind = FileKind::of(path).ok_or_else(|| format!("{} is not a file this edits a line of", path.display()))?;
    let r = read_for_edit(path)?;
    Ok(offers_in(path, kind, &r.bytes))
}

pub fn quotes(line: &str, quoted: &str) -> bool {
    let (l, q) = (line.trim(), quoted.trim());
    if q.is_empty() {
        return false;
    }
    match q.strip_suffix('…') {
        Some(prefix) => l.starts_with(prefix.trim_end()),
        None => l == q,
    }
}

pub fn offer_for(path: &Path, quoted: &str) -> Option<Offer> {
    let all = offers(path).ok()?;
    let mut hits = all.into_iter().filter(|o| quotes(&o.text, quoted));
    let one = hits.next()?;
    hits.next().is_none().then_some(one)
}
