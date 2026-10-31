#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use std::path::PathBuf;

use hemostat_sensor_win::acl::{self, Ace};

const ATTR_DIRECTORY: u32 = 0x10;

const ATTR_REPARSE_POINT: u32 = 0x400;

#[cfg(target_os = "windows")]
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;

#[cfg(target_os = "windows")]
const BACKUP_SEMANTICS: u32 = 0x0200_0000;

pub(crate) fn root() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string())).join("hemostat")
}

pub(crate) struct DirFacts {

    pub(crate) attributes: Option<u32>,

    pub(crate) owner: Result<String, u32>,

    pub(crate) dacl: Result<Vec<Ace>, u32>,
}

pub(crate) fn dacl_refusal(what: &str, dacl: &Result<Vec<Ace>, u32>) -> Option<String> {
    match dacl {
        Err(rc) => Some(format!("the DACL of {what} could not be read (error {rc}), so who can change it is unknown")),
        Ok(aces) => acl::grantee_beyond_admins(aces).map(|sid| {
            format!(
                "{what} grants access to {sid}, not only to SYSTEM and Administrators, so someone other than an \
                 administrator could change what HEMOSTAT keeps there"
            )
        }),
    }
}

pub(crate) fn aside(path: &str, stamp: u64) -> String {
    format!("Move it aside from an elevated prompt, then run this again: move \"{path}\" \"{path}.untrusted-{stamp}\"")
}

pub(crate) fn refusal(dir: &str, f: &DirFacts, session: Option<&str>, stamp: u64) -> Option<String> {
    let Some(attributes) = f.attributes else {
        return Some(format!("{dir} does not exist"));
    };
    let move_it = aside(dir, stamp);
    if attributes & ATTR_REPARSE_POINT != 0 {
        return Some(format!(
            "{dir} is a junction or link (a reparse point), not a directory: what it points at is not the \
             agent's. {move_it}"
        ));
    }
    if attributes & ATTR_DIRECTORY == 0 {
        return Some(format!("{dir} is a file, not a directory. {move_it}"));
    }
    match &f.owner {
        Err(rc) => {
            return Some(format!(
                "the owner of {dir} could not be read (error {rc}), so who controls it is unknown. {move_it}"
            ))
        }
        Ok(sid) if !acl::is_admin_sid(sid) => {
            if session.is_some_and(|me| me.eq_ignore_ascii_case(sid)) && dacl_refusal(dir, &f.dacl).is_none() {
                return Some(format!(
                    "{dir} is owned by your own account ({sid}), not by SYSTEM or Administrators, as an older \
                     HEMOSTAT leaves it on a client edition. Nobody else can write in it, so give it to \
                     Administrators from an elevated prompt, then run this again: takeown /f \"{dir}\" /a /r"
                ));
            }
            return Some(format!(
                "{dir} is owned by {sid}, not by SYSTEM or Administrators. Its owner can rewrite its DACL at any \
                 time, so it is not the agent's to trust — the red team may have made it first. {move_it}"
            ));
        }
        Ok(_) => {}
    }
    dacl_refusal(dir, &f.dacl).map(|why| format!("{why}. {move_it}"))
}

pub(crate) fn component_ok(part: &str) -> bool {
    !part.is_empty() && part != "." && part != ".." && !part.contains(['\\', '/', ':']) && !part.chars().any(char::is_control)
}

fn levels(parts: &[&str]) -> Result<Vec<PathBuf>, String> {
    let mut dir = root();
    let mut out = vec![dir.clone()];
    for p in parts {
        if !component_ok(p) {
            return Err(format!("`{p}` is not one directory name"));
        }
        dir.push(p);
        out.push(dir.clone());
    }
    Ok(out)
}

#[cfg(target_os = "windows")]
fn text(p: &std::path::Path) -> Result<&str, String> {
    p.to_str().ok_or_else(|| format!("{} is not valid Unicode", p.display()))
}

#[cfg(target_os = "windows")]
fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[cfg(target_os = "windows")]
fn facts(dir: &std::path::Path) -> Result<DirFacts, String> {
    use std::os::windows::fs::MetadataExt as _;
    let s = text(dir)?;
    match std::fs::symlink_metadata(dir) {
        Ok(md) => Ok(DirFacts {
            attributes: Some(md.file_attributes()),
            owner: acl::owner_of_read(s),
            dacl: acl::dacl_of_read(s),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(DirFacts { attributes: None, owner: Err(2), dacl: Err(2) })
        }
        Err(e) => Err(format!("{s} could not be examined: {e}. {}", aside(s, now()))),
    }
}

#[cfg(target_os = "windows")]
fn judge(s: &str, f: &DirFacts) -> Option<String> {
    let session = match &f.owner {
        Ok(sid) if !acl::is_admin_sid(sid) => crate::win_accounts::session().map(|me| me.sid),
        _ => None,
    };
    refusal(s, f, session.as_deref(), now())
}

#[cfg(target_os = "windows")]
pub(crate) fn ensure_dir(dir: &std::path::Path) -> Result<(), String> {
    let s = text(dir)?;
    let absent = || std::fs::symlink_metadata(dir).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound);
    if absent() {

        if let Err(e) = acl::create_private_dir(s) {
            if absent() {
                return Err(format!("{e}. It is made from an elevated administrator's shell"));
            }
        }
    }
    match judge(s, &facts(dir)?) {
        None => Ok(()),
        Some(why) => Err(why),
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn ensure(parts: &[&str]) -> Result<PathBuf, String> {
    let levels = levels(parts)?;
    for d in &levels {
        ensure_dir(d)?;
    }
    levels.last().cloned().ok_or_else(|| "no directory was named".to_string())
}

#[cfg(target_os = "windows")]
pub(crate) fn verify(parts: &[&str]) -> Result<Option<PathBuf>, String> {
    let levels = levels(parts)?;
    for d in &levels {
        let f = facts(d)?;
        if f.attributes.is_none() {
            return Ok(None);
        }
        if let Some(why) = judge(text(d)?, &f) {
            return Err(why);
        }
    }
    Ok(levels.last().cloned())
}

#[cfg(target_os = "windows")]
pub(crate) fn private_file(path: &std::path::Path) -> Result<(), String> {
    let s = text(path)?;
    match dacl_refusal(s, &acl::dacl_of_read(s)) {
        None => Ok(()),
        Some(why) => Err(format!("{why}. {}", aside(s, now()))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadError {

    Absent,

    NotRegular(&'static str),

    TooLarge(u64),

    Io(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Absent => f.write_str("it is not there"),
            ReadError::NotRegular(why) => f.write_str(why),
            ReadError::TooLarge(n) => write!(f, "{n} bytes, over the cap"),
            ReadError::Io(e) => f.write_str(e),
        }
    }
}

pub(crate) fn not_regular(attributes: u32, is_file: bool) -> Option<&'static str> {
    if attributes & ATTR_REPARSE_POINT != 0 {
        return Some("a link or other reparse point, not a file");
    }
    if !is_file {
        return Some("not a regular file (a directory or a device)");
    }
    None
}

pub(crate) fn not_appendable(attributes: u32, is_file: bool, links: Result<u32, u32>) -> Option<String> {
    if let Some(why) = not_regular(attributes, is_file) {
        return Some(why.to_string());
    }
    match links {
        Ok(1) => None,
        Ok(n) => Some(format!(
            "one of {n} names for one file (a hard link), so a line written here lands in that file wherever its \
             other name is"
        )),
        Err(rc) => Some(format!("a file whose number of names could not be read (error {rc}), so it may be a hard link")),
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn read_regular(path: &std::path::Path, cap: u64) -> Result<Vec<u8>, ReadError> {
    use std::io::Read as _;
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    let f = match std::fs::OpenOptions::new().read(true).custom_flags(OPEN_REPARSE_POINT | BACKUP_SEMANTICS).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ReadError::Absent),
        Err(e) => return Err(ReadError::Io(e.to_string())),
    };
    let md = f.metadata().map_err(|e| ReadError::Io(e.to_string()))?;
    if let Some(why) = not_regular(md.file_attributes(), md.is_file()) {
        return Err(ReadError::NotRegular(why));
    }
    if md.len() > cap {
        return Err(ReadError::TooLarge(md.len()));
    }
    let mut buf = Vec::new();
    f.take(cap.saturating_add(1)).read_to_end(&mut buf).map_err(|e| ReadError::Io(e.to_string()))?;
    let n = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    if n > cap {
        return Err(ReadError::TooLarge(n));
    }
    Ok(buf)
}

#[cfg(target_os = "windows")]
pub(crate) fn write_atomic(dir: &std::path::Path, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    use std::io::Write as _;
    use std::os::windows::fs::OpenOptionsExt as _;
    if !component_ok(name) {
        return Err(format!("`{name}` is not one file name"));
    }
    let dest = dir.join(name);
    let uniq = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let tmp = dir.join(format!("{name}.{}-{uniq}.tmp", std::process::id()));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(OPEN_REPARSE_POINT)
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(bytes)?;
            f.sync_all()
        });
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{} could not be written: {e}", dest.display()));
    }
    if let Err(e) = std::fs::rename(&tmp, &dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{} could not be put in place: {e}", dest.display()));
    }
    Ok(dest)
}

#[cfg(target_os = "windows")]
pub(crate) fn append_regular(dir: &std::path::Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    if !component_ok(name) {
        return Err(format!("`{name}` is not one file name"));
    }
    let path = dir.join(name);
    let shown = path.display().to_string();

    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .custom_flags(OPEN_REPARSE_POINT | BACKUP_SEMANTICS)
        .open(&path)
        .map_err(|e| format!("{shown} could not be opened without following a link: {e}"))?;
    let md = f.metadata().map_err(|e| format!("{shown} could not be examined: {e}"))?;
    if let Some(why) = not_appendable(md.file_attributes(), md.is_file(), hemostat_sensor_win::localpath::link_count(&f)) {
        return Err(format!("{shown} is {why}; nothing was written to it. {}", aside(&shown, now())));
    }
    f.write_all(bytes).map_err(|e| format!("{shown} could not be appended to: {e}"))
}

pub(crate) const WATCHDOG_BIN: &str = "bin";

pub(crate) const WATCHDOG_EXE: &str = "mahoraga.exe";

pub(crate) const WATCHDOG_WRAPPER: &str = "watchdog.cmd";

pub(crate) const MAX_SELF: u64 = 256 << 20;

pub(crate) const ROLE_ENV: &str = "HEMOSTAT_ROLE";

pub(crate) fn role_ok(role: &str) -> bool {
    !role.is_empty() && role.len() <= 64 && role.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

pub(crate) fn wrapper_body(copy: &str, every: u64, role: Option<&str>) -> Result<String, String> {
    if copy.chars().any(|c| c.is_control() || matches!(c, '"' | '%' | '!' | '^')) {
        return Err(format!(
            "{copy} holds a character cmd.exe would read as syntax; refusing to write a wrapper that runs it"
        ));
    }
    let role_line = match role {
        None => String::new(),
        Some(r) if role_ok(r) => format!("set {ROLE_ENV}={r}\r\n"),
        Some(r) => {
            return Err(format!(
                "{ROLE_ENV}=`{r}` is not a plain word (letters, digits, `-`, `_`, `.`), so it is not written into \
                 the wrapper a SYSTEM task runs. Set it to this box's packet role, or unset it, and run again"
            ))
        }
    };
    Ok(format!(
        "@echo off\r\nset HEMOSTAT_GOLDEN=1\r\n{role_line}\"{copy}\" services --restore --every {every} --arm\r\n"
    ))
}

#[cfg(target_os = "windows")]
pub(crate) struct WatchdogPlan {

    pub(crate) source: PathBuf,

    bytes: Vec<u8>,

    pub(crate) sha: String,

    pub(crate) copy: PathBuf,

    pub(crate) wrapper: PathBuf,

    pub(crate) role: Option<String>,

    body: String,
}

#[cfg(target_os = "windows")]
fn role_env() -> Result<Option<String>, String> {
    match std::env::var_os(ROLE_ENV) {
        None => Ok(None),
        Some(v) => match v.to_str() {
            Some(s) => Ok(Some(s.trim().to_string()).filter(|s| !s.is_empty())),
            None => Err(format!(
                "{ROLE_ENV} is not valid text, so it cannot be carried into the watchdog. Set it to this box's \
                 packet role, or unset it, and run again"
            )),
        },
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn watchdog_plan(every: u64) -> Result<WatchdogPlan, String> {
    let source = std::env::current_exe().map_err(|e| format!("cannot find this binary: {e}"))?;
    let bytes = read_regular(&source, MAX_SELF).map_err(|e| format!("cannot read this binary, {}: {e}", source.display()))?;
    let sha = crate::win_binvault::sha256_hex(&bytes);
    let short = sha.get(..16).unwrap_or(&sha).to_string();
    let copy = root().join(WATCHDOG_BIN).join(&short).join(WATCHDOG_EXE);
    let wrapper = root().join(WATCHDOG_WRAPPER);
    let role = role_env()?;
    let body = wrapper_body(text(&copy)?, every, role.as_deref())?;
    Ok(WatchdogPlan { source, bytes, sha, copy, wrapper, role, body })
}

#[cfg(target_os = "windows")]
pub(crate) fn check_watchdog(plan: &WatchdogPlan) -> Result<(), String> {
    let short = plan.sha.get(..16).unwrap_or(&plan.sha);
    verify(&[WATCHDOG_BIN, short])?;
    let shown = plan.copy.display().to_string();
    match read_regular(&plan.copy, MAX_SELF) {
        Ok(have) if crate::win_binvault::sha256_hex(&have) == plan.sha => Ok(()),
        Ok(_) => Err(format!(
            "{shown} is already there and is not this binary (its SHA-256 differs). {}",
            aside(&shown, now())
        )),
        Err(ReadError::Absent) => Ok(()),
        Err(e) => Err(format!("{shown} cannot be checked: {e}. {}", aside(&shown, now()))),
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn stage_watchdog(plan: &WatchdogPlan) -> Result<(), String> {
    use crate::win_binvault::sha256_hex;
    let short = plan.sha.get(..16).unwrap_or(&plan.sha);
    let dir = ensure(&[WATCHDOG_BIN, short])?;
    let shown = plan.copy.display().to_string();
    match read_regular(&plan.copy, MAX_SELF) {
        Ok(have) if sha256_hex(&have) == plan.sha => {}
        Ok(_) => {
            return Err(format!(
                "{shown} is already there and is not this binary (its SHA-256 differs). {}",
                aside(&shown, now())
            ))
        }
        Err(ReadError::Absent) => {
            write_atomic(&dir, WATCHDOG_EXE, &plan.bytes)?;

            let back = read_regular(&plan.copy, MAX_SELF).map_err(|e| format!("{shown} cannot be read back: {e}"))?;
            if sha256_hex(&back) != plan.sha {
                return Err(format!("{shown} does not read back as this binary"));
            }
        }
        Err(e) => return Err(format!("{shown} cannot be checked: {e}. {}", aside(&shown, now()))),
    }

    private_file(&plan.copy)?;
    let root = ensure(&[])?;
    let wrapper = write_atomic(&root, WATCHDOG_WRAPPER, plan.body.as_bytes())?;
    private_file(&wrapper)
}
