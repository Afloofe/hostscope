use std::path::Path;

use hs_core::severity::Severity;

use crate::tools::{Invocation, RunError, Runner, Tool};

pub const CONTEXT: &[u8] = b"hemostat/host-id/freebsd/v1";

pub const HOSTID_FILE: &str = "/etc/hostid";

pub fn host_id(uuid: &str) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(CONTEXT);
    h.update(uuid.as_bytes());
    h.finalize().into()
}

pub fn canonical_uuid(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_lowercase();
    let groups: Vec<&str> = s.split('-').collect();
    let shape = [8, 4, 4, 4, 12];
    let ok = groups.len() == shape.len()
        && groups.iter().zip(shape).all(|(g, n)| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit()));
    (ok && s.bytes().any(|b| b != b'0' && b != b'-')).then_some(s)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {

    KernHostuuid,

    EtcHostid,

    None,
}

impl Source {

    pub fn label(self) -> &'static str {
        match self {
            Source::KernHostuuid => "kern.hostuuid",
            Source::EtcHostid => HOSTID_FILE,
            Source::None => "none",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostIdFile {

    Absent,

    Agrees,

    Disagrees(String),

    Only(String),

    Malformed,

    Unreadable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIdentity {

    pub host_id: Option<[u8; 32]>,

    pub source: Source,

    pub hostuuid: Result<String, String>,

    pub hostid_file: HostIdFile,
}

impl HostIdentity {

    pub fn finding(&self) -> Option<(Severity, String)> {
        match (&self.hostid_file, &self.hostuuid) {
            (HostIdFile::Disagrees(file), Ok(kern)) => Some((
                Severity::Warn,
                format!(
                    "kern.hostuuid is {kern} and {HOSTID_FILE} says {file}: the kernel's id was set \
                     from somewhere other than this disk's file (a clone, a moved VM, or an edit). \
                     The host id follows the kernel"
                ),
            )),
            _ if self.source == Source::None => Some((
                Severity::Warn,
                "no host UUID could be read; this run's host id is random, so its records will \
                 not join with another run's"
                    .into(),
            )),
            _ => None,
        }
    }
}

pub fn judge(hostuuid: Result<String, String>, hostid_file: Result<Option<String>, String>) -> HostIdentity {
    let kern = hostuuid.and_then(|s| canonical_uuid(&s).ok_or_else(|| format!("not a usable UUID: {:?}", s.trim())));
    let file = match hostid_file {
        Ok(None) => HostIdFile::Absent,
        Err(why) => HostIdFile::Unreadable(why),
        Ok(Some(text)) => match (canonical_uuid(&text), &kern) {
            (None, _) => HostIdFile::Malformed,
            (Some(u), Ok(k)) if u == *k => HostIdFile::Agrees,
            (Some(u), Ok(_)) => HostIdFile::Disagrees(u),
            (Some(u), Err(_)) => HostIdFile::Only(u),
        },
    };
    let (host_id, source) = match (&kern, &file) {
        (Ok(k), _) => (Some(host_id(k)), Source::KernHostuuid),
        (Err(_), HostIdFile::Only(u)) => (Some(host_id(u)), Source::EtcHostid),
        (Err(_), _) => (None, Source::None),
    };
    HostIdentity { host_id, source, hostuuid: kern, hostid_file: file }
}

pub fn read(runner: &mut dyn Runner, root: &Path) -> HostIdentity {
    let kern = runner
        .run(&Invocation::new(Tool::Sysctl, &["-n", "kern.hostuuid"]).max_output(4096))
        .map_err(|e: RunError| e.to_string())
        .and_then(|o| if o.success() { Ok(o.text()) } else { Err(format!("sysctl exited {:?}", o.status)) });
    let path = root.join(HOSTID_FILE.trim_start_matches('/'));
    #[cfg(unix)]
    let file = match crate::saferead::read_bytes(&path, 4096) {
        Ok(b) => Ok(Some(String::from_utf8_lossy(&b).into_owned())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    };
    #[cfg(not(unix))]
    let file: Result<Option<String>, String> = {
        let _ = path;
        Err("not readable on this platform".into())
    };
    judge(kern, file)
}
