use crate::posture::{Finding, Severity};
use crate::reg::Hive;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {

    pub clsid: String,

    pub path: String,

    pub hive: Hive,

    pub key: String,

    pub user: Option<String>,

    pub shadows_machine: bool,
}

const EXPECTED: &[&str] = &[
    "c:/windows/system32",
    "c:/windows/syswow64",
    "c:/windows/winsxs",
    "c:/windows/microsoft.net",
    "c:/program files",
    "c:/program files (x86)",
    "c:/windows/systemapps",
];

const WRITABLE: &[&str] =
    &["c:/users/public", "c:/windows/temp", "c:/temp", "c:/programdata", "c:/perflogs", "c:/users/"];

fn normalise(p: &str) -> String {

    p.trim()
        .trim_matches('"')
        .replace('\\', "/")
        .to_ascii_lowercase()
        .replace("%systemroot%", "c:/windows")
        .replace("%windir%", "c:/windows")
        .replace("%programfiles%", "c:/program files")
}

pub fn judge(label: &str, r: &Resolution) -> Option<Finding> {
    let p = normalise(&r.path);
    let per_user = r.hive != Hive::Machine;
    let whose = r.user.as_deref().map_or_else(
        || "the per-user hive".to_string(),
        |sid| format!("the per-user hive of {sid}"),
    );

    if per_user && r.shadows_machine {
        return Some(Finding {
            severity: Severity::Critical,
            subject: format!("com:{}", r.clsid),
            what: format!(
                "{label} {} is registered in {whose} as {}, shadowing the machine registration",
                r.clsid, r.path
            ),
            why: "COM resolves a CLSID through HKCU before HKLM, so this replaces a system \
                  component for that account. No file was replaced, no autorun was created, and \
                  the machine key a responder would check still reads correctly — every process \
                  that account runs loads this instead when it instantiates the object"
                .into(),
            fix: Some(format!(
                "capture the value, then delete {} — the machine registration underneath it is \
                 intact",
                r.key
            )),
        });
    }

    if WRITABLE.iter().any(|d| p.starts_with(d)) {
        return Some(Finding {
            severity: Severity::Critical,
            subject: format!("com:{}", r.clsid),
            what: format!("{label} {} loads {} from a user-writable directory", r.clsid, r.path),
            why: "a COM server in a directory unprivileged users can write to can be replaced by \
                  any of them, and it is loaded into whichever process instantiates the object — \
                  for a shell extension, that is Explorer"
                .into(),
            fix: Some(format!("check what {} is, and restrict the directory", r.path)),
        });
    }

    if per_user {
        return Some(Finding {
            severity: Severity::Warn,
            subject: format!("com:{}", r.clsid),
            what: format!("{label} {} is registered in {whose}, loading {}", r.clsid, r.path),
            why: "a per-user COM registration does not appear in a machine-hive sweep, and the \
                  server is loaded into whatever instantiates the object"
                .into(),
            fix: None,
        });
    }

    if !EXPECTED.iter().any(|d| p.starts_with(d)) && !p.is_empty() {
        return Some(Finding {
            severity: Severity::Warn,
            subject: format!("com:{}", r.clsid),
            what: format!("{label} {} loads {}, outside the usual COM server locations", r.clsid, r.path),
            why: "third-party COM servers are ordinary, and they are also how code gets into \
                  Explorer without an autorun entry"
                .into(),
            fix: None,
        });
    }

    None
}

pub fn is_clsid(s: &str) -> bool {
    let t = s.trim();
    t.len() == 38
        && t.starts_with('{')
        && t.ends_with('}')
        && t.get(1..37).is_some_and(|inner| {
            inner.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
                && inner.matches('-').count() == 4
        })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserHive {

    pub sid: String,

    pub classes: String,

    pub clsids: Vec<String>,
}

fn is_sid(s: &str) -> bool {
    s.strip_prefix("S-1-").is_some_and(|rest| {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit() || c == '-')
    })
}

pub fn user_hives(loaded: &[String]) -> Vec<UserHive> {
    loaded
        .iter()
        .filter(|k| is_sid(k))
        .map(|sid| {
            let classes_hive = format!("{sid}_Classes");
            let classes = if loaded.iter().any(|k| k.eq_ignore_ascii_case(&classes_hive)) {
                classes_hive
            } else {
                format!(r"{sid}\Software\Classes")
            };
            UserHive { sid: sid.clone(), classes, clsids: Vec::new() }
        })
        .collect()
}

pub fn unloaded_profiles(profiles: &[String], loaded: &[String]) -> Vec<String> {
    profiles
        .iter()
        .filter(|p| is_sid(p) && !loaded.iter().any(|k| k.eq_ignore_ascii_case(p)))
        .cloned()
        .collect()
}

pub fn resolutions(
    clsid: &str,
    machine: Option<(String, String)>,
    users: Vec<(String, String, String)>,
) -> Vec<Resolution> {
    let shadows_machine = machine.is_some();
    let mut out: Vec<Resolution> = users
        .into_iter()
        .map(|(sid, key, path)| Resolution {
            clsid: clsid.to_string(),
            path,
            hive: Hive::Users,
            key,
            user: Some(sid),
            shadows_machine,
        })
        .collect();
    if let Some((key, path)) = machine {
        out.push(Resolution {
            clsid: clsid.to_string(),
            path,
            hive: Hive::Machine,
            key,
            user: None,
            shadows_machine: false,
        });
    }
    out
}

#[cfg(target_os = "windows")]
pub fn resolve(clsid: &str, users: &[UserHive]) -> Vec<Resolution> {
    use crate::reg::default_value;

    if !is_clsid(clsid) {
        return Vec::new();
    }
    let machine = [
        format!(r"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32"),
        format!(r"SOFTWARE\Classes\WOW6432Node\CLSID\{clsid}\InprocServer32"),
    ]
    .into_iter()
    .find_map(|k| default_value(Hive::Machine, &k).map(|p| (format!(r"HKLM\{k}"), p)));

    let per_user = users
        .iter()
        .filter(|u| u.clsids.iter().any(|c| c.eq_ignore_ascii_case(clsid)))
        .filter_map(|u| {
            let k = format!(r"{}\CLSID\{clsid}\InprocServer32", u.classes);
            default_value(Hive::Users, &k).map(|p| (u.sid.clone(), format!(r"HKU\{k}"), p))
        })
        .collect();
    resolutions(clsid, machine, per_user)
}

#[cfg(not(target_os = "windows"))]
pub fn resolve(_clsid: &str, _users: &[UserHive]) -> Vec<Resolution> {
    Vec::new()
}
