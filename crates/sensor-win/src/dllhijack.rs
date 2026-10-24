use crate::authenticode::Trust;
use crate::posture::{Finding, Severity};

const SYSTEM_DIRS: &[&str] = &[
    "c:\\windows\\system32",
    "c:\\windows",
    "c:\\windows\\system",
    "c:\\windows\\syswow64",
];

pub fn is_system_dir(dir: &str) -> bool {
    let n = normalise_dir(dir);
    SYSTEM_DIRS.iter().any(|s| n == *s || n.starts_with(&format!("{s}\\")))
}

pub fn normalise_dir(dir: &str) -> String {
    let d = dir.trim().trim_matches('"').replace('/', "\\").to_ascii_lowercase();
    let d = d.trim_end_matches('\\');
    d.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathEntry {

    pub dir: String,

    pub position: usize,

    pub user_writable: bool,

    pub exists: bool,

    pub ahead_of_system_dirs: bool,
}

pub fn judge_path_entry(e: &PathEntry) -> Option<Finding> {
    if !e.exists {
        return Some(Finding {
            severity: Severity::Warn,
            subject: format!("dll-search:{}", e.dir),
            what: format!(
                "the PATH entry {} is at position {} and does not exist",
                e.dir, e.position
            ),
            why: "a directory that does not exist still holds its place in the search order. \
                  Whoever can create it decides what every bare-name DLL load finds there first"
                .into(),
            fix: Some("remove the entry, or create the directory owned by Administrators".into()),
        });
    }
    if !e.user_writable {
        return None;
    }

    let severity = if e.ahead_of_system_dirs { Severity::Critical } else { Severity::Warn };
    Some(Finding {
        severity,
        subject: format!("dll-search:{}", e.dir),
        what: format!(
            "the PATH entry {} (position {}) is writable by unprivileged users",
            e.dir, e.position
        ),
        why: "any program that loads a DLL by bare name searches PATH. A writable directory \
              there turns every such load into a chance to run the attacker's copy, and leaves \
              no artefact a persistence sweep would find"
            .into(),
        fix: Some(format!(
            "restrict {} to Administrators and SYSTEM, or remove it from the system PATH",
            e.dir
        )),
    })
}

pub fn order_path_entries(
    path: &str,
    writable: &dyn Fn(&str) -> bool,
    exists: &dyn Fn(&str) -> bool,
) -> Vec<PathEntry> {
    let dirs: Vec<&str> = path.split(';').map(str::trim).filter(|d| !d.is_empty()).collect();

    let first_system = dirs.iter().position(|d| is_system_dir(d));
    dirs.iter()
        .enumerate()
        .map(|(position, d)| PathEntry {
            dir: (*d).to_string(),
            position,
            user_writable: writable(d),
            exists: exists(d),
            ahead_of_system_dirs: match first_system {
                Some(fs) => position < fs,
                None => true,
            },
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownDll {

    pub name: String,

    pub value: String,
}

pub fn judge_known_dll(k: &KnownDll) -> Option<Finding> {

    if k.name.eq_ignore_ascii_case("DllDirectory") {
        return judge_known_dll_directory(&k.value, "%SystemRoot%\\system32");
    }
    if k.name.eq_ignore_ascii_case("DllDirectory32") {
        return judge_known_dll_directory(&k.value, "%SystemRoot%\\syswow64");
    }

    let v = k.value.trim();
    let has_path = v.contains('\\') || v.contains('/') || v.contains(':');
    if !has_path {
        return None;
    }
    Some(Finding {
        severity: Severity::Critical,
        subject: format!("knowndlls:{}", k.name),
        what: format!("the KnownDLLs entry {} resolves to {v} rather than a bare file name", k.name),
        why: "KnownDLLs is the mechanism that makes search-order hijacking impossible for core \
              libraries — the loader maps that section instead of searching. An entry carrying a \
              path redirects a library every process loads, and disables the protection for it"
            .into(),
        fix: Some(format!(
            "the value should be the bare file name; compare {} against a known-good host before \
             changing it, and capture the current value first",
            k.name
        )),
    })
}

fn judge_known_dll_directory(value: &str, expected: &str) -> Option<Finding> {
    if normalise_dir(value) == normalise_dir(expected) {
        return None;
    }
    Some(Finding {
        severity: Severity::Critical,
        subject: "knowndlls:DllDirectory".into(),
        what: format!("the KnownDLLs directory is {value}, not {expected}"),
        why: "every KnownDLLs entry is resolved against this directory. Moving it redirects the \
              whole protected set at once — the single highest-leverage DLL redirection on a \
              Windows host"
            .into(),
        fix: Some(format!("restore it to {expected} and treat this host as compromised")),
    })
}

pub fn judge_safe_dll_search(value: Option<u32>) -> Option<Finding> {
    match value {

        None | Some(1) => None,
        Some(0) => Some(Finding {
            severity: Severity::Critical,
            subject: "dll-search:SafeDllSearchMode".into(),
            what: "SafeDllSearchMode is 0, so the current directory is searched before the \
                   system directories"
                .into(),
            why: "with safe search off, launching any program from a directory the attacker can \
                  write to loads their DLL instead of the system one. It is a host-wide downgrade \
                  of the loader, set with a single registry value"
                .into(),
            fix: Some(
                "set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SafeDllSearchMode \
                 to 1 (a reboot applies it)"
                    .into(),
            ),
        }),
        Some(other) => Some(Finding {
            severity: Severity::Warn,
            subject: "dll-search:SafeDllSearchMode".into(),
            what: format!("SafeDllSearchMode is {other}, which is neither 0 nor 1"),
            why: "the loader treats any non-zero value as enabled, so this is probably safe — \
                  but it is not a value Windows writes, so something set it"
                .into(),
            fix: Some("set it to 1 so the value says what is meant".into()),
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sideload {

    pub exe: String,

    pub dll: String,

    pub exe_signed: bool,

    pub dll_signed: bool,

    pub dir_user_writable: bool,
}

pub fn judge_sideload(s: &Sideload) -> Option<Finding> {
    if !s.exe_signed || s.dll_signed {
        return None;
    }

    if !s.dir_user_writable {
        return None;
    }
    Some(Finding {
        severity: Severity::Critical,

        subject: format!("sideload:{}", s.dll),
        what: format!(
            "the signed binary {} sits in a user-writable directory beside the unsigned {}",
            s.exe, s.dll
        ),
        why: "the signature on the executable is real and verifies, so every check that looks at \
              the binary passes. The code that runs comes from the unsigned DLL next to it, which \
              anyone who can write to that directory can replace"
            .into(),
        fix: Some(format!(
            "check {} against the vendor's copy, and restrict the directory to Administrators",
            s.dll
        )),
    })
}

fn judge_tampered_sideload(exe: &str, dll: &str, why: &str) -> Finding {
    Finding {
        severity: Severity::Critical,
        subject: format!("sideload:{dll}"),
        what: format!(
            "the signed binary {exe} sits in a user-writable directory beside {dll}, whose own \
             signature does not verify: {why}"
        ),
        why: "a DLL that carries a signature which no longer verifies was changed after it was \
              signed, or was signed by someone this host distrusts. The executable beside it is \
              genuine and will load it, and anyone who can write to that directory put it there"
            .into(),
        fix: Some(format!(
            "capture {dll} and compare it against the vendor's copy, and restrict the directory to \
             Administrators"
        )),
    }
}

pub const SIDELOAD_FILE_CAP: usize = 512;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {

    pub files: Vec<String>,

    pub cut_short: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SideloadSweep {

    pub findings: Vec<Finding>,

    pub dirs_examined: usize,

    pub unchecked: Vec<String>,
}

pub fn sweep_sideloads(
    dirs: &[String],
    list: &dyn Fn(&str) -> Option<Listing>,
    verify: &dyn Fn(&str) -> Trust,
) -> SideloadSweep {
    let mut out = SideloadSweep::default();
    let mut verdicts: std::collections::BTreeMap<String, Trust> = Default::default();
    let mut verdict = |path: &str| -> Trust {
        verdicts.entry(path.to_string()).or_insert_with(|| verify(path)).clone()
    };
    let has_ext = |p: &str, want: &str| {
        std::path::Path::new(p).extension().is_some_and(|x| x.eq_ignore_ascii_case(want))
    };

    for dir in dirs {
        let Some(listing) = list(dir) else {
            out.unchecked.push(format!("{dir}: the directory could not be listed"));
            continue;
        };
        out.dirs_examined += 1;
        let mut candidates: Vec<&String> = listing
            .files
            .iter()
            .filter(|p| has_ext(p, "exe") || has_ext(p, "dll"))
            .collect();
        candidates.sort();
        if listing.cut_short || candidates.len() > SIDELOAD_FILE_CAP {
            out.unchecked.push(format!(
                "{dir}: only the first {} executable(s) and DLL(s) of a longer listing were \
                 examined",
                candidates.len().min(SIDELOAD_FILE_CAP)
            ));
            candidates.truncate(SIDELOAD_FILE_CAP);
        }

        let mut signed_exe = None;
        for exe in candidates.iter().filter(|p| has_ext(p, "exe")) {
            match verdict(exe) {
                Trust::Valid => {
                    signed_exe.get_or_insert((*exe).clone());
                }
                Trust::Unknown(why) => out.unchecked.push(format!("{exe}: {why}")),

                Trust::Unsigned | Trust::Broken(_) | Trust::Untrusted(_) => {}
            }
        }

        let Some(exe) = signed_exe else { continue };

        for dll in candidates.iter().filter(|p| has_ext(p, "dll")) {
            match verdict(dll) {
                Trust::Valid => {}
                Trust::Unsigned => out.findings.extend(judge_sideload(&Sideload {
                    exe: exe.clone(),
                    dll: (*dll).clone(),
                    exe_signed: true,
                    dll_signed: false,
                    dir_user_writable: true,
                })),
                Trust::Broken(why) => out.findings.push(judge_tampered_sideload(&exe, dll, &why)),

                Trust::Untrusted(why) | Trust::Unknown(why) => {
                    out.unchecked.push(format!("{dll}: {why}"));
                }
            }
        }
    }
    out
}
