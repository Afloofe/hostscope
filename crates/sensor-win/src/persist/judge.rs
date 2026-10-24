use super::shapes::{
    boot_execute_is_stock, loud_arguments, lsa_package_is_stock, names_interpreter,
    under_writable, winlogon_is_stock,
};
use super::{Coverage, Entry, Observation, Report};
use crate::posture::{Finding, Severity};

fn judge_unlisted(e: &Entry) -> Option<Finding> {
    let member = e.command.trim();
    let (what, carries) = match e.mechanism {
        "lsa-packages" | "lsa-osconfig" => {
            if lsa_package_is_stock(&e.name, member)? {
                return None;
            }
            let carries = if e.name.eq_ignore_ascii_case("Notification Packages") {
                "lsass hands it every password set or changed on this host, in plaintext"
            } else if e.name.eq_ignore_ascii_case("Security Packages") {
                "a security support provider sees the credentials of every logon it takes part in"
            } else {
                "an authentication package handles logons inside the process that holds every \
                 credential on the host"
            };
            let list = if e.mechanism == "lsa-osconfig" {
                format!(r"OSConfig\{}", e.name)
            } else {
                e.name.clone()
            };
            (format!("`{member}` is loaded into lsass.exe from {list}"), carries)
        }
        "boot-execute" if e.name.eq_ignore_ascii_case("BootExecute") => {
            if boot_execute_is_stock(member) {
                return None;
            }
            (
                format!("`{member}` runs from BootExecute at every boot"),
                "it runs in the native subsystem before Win32, any service or any security \
                 product exists, and the list ships holding only the disk check",
            )
        }
        _ => return None,
    };
    Some(Finding {
        severity: Severity::Warn,
        subject: format!("{} · {}", e.mechanism, e.name),
        what,
        why: format!(
            "Windows does not ship this name here: {carries}. Password filters on domain \
             controllers, smart-card packages and boot-time anti-malware scanners are installed \
             the same way, so confirm it is one of yours before acting — and if it is not, treat \
             what it could see as taken"
        ),
        fix: None,
    })
}

fn judge_logon_script(e: &Entry) -> Option<Finding> {
    let script = e.command.trim();
    if e.mechanism != "logon-scripts" || script.is_empty() {
        return None;
    }
    Some(Finding {
        severity: Severity::Warn,
        subject: format!("{} · {}", e.mechanism, e.name),
        what: format!("`{script}` runs at every logon of {}", e.name),
        why: "UserInitMprLogonScript is set in no profile on a stock host, and whatever it \
              names runs as that account every time it logs on (T1037.001). Where the script \
              lives does not decide it: one in System32 or on a share runs the same way. \
              Confirm who set it and what it runs before acting"
            .into(),
        fix: None,
    })
}

pub(super) fn judge_winlogon(e: &Entry) -> Option<Finding> {
    match winlogon_is_stock(&e.name, &e.command) {

        None | Some(true) => None,
        Some(false) => Some(Finding {
            severity: Severity::Critical,
            subject: format!("{} · {}", e.mechanism, e.name),
            what: format!("`{}` runs `{}` at every logon", e.name, e.command),
            why: format!(
                "Winlogon's {} value ships as a single fixed program, and this one is not it: something has been added to run at every logon, before the desktop exists. Appending a command after a comma is one of the oldest persistence tricks on Windows and does not depend on where the added program lives",
                e.name
            ),
            fix: Some(format!(
                "restore {} to its stock value once you have recorded what was there",
                e.name
            )),
        }),
    }
}

pub fn judge_winrm(e: &Entry) -> Option<Finding> {
    if !e.mechanism.starts_with("winrm-") {
        return None;
    }
    let v = e.command.trim();
    match e.name.as_str() {
        n if n.eq_ignore_ascii_case("TrustedHosts") && (v == "*" || v.contains('*')) => {
            Some(Finding {
                severity: Severity::Critical,
                subject: format!("{}:{}", e.mechanism, e.name),
                what: format!("WinRM TrustedHosts is {v}"),
                why: "this host will send its credentials to any server it is pointed at. An \
                      attacker who can influence a connection gets the credentials of whoever \
                      made it"
                    .into(),
                fix: Some("set TrustedHosts to the specific hosts that need it, or clear it".into()),
            })
        }
        n if (n.eq_ignore_ascii_case("AllowUnencrypted") || n.eq_ignore_ascii_case("Basic"))
            && (v == "1" || v.eq_ignore_ascii_case("true")) =>
        {
            Some(Finding {
                severity: Severity::Critical,
                subject: format!("{}:{}", e.mechanism, e.name),
                what: format!("WinRM {} is enabled", e.name),
                why: "WinRM will carry credentials over unencrypted HTTP with basic \
                      authentication, which puts every remote-management logon on the wire in \
                      a form anyone on the path can take"
                    .into(),
                fix: Some(format!("disable {} and require HTTPS or Kerberos", e.name)),
            })
        }
        _ => None,
    }
}

pub fn judge_entry(e: &Entry) -> Option<Finding> {

    if let Some(f) = judge_winrm(e) {
        return Some(f);
    }

    let writable = under_writable(&e.command);
    let loud = loud_arguments(&e.command);
    let interpreter = names_interpreter(&e.command);

    if e.mechanism == "winlogon" {
        if let Some(f) = judge_winlogon(e) {
            return Some(f);
        }
    }

    if e.mechanism == "ifeo-debugger" {
        return Some(Finding {
            severity: Severity::Critical,
            subject: format!("{} · {}", e.mechanism, e.name),
            what: format!("`{}` is substituted for {} at every launch", e.command, e.name),
            why: "an Image File Execution Options Debugger value replaces the program with \
                  another one, every time anybody or anything starts it. Its one legitimate \
                  use is attaching a debugger during development, which is not something a \
                  server does — and it survives the original being reinstalled"
                .into(),
            fix: Some(format!(
                "delete the Debugger value under {} once you have recorded it",
                e.locus
            )),
        });
    }

    if e.mechanism == "appinit-dlls" && e.name.eq_ignore_ascii_case("LoadAppInit_DLLs") {
        return None;
    }
    if e.mechanism == "appinit-dlls" && !e.command.trim().is_empty() {
        return Some(Finding {
            severity: Severity::Critical,
            subject: format!("{} · {}", e.mechanism, e.name),
            what: format!("loads `{}` into every process that links user32", e.command),
            why: "AppInit_DLLs is a global injection point Microsoft deprecated and disables \
                  under Secure Boot, which means a value here either predates that or was put \
                  there by something that expected Secure Boot to be off. Either way it is a \
                  DLL in almost every process on the host"
                .into(),
            fix: Some(format!("clear the value under {} once you have recorded it", e.locus)),
        });
    }

    if e.mechanism == "startup-folder" {
        return Some(Finding {
            severity: Severity::Warn,
            subject: format!("{} · {}", e.mechanism, e.name),
            what: format!("`{}` runs at every user's logon", e.command),
            why: "the all-users Startup folder holds nothing that runs on a stock host, and \
                  whatever is in it starts as every user who logs on. Only administrators can \
                  write the folder, so this was placed with administrator rights — by an \
                  installer or by whoever held them. A shortcut's target is not resolved here: \
                  open it and check what it points at before deciding which"
                .into(),
            fix: None,
        });
    }

    match (writable, loud.is_empty(), interpreter) {

        (Some(dir), false, _) => Some(Finding {
            severity: Severity::Critical,
            subject: format!("{} · {}", e.mechanism, e.name),
            what: format!("runs `{}` from {dir} with {}", e.command, loud.join(", ")),
            why: "a command that starts automatically, runs from a directory any user can \
                  write, and carries arguments whose purpose is to keep it from being read. \
                  Each of those is explainable alone; together they are not"
                .into(),
            fix: Some(format!("record {}, then remove the entry", e.locus)),
        }),

        (Some(dir), true, _) => Some(Finding {
            severity: Severity::Warn,
            subject: format!("{} · {}", e.mechanism, e.name),
            what: format!("runs `{}` from {dir}", e.command),
            why: "anything that starts automatically out of a directory a non-administrator \
                  can write can be replaced by that non-administrator, and then it runs with \
                  whatever privilege the autostart has. Some installers do use ProgramData \
                  legitimately, so confirm what this is before removing it"
                .into(),
            fix: None,
        }),

        (None, false, Some(i)) => Some(Finding {
            severity: Severity::Critical,
            subject: format!("{} · {}", e.mechanism, e.name),
            what: format!("runs {i} with {}", loud.join(", ")),
            why: "an autostart that invokes an interpreter with a hidden window, a base64 \
                  payload or an in-memory download is describing how it avoids being read. \
                  Stock Windows autostarts contain none of those arguments"
                .into(),
            fix: Some(format!("decode the command and record it before touching {}", e.locus)),
        }),
        (None, false, None) => Some(Finding {
            severity: Severity::Warn,
            subject: format!("{} · {}", e.mechanism, e.name),
            what: format!("runs with {}", loud.join(", ")),
            why: "the arguments here are the kind used to keep a command from being read, \
                  though no interpreter is named. Worth decoding before anything else"
                .into(),
            fix: None,
        }),

        (None, true, _) => judge_unlisted(e).or_else(|| judge_logon_script(e)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageEvidence {

    pub path: String,

    pub signed: bool,

    pub signer: Option<String>,

    pub writable: Option<bool>,
}

const WINDOWS_SIGNER: &str = "Microsoft Windows";

pub fn defender_driver_path(command: &str, defender_data: &str) -> Option<String> {
    let c = command.trim().trim_matches('"');
    let c = c.strip_prefix(r"\??\").unwrap_or(c);
    let root = defender_data.trim_end_matches('\\');
    if !c.get(..root.len())?.eq_ignore_ascii_case(root) {
        return None;
    }
    let rest = c.get(root.len()..)?;
    let climbs = rest.split(['\\', '/']).any(|seg| {
        let t = seg.trim_matches(' ');
        !t.is_empty() && t.bytes().all(|b| b == b'.')
    });
    let ok = rest.len() > 1
        && rest.starts_with('\\')
        && rest.to_ascii_lowercase().ends_with(".sys")
        && !rest.contains('"')
        && !climbs;
    ok.then(|| c.to_string())
}

pub fn lower_defender_driver(f: &mut Finding, e: &Entry, ev: &ImageEvidence) -> bool {
    if e.mechanism != "services" || f.severity != Severity::Warn || !f.subject.starts_with("services · ") {
        return false;
    }
    if !ev.signed || ev.signer.as_deref() != Some(WINDOWS_SIGNER) || ev.writable != Some(false) {
        return false;
    }
    f.severity = Severity::Note;
    f.what = format!("{} — a kernel driver signed by {WINDOWS_SIGNER}, in Defender's data directory", f.what);
    f.why = format!(
        "a service whose image is under ProgramData is a Warn because a non-administrator could \
         usually replace the file. Not here: {} verifies as signed by {WINDOWS_SIGNER}, and \
         neither it nor any directory up to Defender's data directory lets an unprivileged \
         account write. Defender installs a kernel driver of this kind for each scan, as \
         MpKsl<hex> with a copy of MpKslDrv.sys, and leaves it registered. The name did not \
         lower this; the signature and the ACLs did, and without either it is a Warn. It is a \
         Note and not nothing because an administrator can register any Windows-signed driver \
         from there, a vulnerable one included",
        ev.path
    );
    true
}

pub fn judge(entries: &[Entry], observations: &[Observation]) -> Vec<Finding> {
    judge_with(entries, observations, &std::collections::BTreeMap::new())
}

pub fn judge_with(
    entries: &[Entry],
    observations: &[Observation],
    images: &std::collections::BTreeMap<String, ImageEvidence>,
) -> Vec<Finding> {
    let mut out: Vec<Finding> = entries
        .iter()
        .filter_map(|e| {
            let mut f = judge_entry(e)?;
            if let Some(ev) = images.get(&e.locus) {
                lower_defender_driver(&mut f, e, ev);
            }
            Some(f)
        })
        .collect();

    let appinit_off = entries.iter().any(|e| {
        e.mechanism == "appinit-dlls"
            && e.name.eq_ignore_ascii_case("LoadAppInit_DLLs")
            && e.command.trim() == "0"
    });
    if appinit_off {
        for f in &mut out {
            if f.subject.starts_with("appinit-dlls") {
                f.severity = Severity::Warn;
                f.why = format!(
                    "{} — but LoadAppInit_DLLs is 0 on this host, so the loader ignores the \
                     list and nothing here is being injected today. One registry write \
                     reverses that, which is why it is still on the page",
                    f.why
                );
            }
        }
    }

    for o in observations {
        match o.coverage {
            Coverage::Unreadable => out.push(Finding {
                severity: Severity::Warn,
                subject: format!("{} · coverage", o.id),
                what: "exists but could not be read".into(),
                why: format!(
                    "{} is NOT clean, it is unchecked — nothing here is a statement about \
                     what it holds. Re-run elevated",
                    o.name
                ),
                fix: Some("re-run as an administrator".into()),
            }),
            Coverage::Partial => out.push(Finding {
                severity: Severity::Warn,
                subject: format!("{} · coverage", o.id),
                what: format!("read in part: {} locus/loci refused", o.refused.len()),
                why: format!(
                    "the parts of {} that refused are unexamined, and what was found in the \
                     rest says nothing about them",
                    o.name
                ),
                fix: Some("re-run as an administrator".into()),
            }),
            _ => {}
        }
    }

    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    out
}

pub fn assemble(entries: Vec<Entry>, observations: Vec<Observation>) -> Report {
    assemble_with(entries, observations, &std::collections::BTreeMap::new())
}

pub fn assemble_with(
    entries: Vec<Entry>,
    observations: Vec<Observation>,
    images: &std::collections::BTreeMap<String, ImageEvidence>,
) -> Report {
    let findings = judge_with(&entries, &observations, images);
    let established = observations.iter().filter(|o| o.coverage.established()).count();
    let total = observations.len();
    Report { observations, entries, findings, established, total }
}
