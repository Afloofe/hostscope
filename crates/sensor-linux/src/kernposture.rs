use std::fs;

use crate::triage::{rank, Finding, Severity};

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub privileged: bool,
}

fn read_state(path: &str) -> std::io::Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_string())
}

struct Knob {
    path: &'static str,
    subject: &'static str,

    note_when: &'static str,

    absent_is_weak: Option<&'static str>,
    why: &'static str,
}

static POSTURE_KNOBS: &[Knob] = &[
    Knob {
        path: "/proc/sys/kernel/kptr_restrict",
        subject: "kptr_restrict",
        note_when: "0",
        absent_is_weak: None,
        why: "kernel pointers are exposed to userspace, easing kernel-memory targeting",
    },
    Knob {
        path: "/proc/sys/kernel/dmesg_restrict",
        subject: "dmesg_restrict",
        note_when: "0",
        absent_is_weak: None,
        why: "the kernel log is world-readable — useful reconnaissance, and its absence would \
              hide a rootkit's own oops/warnings",
    },
    Knob {
        path: "/proc/sys/kernel/yama/ptrace_scope",
        subject: "ptrace_scope",
        note_when: "0",

        absent_is_weak: Some(
            "the Yama LSM is not active on this kernel, so ptrace falls back to the classic \
             same-uid rule — the same posture ptrace_scope=0 describes",
        ),
        why: "any process may ptrace any other of the same uid — the friendliest setting for \
              userland injection",
    },
    Knob {
        path: "/proc/sys/kernel/unprivileged_bpf_disabled",
        subject: "unprivileged_bpf",
        note_when: "0",

        absent_is_weak: None,
        why: "unprivileged users can load BPF programs — the surface for an eBPF-based rootkit \
              loaded without root",
    },
];

fn posture_finding(k: &Knob, state: &std::io::Result<String>) -> Option<Finding> {
    match state {
        Ok(v) if v == k.note_when => Some(Finding::flag(
            Severity::Note,
            k.subject,
            format!("{}={}", k.subject, k.note_when),
            "weakened setting",
            k.why,
        )),
        Ok(_) => None,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => k.absent_is_weak.map(|absent| {
            Finding::flag(
                Severity::Note,
                k.subject,
                format!("{} is absent", k.path),
                "weakened setting",
                absent,
            )
        }),
        Err(e) => Some(Finding::flag(
            Severity::Note,
            k.subject,
            format!("{} could not be read ({e})", k.path),
            "DID NOT RUN",
            "this is not a reading of the parameter — it is the absence of one. A posture \
             section that silently drops a knob it could not open reads exactly like one that \
             checked it and found nothing wrong",
        )),
    }
}

fn kexec_finding(path: &str, what: &str, state: &std::io::Result<String>) -> Option<Finding> {
    match state {
        Ok(v) if v == "1" => {
            let sev = if path.ends_with("kexec_loaded") { Severity::Warn } else { Severity::Note };
            Some(Finding::flag(
                sev,
                "kexec",
                path.to_string(),
                what,
                "a staged kexec image replaces the running kernel on the next boot without \
                 touching the bootloader or disk — confirm who loaded it",
            ))
        }
        Ok(_) => None,

        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,

        Err(e) => Some(Finding::flag(
            Severity::Note,
            "kexec",
            format!("{path} could not be read ({e})"),
            "DID NOT RUN",
            "whether a replacement kernel is staged for the next boot was not established by \
             this run",
        )),
    }
}

fn unread_state(path: &str, e: &std::io::Error) -> (String, String) {
    if e.kind() == std::io::ErrorKind::NotFound {
        (
            format!("{path} is absent"),
            "this kernel has no such parameter, so nothing here enforces it".to_string(),
        )
    } else {
        (
            format!("{path} could not be read ({e})"),
            "this is not a reading of the parameter — it is the absence of one".to_string(),
        )
    }
}

pub(crate) fn euid() -> Option<u32> {
    parse_euid(&fs::read_to_string("/proc/self/status").ok()?)
}

fn parse_euid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().nth(1))
        .and_then(|e| e.parse().ok())
}

fn kallsyms_readable() -> bool {
    let Ok(s) = crate::saferead::read_kernel_text("/proc/kallsyms") else {
        return false;
    };
    s.lines()
        .take(64)
        .any(|l| l.split_whitespace().next().is_some_and(|a| !a.trim_matches('0').is_empty()))
}

fn kcore_readable() -> bool {
    fs::File::open("/proc/kcore").is_ok()
}

fn tracefs_available() -> bool {
    fs::metadata("/sys/kernel/tracing/available_filter_functions").is_ok()
        || fs::metadata("/sys/kernel/debug/tracing/available_filter_functions").is_ok()
}

pub(crate) fn boot_param<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    cmdline
        .split_whitespace()
        .take_while(|t| *t != "--")
        .filter_map(|t| t.split_once('='))
        .filter(|(k, _)| *k == key)
        .map(|(_, v)| v)
        .last()
}

pub fn report() -> Report {
    let mut f = Vec::new();
    let privileged = euid() == Some(0);

    const SIG_ENFORCE: &str = "/sys/module/module/parameters/sig_enforce";
    match read_state(SIG_ENFORCE).as_deref() {
        Ok("Y") => f.push(Finding::flag(
            Severity::Note,
            "module signing",
            "sig_enforce=Y",
            "the kernel enforces module signatures",
            "an unsigned rootkit module cannot be loaded without also defeating signing",
        )),
        Ok("N") => f.push(Finding::flag(
            Severity::Warn,
            "module signing",
            "sig_enforce=N",
            "the kernel does NOT enforce module signatures",
            "an unsigned kernel module — the classic rootkit LKM — can be loaded with insmod. \
             This is the gate a kernel rootkit walks through; confirm Secure Boot or a locked \
             module loader compensates",
        )),
        Ok(other) => f.push(Finding::flag(
            Severity::Note,
            "module signing",
            format!("sig_enforce={other}"),
            "unexpected sig_enforce value",
            "could not read the module-signature enforcement state cleanly",
        )),

        Err(e) => {
            let (locus, why) = unread_state(SIG_ENFORCE, e);
            f.push(Finding::flag(
                Severity::Warn,
                "module signing",
                locus,
                "whether the kernel enforces module signatures was NOT established",
                format!(
                    "{why}. Treat the load gate as open until something confirms otherwise: \
                     an unsigned kernel module is how a rootkit LKM gets in, and this is the \
                     row that would have said so"
                ),
            ));
        }
    }

    const MODULES_DISABLED: &str = "/proc/sys/kernel/modules_disabled";
    match read_state(MODULES_DISABLED).as_deref() {
        Ok("1") => f.push(Finding::flag(
            Severity::Note,
            "module loading",
            "modules_disabled=1",
            "module loading is sealed for this boot",
            "no kernel module can be loaded, signed or not — the load gate is shut",
        )),
        Ok("0") => f.push(Finding::flag(
            Severity::Note,
            "module loading",
            "modules_disabled=0",
            "modules can still be loaded",
            "runtime module loading is open; combined with sig_enforce=N this is a wide-open \
             door for a rootkit LKM",
        )),
        Ok(_) => {}
        Err(e) => {
            let (locus, why) = unread_state(MODULES_DISABLED, e);
            f.push(Finding::flag(
                Severity::Note,
                "module loading",
                locus,
                "whether module loading is sealed for this boot was NOT established",
                why,
            ));
        }
    }

    let sb_var = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
    if fs::metadata("/sys/firmware/efi").is_ok() {
        match fs::read(sb_var).ok().and_then(|b| b.last().copied()) {
            Some(1) => f.push(Finding::flag(
                Severity::Note,
                "Secure Boot",
                "enabled",
                "UEFI Secure Boot is on",
                "the boot chain and (usually) module signing are anchored to firmware keys",
            )),
            Some(_) => f.push(Finding::flag(
                Severity::Note,
                "Secure Boot",
                "disabled",
                "UEFI firmware present but Secure Boot is off",
                "nothing anchors the kernel and modules to firmware keys; a tampered kernel or \
                 unsigned module is not stopped at boot",
            )),
            None => {}
        }
    }

    match read_state("/sys/kernel/security/lockdown") {
        Ok(l) => {
            let active =
                l.split(['[', ']']).nth(1).or(Some(l.as_str())).unwrap_or("none").to_string();
            f.push(Finding::flag(
                Severity::Note,
                "kernel lockdown",
                active.clone(),
                format!("kernel lockdown is '{active}'"),
                "'none' leaves kernel memory writable through the documented interfaces and \
                 keeps /proc/kcore readable — good for this scan, and for an attacker",
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => f.push(Finding::flag(
            Severity::Note,
            "kernel lockdown",
            format!("/sys/kernel/security/lockdown could not be read ({e})"),
            "DID NOT RUN",
            "this run did not establish whether kernel lockdown is active",
        )),
    }

    let ks = kallsyms_readable();
    let kc = kcore_readable();
    let tf = tracefs_available();
    if privileged && (!ks || !kc || !tf) {
        let mut blinded = Vec::new();
        if !ks {
            blinded.push("kallsyms addresses are zeroed");
        }
        if !kc {
            blinded.push("/proc/kcore is unreadable");
        }
        if !tf {
            blinded.push("tracefs is unavailable");
        }
        f.push(Finding::flag(
            Severity::Warn,
            "blinded while privileged",
            blinded.join("; "),
            "a uid-0 agent cannot read kernel state it is entitled to read",
            "a privileged reader should see all of these. Their absence is either aggressive \
             hardening or a rootkit turning off exactly the vantages that would expose it — a \
             blinded privileged scan is not a clean one, so this is a lead, not an all-clear",
        ));
    }
    if !privileged {

        f.push(Finding::flag(
            Severity::Note,
            "blinded while privileged",
            "not established",
            "DID NOT RUN: this check needs uid 0",
            "kallsyms, /proc/kcore and tracefs are all closed to an unprivileged reader \
             whatever the kernel's posture, so their absence here is not evidence. Re-run as \
             root: a rootkit closing exactly these vantages is what this row exists to catch",
        ));
    }

    for (path, what) in [
        ("/sys/kernel/kexec_loaded", "a kexec kernel is staged for the next reboot"),
        ("/sys/kernel/kexec_crash_loaded", "a kexec crash kernel is loaded"),
    ] {
        if let Some(finding) = kexec_finding(path, what, &read_state(path)) {
            f.push(finding);
        }
    }

    let cmdline = match read_state("/proc/cmdline") {
        Ok(c) => Some(c),
        Err(e) => {
            f.push(Finding::flag(
                Severity::Note,
                "kernel cmdline",
                format!("/proc/cmdline could not be read ({e})"),
                "DID NOT RUN",
                "the boot parameters were not examined by this run, so nothing here rules out \
                 a kernel told at boot to drop its own defences",
            ));
            None
        }
    };
    if let Some(cmdline) = cmdline {
        for (needle, why) in [
            ("module.sig_enforce=0", "module signing was turned off on the kernel command line"),
            ("lockdown=none", "kernel lockdown was explicitly disabled at boot"),
            ("nokaslr", "kernel address randomization was disabled, easing kernel-text patching"),
            ("rdinit=", "a custom early init was set — an initramfs-stage hijack"),
        ] {
            if cmdline.contains(needle) {
                f.push(Finding::flag(
                    Severity::Warn,
                    "kernel cmdline",
                    needle.to_string(),
                    format!("boot parameter present: {needle}"),
                    why,
                ));
            }
        }

        if let Some(path) = boot_param(&cmdline, "init") {
            let normal = ["/sbin/init", "/usr/lib/systemd/systemd", "/lib/systemd/systemd", "/usr/sbin/init"];
            if !path.is_empty() && !normal.contains(&path) {
                f.push(Finding::flag(
                    Severity::Warn,
                    "kernel cmdline",
                    format!("init={path}"),
                    "the kernel was told to run a non-standard init",
                    "init= overrides PID 1; an unexpected path is a boot-stage backdoor",
                ));
            }
        }
    }

    for k in POSTURE_KNOBS {
        if let Some(finding) = posture_finding(k, &read_state(k.path)) {
            f.push(finding);
        }
    }

    rank(&mut f);
    Report { findings: f, privileged }
}
