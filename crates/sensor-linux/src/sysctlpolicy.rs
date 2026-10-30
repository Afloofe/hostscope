use std::path::PathBuf;

use crate::rootkit::{Finding, Severity};

pub const DROP_IN: &str = "/etc/sysctl.d/99-zz-hemostat-hardening.conf";

pub const LEGACY_DROP_IN: &str = "/etc/sysctl.d/00-hemostat-hardening.conf";

pub fn overriding_files(keys: &[&str]) -> (Vec<(PathBuf, String)>, Vec<String>) {
    let mine = PathBuf::from(DROP_IN);
    let Some(my_name) = mine.file_name().and_then(|n| n.to_str()) else {
        return (Vec::new(), Vec::new());
    };
    let mut out = Vec::new();

    let mut unreadable = Vec::new();

    for dir in ["/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d"] {
        let rd = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                unreadable.push(format!("{dir} ({e})"));
                continue;
            }
        };
        for e in rd.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("conf") {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };

            if name == my_name {
                continue;
            }
            if name <= my_name {
                continue;
            }

            let Some((text, truncated)) = crate::saferead::read_scan_target_bounded(&path) else {
                unreadable.push(format!("{} (unreadable)", path.display()));
                continue;
            };
            if truncated {
                unreadable.push(format!("{} (read only in part)", path.display()));
            }
            for line in text.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.starts_with(';') {
                    continue;
                }
                let Some((k, _)) = line.split_once('=') else { continue };
                for key in keys {
                    if sysctl_key_matches(k, key) {
                        out.push((path.clone(), (*key).to_string()));
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    (out, unreadable)
}

pub fn sysctl_key_matches(written: &str, key: &str) -> bool {
    let written = written.trim();
    let written = written.strip_prefix('-').unwrap_or(written).trim();
    let norm = |s: &str| s.replace('/', ".");
    let (w, k) = (norm(written), norm(key));
    let (wp, kp): (Vec<&str>, Vec<&str>) = (w.split('.').collect(), k.split('.').collect());
    wp.len() == kp.len() && wp.iter().zip(&kp).all(|(a, b)| glob_component(a, b))
}

fn glob_component(pattern: &str, value: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == value,
        Some((head, tail)) => {
            value.len() >= head.len() + tail.len()
                && value.starts_with(head)
                && glob_component(tail, &value[value.len().saturating_sub(tail.len())..])
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auto {

    Offer,

    ReportOnly(&'static str),
}

#[derive(Debug, Clone, Copy)]
pub struct Control {

    pub keys: &'static [&'static str],

    pub want: &'static str,

    pub stronger: &'static [(&'static str, &'static str)],

    pub severity: Severity,

    pub why: &'static str,

    pub breaks: &'static str,

    pub auto: Auto,
}

pub const CONTROLS: &[Control] = &[
    Control {
        keys: &["kernel.randomize_va_space"],
        want: "2",
        stronger: &[],
        severity: Severity::Critical,
        why: "full address-space randomisation is what makes memory-corruption exploits \
              unreliable. A 0 here is not a default anywhere — somebody turned it off, and \
              turning it off is a step in several exploitation guides",
        breaks: "software that needs a fixed memory layout: some old JITs, a few licence \
                 dongles, and debugging workflows that assume stable addresses",
        auto: Auto::Offer,
    },
    Control {
        keys: &["fs.protected_symlinks"],
        want: "1",
        stronger: &[],
        severity: Severity::Warn,
        why: "without it, following a symlink in a world-writable sticky directory across \
              owners is allowed — the classic /tmp symlink race that turns a root-owned \
              write into an arbitrary-file overwrite",
        breaks: "legacy build systems and spool code that deliberately follow another user's \
                 symlink in /tmp. Denials appear as EACCES and are logged",
        auto: Auto::Offer,
    },
    Control {
        keys: &["fs.protected_hardlinks"],
        want: "1",
        stronger: &[],
        severity: Severity::Warn,
        why: "without it, a user can hardlink a file they cannot read into a directory they \
              control and wait for something privileged to write through it",
        breaks: "code that hardlinks a file it neither owns nor can read, across UIDs in /tmp. \
                 A distribution default for a decade",
        auto: Auto::Offer,
    },
    Control {
        keys: &["fs.protected_fifos"],
        want: "1",
        stronger: &[("", "2")],
        severity: Severity::Note,
        why: "stops a process being tricked into opening a FIFO another user planted in a \
              shared directory",
        breaks: "very little; it has been the systemd default for years",
        auto: Auto::Offer,
    },
    Control {
        keys: &["fs.suid_dumpable"],
        want: "0",
        stronger: &[],
        severity: Severity::Warn,
        why: "a setuid program that dumps core writes memory it holds privileged to a file — \
              which is a way to read secrets out of a process you could not otherwise touch",
        breaks: "debugging crashes in setuid binaries. Rarely wanted on a server",
        auto: Auto::Offer,
    },
    Control {
        keys: &["kernel.dmesg_restrict"],
        want: "1",
        stronger: &[],
        severity: Severity::Warn,
        why: "the kernel ring buffer leaks addresses and hardware detail useful for building \
              an exploit against this specific kernel",
        breaks: "non-root `dmesg`, and monitoring or log-shipping agents that read /dev/kmsg \
                 as an unprivileged user. Root and CAP_SYSLOG are unaffected, and journald \
                 still ingests kernel messages",
        auto: Auto::Offer,
    },
    Control {
        keys: &["kernel.yama.ptrace_scope"],
        want: "1",
        stronger: &[("", "2"), ("", "3")],
        severity: Severity::Note,
        why: "restricts ptrace to descendants, so one compromised process cannot read the \
              memory — and the credentials — of every other process the same user owns",
        breaks: "debuggers attaching to a running process they did not start (gdb -p, strace \
                 -p) without root, and some crash-reporting agents",
        auto: Auto::Offer,
    },
    Control {
        keys: &["kernel.unprivileged_bpf_disabled"],
        want: "2",

        stronger: &[("", "1")],
        severity: Severity::Warn,
        why: "unprivileged BPF has been a repeated source of local privilege escalation. 2 \
              closes it without disturbing anything that already has privilege",
        breaks: "unprivileged tooling that loads BPF — some profilers run by ordinary users. \
                 Root-run tools, this agent's own included, are unaffected",
        auto: Auto::Offer,
    },
    Control {
        keys: &["net.core.bpf_jit_harden"],
        want: "1",
        stronger: &[("", "2")],
        severity: Severity::Note,
        why: "constant blinding makes it much harder to smuggle an executable payload into \
              the kernel through a JIT-compiled BPF program",
        breaks: "a measurable slowdown in BPF-heavy paths; nothing functional",
        auto: Auto::Offer,
    },
    Control {
        keys: &[
            "net.ipv4.conf.all.accept_redirects",
            "net.ipv4.conf.default.accept_redirects",
            "net.ipv6.conf.all.accept_redirects",
            "net.ipv6.conf.default.accept_redirects",
        ],
        want: "0",
        stronger: &[],
        severity: Severity::Warn,
        why: "an ICMP redirect rewrites this host's routing table on the say-so of anything \
              on the local segment, which is a way to put an attacker in the middle of \
              traffic that was never going past them",
        breaks: "networks that genuinely rely on redirects to steer hosts to a better \
                 gateway. Uncommon, and a design most places have moved off",
        auto: Auto::Offer,
    },
    Control {
        keys: &[
            "net.ipv4.conf.all.accept_source_route",
            "net.ipv4.conf.default.accept_source_route",
            "net.ipv6.conf.all.accept_source_route",
            "net.ipv6.conf.default.accept_source_route",
        ],
        want: "0",
        stronger: &[("net.ipv6.", "-1")],
        severity: Severity::Warn,
        why: "source routing lets the sender choose the return path, which is how filtering \
              and anti-spoofing get walked around",
        breaks: "effectively nothing — it has been disabled by default for years and there \
                 is almost no legitimate use left",
        auto: Auto::Offer,
    },
    Control {
        keys: &["net.ipv4.conf.all.send_redirects", "net.ipv4.conf.default.send_redirects"],
        want: "0",
        stronger: &[],
        severity: Severity::Note,
        why: "a host that is not a router has no business emitting redirects, and doing so \
              tells the segment about its routing table",
        breaks: "nothing on a host that is not routing between networks. If this machine IS \
                 a router, leave it alone",
        auto: Auto::Offer,
    },
    Control {
        keys: &["net.ipv4.icmp_echo_ignore_broadcasts"],
        want: "1",
        stronger: &[],
        severity: Severity::Note,
        why: "answering broadcast pings makes this host a usable amplifier in a smurf attack \
              against somebody else",
        breaks: "broadcast-ping based discovery, which almost nothing uses",
        auto: Auto::Offer,
    },
    Control {
        keys: &["net.ipv4.tcp_syncookies"],
        want: "1",
        stronger: &[],
        severity: Severity::Note,
        why: "keeps the host answering during a SYN flood instead of filling its backlog",
        breaks: "nothing in practice; it only engages when the backlog is already full. This \
                 is the kernel default",
        auto: Auto::Offer,
    },
    Control {
        keys: &["net.ipv4.conf.all.log_martians", "net.ipv4.conf.default.log_martians"],
        want: "1",
        stronger: &[],
        severity: Severity::Note,
        why: "records packets arriving with impossible source addresses, which is often the \
              first visible sign of spoofing on the segment",
        breaks: "log volume on a noisy network. Nothing functional",
        auto: Auto::Offer,
    },

    Control {
        keys: &["kernel.kptr_restrict"],
        want: "1",

        stronger: &[("", "2")],
        severity: Severity::Warn,
        why: "kernel pointers in /proc/kallsyms and sysfs hand an attacker the addresses \
              needed to aim an exploit at this kernel",
        breaks: "at 1, unprivileged symbol resolution (perf, bpftrace). At 2, symbol \
                 resolution for EVERYONE including root",
        auto: Auto::ReportOnly(
            "setting this to 2 would blind THIS AGENT: the syscall-hook, ftrace-hook, \
             kptr-hook, kernel-walk and sysmap checks all resolve symbols through \
             /proc/kallsyms and report DID NOT RUN when it reads as zeros. Hardening the \
             host by disabling its rootkit detection is not a trade to make during an \
             incident. Set it deliberately, after the sweep, if you want it",
        ),
    },
    Control {
        keys: &["net.ipv4.conf.all.rp_filter"],
        want: "1",
        stronger: &[],
        severity: Severity::Note,
        why: "strict reverse-path filtering drops packets arriving on an interface the reply \
              would not leave by, which stops a lot of spoofing",
        breaks: "any host with more than one path to a network — multi-homed servers, \
                 policy routing, some VPN and container setups — where asymmetric routing is \
                 correct and strict mode silently drops legitimate traffic",
        auto: Auto::ReportOnly(
            "strict mode is right on a single-homed host and quietly breaks a multi-homed \
             one, and this agent cannot tell which this is from the routing table alone. \
             Decide it yourself",
        ),
    },
    Control {
        keys: &["kernel.modules_disabled"],
        want: "1",
        stronger: &[],
        severity: Severity::Note,
        why: "once set, no further kernel module can be loaded — which closes the most direct \
              route a root-level attacker has into the kernel",
        breaks: "every module load for the rest of this boot: hot-plugged hardware, \
                 filesystems mounted for the first time, network drivers",
        auto: Auto::ReportOnly(
            "this is a ONE-WAY door. It cannot be unset without rebooting, so an undo \
             journal cannot reverse it and a mistake costs a reboot of a machine that may be \
             mid-incident",
        ),
    },
    Control {
        keys: &["kernel.kexec_load_disabled"],
        want: "1",
        stronger: &[],
        severity: Severity::Note,
        why: "kexec can boot a new kernel straight from a running one, bypassing Secure Boot \
              and every measurement taken at boot",
        breaks: "kdump crash capture, and kexec-based fast reboots",
        auto: Auto::ReportOnly(
            "also a one-way door until reboot, and it disables kdump — which is how a crash \
             during an incident would have been captured",
        ),
    },
];

pub fn proc_path(key: &str) -> Option<PathBuf> {
    let leads = key.chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
    (leads && !key.contains('/')).then(|| PathBuf::from("/proc/sys").join(key.replace('.', "/")))
}

pub fn read(key: &str) -> Option<String> {
    std::fs::read_to_string(proc_path(key)?).ok().map(|s| s.trim().to_string())
}

pub fn write(key: &str, value: &str) -> Result<(), String> {
    let p = proc_path(key).ok_or_else(|| format!("{key:?} is not a sysctl key"))?;
    if !p.exists() {
        return Err(format!("{key} does not exist on this kernel"));
    }
    std::fs::write(&p, format!("{value}\n")).map_err(|e| format!("{key}: {e}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,
}

pub fn holds(c: &Control, key: &str, value: &str) -> bool {
    value == c.want
        || c.stronger.iter().any(|(prefix, v)| key.starts_with(prefix) && value == *v)
}

fn recorded_keys(c: &Control, now: impl Fn(&str) -> Option<String>) -> Vec<&'static str> {
    c.keys
        .iter()
        .copied()
        .filter(|k| !now(k).is_some_and(|v| v != c.want && holds(c, k, &v)))
        .collect()
}

pub fn failing(c: &Control) -> Vec<(String, String)> {
    c.keys
        .iter()
        .filter_map(|k| read(k).map(|v| (k.to_string(), v)))
        .filter(|(k, v)| !holds(c, k, v))
        .collect()
}

pub fn report() -> Report {
    if !PathBuf::from("/proc/sys").is_dir() {
        return Report {
            findings: Vec::new(),
            available: false,
            reason: Some("/proc/sys is not present, so no kernel tunable could be read".into()),
        };
    }

    let mut findings = Vec::new();
    for c in CONTROLS {
        let bad = failing(c);
        if bad.is_empty() {
            continue;
        }
        let listed: Vec<String> =
            bad.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let why = match c.auto {
            Auto::Offer => format!("{}. Applying this costs: {}", c.why, c.breaks),
            Auto::ReportOnly(reason) => {
                format!("{}. NOT OFFERED AS A FIX — {reason}. Cost if you do it: {}", c.why, c.breaks)
            }
        };
        findings.push(Finding {
            severity: c.severity,
            subject: format!("sysctl · {}", c.keys[0]),
            what: format!(
                "{} (should be {})",
                listed.join(", "),
                c.want
            ),
            why,
        });
    }
    Report { findings, available: true, reason: None }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {

    pub was: Vec<(String, String)>,

    pub now: String,

    pub persisted: bool,

    pub persist_error: Option<String>,
}

pub fn apply(c: &Control) -> Result<Applied, String> {
    if let Auto::ReportOnly(reason) = c.auto {
        return Err(format!("this one is not applied automatically: {reason}"));
    }
    let bad = failing(c);
    if bad.is_empty() {
        return Err("already at the hardened value".into());
    }

    let mut done: Vec<(String, String)> = Vec::new();
    let undo = |done: &[(String, String)]| {
        for (k, old) in done {
            let _ = write(k, old);
        }
    };

    for (key, old) in &bad {
        if let Err(e) = write(key, c.want) {
            undo(&done);
            return Err(format!(
                "{e}; the {} key(s) already changed were put back, so nothing is half-applied",
                done.len()
            ));
        }

        match read(key) {
            Some(now) if now == c.want => done.push((key.clone(), old.clone())),
            Some(now) => {
                undo(&done);
                return Err(format!(
                    "{key} was written as {} but reads back as {now}; the kernel did not take \
                     it. Everything already changed was put back",
                    c.want
                ));
            }
            None => {
                undo(&done);
                return Err(format!("{key} vanished while being written"));
            }
        }
    }

    let (persisted, persist_error) = match persist(c) {
        Ok(()) => (true, None),
        Err(e) => (false, Some(e)),
    };
    Ok(Applied { was: done, now: c.want.to_string(), persisted, persist_error })
}

const SYSCTL_D: &str = "/etc/sysctl.d";

fn drop_in_name(path: &str) -> Result<&str, String> {
    let p = std::path::Path::new(path);
    match (p.parent(), p.file_name().and_then(|n| n.to_str())) {
        (Some(dir), Some(name)) if dir == std::path::Path::new(SYSCTL_D) => Ok(name),
        _ => Err(format!("{path} is not a drop-in in {SYSCTL_D}")),
    }
}

pub fn persist(c: &Control) -> Result<(), String> {
    let name = drop_in_name(DROP_IN)?;
    let dir = crate::safewrite::Pinned::create(std::path::Path::new(SYSCTL_D), 0o755)
        .map_err(|e| format!("{SYSCTL_D}: {e}"))?;
    let existing = dir
        .read_own(name, crate::saferead::MAX_SCAN_BYTES)
        .map_err(|e| format!("{DROP_IN}: {e}"))?
        .unwrap_or_default();
    let mut lines: Vec<String> = existing
        .lines()
        .filter(|l| {
            let key = l.split('=').next().unwrap_or("").trim();
            !c.keys.contains(&key)
        })
        .map(str::to_string)
        .collect();
    if lines.is_empty() {
        lines.push("# Written by HEMOSTAT. Each value was applied to the running kernel and".into());
        lines.push("# read back before being recorded here. Delete a line to stop persisting it.".into());
    }
    for k in recorded_keys(c, read) {
        lines.push(format!("{k} = {}", c.want));
    }
    dir.replace(name, format!("{}\n", lines.join("\n")).as_bytes(), 0o644)
        .map_err(|e| format!("{DROP_IN}: {e}"))?;

    let legacy = drop_in_name(LEGACY_DROP_IN).ok();
    if let Some((legacy, old_text)) = legacy.and_then(|l| {
        dir.read_own(l, crate::saferead::MAX_SCAN_BYTES).ok().flatten().map(|t| (l, t))
    }) {
        let kept: Vec<&str> = old_text
            .lines()
            .filter(|l| {
                let key = l.split('=').next().unwrap_or("").trim();
                !c.keys.contains(&key)
            })
            .collect();
        let meaningful = kept.iter().any(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        });
        let _ = if meaningful {
            dir.replace(legacy, format!("{}\n", kept.join("\n")).as_bytes(), 0o644)
        } else {
            dir.remove(legacy)
        };
    }

    let (clashes, unreadable) = overriding_files(c.keys);
    if !unreadable.is_empty() {
        return Err(format!(
            "recorded in {DROP_IN}, but whether it survives a reboot was NOT established: {} \
             could not be read, and systemd-sysctl applies every drop-in across those \
             directories in filename order with the last setter winning. Re-check with access \
             to them before treating this as persisted",
            unreadable.join(", ")
        ));
    }
    if !clashes.is_empty() {
        let names: Vec<String> = clashes
            .iter()
            .map(|(p, k)| format!("{} sets {k}", p.display()))
            .collect();
        return Err(format!(
            "recorded in {DROP_IN}, but it will NOT survive a reboot: {} — systemd-sysctl \
             sorts every drop-in by filename and the last one to set a key wins. Remove or \
             edit the offending line, then re-apply",
            names.join("; ")
        ));
    }
    Ok(())
}

pub fn unpersist(keys: &[&str]) -> Result<(), String> {
    let name = drop_in_name(DROP_IN)?;
    let dir = match crate::safewrite::Pinned::open(std::path::Path::new(SYSCTL_D)) {
        Ok(d) => d,

        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{SYSCTL_D}: {e}")),
    };
    let Some(text) = dir
        .read_own(name, crate::saferead::MAX_SCAN_BYTES)
        .map_err(|e| format!("{DROP_IN}: {e}"))?
    else {

        return Ok(());
    };
    match without_keys(&text, keys) {
        Some(body) => dir.replace(name, body.as_bytes(), 0o644).map_err(|e| format!("{DROP_IN}: {e}")),
        None => dir.remove(name).map_err(|e| format!("{DROP_IN}: {e}")),
    }
}

pub fn without_keys(text: &str, keys: &[&str]) -> Option<String> {
    let kept: Vec<&str> = text
        .lines()
        .filter(|l| {
            let key = l.split('=').next().unwrap_or("").trim();
            !keys.contains(&key)
        })
        .collect();
    let meaningful = kept.iter().any(|l| {
        let t = l.trim();
        !t.is_empty() && !t.starts_with('#')
    });
    if meaningful {
        Some(format!("{}\n", kept.join("\n")))
    } else {
        None
    }
}
