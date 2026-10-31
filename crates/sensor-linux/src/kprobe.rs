use crate::rootkit::{Finding, Severity};

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,

    pub kprobe_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Kprobe {

    addr: String,

    symbol: String,

    offset: String,

    kind: char,

    module: Option<String>,

    disabled: bool,

    gone: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KprobeEvent {

    kind: char,

    group: String,

    event: String,

    module: Option<String>,

    symbol: String,
}

const SENSITIVE_SYSCALLS: &[&str] = &[
    "getdents", "getdents64", "readdir", "kill", "tkill", "tgkill", "execve",
    "execveat", "ptrace", "openat", "openat2", "open", "read", "write", "bpf",
    "init_module", "finit_module", "delete_module",
];

const SYSCALL_PREFIXES: &[&str] = &[
    "__x64_sys_", "__ia32_sys_", "__x32_compat_sys_", "__arm64_sys_",
    "__se_sys_", "__do_sys_", "ksys_", "sys_",
];

fn strip_syscall_prefix(symbol: &str) -> Option<&str> {
    for p in SYSCALL_PREFIXES {
        if let Some(rest) = symbol.strip_prefix(p) {

            return Some(rest.split('.').next().unwrap_or(rest));
        }
    }
    None
}

fn sensitive_reason(symbol: &str) -> Option<&'static str> {
    match symbol {
        "kallsyms_lookup_name" => {
            return Some(
                "kallsyms_lookup_name — the symbol resolver unexported in Linux 5.7, which is why \
                 modern rootkits kprobe it to recover the address of everything else they hook",
            );
        }
        "filldir" | "filldir64" | "__filldir64" => {
            return Some(
                "the directory-fill callback a getdents-hiding rootkit rewrites to drop entries \
                 from a listing",
            );
        }
        "tcp4_seq_show" | "tcp6_seq_show" | "udp4_seq_show" | "udp6_seq_show" => {
            return Some(
                "a /proc/net socket lister hooked to hide a listening port or an active \
                 connection from netstat/ss",
            );
        }
        "ip_rcv" | "ip6_rcv" => {
            return Some(
                "the IP receive path, hooked for a passive packet-triggered backdoor \
                 (a magic packet that opens a shell)",
            );
        }
        _ => {}
    }
    if symbol.starts_with("security_") {

        return Some(
            "an LSM security_* hook — a kprobe on the access-control path can silently grant or \
             deny permission checks (privilege escalation, or hiding an action from audit)",
        );
    }
    if let Some(base) = strip_syscall_prefix(symbol) {
        if SENSITIVE_SYSCALLS.contains(&base) {
            return Some(
                "a syscall entry point of the class rootkits hook to hide files, processes, \
                 modules or network state, or to run a signal/exec-based control channel",
            );
        }
    }
    None
}

fn split_sym_offset(tok: &str) -> (String, String) {
    match tok.find('+') {
        Some(i) => (tok[..i].to_string(), tok[i + 1..].to_string()),
        None => (tok.to_string(), String::new()),
    }
}

fn parse_kprobe_line(line: &str) -> Option<Kprobe> {
    let mut toks = line.split_whitespace();
    let addr = toks.next()?.to_string();
    let kind = match toks.next()? {
        "k" => 'k',
        "r" => 'r',
        _ => return None,
    };
    let (symbol, offset) = split_sym_offset(toks.next()?);

    let mut module = None;
    let mut disabled = false;
    let mut gone = false;
    for t in toks {
        if t.starts_with('[') {

            disabled |= t.contains("[DISABLED]");
            gone |= t.contains("[GONE]");
        } else if module.is_none() {
            module = Some(t.to_string());
        }
    }
    Some(Kprobe { addr, symbol, offset, kind, module, disabled, gone })
}

fn parse_kprobes_list(text: &str) -> Vec<Kprobe> {
    text.lines().filter_map(parse_kprobe_line).collect()
}

fn parse_kprobe_event_line(line: &str) -> Option<KprobeEvent> {
    let mut toks = line.split_whitespace();
    let head = toks.next()?;
    let (kindpart, ge) = head.split_once(':')?;
    let kind = match kindpart.chars().next()? {
        'p' => 'k',
        'r' => 'r',
        _ => return None,
    };
    let (group, event) = ge.split_once('/').unwrap_or(("", ge));
    let probe = toks.next()?;
    let (module, symraw) = match probe.split_once(':') {
        Some((m, s)) => (Some(m.to_string()), s),
        None => (None, probe),
    };
    let symbol = symraw.split('+').next().unwrap_or(symraw).to_string();
    Some(KprobeEvent { kind, group: group.to_string(), event: event.to_string(), module, symbol })
}

fn parse_kprobe_events(text: &str) -> Vec<KprobeEvent> {
    text.lines().filter_map(parse_kprobe_event_line).collect()
}

fn finding_for_kprobe(kp: &Kprobe, reason: &str) -> Finding {
    let kindword = if kp.kind == 'r' { "kretprobe" } else { "kprobe" };
    let off = if kp.offset.is_empty() { String::new() } else { format!("+{}", kp.offset) };
    let modpart = match &kp.module {
        Some(m) => format!(", probed address resolving inside module `{m}`"),
        None => String::new(),
    };
    let state = if kp.gone {
        " [GONE — defunct, its owning module was unloaded]"
    } else if kp.disabled {
        " [DISABLED — registered but not currently firing]"
    } else {
        ""
    };
    let severity = if kp.gone { Severity::Note } else { Severity::Warn };
    Finding {
        severity,
        subject: format!("{kindword} on {}", kp.symbol),
        what: format!(
            "a {kindword} is registered at {}{off} (addr {}){modpart}{state}",
            kp.symbol, kp.addr
        ),
        why: format!(
            "{reason}. Since kallsyms_lookup_name was unexported in Linux 5.7, kernel rootkits \
             register a kprobe on the target rather than patching the syscall table or its \
             prologue — so this class of hook is invisible to the kernel-text and ftrace scans \
             and is caught here or not at all. This is a lead, not a verdict: legitimate \
             observability (bpftrace, perf, SystemTap) also kprobes syscalls and lands in the \
             same list, so confirm what registered it — treat it as critical only if the \
             registrant is a hidden or unrecognised module."
        ),
    }
}

fn finding_for_event(ev: &KprobeEvent, reason: &str) -> Finding {
    let kindword = if ev.kind == 'r' { "kretprobe" } else { "kprobe" };
    let modpart = match &ev.module {
        Some(m) => format!(" in module `{m}`"),
        None => String::new(),
    };
    Finding {
        severity: Severity::Note,
        subject: format!("kprobe_events entry on {}", ev.symbol),
        what: format!(
            "tracefs defines a dynamic {kindword} event `{}/{}` on {}{modpart}",
            ev.group, ev.event, ev.symbol
        ),
        why: format!(
            "{reason}. This came from the tracefs kprobe_events interface — how bpftrace, perf \
             and ftrace install kprobes — so it is almost always legitimate observability, shown \
             as context. The registered-kprobe list is the stronger signal; this matters only if \
             an attacker is driving the tracing subsystem itself."
        ),
    }
}

fn read_first(paths: &[&str]) -> Option<String> {
    paths.iter().find_map(|p| crate::saferead::read_kernel_text(p).ok())
}

pub fn report() -> Report {
    let Ok(list_text) = crate::saferead::read_kernel_text("/sys/kernel/debug/kprobes/list") else {
        return Report {
            available: false,
            reason: Some(
                "/sys/kernel/debug/kprobes/list could not be read — it is root-only and needs \
                 CONFIG_KPROBES=y with debugfs mounted at /sys/kernel/debug; without it a \
                 kprobe-based hook cannot be enumerated, so this is 'could not look', not 'clean'"
                    .into(),
            ),
            ..Report::default()
        };
    };

    let kprobes = parse_kprobes_list(&list_text);
    let mut findings = Vec::new();
    for kp in &kprobes {
        if let Some(reason) = sensitive_reason(&kp.symbol) {
            findings.push(finding_for_kprobe(kp, reason));
        }
    }

    if let Some(text) = read_first(&[
        "/sys/kernel/tracing/kprobe_events",
        "/sys/kernel/debug/tracing/kprobe_events",
    ]) {
        for ev in parse_kprobe_events(&text) {
            if let Some(reason) = sensitive_reason(&ev.symbol) {
                findings.push(finding_for_event(&ev, reason));
            }
        }
    }

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    Report { findings, available: true, reason: None, kprobe_count: kprobes.len() }
}
