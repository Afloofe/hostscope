use crate::rootkit::{Finding, Severity};
use crate::syscallhook::{
    kallsyms_is_restricted, ktext_bounds, module_at, parse_kallsyms, parse_modules, ModuleRange,
    WATCHED_FNS,
};

const ENABLED_FUNCTIONS: &[&str] = &[
    "/sys/kernel/tracing/enabled_functions",
    "/sys/kernel/debug/tracing/enabled_functions",
];

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,

    pub traced_functions: usize,

    pub watched_traced: usize,
}

struct TraceLine {
    func: String,
    addrs: Vec<u64>,
    named_modules: Vec<String>,
}

fn parse_trace_line(line: &str) -> Option<TraceLine> {
    let func = line.split_whitespace().next()?.to_string();
    if func.is_empty() {
        return None;
    }
    Some(TraceLine { func, addrs: hex_addrs(line), named_modules: bracket_modules(line) })
}

fn bracket_modules(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(open) = rest.find('[') {
        let after = &rest[open + 1..];
        if let Some(close) = after.find(']') {
            let name = &after[..close];
            if !name.is_empty() && !out.iter().any(|n| n == name) {
                out.push(name.to_string());
            }
            rest = &after[close + 1..];
        } else {
            break;
        }
    }
    out
}

const KERNEL_VA_MIN: u64 = 0xffff_8000_0000_0000;

fn hex_addrs(line: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b.get(i) == Some(&b'0') && matches!(b.get(i + 1), Some(&b'x') | Some(&b'X')) {
            let start = i + 2;
            let mut j = start;
            while b.get(j).is_some_and(|c| c.is_ascii_hexdigit()) {
                j += 1;
            }
            if j > start {
                if let Ok(v) = u64::from_str_radix(line.get(start..j).unwrap_or(""), 16) {
                    if v >= KERNEL_VA_MIN {
                        out.push(v);
                    }
                }
            }
            i = j.max(i + 2);
        } else {
            i += 1;
        }
    }
    out
}

fn classify(
    line: &TraceLine,
    modules: &[ModuleRange],
    ktext: Option<(u64, u64)>,
) -> Option<Finding> {
    let watched = WATCHED_FNS.contains(&line.func.as_str());

    let addr_module = line.addrs.iter().find_map(|a| module_at(modules, *a)).map(|m| m.name.clone());
    let module_name = addr_module.clone().or_else(|| {
        if watched { line.named_modules.first().cloned() } else { None }
    });

    if let Some(name) = module_name {
        let sev = if watched { Severity::Critical } else { Severity::Warn };
        let lead = if watched {
            "a syscall handler dispatched through ftrace into a loaded module is an ftrace-based \
             kernel hook — the technique that leaves the prologue clean, so the inline scan cannot \
             see it"
        } else {
            "a loaded module has installed an ftrace hook on this kernel function; usually a \
             rootkit, occasionally a live-patch — identify the module before trusting it"
        };
        return Some(Finding {
            severity: sev,
            subject: format!("ftrace: {}", line.func),
            what: format!("is traced with a callback in loaded module `{name}`"),
            why: format!("{lead}. Module `{name}` is not hidden from /proc/modules unless it also \
                          unlinked itself"),
        });
    }

    if watched {
        let outside = line.addrs.iter().any(|a| ktext.is_some_and(|(s, e)| *a < s || *a >= e));
        if outside {
            return Some(Finding {
                severity: Severity::Warn,
                subject: format!("ftrace: {}", line.func),
                what: "is traced with a callback outside kernel text".into(),
                why: "a syscall redirected through ftrace to code outside the kernel's own .text: \
                      a BPF fentry monitor, a live-patch, or a rootkit trampoline all look alike \
                      here — identify the tracer. The inline-prologue scan will not see it, because \
                      the prologue stays the legitimate ftrace call"
                    .into(),
            });
        }

        return Some(Finding {
            severity: Severity::Note,
            subject: format!("ftrace: {}", line.func),
            what: "has an ftrace ops attached".into(),
            why: if ktext.is_some() {
                "a syscall handler is being traced; on a quiet server that is itself worth a \
                 glance, though the callback resolves inside kernel text"
                    .into()
            } else {
                "a syscall handler is being traced, and where its callback lands was NOT \
                 judged: kallsyms gave no kernel-text bounds. Identify the tracer by hand"
                    .into()
            },
        });
    }
    None
}

pub fn report() -> Report {
    let Ok(kallsyms) = crate::saferead::read_kernel_text("/proc/kallsyms") else {
        return unavailable("/proc/kallsyms could not be read");
    };
    let (by_name, _sorted) = parse_kallsyms(&kallsyms);
    if kallsyms_is_restricted(&by_name) {
        return unavailable(
            "/proc/kallsyms returned only zeroed addresses — this needs root; without symbol \
             addresses an ftrace callback cannot be placed inside or outside kernel text",
        );
    }

    let Some((path, text)) = ENABLED_FUNCTIONS
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok().map(|t| (*p, t)))
    else {
        return unavailable(
            "tracefs enabled_functions could not be read (tried /sys/kernel/tracing and \
             /sys/kernel/debug/tracing) — this needs root and a mounted tracefs",
        );
    };
    let _ = path;

    let modules_read = crate::saferead::read_kernel_text("/proc/modules");
    let modules = modules_read.as_ref().map(|t| parse_modules(t)).unwrap_or_default();
    let ktext = ktext_bounds(&by_name);

    let mut findings = Vec::new();

    findings.extend(crate::kptrhooks::partial_scan(
        "ftrace-hooks",
        modules_read.is_err(),
        ktext.is_none(),
    ));
    let mut traced_functions = 0;
    let mut watched_traced = 0;
    for line in text.lines() {
        let Some(tl) = parse_trace_line(line) else { continue };
        traced_functions += 1;
        if WATCHED_FNS.contains(&tl.func.as_str()) {
            watched_traced += 1;
        }
        if let Some(f) = classify(&tl, &modules, ktext) {
            findings.push(f);
        }
    }

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    Report { findings, available: true, reason: None, traced_functions, watched_traced }
}

fn unavailable(reason: &str) -> Report {
    Report {
        findings: Vec::new(),
        available: false,
        reason: Some(reason.to_string()),
        traced_functions: 0,
        watched_traced: 0,
    }
}
