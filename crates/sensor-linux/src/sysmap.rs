use std::collections::BTreeMap;
use std::fs;

use crate::rootkit::{Finding, Severity};

const ANCHOR: &str = "_stext";

const WATCHED: &[&str] = &[
    "_stext",
    "_etext",
    "sys_call_table",
    "__x64_sys_getdents64",
    "__x64_sys_getdents",
    "__x64_sys_kill",
    "__x64_sys_newuname",
    "__x64_sys_openat",
    "__x64_sys_read",
    "__x64_sys_write",
    "__x64_sys_bpf",
    "m_show",
    "tcp4_seq_show",
    "tcp6_seq_show",
    "udp4_seq_show",
    "udp6_seq_show",
];

const MIN_COMPARED: usize = 3;

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,

    pub map_path: Option<String>,

    pub release: Option<String>,

    pub compared: usize,

    pub slide: Option<i128>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SymMismatch {
    name: String,

    on_disk: u64,

    live: u64,

    expected: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Comparison {

    slide: i128,

    compared: usize,

    agree: usize,

    tampered: Vec<SymMismatch>,

    wholesale: bool,

    missing: Vec<(String, &'static str)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {

    Ran(Comparison),

    DidNotRun(String),
}

fn parse_symbol_map(text: &str) -> BTreeMap<String, u64> {
    let mut by_name = BTreeMap::new();
    for line in text.lines() {
        let mut f = line.split_whitespace();
        let (Some(addr), Some(_ty), Some(name)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if let Ok(a) = u64::from_str_radix(addr, 16) {
            by_name.entry(name.to_string()).or_insert(a);
        }
    }
    by_name
}

fn is_restricted(map: &BTreeMap<String, u64>) -> bool {
    !map.is_empty() && map.values().all(|a| *a == 0)
}

fn lists_data_symbols(text: &str) -> bool {
    text.lines().any(|line| {
        let mut f = line.split_whitespace();
        let (Some(_addr), Some(ty)) = (f.next(), f.next()) else { return false };
        !matches!(ty, "t" | "T" | "w" | "W")
    })
}

fn is_data_symbol(name: &str) -> bool {
    matches!(name, "sys_call_table" | "ia32_sys_call_table" | "x32_sys_call_table")
}

fn is_strong_absence(name: &str) -> bool {
    const LOAD_BEARING: &[&str] = &[

        "sys_call_table",
        "ia32_sys_call_table",
        "x32_sys_call_table",

        "_stext",
        "_etext",
    ];
    LOAD_BEARING.contains(&name)
        || name.starts_with("__x64_sys_")
        || name.starts_with("__arm64_sys_")
        || name.starts_with("__ia32_sys_")
        || name.starts_with("ksys_")
}

fn classify(disk: &BTreeMap<String, u64>, live: &BTreeMap<String, u64>) -> Comparison {
    let mut c = Comparison::default();

    for &name in WATCHED {
        match (disk.get(name), live.get(name)) {
            (Some(_), None) => c.missing.push((name.to_string(), "/proc/kallsyms")),
            (None, Some(_)) => c.missing.push((name.to_string(), "System.map")),
            _ => {}
        }
    }

    let (disk_anchor, live_anchor) = (disk[ANCHOR] as i128, live[ANCHOR] as i128);
    c.slide = live_anchor - disk_anchor;

    let mut off = Vec::new();
    for &name in WATCHED {
        let (Some(&dd), Some(&ll)) = (disk.get(name), live.get(name)) else {
            continue;
        };
        c.compared += 1;
        let delta = ll as i128 - dd as i128;
        if delta == c.slide {
            c.agree += 1;
        } else {
            off.push(SymMismatch {
                name: name.to_string(),
                on_disk: dd,
                live: ll,
                expected: (dd as i128 + c.slide) as u64,
            });
        }
    }

    if off.is_empty() {
        return c;
    }

    let non_anchor_agree = c.agree.saturating_sub(1);
    if non_anchor_agree >= 1 && c.agree > off.len() {
        c.tampered = off;
    } else {
        c.wholesale = true;
    }
    c
}

fn evaluate(disk: Option<&BTreeMap<String, u64>>, live: &BTreeMap<String, u64>) -> Outcome {
    if live.is_empty() {
        return Outcome::DidNotRun("/proc/kallsyms was empty or unparseable".into());
    }
    if is_restricted(live) {
        return Outcome::DidNotRun(
            "/proc/kallsyms returned only zeroed addresses — this needs root (CAP_SYSLOG) and \
             kernel.kptr_restrict permitting symbol addresses; without them there is nothing to \
             compare and a zero result is not a clean one"
                .into(),
        );
    }
    let Some(disk) = disk else {
        return Outcome::DidNotRun(
            "no System.map found under /boot (tried System.map-<release> and System.map); \
             minimal and cloud images often ship without one, so this is an untested host, not \
             a clean one"
                .into(),
        );
    };
    if disk.is_empty() {
        return Outcome::DidNotRun("the System.map on disk was empty or unparseable".into());
    }
    if !disk.contains_key(ANCHOR) || !live.contains_key(ANCHOR) {
        return Outcome::DidNotRun(format!(
            "the anchor symbol `{ANCHOR}` is not in both maps, so the KASLR slide cannot be \
             derived and no comparison is trustworthy"
        ));
    }
    let c = classify(disk, live);
    if c.compared < MIN_COMPARED {
        return Outcome::DidNotRun(format!(
            "only {} watched kernel symbol(s) are present in both maps — too few to tell a \
             single rewritten entry from a version mismatch",
            c.compared
        ));
    }
    Outcome::Ran(c)
}

fn fmt_slide(slide: i128) -> String {
    if slide < 0 {
        format!("-0x{:x}", slide.unsigned_abs())
    } else {
        format!("+0x{:x}", slide)
    }
}

fn findings_for(
    c: &Comparison,
    map_path: &str,
    exact_version: bool,
    live_lists_data: bool,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let slide = fmt_slide(c.slide);

    for m in &c.tampered {
        findings.push(Finding {
            severity: Severity::Critical,
            subject: format!("kallsyms entry `{}`", m.name),
            what: format!(
                "live at {:#018x} but the on-disk {map_path} plus the uniform KASLR slide \
                 ({slide}) puts it at {:#018x} (build-time {:#018x})",
                m.live, m.expected, m.on_disk
            ),
            why: "every kernel symbol relocates by one KASLR slide at boot, so one symbol landing \
                  at a *different* offset than the rest cannot be relocation — its /proc/kallsyms \
                  entry was rewritten after boot. That is how a kernel rootkit points a symbol name \
                  at its own handler or hides where it patched, and it poisons every other check \
                  that trusts kallsyms. Treat the host as compromised and audit the live symbol \
                  table against the kernel image"
                .into(),
        });
    }

    if c.wholesale {
        let severity = if exact_version { Severity::Critical } else { Severity::Warn };
        findings.push(Finding {
            severity,
            subject: "kallsyms vs System.map".into(),
            what: format!(
                "of {} watched symbols in both maps, only {} share a single KASLR slide — no one \
                 relocation reconciles /proc/kallsyms with {map_path}",
                c.compared, c.agree
            ),
            why: if exact_version {
                "this is System.map-<release> for the *running* kernel, yet the live symbol table \
                 does not relocate from it by any single slide — the running kernel is not the \
                 image this map describes, or the live table has been wholesale rewritten. Confirm \
                 the running kernel build and treat a match against the expected image as compromise"
                    .into()
            } else {
                "the running kernel does not relocate from this map by any single slide. The common \
                 benign cause is a fallback/unversioned System.map that describes a different build \
                 (a kernel upgraded but not rebooted, or a shared /boot); confirm the map matches \
                 the running kernel before treating it as tampering, then escalate if it should have"
                    .into()
            },
        });
    }

    for (name, missing_from) in &c.missing {

        let build_option = is_data_symbol(name)
            && *missing_from == "/proc/kallsyms"
            && !live_lists_data;
        let handler = is_strong_absence(name) && !build_option;
        findings.push(Finding {
            severity: if handler { Severity::Warn } else { Severity::Note },
            subject: format!("symbol `{name}`"),
            what: format!("is present in one symbol map but absent from {missing_from}"),
            why: if handler {
                "a load-bearing symbol that the kernel image defines but the live symbol table \
                 omits (or the reverse) is a lead that kallsyms was scrubbed of it; for the same \
                 kernel build the two maps should name the same symbols. Scrubbing the dispatch \
                 table or the text bounds is the cheapest way to blind the syscall-table and \
                 inline-hook scans, so their absence is never ordinary. Corroborate against the \
                 kernel-text scan before acting"
                    .into()
            } else {
                "the two symbol maps name a slightly different symbol set. Usually a build/version \
                 difference between the on-disk map and the running kernel rather than tampering \
                 for a non-handler symbol; noted for context"
                    .into()
            },
        });
    }

    findings
}

fn kernel_release() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn system_map_candidates(release: Option<&str>) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    if let Some(rel) = release {
        out.push((format!("/boot/System.map-{rel}"), true));
    }
    out.push(("/boot/System.map".to_string(), false));
    out
}

fn read_system_map(release: Option<&str>) -> Option<(String, String, bool)> {
    for (path, exact) in system_map_candidates(release) {

        if let Some(text) = crate::saferead::read_scan_target(std::path::Path::new(&path)) {
            return Some((text, path, exact));
        }
    }
    None
}

pub fn report() -> Report {
    let release = kernel_release();

    let Ok(kall_text) = crate::saferead::read_kernel_text("/proc/kallsyms") else {
        return Report {
            available: false,
            reason: Some("/proc/kallsyms could not be read".into()),
            release,
            ..Report::default()
        };
    };
    let live = parse_symbol_map(&kall_text);

    let map = read_system_map(release.as_deref());
    let disk = map.as_ref().map(|(text, _, _)| parse_symbol_map(text));
    let map_path = map.as_ref().map(|(_, path, _)| path.clone());
    let exact_version = map.as_ref().map(|(_, _, exact)| *exact).unwrap_or(false);

    match evaluate(disk.as_ref(), &live) {
        Outcome::DidNotRun(reason) => Report {
            available: false,
            reason: Some(reason),
            map_path,
            release,
            ..Report::default()
        },
        Outcome::Ran(c) => {
            let path = map_path.clone().unwrap_or_else(|| "System.map".into());
            let mut findings =
                findings_for(&c, &path, exact_version, lists_data_symbols(&kall_text));
            findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
            Report {
                findings,
                available: true,
                reason: None,
                map_path,
                release,
                compared: c.compared,
                slide: Some(c.slide),
            }
        }
    }
}
