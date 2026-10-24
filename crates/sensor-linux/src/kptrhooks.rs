use std::collections::BTreeSet;

use crate::rootkit::{Finding, Severity};
use crate::syscallhook::{
    kallsyms_is_restricted, ktext_bounds, module_at, parse_kallsyms, parse_modules, Kcore,
    ModuleRange,
};

const OPS_SYMBOLS: &[&str] = &[

    "tcp4_seq_afinfo",
    "tcp6_seq_afinfo",
    "udp4_seq_afinfo",
    "udp6_seq_afinfo",
    "tcp4_seq_ops",
    "tcp6_seq_ops",
    "udp_seq_ops",
    "udp6_seq_ops",

    "proc_root_operations",
    "proc_root_inode_operations",
];

const MAX_SLOTS: usize = 8;

const KERNEL_CANONICAL_MIN: u64 = 0xffff_8000_0000_0000;

const NETFILTER_FAMILY_PREFIXES: &[&str] = &[
    "nf_", "nft_", "nft", "xt_", "x_tables", "iptable_", "ip_tables", "ip6table_", "ip6_tables",
    "ip6t_", "ipt_", "arptable_", "arp_tables", "ebtable", "ebt_", "br_netfilter", "nfnetlink",
    "ip_set", "ip_vs", "ipvs",
];

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,

    pub ops_structs_checked: usize,

    pub pointers_checked: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PtrClass {

    NotKernelPtr,

    InText,

    InModule(String),

    KnownOutsideText,

    Unaccounted,
}

fn classify_pointer(
    ptr: u64,
    ktext: (u64, u64),
    modules: &[ModuleRange],
    known: &BTreeSet<u64>,
) -> PtrClass {
    if ptr < KERNEL_CANONICAL_MIN {
        return PtrClass::NotKernelPtr;
    }
    let (stext, etext) = ktext;
    if ptr >= stext && ptr < etext {
        return PtrClass::InText;
    }
    if let Some(m) = module_at(modules, ptr) {
        return PtrClass::InModule(m.name.clone());
    }

    if known.contains(&ptr) {
        PtrClass::KnownOutsideText
    } else {
        PtrClass::Unaccounted
    }
}

fn slot_finding(struct_name: &str, ptr: u64, class: &PtrClass) -> Option<Finding> {
    match class {
        PtrClass::InModule(module) => Some(Finding {
            severity: Severity::Warn,
            subject: format!("ops struct `{struct_name}`"),
            what: format!(
                "holds a function pointer {ptr:#x} that resolves into loaded module `{module}`"
            ),
            why: format!(
                "a built-in VFS/seq_file ops struct whose function pointer lands in a loaded \
                 module is the shape of a connection- or file-hiding hook — a rewritten \
                 tcp4_seq_show filters /proc/net/tcp, a rewritten iterate/filldir hides files \
                 below getdents. This is read from kernel memory via /proc/kcore, but struct \
                 offsets vary by kernel, so validate the layout in-guest before acting; then \
                 identify module `{module}`"
            ),
        }),
        PtrClass::Unaccounted => Some(Finding {

            severity: Severity::Warn,
            subject: format!("ops struct `{struct_name}`"),
            what: format!(
                "holds a pointer {ptr:#x} that lands outside all kernel text and every loaded \
                 module and matches no kallsyms symbol"
            ),
            why: "if this slot is a function pointer, a target that is neither kernel .text nor \
                  any loaded module nor any named symbol is the shape of a hook into unaccounted \
                  executable memory. But a blind window read cannot prove this slot is a function \
                  pointer rather than a data pointer, and struct offsets vary by kernel — so this \
                  is a LEAD: confirm against the running kernel's real struct layout (and rule out \
                  a data field) before acting"
                .into(),
        }),

        PtrClass::NotKernelPtr | PtrClass::InText | PtrClass::KnownOutsideText => None,
    }
}

fn window_slots(sorted: &[u64], addr: u64) -> usize {
    let next = match sorted.binary_search(&addr) {
        Ok(i) => sorted.get(i + 1).copied().unwrap_or(addr.saturating_add(64)),
        Err(i) => sorted.get(i).copied().unwrap_or(addr.saturating_add(64)),
    };
    ((next.saturating_sub(addr) / 8) as usize).clamp(1, MAX_SLOTS)
}

pub(crate) fn partial_scan(which: &str, no_modules: bool, no_text_bounds: bool) -> Option<Finding> {
    let missing = match (no_modules, no_text_bounds) {
        (false, false) => return None,
        (true, false) => "/proc/modules could not be read, so a pointer into a module cannot be named as one",
        (false, true) => "kallsyms gave no _stext/_etext, so a pointer outside kernel text cannot be told apart",
        (true, true) => "neither /proc/modules nor the kernel-text bounds were available, so no pointer could be classified",
    };
    Some(Finding {
        severity: Severity::Note,
        subject: format!("{which} coverage"),
        what: format!("ran in part: {missing}"),
        why: "the checks that need these did not run; their silence below is not a clean result"
            .into(),
    })
}

fn loaded_module_names(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

fn looks_like_nf_hook(sym: &str) -> bool {
    sym.contains("nf_hook") || sym.contains("netfilter_hook") || sym.contains("nfhook")
}

fn is_netfilter_family(module: &str) -> bool {
    NETFILTER_FAMILY_PREFIXES.iter().any(|p| module.starts_with(p))
}

fn netfilter_hook_modules(kallsyms: &str, loaded: &BTreeSet<String>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in kallsyms.lines() {
        let mut f = line.split_whitespace();
        let (Some(_addr), Some(_ty), Some(name)) = (f.next(), f.next(), f.next()) else {
            continue;
        };

        let Some(module) = f
            .next()
            .and_then(|t| t.strip_prefix('['))
            .and_then(|t| t.strip_suffix(']'))
        else {
            continue;
        };
        if module.is_empty() || !loaded.contains(module) || is_netfilter_family(module) {
            continue;
        }
        if looks_like_nf_hook(name) {
            let hit = (module.to_string(), name.to_string());
            if !out.contains(&hit) {
                out.push(hit);
            }
        }
    }
    out
}

fn le_u64(b: &[u8], off: usize) -> u64 {
    b.get(off..off + 8).and_then(|s| s.try_into().ok()).map_or(0, u64::from_le_bytes)
}

pub fn report() -> Report {
    let Ok(kallsyms) = crate::saferead::read_kernel_text("/proc/kallsyms") else {
        return unavailable("/proc/kallsyms could not be read");
    };
    let (by_name, sorted) = parse_kallsyms(&kallsyms);
    if by_name.is_empty() {
        return unavailable("/proc/kallsyms was empty");
    }
    if kallsyms_is_restricted(&by_name) {
        return unavailable(
            "/proc/kallsyms returned only zeroed addresses — this needs root (CAP_SYSLOG) and \
             kernel.kptr_restrict permitting symbol addresses; without them no ops struct can be \
             located and the function-pointer scan did not run",
        );
    }
    let Some(ktext) = ktext_bounds(&by_name) else {
        return unavailable(
            "kallsyms did not expose _stext/_etext, so 'inside kernel text' could not be judged \
             and the function-pointer scan did not run",
        );
    };

    let mut kcore = match Kcore::open() {
        Ok(k) => k,
        Err(e) => {
            return unavailable(&format!(
                "/proc/kcore could not be opened ({e}) — this needs root and a kernel not in \
                 lockdown-confidentiality; the function-pointer scan did not run"
            ));
        }
    };

    let modules_text = match crate::saferead::read_kernel_text("/proc/modules") {
        Ok(t) => t,
        Err(e) => {
            return unavailable(&format!(
                "/proc/modules could not be read ({e}) — without the loaded-module ranges the \
                 pointer classification is unreliable, so the function-pointer scan did not run"
            ));
        }
    };
    let modules = parse_modules(&modules_text);
    let loaded = loaded_module_names(&modules_text);
    let known: BTreeSet<u64> = sorted.iter().copied().collect();

    let mut findings = Vec::new();
    let mut ops_structs_checked = 0;
    let mut pointers_checked = 0;

    for sym in OPS_SYMBOLS {
        let Some(&addr) = by_name.get(*sym) else {
            continue;
        };
        let slots = window_slots(&sorted, addr);
        let mut buf = vec![0u8; slots * 8];
        if kcore.read_at(addr, &mut buf).is_err() {
            continue;
        }
        ops_structs_checked += 1;
        for i in 0..slots {
            let ptr = le_u64(&buf, i * 8);
            let class = classify_pointer(ptr, ktext, &modules, &known);
            if class != PtrClass::NotKernelPtr {
                pointers_checked += 1;
            }
            if let Some(f) = slot_finding(sym, ptr, &class) {
                findings.push(f);
            }
        }
    }

    for (module, sym) in netfilter_hook_modules(&kallsyms, &loaded) {
        findings.push(Finding {
            severity: Severity::Warn,
            subject: format!("module `{module}`"),
            what: format!(
                "defines a netfilter-hook-shaped symbol `{sym}` and is not a recognised in-tree \
                 netfilter module"
            ),
            why: "a loaded module outside the in-tree netfilter family (nf_*, xt_*, iptable_*, \
                  nft_*) that ships a netfilter-hook handler may have registered its own nf_hook \
                  to drop, redirect, or exfiltrate traffic — a common C2 and port-knock \
                  primitive. This is a heuristic from kallsyms symbol names, not a registration \
                  read, so it is a lead: confirm with a net->nf.hooks kcore walk in-guest"
                .into(),
        });
    }

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    Report {
        findings,
        available: true,
        reason: None,
        ops_structs_checked,
        pointers_checked,
    }
}

fn unavailable(reason: &str) -> Report {
    Report {
        findings: Vec::new(),
        available: false,
        reason: Some(reason.to_string()),
        ops_structs_checked: 0,
        pointers_checked: 0,
    }
}
