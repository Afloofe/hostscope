use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::rootkit::{Finding, Severity};

pub(crate) const WATCHED_FNS: &[&str] = &[

    "__x64_sys_getdents64",
    "__x64_sys_getdents",
    "ksys_getdents64",
    "__x64_sys_kill",
    "__x64_sys_newuname",

    "filldir",
    "filldir64",

    "__x64_sys_execve",
    "__x64_sys_execveat",
    "__x64_sys_ptrace",
    "__x64_sys_openat",
    "__x64_sys_read",
    "__x64_sys_write",

    "__x64_sys_finit_module",
    "__x64_sys_init_module",
    "__x64_sys_delete_module",

    "__x64_sys_bpf",

    "tcp4_seq_show",
    "tcp6_seq_show",
    "udp4_seq_show",
    "udp6_seq_show",

    "x64_sys_call",
    "do_syscall_64",
];

const SYSCALL_TABLE_MAX: usize = 512;

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,

    pub functions_checked: usize,

    pub table_entries_checked: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleRange {
    pub(crate) name: String,
    pub(crate) base: u64,
    pub(crate) size: u64,
}

impl ModuleRange {
    pub(crate) fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base.saturating_add(self.size)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Redirect {

    None,

    Trampoline { kind: &'static str, target: Option<u64> },
}

pub(crate) fn parse_kallsyms(text: &str) -> (BTreeMap<String, u64>, Vec<u64>) {
    let mut by_name = BTreeMap::new();
    let mut addrs = Vec::new();
    for line in text.lines() {
        let mut f = line.split_whitespace();
        let (Some(addr), Some(_ty), Some(name)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if let Ok(a) = u64::from_str_radix(addr, 16) {
            addrs.push(a);

            by_name.entry(name.to_string()).or_insert(a);
        }
    }
    addrs.sort_unstable();
    addrs.dedup();
    (by_name, addrs)
}

fn next_addr(sorted: &[u64], addr: u64) -> u64 {
    match sorted.binary_search(&addr) {
        Ok(i) => sorted.get(i + 1).copied().unwrap_or(addr.saturating_add(64)),

        Err(i) => sorted.get(i).copied().unwrap_or(addr.saturating_add(64)),
    }
}

fn table_entry_count(sorted: &[u64], table: u64) -> usize {
    ((next_addr(sorted, table).saturating_sub(table) / 8) as usize).clamp(1, SYSCALL_TABLE_MAX)
}

pub(crate) fn kallsyms_is_restricted(by_name: &BTreeMap<String, u64>) -> bool {
    !by_name.is_empty() && by_name.values().all(|a| *a == 0)
}

pub(crate) fn parse_modules(text: &str) -> Vec<ModuleRange> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (Some(name), Some(size)) = (f.first(), f.get(1)) else {
            continue;
        };

        let base = f.iter().find_map(|t| {
            t.strip_prefix("0x").and_then(|h| u64::from_str_radix(h, 16).ok())
        });
        let size = size.parse::<u64>().unwrap_or(0);
        let base = base.unwrap_or(0);
        if base != 0 && size != 0 {
            out.push(ModuleRange { name: (*name).to_string(), base, size });
        }
    }
    out
}

pub(crate) fn module_at(modules: &[ModuleRange], addr: u64) -> Option<&ModuleRange> {
    modules.iter().find(|m| m.contains(addr))
}

pub(crate) fn ktext_bounds(by_name: &BTreeMap<String, u64>) -> Option<(u64, u64)> {
    match (by_name.get("_stext"), by_name.get("_etext")) {
        (Some(&s), Some(&e)) if e > s => Some((s, e)),
        _ => None,
    }
}

pub(crate) struct Kcore {
    file: File,
    segments: Vec<(u64, u64, u64)>,
}

impl Kcore {

    pub(crate) fn open() -> std::io::Result<Self> {
        let mut file = File::open("/proc/kcore")?;
        let mut ehdr = [0u8; 64];
        file.read_exact(&mut ehdr)?;
        if ehdr.get(0..4) != Some(b"\x7fELF".as_slice()) || ehdr.get(4) != Some(&2) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "/proc/kcore is not an ELF64 image",
            ));
        }
        let phoff = le_u64(&ehdr, 32);
        let phentsize = u64::from(le_u16(&ehdr, 54));
        let phnum = le_u16(&ehdr, 56) as usize;

        if phentsize < 56 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("/proc/kcore declares a {phentsize}-byte program header (needs >= 56)"),
            ));
        }

        let mut segments = Vec::new();
        for i in 0..phnum {
            let mut ph = [0u8; 56];
            let at = (i as u64)
                .checked_mul(phentsize)
                .and_then(|off| phoff.checked_add(off))
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "/proc/kcore program-header table overflows a 64-bit offset",
                    )
                })?;
            file.seek(SeekFrom::Start(at))?;
            file.read_exact(&mut ph)?;
            if le_u32(&ph, 0) != 1 {
                continue;
            }
            let p_offset = le_u64(&ph, 8);
            let p_vaddr = le_u64(&ph, 16);
            let p_memsz = le_u64(&ph, 40);
            if p_memsz != 0 {
                segments.push((p_vaddr, p_memsz, p_offset));
            }
        }
        Ok(Self { file, segments })
    }

    pub(crate) fn read_at(&mut self, va: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let off = translate(&self.segments, va).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("va {va:#x} is in no kcore PT_LOAD segment"),
            )
        })?;
        self.file.seek(SeekFrom::Start(off))?;
        self.file.read_exact(buf)
    }
}

fn le_u16(b: &[u8], off: usize) -> u16 {
    b.get(off..off + 2).and_then(|s| s.try_into().ok()).map_or(0, u16::from_le_bytes)
}
fn le_u32(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4).and_then(|s| s.try_into().ok()).map_or(0, u32::from_le_bytes)
}
fn le_u64(b: &[u8], off: usize) -> u64 {
    b.get(off..off + 8).and_then(|s| s.try_into().ok()).map_or(0, u64::from_le_bytes)
}
fn le_i32(b: &[u8], off: usize) -> i32 {
    b.get(off..off + 4).and_then(|s| s.try_into().ok()).map_or(0, i32::from_le_bytes)
}

fn translate(segments: &[(u64, u64, u64)], va: u64) -> Option<u64> {
    for &(vaddr, memsz, offset) in segments {
        if va >= vaddr && va < vaddr.saturating_add(memsz) {

            return offset.checked_add(va - vaddr);
        }
    }
    None
}

fn decode_entry_trampoline(bytes: &[u8], fn_start: u64) -> Redirect {

    let skipped: usize = if bytes.starts_with(&[0xf3, 0x0f, 0x1e, 0xfa]) { 4 } else { 0 };
    let b = bytes.get(skipped..).unwrap_or(&[]);
    let at = |i: usize| b.get(i).copied();

    if at(0) == Some(0x48) && at(1) == Some(0xb8) {
        let target = le_u64(b, 2);

        if b.get(10..).is_some_and(|t| window_has(t, &[0xff, 0xe0], 6)) {
            return Redirect::Trampoline { kind: "movabs rax; jmp rax", target: Some(target) };
        }
    }

    if at(0) == Some(0x49) && at(1) == Some(0xbb) {
        let target = le_u64(b, 2);
        if b.get(10..).is_some_and(|t| window_has(t, &[0x41, 0xff, 0xe3], 4)) {
            return Redirect::Trampoline { kind: "movabs r11; jmp r11", target: Some(target) };
        }
    }

    if at(0) == Some(0xe9) && b.len() >= 5 {
        let rel = le_i32(b, 1);

        let ip_after = fn_start.wrapping_add(skipped as u64).wrapping_add(5);
        let target = ip_after.wrapping_add(rel as i64 as u64);
        return Redirect::Trampoline { kind: "jmp rel32", target: Some(target) };
    }

    if at(0) == Some(0x68) && at(5) == Some(0xc3) {
        return Redirect::Trampoline { kind: "push; ret", target: Some(u64::from(le_u32(b, 1))) };
    }

    if at(0) == Some(0xff) && at(1) == Some(0x25) {
        return Redirect::Trampoline { kind: "jmp [rip+disp]", target: None };
    }
    Redirect::None
}

fn window_has(hay: &[u8], needle: &[u8], within: usize) -> bool {
    let end = hay.len().min(within + needle.len());
    hay.get(..end)
        .map(|h| h.windows(needle.len()).any(|w| w == needle))
        .unwrap_or(false)
}

fn prologue_finding(
    subject: &str,
    redirect: &Redirect,
    fn_start: u64,
    fn_end: u64,
    modules: &[ModuleRange],
    ktext: Option<(u64, u64)>,
) -> Option<Finding> {
    let Redirect::Trampoline { kind, target } = redirect else {
        return None;
    };
    let base = format!("its entry begins with an inline `{kind}` trampoline");
    match target {
        Some(t) if *t >= fn_start && *t < fn_end => None,
        Some(t) => {
            if let Some(m) = module_at(modules, *t) {
                Some(Finding {
                    severity: Severity::Critical,
                    subject: subject.to_string(),
                    what: format!("{base} that jumps to {t:#x}, inside loaded module `{}`", m.name),
                    why: format!(
                        "a syscall handler whose first instruction jumps into a loaded module is \
                         an inline kernel hook — the goofkit class patches the prologue exactly \
                         this way. This is read from kernel text via /proc/kcore, so it does not \
                         depend on any magic string or on whether the rootkit also hooks stat. \
                         Identify module `{}` (it is not hidden from /proc/modules unless it also \
                         unlinked itself) and treat the host as compromised",
                        m.name
                    ),
                })
            } else if ktext.is_some_and(|(s, e)| *t < s || *t >= e) {
                Some(Finding {
                    severity: Severity::Critical,
                    subject: subject.to_string(),
                    what: format!("{base} that jumps to {t:#x}, outside kernel text"),
                    why: "a syscall handler redirected outside the kernel's own .text — into the \
                          module space, a data page, or freshly allocated executable memory — is \
                          an inline hook, whatever installed it"
                        .into(),
                })
            } else {
                Some(Finding {
                    severity: Severity::Warn,
                    subject: subject.to_string(),
                    what: format!("{base} that jumps to {t:#x}, elsewhere in kernel text"),
                    why: "the compiler does not emit a jump trampoline at a syscall entry; this \
                          one stays inside kernel text, so it may be a legitimate static call or \
                          it may be a hook whose handler sits in the kernel's own text — worth \
                          resolving the target symbol before trusting the host"
                        .into(),
                })
            }
        }
        None => Some(Finding {
            severity: Severity::Warn,
            subject: subject.to_string(),
            what: format!("{base} whose destination is an indirect pointer"),
            why: "an indirect jump at a function entry is not something the toolchain emits here; \
                  read the pointer it dereferences to see where control actually goes"
                .into(),
        }),
    }
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
             kernel.kptr_restrict permitting symbol addresses; without them the kernel-text scan \
             cannot locate a single function and did not run",
        );
    }

    let mut kcore = match Kcore::open() {
        Ok(k) => k,
        Err(e) => {
            return unavailable(&format!(
                "/proc/kcore could not be opened ({e}) — this needs root and a kernel not in \
                 lockdown-confidentiality; the kernel-text scan did not run"
            ));
        }
    };

    let modules_read = crate::saferead::read_kernel_text("/proc/modules");
    let modules = modules_read.as_ref().map(|t| parse_modules(t)).unwrap_or_default();
    let ktext = ktext_bounds(&by_name);

    let mut findings = Vec::new();

    findings.extend(crate::kptrhooks::partial_scan(
        "syscall-hooks",
        modules_read.is_err(),
        ktext.is_none(),
    ));
    let mut functions_checked = 0;

    for name in WATCHED_FNS {
        let Some(&start) = by_name.get(*name) else { continue };
        let end = next_addr(&sorted, start);
        let mut buf = [0u8; 16];
        if kcore.read_at(start, &mut buf).is_err() {
            continue;
        }
        functions_checked += 1;
        let redirect = decode_entry_trampoline(&buf, start);
        if let Some(f) = prologue_finding(name, &redirect, start, end, &modules, ktext) {
            findings.push(f);
        }
    }

    let mut table_entries_checked = 0;
    if let Some(&table) = by_name.get("sys_call_table") {

        let count = table_entry_count(&sorted, table);
        let mut raw = vec![0u8; count * 8];
        if kcore.read_at(table, &mut raw).is_ok() {
            for nr in 0..count {
                let ptr = le_u64(&raw, nr * 8);
                if ptr == 0 {
                    continue;
                }
                table_entries_checked += 1;
                if let Some(m) = module_at(&modules, ptr) {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        subject: format!("sys_call_table[{nr}]"),
                        what: format!("points to {ptr:#x}, inside loaded module `{}`", m.name),
                        why: format!(
                            "a live syscall whose table entry lands in a module is a classic \
                             syscall-table hook; the handler for syscall {nr} has been replaced \
                             by code in module `{}`",
                            m.name
                        ),
                    });
                } else if ktext.is_some_and(|(s, e)| ptr < s || ptr >= e) {
                    findings.push(Finding {
                        severity: Severity::Warn,
                        subject: format!("sys_call_table[{nr}]"),
                        what: format!("points to {ptr:#x}, outside kernel text"),
                        why: "a syscall table entry should point into the kernel's own .text; one \
                              that does not has been redirected"
                            .into(),
                    });
                }
            }
        }
    }

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    Report {
        findings,
        available: true,
        reason: None,
        functions_checked,
        table_entries_checked,
    }
}

fn unavailable(reason: &str) -> Report {
    Report {
        findings: Vec::new(),
        available: false,
        reason: Some(reason.to_string()),
        functions_checked: 0,
        table_entries_checked: 0,
    }
}
