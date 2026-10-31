use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use crate::rootkit::{Finding, Severity};

#[derive(Debug, Clone, Default)]
pub struct Report {

    pub findings: Vec<Finding>,

    pub available: bool,

    pub reason: Option<String>,

    pub proc_count: usize,

    pub sysfs_count: usize,

    pub tagged_count: usize,

    pub taint: u64,
}

pub(crate) fn name_key(bytes: &[u8]) -> Cow<'_, str> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if !text.contains('\\') {
            return Cow::Borrowed(text);
        }
    }
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(&chunk.valid().replace('\\', "\\\\"));
        for b in chunk.invalid() {
            let _ = write!(out, "\\x{b:02x}");
        }
    }
    Cow::Owned(out)
}

fn proc_module_names(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

fn kallsyms_module_tags(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        if let Some(tok) = line.split_whitespace().nth(3) {
            if let Some(name) = tok.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
                if !name.is_empty() {
                    out.insert(name.to_string());
                }
            }
        }
    }
    out
}

fn hidden_modules(
    proc: &BTreeSet<String>,
    sysfs: &BTreeSet<String>,
    tags: &BTreeSet<String>,
) -> Vec<(String, Vec<&'static str>)> {
    let mut out = Vec::new();
    for name in sysfs {
        if proc.contains(name) {
            continue;
        }
        let mut sources = vec!["/sys/module"];
        if tags.contains(name) {
            sources.push("kallsyms symbol tags");
        }
        out.push((name.clone(), sources));
    }
    out
}

fn sysfs_loaded_modules() -> Option<BTreeSet<String>> {
    loaded_modules_in(Path::new("/sys/module"))
}

fn loaded_modules_in(sys_module: &Path) -> Option<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    let dir = fs::read_dir(sys_module).ok()?;
    for entry in dir.flatten() {
        if fs::metadata(entry.path().join("initstate")).is_ok() {
            out.insert(name_key(entry.file_name().as_bytes()).into_owned());
        }
    }
    Some(out)
}

const TAINT_OOT_MODULE: u64 = 1 << 12;

const TAINT_UNSIGNED_MODULE: u64 = 1 << 13;

fn global_taint() -> Option<u64> {
    crate::saferead::read_kernel_text("/proc/sys/kernel/tainted")
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn accounted_taint_letters() -> Option<BTreeSet<char>> {
    let mut out = BTreeSet::new();
    let dir = fs::read_dir("/sys/module").ok()?;
    for entry in dir.flatten() {

        let path = entry.path().join("taint");
        if let Ok(s) = crate::saferead::read_kernel_text(&path) {
            out.extend(s.trim().chars());
        }
    }
    Some(out)
}

fn unaccounted_module_taint(global: u64, accounted: &BTreeSet<char>) -> Vec<(char, &'static str)> {
    let mut out = Vec::new();
    if global & TAINT_OOT_MODULE != 0 && !accounted.contains(&'O') {
        out.push(('O', "an out-of-tree module"));
    }
    if global & TAINT_UNSIGNED_MODULE != 0 && !accounted.contains(&'E') {
        out.push(('E', "an unsigned module"));
    }
    out
}

fn skip_findings(skipped: &[(&str, &str)]) -> Vec<Finding> {
    skipped
        .iter()
        .map(|(check, why)| Finding {
            severity: Severity::Note,
            subject: format!("{check} cross-view skipped"),
            what: format!("the {check} check did not run: {why}"),
            why: "this is 'could not look', not 'nothing there' — a self-hiding module is \
                  found by comparing two views of the same list, and with one of them missing \
                  nothing in this report says whether one is loaded"
                .into(),
        })
        .collect()
}

struct Views {

    proc: BTreeSet<String>,

    sysfs: Option<BTreeSet<String>>,

    tags: Option<BTreeSet<String>>,

    taint: Option<u64>,

    accounted: Option<BTreeSet<char>>,
}

fn cross_views(v: &Views) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut skipped: Vec<(&str, &str)> = Vec::new();

    if v.sysfs.is_none() {
        skipped.push(("/sys/module", "the sysfs module directory could not be listed"));
    }
    if v.tags.is_none() {
        skipped.push(("/proc/kallsyms", "the kernel symbol table could not be read"));
    }
    let sysfs = v.sysfs.clone().unwrap_or_default();
    let tags = v.tags.clone().unwrap_or_default();
    for (name, sources) in hidden_modules(&v.proc, &sysfs, &tags) {
        findings.push(Finding {
            severity: Severity::Critical,
            subject: format!("hidden module `{name}`"),
            what: format!(
                "is present in {} but absent from /proc/modules",
                sources.join(" and ")
            ),
            why: "a loaded kernel module missing from /proc/modules has unlinked itself from the \
                  list lsmod walks — the self-hiding a kernel rootkit does first (list_del on its \
                  own module). It left the sysfs directory or its exported symbols behind, which \
                  is how this catches it. Identify and unload it; treat the host as compromised"
                .into(),
        });
    }

    match (v.taint, &v.accounted) {
        (Some(mask), Some(accounted)) => {
            for (letter, desc) in unaccounted_module_taint(mask, accounted) {
                findings.push(Finding {
                    severity: Severity::Warn,
                    subject: format!("unaccounted kernel taint '{letter}'"),
                    what: format!(
                        "the kernel carries the module taint '{letter}' but no module in \
                         /sys/module accounts for it — {desc} tainted this kernel and is not \
                         visible"
                    ),
                    why: "the global taint mask is set when a module taints the kernel and is \
                          NOT cleared when that module unloads, so this is a lead, not proof: \
                          either a tainting module was loaded and unloaded, or one is hidden \
                          from /sys/module as well as /proc/modules — the harder self-hide the \
                          module cross-view above cannot see. On a freshly-booted host that \
                          loaded no such module legitimately, treat it as a hidden module and \
                          hunt it with the kcore module-list walk"
                        .into(),
                });
            }
        }
        _ => skipped.push((
            "kernel taint",
            "the global taint mask or the per-module taint files could not be read",
        )),
    }

    findings.extend(skip_findings(&skipped));
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    findings
}

pub fn report() -> Report {

    let Ok(proc_text) = crate::saferead::read_kernel_bytes("/proc/modules").map(|b| name_key(&b).into_owned()) else {
        return Report {
            available: false,
            reason: Some("/proc/modules could not be read, so no baseline to compare against".into()),
            ..Report::default()
        };
    };
    let v = Views {
        proc: proc_module_names(&proc_text),
        sysfs: sysfs_loaded_modules(),
        tags: crate::saferead::read_kernel_bytes("/proc/kallsyms").ok().map(|t| kallsyms_module_tags(&name_key(&t))),
        taint: global_taint(),
        accounted: accounted_taint_letters(),
    };
    Report {
        findings: cross_views(&v),
        available: true,
        reason: None,
        proc_count: v.proc.len(),
        sysfs_count: v.sysfs.as_ref().map_or(0, BTreeSet::len),
        tagged_count: v.tags.as_ref().map_or(0, BTreeSet::len),
        taint: v.taint.unwrap_or(0),
    }
}
